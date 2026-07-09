import express from "express";
import multer from "multer";
import path from "path";
import crypto from "crypto";
import session from "express-session";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 20 * 1024 * 1024 }, // batas Open Cloud: 20 MB per aset
});

const {
  ROBLOX_CLIENT_ID,
  ROBLOX_CLIENT_SECRET,
  ROBLOX_REDIRECT_URI,
  SESSION_SECRET,
} = process.env;

app.set("trust proxy", 1);
app.use(express.static(path.join(__dirname, "public")));
app.use(express.json());

app.use(
  session({
    name: "ru_sid",
    secret: SESSION_SECRET || "ganti-string-rahasia-ini-di-.env",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 24 * 7, // 7 hari
    },
  })
);

const ROBLOX_ASSETS_URL = "https://apis.roblox.com/assets/v1/assets";
const OAUTH_AUTHORIZE_URL = "https://apis.roblox.com/oauth/v1/authorize";
const OAUTH_TOKEN_URL = "https://apis.roblox.com/oauth/v1/token";
const OAUTH_USERINFO_URL = "https://apis.roblox.com/oauth/v1/userinfo";
const OAUTH_REVOKE_URL = "https://apis.roblox.com/oauth/v1/token/revoke";

// Scope yang dibutuhkan tool ini. Sesuaikan dengan yang dicentang di
// Creator Dashboard -> OAuth Apps saat membuat aplikasi.
// CATATAN: Roblox belum menyediakan scope OAuth untuk publish Place
// (universe-place:write bukan scope yang valid per dokumentasi resmi Roblox,
// publish Place hanya didukung lewat Open Cloud API Key biasa).
const OAUTH_SCOPES = "openid profile asset:read asset:write group:read";

function base64url(buf) {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function oauthConfigured() {
  return Boolean(ROBLOX_CLIENT_ID && ROBLOX_CLIENT_SECRET && ROBLOX_REDIRECT_URI);
}

// ===================== LOGIN DENGAN ROBLOX (OAuth2 + PKCE) =====================

// Mulai proses login: redirect user ke halaman authorize resmi Roblox.
app.get("/auth/login", (req, res) => {
  if (!oauthConfigured()) {
    return res
      .status(500)
      .send("Server belum dikonfigurasi. Isi ROBLOX_CLIENT_ID, ROBLOX_CLIENT_SECRET, dan ROBLOX_REDIRECT_URI di .env (lihat README).");
  }

  const state = base64url(crypto.randomBytes(16));
  const codeVerifier = base64url(crypto.randomBytes(32));
  const codeChallenge = base64url(crypto.createHash("sha256").update(codeVerifier).digest());

  req.session.oauth = { state, codeVerifier };

  const url = new URL(OAUTH_AUTHORIZE_URL);
  url.searchParams.set("client_id", ROBLOX_CLIENT_ID);
  url.searchParams.set("redirect_uri", ROBLOX_REDIRECT_URI);
  url.searchParams.set("scope", OAUTH_SCOPES);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("state", state);
  url.searchParams.set("code_challenge", codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");

  res.redirect(url.toString());
});

// Roblox redirect balik ke sini setelah user login & approve di roblox.com.
app.get("/auth/callback", async (req, res) => {
  try {
    const { code, state, error, error_description } = req.query;

    if (error) {
      return res.status(400).send("Login Roblox dibatalkan/gagal: " + (error_description || error));
    }

    const saved = req.session.oauth;
    if (!saved || !code || state !== saved.state) {
      return res.status(400).send("State tidak cocok (kadaluarsa atau CSRF). Silakan login ulang.");
    }

    const body = new URLSearchParams({
      client_id: ROBLOX_CLIENT_ID,
      client_secret: ROBLOX_CLIENT_SECRET,
      grant_type: "authorization_code",
      code: String(code),
      redirect_uri: ROBLOX_REDIRECT_URI,
      code_verifier: saved.codeVerifier,
    });

    const tokenRes = await fetch(OAUTH_TOKEN_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });
    const tokenData = await tokenRes.json();

    if (!tokenRes.ok) {
      return res
        .status(400)
        .send("Gagal menukar kode login jadi token: " + (tokenData.error_description || tokenData.error || JSON.stringify(tokenData)));
    }

    const userRes = await fetch(OAUTH_USERINFO_URL, {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const userInfo = await userRes.json();

    req.session.tokens = {
      accessToken: tokenData.access_token,
      refreshToken: tokenData.refresh_token,
      expiresAt: Date.now() + (tokenData.expires_in || 3600) * 1000,
    };
    req.session.user = {
      id: userInfo.sub,
      username: userInfo.preferred_username || userInfo.nickname || userInfo.name || userInfo.sub,
      displayName: userInfo.name || userInfo.nickname,
    };
    delete req.session.oauth;

    res.redirect("/");
  } catch (err) {
    console.error(err);
    res.status(500).send("Terjadi kesalahan saat login: " + err.message);
  }
});

// Dipanggil frontend untuk tahu status login saat ini.
app.get("/auth/me", (req, res) => {
  if (!req.session.user || !req.session.tokens) {
    return res.json({ loggedIn: false, oauthConfigured: oauthConfigured() });
  }
  res.json({ loggedIn: true, user: req.session.user });
});

// Logout: hapus sesi lokal + cabut token di sisi Roblox.
app.post("/auth/logout", async (req, res) => {
  const tokens = req.session.tokens;
  req.session.destroy(async () => {
    res.clearCookie("ru_sid");
    if (tokens?.refreshToken && oauthConfigured()) {
      try {
        await fetch(OAUTH_REVOKE_URL, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            client_id: ROBLOX_CLIENT_ID,
            client_secret: ROBLOX_CLIENT_SECRET,
            token: tokens.refreshToken,
          }),
        });
      } catch (e) {
        console.error("Gagal revoke token ke Roblox:", e.message);
      }
    }
    res.json({ ok: true });
  });
});

// Pastikan access token masih hidup, refresh otomatis kalau sudah/hampir kadaluarsa.
async function ensureAccessToken(req) {
  const t = req.session.tokens;
  if (!t) return null;
  if (Date.now() < t.expiresAt - 30_000) return t.accessToken;
  if (!t.refreshToken) return null;

  const resp = await fetch(OAUTH_TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: ROBLOX_CLIENT_ID,
      client_secret: ROBLOX_CLIENT_SECRET,
      grant_type: "refresh_token",
      refresh_token: t.refreshToken,
    }),
  });
  const data = await resp.json();
  if (!resp.ok) return null;

  req.session.tokens = {
    accessToken: data.access_token,
    refreshToken: data.refresh_token || t.refreshToken,
    expiresAt: Date.now() + (data.expires_in || 3600) * 1000,
  };
  return req.session.tokens.accessToken;
}

// Middleware: wajib sudah login lewat /auth/login sebelum akses endpoint Roblox.
async function requireAuth(req, res, next) {
  const token = await ensureAccessToken(req);
  if (!token) {
    return res.status(401).json({ error: "Belum login Roblox. Klik \"Login dengan Roblox\" dulu.", needLogin: true });
  }
  req.robloxAccessToken = token;
  next();
}

// ===================== ENDPOINT ROBLOX (pakai token OAuth, bukan API key) =====================

// Upload aset baru (Model .rbxm/.rbxmx)
app.post("/api/upload", requireAuth, upload.single("file"), async (req, res) => {
  try {
    const { assetType, displayName, description, creatorType, creatorId } = req.body;

    if (!req.file) return res.status(400).json({ error: "File model wajib dipilih." });
    if (!creatorId) return res.status(400).json({ error: "User ID / Group ID wajib diisi." });

    const creator =
      creatorType === "group" ? { groupId: String(creatorId) } : { userId: String(creatorId) };

    const requestPayload = {
      assetType: assetType || "Model",
      displayName: displayName || req.file.originalname,
      description: description || "",
      creationContext: { creator },
    };

    // Roblox mewajibkan MIME type spesifik sesuai jenis aset dan ekstensi file.
    // "application/octet-stream" generik akan ditolak.
    const ext = path.extname(req.file.originalname).toLowerCase();

    const mimeByType = {
      Model: { ".rbxm": "model/x-rbxm", ".rbxmx": "model/x-rbxmx" },
      Animation: { ".rbxm": "model/x-rbxm", ".rbxmx": "model/x-rbxmx" },
      Audio: { ".mp3": "audio/mpeg", ".ogg": "audio/ogg" },
    };

    const allowedForType = mimeByType[requestPayload.assetType];
    if (!allowedForType) {
      return res.status(400).json({ error: "assetType tidak dikenali." });
    }

    const contentType = allowedForType[ext];
    if (!contentType) {
      const allowedExts = Object.keys(allowedForType).join(", ");
      return res.status(400).json({
        error: "Ekstensi file tidak didukung untuk jenis aset " + requestPayload.assetType + ". Gunakan: " + allowedExts,
      });
    }

    // Deteksi dini: file .rbxm/.rbxmx yang pernah di-"Convert to Package" di Studio
    // menyimpan instance PackageLink di dalamnya. Roblox akan tetap membuat asetnya
    // sebagai Package walau assetType di sini diset "Model", jadi kita cegat dari awal
    // supaya user tidak bingung kenapa hasil upload-nya beda dari yang diminta.
    const isModelLike = requestPayload.assetType === "Model" || requestPayload.assetType === "Animation";
    if (isModelLike && req.body.allowPackage !== "true") {
      const rawText = req.file.buffer.toString("latin1");
      if (rawText.includes("PackageLink")) {
        return res.status(400).json({
          error: "File ini terdeteksi mengandung data Package (PackageLink), bukan Model murni. Roblox akan otomatis membuatnya sebagai Package walau assetType diset \"" + requestPayload.assetType + "\".",
          isPackage: true,
        });
      }
    }

    const form = new FormData();
    form.append("request", JSON.stringify(requestPayload));
    form.append(
      "fileContent",
      new Blob([req.file.buffer], { type: contentType }),
      req.file.originalname
    );

    const robloxRes = await fetch(ROBLOX_ASSETS_URL, {
      method: "POST",
      headers: { Authorization: `Bearer ${req.robloxAccessToken}` },
      body: form,
    });

    const data = await robloxRes.json();

    if (!robloxRes.ok) {
      return res.status(robloxRes.status).json({
        error: data.message || "Roblox menolak permintaan upload.",
        detail: data,
      });
    }

    // Roblox mengembalikan objek Operation, mis. { path: "operations/abcd1234" }
    res.json(data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || "Terjadi kesalahan pada server lokal." });
  }
});

// Cek status Operation (proses upload di Roblox berjalan async)
app.get("/api/operation", requireAuth, async (req, res) => {
  try {
    const { opPath } = req.query;
    if (!opPath) return res.status(400).json({ error: "opPath wajib diisi." });

    const robloxRes = await fetch(`https://apis.roblox.com/assets/v1/${opPath}`, {
      headers: { Authorization: `Bearer ${req.robloxAccessToken}` },
    });

    const data = await robloxRes.json();

    if (!robloxRes.ok) {
      return res.status(robloxRes.status).json({
        error: data.message || "Gagal memeriksa status upload.",
        detail: data,
      });
    }

    res.json(data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || "Terjadi kesalahan pada server lokal." });
  }
});

// Publish file .rbxl/.rbxlx ke Place yang SUDAH ADA (harus dibuat manual dulu di roblox.com/Studio)
//
// CATATAN: Roblox belum menyediakan scope OAuth untuk publish Place, jadi
// endpoint ini TIDAK memakai requireAuth/token OAuth seperti endpoint lain
// -- tetap butuh Open Cloud API Key manual (dengan izin universe-places:write)
// yang dikirim dari form khusus di tab Publish Place.
app.post("/api/publish-place", upload.single("file"), async (req, res) => {
  try {
    const { apiKey, universeId, placeId, versionType } = req.body;

    if (!apiKey) return res.status(400).json({ error: "Open Cloud API Key wajib diisi (khusus fitur ini, belum didukung OAuth oleh Roblox)." });
    if (!universeId || !placeId) return res.status(400).json({ error: "Universe ID dan Place ID wajib diisi." });
    if (!req.file) return res.status(400).json({ error: "File .rbxl/.rbxlx wajib dipilih." });

    const ext = path.extname(req.file.originalname).toLowerCase();
    const contentTypeMap = { ".rbxl": "application/octet-stream", ".rbxlx": "application/xml" };
    const contentType = contentTypeMap[ext];
    if (!contentType) {
      return res.status(400).json({ error: "File harus berformat .rbxl atau .rbxlx." });
    }

    const vType = versionType === "Saved" ? "Saved" : "Published";
    const url = `https://apis.roblox.com/universes/v1/${universeId}/places/${placeId}/versions?versionType=${vType}`;

    const robloxRes = await fetch(url, {
      method: "POST",
      headers: {
        "x-api-key": apiKey,
        "Content-Type": contentType,
      },
      body: req.file.buffer,
    });

    const text = await robloxRes.text();
    let data;
    try { data = JSON.parse(text); } catch { data = { raw: text }; }

    if (!robloxRes.ok) {
      return res.status(robloxRes.status).json({
        error: data.message || "Roblox menolak publish place.",
        detail: data,
      });
    }

    res.json(data); // { versionNumber: N }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || "Terjadi kesalahan pada server lokal." });
  }
});

// Deteksi grup yang dimiliki/dikelola user, filter yang rolenya Owner/Admin/Developer
// (endpoint publik Roblox, tidak butuh token — dipakai untuk mengisi dropdown grup)
app.get("/api/groups", async (req, res) => {
  try {
    const { userId } = req.query;
    if (!userId) return res.status(400).json({ error: "userId wajib diisi." });

    const robloxRes = await fetch(
      `https://groups.roblox.com/v2/users/${encodeURIComponent(userId)}/groups/roles`
    );
    const data = await robloxRes.json();

    if (!robloxRes.ok) {
      return res.status(robloxRes.status).json({
        error: data.errors?.[0]?.message || "Gagal mengambil daftar grup dari Roblox.",
        detail: data,
      });
    }

    const KEYWORDS = /owner|admin|developer|creator|manager/i;
    const all = (data.data || []).map((entry) => ({
      id: entry.group.id,
      name: entry.group.name,
      roleName: entry.role.name,
      rank: entry.role.rank,
    }));

    const eligible = all.filter((g) => KEYWORDS.test(g.roleName) || g.rank >= 200);

    res.json({ groups: eligible, allGroups: all });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || "Terjadi kesalahan pada server lokal." });
  }
});

// Cek status moderasi sebuah aset berdasarkan Asset ID
app.get("/api/asset-status", requireAuth, async (req, res) => {
  try {
    const { assetId } = req.query;
    if (!assetId) return res.status(400).json({ error: "assetId wajib diisi." });

    const robloxRes = await fetch(`https://apis.roblox.com/assets/v1/assets/${assetId}`, {
      headers: { Authorization: `Bearer ${req.robloxAccessToken}` },
    });
    const data = await robloxRes.json();

    if (!robloxRes.ok) {
      return res.status(robloxRes.status).json({
        error: data.message || "Gagal memeriksa status aset.",
        detail: data,
      });
    }

    res.json(data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || "Terjadi kesalahan pada server lokal." });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n✔ Roblox Model Uploader (OAuth login) berjalan di http://localhost:${PORT}\n`);
  if (!oauthConfigured()) {
    console.log("⚠ ROBLOX_CLIENT_ID / ROBLOX_CLIENT_SECRET / ROBLOX_REDIRECT_URI belum diisi di .env — tombol login belum akan berfungsi.\n");
  }
});
