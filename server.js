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

// ===================== SCAN STRUKTUR .rbxm (dibangun sendiri, TANPA library luar) =====================
//
// Ini parser biner .rbxm minimal yang saya tulis sendiri dari spesifikasi
// format Roblox -- CUMA BACA, tidak pernah menulis ulang file, jadi tidak
// ada resiko file kamu jadi corrupt. Tujuannya: kasih tau class apa aja
// yang ada di dalam file (termasuk PackageLink) tanpa gantung ke library
// pihak ketiga yang beberapa kali gagal sebelumnya.
//
// Kalau ada bug di parser ini, paling parah hasil scan salah/kosong --
// TIDAK BISA merusak file aslinya, karena file cuma dibaca, tidak ditulis.

// Decompress 1 block LZ4 mentah (format yang dipakai Roblox per-chunk).
function lz4BlockDecompress(input, outSize) {
  const out = Buffer.alloc(outSize);
  let ip = 0, op = 0;
  while (ip < input.length) {
    const token = input[ip++];
    let litLen = token >> 4;
    if (litLen === 15) {
      let b;
      do { b = input[ip++]; litLen += b; } while (b === 255);
    }
    input.copy(out, op, ip, ip + litLen);
    ip += litLen; op += litLen;
    if (ip >= input.length) break; // blok berakhir setelah literal terakhir
    const offset = input[ip] | (input[ip + 1] << 8);
    ip += 2;
    let matchLen = token & 0x0f;
    if (matchLen === 15) {
      let b;
      do { b = input[ip++]; matchLen += b; } while (b === 255);
    }
    matchLen += 4;
    let matchStart = op - offset;
    for (let i = 0; i < matchLen; i++) {
      out[op++] = out[matchStart++];
    }
  }
  return out;
}

// Baca semua chunk top-level (nama + data yang sudah didekompresi) dari file .rbxm.
function readAllChunks(buffer) {
  const MAGIC = Buffer.from("<roblox!\x89\xff\r\n\x1a\n", "binary");
  if (buffer.length < 32 || !buffer.subarray(0, 14).equals(MAGIC)) {
    throw new Error("Bukan file .rbxm biner yang valid (magic header tidak cocok).");
  }
  let pos = 32;
  const chunks = [];
  while (pos + 16 <= buffer.length) {
    const chunkName = buffer.toString("ascii", pos, pos + 4).replace(/\0+$/, "");
    const compLen = buffer.readInt32LE(pos + 4);
    const uncompLen = buffer.readInt32LE(pos + 8);
    pos += 16;
    if (chunkName === "END") break;
    let data;
    if (compLen === 0) {
      data = buffer.subarray(pos, pos + uncompLen);
      pos += uncompLen;
    } else {
      const compressed = buffer.subarray(pos, pos + compLen);
      data = lz4BlockDecompress(compressed, uncompLen);
      pos += compLen;
    }
    chunks.push({ name: chunkName, data });
  }
  return chunks;
}

// Nama property yang biasanya nyimpen referensi aset (gambar/suara/mesh),
// termasuk PackageId (dipakai buat percobaan "convert ke Model penuh" --
// mengosongkan PackageId di dalam PackageLink, tanpa mengubah struktur tree).
// Ini cuma dipakai buat FILTER mana yang ditampilkan di hasil scan -- tidak
// pernah dipakai buat menulis ulang apapun secara langsung.
const ASSET_PROPERTY_NAMES = new Set([
  "Image", "HoverImage", "PressedImage", "Texture", "SoundId", "AnimationId",
  "MeshId", "TextureID", "TextureId", "ColorMap", "MetalnessMap", "NormalMap", "RoughnessMap",
  "PackageId",
]);

// Baca class + (kalau bisa) nilai property yang berhubungan dengan aset.
// SANGAT DEFENSIF: kalau data nggak sesuai pola yang diharapkan (misal
// panjang string kebaca aneh/di luar batas buffer), langsung ditandai
// "unknown" alih-alih maksa dibaca -- karena ini FITUR BACA SAJA, salah baca
// cuma bikin hasil scan kurang lengkap, TIDAK PERNAH merusak file aslinya.
function parseRbxmFile(buffer) {
  const chunks = readAllChunks(buffer);
  const classes = [];
  const classById = {};

  for (const { name, data } of chunks) {
    if (name !== "INST") continue;
    let p = 4;
    const nameLen = data.readInt32LE(p); p += 4;
    const className = data.toString("utf8", p, p + nameLen); p += nameLen;
    p += 1;
    const numInstances = data.readInt32LE(p);
    const classId = data.readInt32LE(0);
    classes.push({ className, count: numInstances });
    classById[classId] = { className, numInstances };
  }

  // Pola yang menandakan sebuah string kemungkinan referensi aset Roblox --
  // dipakai buat scan LUAS (bukan cuma nama property yang sudah dikenal),
  // supaya ID yang "nyempil" di tempat nggak biasa (misal StringValue.Value
  // yang dipakai script buat load gambar dinamis) tetap ketemu.
  const ASSET_ID_PATTERN = /rbxassetid:\/\/\d+/i;

  const properties = [];
  for (const { name, data } of chunks) {
    if (name !== "PROP") continue;
    try {
      let p = 0;
      const classId = data.readInt32LE(p); p += 4;
      const propNameLen = data.readInt32LE(p); p += 4;
      if (propNameLen < 0 || propNameLen > 200) continue;
      const propName = data.toString("utf8", p, p + propNameLen); p += propNameLen;

      const cls = classById[classId];
      if (!cls) continue;

      const isCurated = ASSET_PROPERTY_NAMES.has(propName);
      const dataType = data.readUInt8(p); p += 1;

      if (dataType !== 0x01) {
        // Cuma laporkan "tidak terbaca" buat property yang memang dikenal
        // relevan -- kalau semua property non-string dilaporkan juga hasilnya
        // bakal penuh noise (Vector3/CFrame/dll memang wajar bukan string).
        if (isCurated) {
          properties.push({
            class: cls.className, property: propName,
            values: [], rawType: dataType, note: "Format tersimpan bukan string biasa (kode tipe: " + dataType + "), belum bisa dibaca isinya oleh scanner ini.",
          });
        }
        continue;
      }

      const values = [];
      let ok = true;
      for (let i = 0; i < cls.numInstances; i++) {
        if (p + 4 > data.length) { ok = false; break; }
        const len = data.readInt32LE(p); p += 4;
        if (len < 0 || p + len > data.length) { ok = false; break; }
        values.push(data.toString("utf8", p, p + len));
        p += len;
      }

      if (!ok) {
        if (isCurated) {
          properties.push({
            class: cls.className, property: propName,
            values: [], rawType: dataType, note: "Gagal parsing (data di luar dugaan) -- kemungkinan bukan string sesederhana yang diasumsikan.",
          });
        }
        continue;
      }

      const hasAssetIdPattern = values.some(v => ASSET_ID_PATTERN.test(v));
      if (isCurated || hasAssetIdPattern) {
        properties.push({ class: cls.className, property: propName, values, rawType: dataType, note: null });
      }
    } catch (e) {
      // Lewati chunk PROP yang gagal diparse -- tidak menghentikan scan chunk lain.
      continue;
    }
  }

  return { classes, properties };
}

app.post("/api/rbxm/scan-classes", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "File .rbxm wajib dipilih." });
    if (path.extname(req.file.originalname).toLowerCase() !== ".rbxm") {
      return res.status(400).json({ error: "Fitur ini cuma dukung file .rbxm (biner), bukan .rbxmx." });
    }

    let parsed;
    try {
      parsed = parseRbxmFile(req.file.buffer);
    } catch (e) {
      return res.status(400).json({ error: "Gagal parsing file: " + e.message });
    }

    const classes = parsed.classes.sort((a, b) => b.count - a.count);
    const packageLinkCount = classes.find(c => c.className === "PackageLink")?.count || 0;
    res.json({ classes, packageLinkCount, properties: parsed.properties });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || "Terjadi kesalahan pada server lokal." });
  }
});

// Sama seperti readAllChunks, tapi juga catat posisi byte tiap chunk di
// FILE ASLI (bukan cuma data yang sudah didekompresi) -- dibutuhkan buat
// bisa "menyuntik" chunk baru ke posisi yang tepat waktu proses hapus/edit.
function readAllChunksWithOffsets(buffer) {
  const MAGIC = Buffer.from("<roblox!\x89\xff\r\n\x1a\n", "binary");
  if (buffer.length < 32 || !buffer.subarray(0, 14).equals(MAGIC)) {
    throw new Error("Bukan file .rbxm biner yang valid (magic header tidak cocok).");
  }
  let pos = 32;
  const chunks = [];
  while (pos + 16 <= buffer.length) {
    const chunkName = buffer.toString("ascii", pos, pos + 4).replace(/\0+$/, "");
    const compLen = buffer.readInt32LE(pos + 4);
    const uncompLen = buffer.readInt32LE(pos + 8);
    const headerStart = pos;
    pos += 16;
    if (chunkName === "END") break;
    const dataStart = pos;
    let data;
    if (compLen === 0) {
      data = buffer.subarray(pos, pos + uncompLen);
      pos += uncompLen;
    } else {
      data = lz4BlockDecompress(buffer.subarray(pos, pos + compLen), uncompLen);
      pos += compLen;
    }
    chunks.push({ name: chunkName, data, headerStart, dataEnd: pos });
  }
  return chunks;
}

// Hapus (kosongkan) SEMUA kemunculan 1 nilai spesifik pada 1 class+property
// tertentu di dalam file .rbxm. Chunk lain (INST, PRNT, PROP lainnya) TIDAK
// disentuh sama sekali -- hanya PROP chunk yang cocok class+property yang
// ditulis ulang (sebagai chunk uncompressed baru), lalu disambung balik ke
// posisi yang sama di file. Kalau target tidak ketemu / hasil parsing
// mencurigakan, GAGAL dengan jelas -- tidak pernah memaksa nulis file yang
// meragukan.
function cleanAssetValue(buffer, targetClass, targetProperty, targetValue) {
  const chunks = readAllChunksWithOffsets(buffer);

  const classById = {};
  for (const c of chunks) {
    if (c.name !== "INST") continue;
    let p = 4;
    const nameLen = c.data.readInt32LE(p); p += 4;
    const className = c.data.toString("utf8", p, p + nameLen); p += nameLen;
    const classId = c.data.readInt32LE(0);
    if (className === targetClass) classById[classId] = className;
  }
  if (!Object.keys(classById).length) {
    throw new Error("Class \"" + targetClass + "\" tidak ditemukan di file ini.");
  }

  // Bersihkan SEMUA PROP chunk yang cocok class+property, bukan cuma yang
  // pertama ketemu -- penting buat file "kit gabungan" yang bisa punya lebih
  // dari 1 kelompok class/instance yang sama (classId beda-beda).
  let cursor = 32;
  const pieces = [buffer.subarray(0, 32)];
  let totalCleared = 0;
  let matchedChunkCount = 0;

  for (const c of chunks) {
    let isTarget = false;
    if (c.name === "PROP") {
      const classId = c.data.readInt32LE(0);
      if (classId in classById) {
        let p = 4;
        const propNameLen = c.data.readInt32LE(p); p += 4;
        const propName = c.data.toString("utf8", p, p + propNameLen);
        if (propName === targetProperty) isTarget = true;
      }
    }

    if (!isTarget) {
      pieces.push(buffer.subarray(cursor, c.dataEnd));
      cursor = c.dataEnd;
      continue;
    }

    matchedChunkCount++;
    const data = c.data;
    let p = 4;
    const propNameLen = data.readInt32LE(p); p += 4;
    p += propNameLen;
    const dataType = data.readUInt8(p); p += 1;

    if (dataType !== 0x01) {
      throw new Error("Property ini bukan format string sederhana (tipe: " + dataType + "), belum bisa diedit otomatis.");
    }

    const valuePieces = [data.subarray(0, p)];
    let foundInThisChunk = 0;
    while (p < data.length) {
      if (p + 4 > data.length) throw new Error("Struktur property rusak/tidak terduga saat parsing.");
      const len = data.readInt32LE(p);
      const valStart = p + 4;
      if (len < 0 || valStart + len > data.length) throw new Error("Struktur property rusak/tidak terduga saat parsing.");
      const val = data.toString("utf8", valStart, valStart + len);
      if (val === targetValue) {
        valuePieces.push(Buffer.alloc(4));
        foundInThisChunk++;
      } else {
        valuePieces.push(data.subarray(p, valStart + len));
      }
      p = valStart + len;
    }

    totalCleared += foundInThisChunk;

    if (foundInThisChunk === 0) {
      pieces.push(buffer.subarray(cursor, c.dataEnd));
      cursor = c.dataEnd;
      continue;
    }

    const newData = Buffer.concat(valuePieces);
    const newChunkHeader = Buffer.alloc(16);
    newChunkHeader.write("PROP", 0, "ascii");
    newChunkHeader.writeInt32LE(0, 4);
    newChunkHeader.writeInt32LE(newData.length, 8);
    newChunkHeader.writeInt32LE(0, 12);
    pieces.push(newChunkHeader, newData);
    cursor = c.dataEnd;
  }

  pieces.push(buffer.subarray(cursor));

  if (!matchedChunkCount) {
    throw new Error("Property \"" + targetClass + "." + targetProperty + "\" tidak ditemukan di file ini.");
  }
  if (!totalCleared) {
    throw new Error("Nilai \"" + targetValue + "\" tidak ditemukan pada property ini.");
  }

  return { buffer: Buffer.concat(pieces), clearedCount: totalCleared };
}

app.post("/api/rbxm/clean-value", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "File .rbxm wajib dipilih." });

    let targets;
    try { targets = JSON.parse(req.body.targets || "[]"); } catch { targets = []; }
    if (!Array.isArray(targets) || !targets.length) {
      return res.status(400).json({ error: "Pilih minimal 1 item yang mau dibersihkan." });
    }

    let buffer = req.file.buffer;
    let totalCleared = 0;
    const failed = [];

    for (const t of targets) {
      if (!t || !t.class || !t.property || !t.value) continue;
      try {
        const result = cleanAssetValue(buffer, t.class, t.property, t.value);
        buffer = result.buffer;
        totalCleared += result.clearedCount;
      } catch (e) {
        failed.push(t.class + "." + t.property + " = " + t.value + ": " + e.message);
      }
    }

    if (!totalCleared) {
      return res.status(400).json({ error: "Tidak ada yang berhasil dibersihkan.", detail: failed });
    }

    const outName = req.file.originalname.replace(/\.rbxm$/i, "") + " [cleaned].rbxm";
    res.setHeader("Content-Type", "application/octet-stream");
    res.setHeader("Content-Disposition", `attachment; filename="${outName.replace(/"/g, "")}"`);
    res.setHeader("X-Cleared-Count", String(totalCleared));
    if (failed.length) res.setHeader("X-Failed-Items", encodeURIComponent(JSON.stringify(failed)));
    res.send(buffer);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || "Terjadi kesalahan pada server lokal." });
  }
});

// Cek siapa pemilik/creator asli sebuah asset ID (dipakai buat bandingin
// sama akun kamu sendiri -- biar ketauan mana ID yang "asing"/bukan punya
// kamu tanpa harus nunggu popup Roblox yang kadang nggak konsisten muncul).
app.get("/api/asset-owner", async (req, res) => {
  try {
    const { assetId } = req.query;
    if (!assetId || !/^\d+$/.test(String(assetId))) {
      return res.status(400).json({ error: "assetId tidak valid." });
    }

    const robloxRes = await fetch(`https://economy.roblox.com/v2/assets/${assetId}/details`);
    if (!robloxRes.ok) {
      return res.status(robloxRes.status).json({ error: "Gagal ambil info asset dari Roblox (mungkin aset privat/tidak ada)." });
    }
    const data = await robloxRes.json();

    res.json({
      assetId: Number(assetId),
      name: data.Name || null,
      creatorId: data.Creator?.Id ?? null,
      creatorName: data.Creator?.Name ?? null,
      creatorType: data.Creator?.CreatorType ?? null,
    });
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
