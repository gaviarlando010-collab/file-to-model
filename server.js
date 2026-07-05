import express from "express";
import multer from "multer";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 20 * 1024 * 1024 }, // batas Open Cloud: 20 MB per aset
});

app.use(express.static(path.join(__dirname, "public")));
app.use(express.json());

const ROBLOX_ASSETS_URL = "https://apis.roblox.com/assets/v1/assets";

// Upload aset baru (Model .rbxm/.rbxmx)
app.post("/api/upload", upload.single("file"), async (req, res) => {
  try {
    const { apiKey, assetType, displayName, description, creatorType, creatorId } = req.body;

    if (!apiKey) return res.status(400).json({ error: "API Key wajib diisi." });
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

    const form = new FormData();
    form.append("request", JSON.stringify(requestPayload));
    form.append(
      "fileContent",
      new Blob([req.file.buffer], { type: contentType }),
      req.file.originalname
    );

    const robloxRes = await fetch(ROBLOX_ASSETS_URL, {
      method: "POST",
      headers: { "x-api-key": apiKey },
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
app.get("/api/operation", async (req, res) => {
  try {
    const { opPath } = req.query;
    const apiKey = req.headers["x-api-key"];

    if (!apiKey) return res.status(400).json({ error: "API Key wajib diisi." });
    if (!opPath) return res.status(400).json({ error: "opPath wajib diisi." });

    const robloxRes = await fetch(`https://apis.roblox.com/assets/v1/${opPath}`, {
      headers: { "x-api-key": apiKey },
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
app.post("/api/publish-place", upload.single("file"), async (req, res) => {
  try {
    const { apiKey, universeId, placeId, versionType } = req.body;

    if (!apiKey) return res.status(400).json({ error: "API Key wajib diisi." });
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
      headers: { "x-api-key": apiKey, "Content-Type": contentType },
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
app.get("/api/asset-status", async (req, res) => {
  try {
    const { assetId } = req.query;
    const apiKey = req.headers["x-api-key"];

    if (!apiKey) return res.status(400).json({ error: "API Key wajib diisi." });
    if (!assetId) return res.status(400).json({ error: "assetId wajib diisi." });

    const robloxRes = await fetch(`https://apis.roblox.com/assets/v1/assets/${assetId}`, {
      headers: { "x-api-key": apiKey },
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
  console.log(`\n✔ Roblox Model Uploader berjalan di http://localhost:${PORT}\n`);
});
