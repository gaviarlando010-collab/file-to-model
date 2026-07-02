require("dotenv").config();
const express = require("express");
const multer = require("multer");
const axios = require("axios");
const FormData = require("form-data");
const path = require("path");
const fs = require("fs");

const app = express();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 20 * 1024 * 1024 }, // 20MB, sesuai limit Open Cloud
});

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// UPLOAD_PASSWORD tetap dari .env (ini kunci gerbang, gak diubah lewat website
// biar gak ada yang bisa reset password lewat form terbuka)
const UPLOAD_PASSWORD = process.env.UPLOAD_PASSWORD;

// Ekstensi file yang didukung Open Cloud Assets API untuk tipe "Model"
const ALLOWED_EXTENSIONS = [".fbx", ".rbxm", ".rbxmx"];

// =========================================================
// PENYIMPANAN SETTINGS (API Key, User ID, Group ID)
// Disimpan di file lokal ./data/settings.json supaya bisa
// diisi/diubah dari website tanpa perlu redeploy.
// Kalau file belum ada / field kosong, fallback ke .env
// =========================================================
const DATA_DIR = path.join(__dirname, "data");
const SETTINGS_PATH = path.join(DATA_DIR, "settings.json");

function readSettingsFile() {
  try {
    const raw = fs.readFileSync(SETTINGS_PATH, "utf-8");
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

function writeSettingsFile(settings) {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
  fs.writeFileSync(SETTINGS_PATH, JSON.stringify(settings, null, 2), "utf-8");
}

function getConfig() {
  const stored = readSettingsFile();
  return {
    apiKey: stored.apiKey || process.env.ROBLOX_API_KEY || "",
    userId: stored.userId || process.env.ROBLOX_USER_ID || "",
    groupId: stored.groupId || process.env.ROBLOX_GROUP_ID || "",
  };
}

function maskKey(key) {
  if (!key) return "";
  if (key.length <= 8) return "••••••••";
  return key.slice(0, 4) + "••••••••" + key.slice(-4);
}

function requirePassword(req, res) {
  const provided = req.headers["x-upload-password"] || req.body?.password;
  if (!UPLOAD_PASSWORD || provided !== UPLOAD_PASSWORD) {
    res.status(401).json({ error: "Password salah." });
    return false;
  }
  return true;
}

function getCreationContext() {
  const { userId, groupId } = getConfig();
  if (groupId) {
    return { creator: { groupId: String(groupId) } };
  }
  return { creator: { userId: String(userId) } };
}

async function pollOperation(operationPath, apiKey) {
  // operationPath contoh: "operations/1234567890"
  const url = `https://apis.roblox.com/assets/v1/${operationPath}`;
  const maxAttempts = 20;

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const res = await axios.get(url, {
      headers: { "x-api-key": apiKey },
    });

    if (res.data.done) {
      return res.data;
    }
    await new Promise((r) => setTimeout(r, 2000)); // tunggu 2 detik sebelum cek lagi
  }

  throw new Error("Timeout menunggu proses upload selesai di Roblox.");
}

app.post("/api/upload", upload.single("file"), async (req, res) => {
  try {
    const { password, displayName, description } = req.body;

    if (!UPLOAD_PASSWORD || password !== UPLOAD_PASSWORD) {
      return res.status(401).json({ error: "Password salah." });
    }

    if (!req.file) {
      return res.status(400).json({ error: "File belum diupload." });
    }

    const ext = path.extname(req.file.originalname).toLowerCase();
    if (!ALLOWED_EXTENSIONS.includes(ext)) {
      return res.status(400).json({
        error: `Format file .${ext} tidak didukung. Pakai: ${ALLOWED_EXTENSIONS.join(", ")}`,
      });
    }

    const config = getConfig();
    if (!config.apiKey || (!config.userId && !config.groupId)) {
      return res.status(500).json({
        error:
          "Roblox API Key / User ID belum diisi. Buka tab Settings dulu buat isi konfigurasinya.",
      });
    }

    const requestPayload = {
      assetType: "Model",
      displayName: displayName || req.file.originalname,
      description: description || "Uploaded via mobile uploader",
      creationContext: getCreationContext(),
    };

    const form = new FormData();
    form.append("request", JSON.stringify(requestPayload));
    form.append("fileContent", req.file.buffer, {
      filename: req.file.originalname,
      contentType: "application/octet-stream",
    });

    const uploadRes = await axios.post(
      "https://apis.roblox.com/assets/v1/assets",
      form,
      {
        headers: {
          ...form.getHeaders(),
          "x-api-key": config.apiKey,
        },
        maxBodyLength: Infinity,
        maxContentLength: Infinity,
      }
    );

    // uploadRes.data.path = "operations/xxxxx"
    const operationResult = await pollOperation(uploadRes.data.path, config.apiKey);

    if (operationResult.response) {
      return res.json({
        success: true,
        assetId: operationResult.response.assetId,
        message: "Berhasil diupload sebagai Model! Cari di tab 'Model' Toolbox.",
      });
    }

    return res.json({
      success: false,
      message: "Upload selesai tapi tidak ada detail asset (cek moderasi Roblox).",
      raw: operationResult,
    });
  } catch (err) {
    const robloxError = err.response?.data;
    console.error("Upload error:", robloxError || err.message);
    return res.status(500).json({
      error:
        robloxError?.message ||
        robloxError?.errors?.[0]?.message ||
        err.message ||
        "Gagal upload ke Roblox.",
    });
  }
});

app.get("/api/health", (req, res) => {
  const config = getConfig();
  res.json({
    ok: true,
    configured: Boolean(config.apiKey && (config.userId || config.groupId)),
  });
});

// Ambil settings saat ini (API key ditampilkan tersamar, bukan full)
app.get("/api/settings", (req, res) => {
  if (!requirePassword(req, res)) return;
  const config = getConfig();
  res.json({
    apiKeyMasked: maskKey(config.apiKey),
    hasApiKey: Boolean(config.apiKey),
    userId: config.userId,
    groupId: config.groupId,
  });
});

// Simpan/update settings dari website
app.post("/api/settings", (req, res) => {
  if (!requirePassword(req, res)) return;

  const { apiKey, userId, groupId } = req.body;
  const current = readSettingsFile();

  const updated = {
    apiKey: apiKey && apiKey.trim() ? apiKey.trim() : current.apiKey || "",
    userId: userId !== undefined ? String(userId).trim() : current.userId || "",
    groupId: groupId !== undefined ? String(groupId).trim() : current.groupId || "",
  };

  writeSettingsFile(updated);

  res.json({
    success: true,
    message: "Settings tersimpan.",
    apiKeyMasked: maskKey(updated.apiKey),
    userId: updated.userId,
    groupId: updated.groupId,
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Roblox Asset Uploader jalan di port ${PORT}`);
});
