# Roblox Asset Uploader (Mobile-Friendly)

Website buat upload file 3D model (.fbx / .rbxm / .rbxmx) langsung ke Roblox
sebagai asset tipe **Model** (bukan Package) lewat **Open Cloud Assets API**.
Dibuat biar bisa dipakai dari HP tanpa perlu buka Roblox Studio.

## Cara Cepat (isi API Key & User ID dari website)

1. Deploy dulu website ini ke Railway (lihat langkah 5 di bawah) dengan cuma isi
   `UPLOAD_PASSWORD` di Variables (ROBLOX_API_KEY/USER_ID boleh dikosongkan)
2. Buka website dari HP → tab **⚙️ Settings**
3. Isi password, API Key, User ID (dan Group ID kalau perlu) → **Simpan Settings**
4. Settings otomatis kesimpen di server (`data/settings.json`), tinggal pindah ke
   tab **Upload** buat mulai upload

⚠️ **Catatan soal Railway:** kalau kamu deploy tanpa "Volume" (disk permanen),
file `data/settings.json` bisa ke-reset tiap kali Railway redeploy project kamu
(misal habis push update code baru). Kalau mau settings ini permanen walau
sering update code, tambahin **Volume** di Railway dan mount ke folder `/app/data`
(Railway dashboard → Settings → Volumes). Kalau kamu jarang push ulang, gak
perlu khawatir soal ini.

## 1. Ambil Open Cloud API Key

1. Buka https://create.roblox.com/dashboard/credentials
2. Klik **Create API Key**
3. Kasih nama bebas, lalu di bagian **Permissions**, tambahkan:
   - API System: **Assets API**
   - Permission: `asset:read`, `asset:write`
4. Di bagian **Security**, boleh diisi IP restriction atau dibiarkan default
5. Save, lalu copy API Key-nya (cuma muncul sekali!)

## 2. Cari User ID / Group ID kamu

- User ID: buka profil Roblox kamu, lihat URL `roblox.com/users/XXXXXXX/profile` → itu User ID-nya
- Group ID (opsional, kalau mau upload sebagai asset group): lihat URL halaman group

## 3. Setup environment

Copy `.env.example` jadi `.env`, lalu isi:

```
ROBLOX_API_KEY=api_key_dari_langkah_1
ROBLOX_USER_ID=user_id_kamu
ROBLOX_GROUP_ID=
UPLOAD_PASSWORD=password_bebas_buat_lock_website
PORT=3000
```

## 4. Jalanin lokal (opsional, buat testing)

```bash
npm install
npm start
```

Buka `http://localhost:3000`

## 5. Deploy ke Railway (biar bisa diakses dari HP)

1. Push folder ini ke GitHub repo
2. Buka Railway → New Project → Deploy from GitHub repo
3. Di tab **Variables**, masukin semua isi `.env` kamu (ROBLOX_API_KEY, ROBLOX_USER_ID, UPLOAD_PASSWORD, dst)
4. Railway otomatis kasih domain publik (`xxxxx.up.railway.app`)
5. Buka domain itu dari browser HP kamu → upload deh

## Catatan Penting

- **File harus format .fbx, .rbxm, atau .rbxmx** — kalau kamu punya model dalam
  format lain (misal .obj), perlu dikonversi ke .fbx dulu (bisa pakai Blender
  atau converter online) sebelum upload.
- Limit ukuran file **20MB per upload**.
- Roblox membatasi jumlah upload lewat Open Cloud (sekitar 100/bulan kalau
  akun kamu sudah ID-verified). Kalau belum verified, limitnya lebih ketat.
- `.rbxm`/`.rbxmx` yang diedit di luar Roblox Studio kadang gagal diproses —
  paling aman kalau file itu hasil export langsung dari Studio.
- Proses upload butuh beberapa detik sampai menit karena Roblox butuh waktu
  moderasi/processing di belakang layar — website ini otomatis nunggu
  (polling) sampai selesai, jangan ditutup pas status masih "loading".
- Password di form cuma proteksi sederhana biar link kamu gak dipakai
  sembarangan orang — bukan pengganti keamanan API key. Jangan share domain
  Railway kamu ke publik.
