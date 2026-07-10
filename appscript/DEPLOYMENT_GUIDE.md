# 📘 Panduan Deployment: Event Viewer Analyzer (Google Apps Script)

Panduan langkah demi langkah untuk men-deploy aplikasi ke Google Apps Script dan membuat Web App yang dapat diakses oleh seluruh tim IT Anda.

---

## Prasyarat
- Akun Google Workspace atau akun Gmail
- Akses ke [Google Apps Script](https://script.google.com)
- *(Opsional)* API Key Gemini dari [Google AI Studio](https://aistudio.google.com/apikey)

---

## Langkah 1: Buat Proyek Apps Script Baru

1. Buka browser, kunjungi **https://script.google.com**
2. Klik **"New project"** (Proyek baru)
3. Beri nama proyek: `Event Viewer Analyzer`

---

## Langkah 2: Salin File-File ke Proyek

Proyek Anda berisi file-file berikut di folder `appscript/`:

| File Lokal | Cara Menambahkan di GAS |
|---|---|
| `Code.gs` | Tempel di file `Code.gs` bawaan (ganti isi default) |
| `HeuristicEngine.gs` | Klik **+** → **Script** → beri nama `HeuristicEngine` → tempel |
| `DefenderDirectory.gs` | Klik **+** → **Script** → beri nama `DefenderDirectory` → tempel |
| `LogParser.gs` | Klik **+** → **Script** → beri nama `LogParser` → tempel |
| `Scenarios.gs` | Klik **+** → **Script** → beri nama `Scenarios` → tempel |
| `Index.html` | Klik **+** → **HTML** → beri nama `Index` → tempel |

> **PENTING**: Untuk file HTML, pastikan namanya persis `Index` (tanpa `.html` — GAS menambahkannya otomatis).

---

## Langkah 3: Konfigurasi Manifest (appsscript.json)

1. Di Editor, klik **⚙️ Project Settings** (ikon roda gigi di sidebar kiri)
2. Centang **"Show appsscript.json manifest file in editor"**
3. Kembali ke Editor, buka file `appsscript.json`
4. Ganti isinya dengan konten dari file `appsscript.json` di folder `appscript/`

---

## Langkah 4: Deploy sebagai Web App

1. Klik **Deploy** → **New deployment**
2. Klik ikon ⚙️ di samping "Select type" → pilih **Web app**
3. Isi konfigurasi:
   - **Description**: `Event Viewer Analyzer v1.0`
   - **Execute as**: `Me` (akun Anda)
   - **Who has access**: 
     - `Anyone within [nama domain]` (untuk organisasi)
     - Atau `Anyone` (untuk akses publik)
4. Klik **Deploy**
5. **Salin URL** Web App yang muncul — ini adalah link aplikasi Anda!

---

## Langkah 5: Konfigurasi API Key *(Opsional)*

Setelah membuka Web App di browser:

1. Klik tombol **🔑 API Key** di pojok kanan atas
2. Masukkan **Gemini API Key** Anda
3. Klik **💾 Simpan**

> API Key disimpan aman di `PropertiesService` server Google — tidak terekspos ke browser.

Tanpa API Key, analisis tetap berjalan menggunakan **mode Heuristik + Knowledge Base lokal**.

---

## Langkah 6: Knowledge Base (Otomatis)

Saat pertama kali fungsi analisis dipanggil, sistem akan **otomatis membuat** Google Sheets bernama `EventViewerAnalyzer_KB` di Google Drive Anda berisi:
- **Sheet "WindowsEventDB"**: 30+ Event ID penting Windows beserta tingkat keparahan dan deskripsinya
- **Sheet "Config"**: Konfigurasi runtime (model AI, batas log, versi)

Anda bisa **menambahkan Event ID baru** langsung di Google Sheets kapan saja tanpa mengubah kode!

---

## Cara Menggunakan

1. Buka URL Web App yang telah di-deploy
2. Seret file `.xml` atau `.csv` hasil ekspor Windows Event Viewer ke zona unggah
3. Gunakan filter untuk menyaring log berdasarkan tingkat keparahan, channel, atau kata kunci
4. Klik **"✨ Jalankan Analisis AI"** untuk mendapatkan laporan diagnostik
5. Unduh laporan sebagai file `.md` atau salin ke clipboard

---

## Pemecahan Masalah

| Masalah | Solusi |
|---|---|
| "Anda tidak memiliki akses" | Pastikan deployment diatur ke "Anyone" atau "Anyone within domain" |
| Analisis AI gagal | Periksa apakah API Key sudah diisi dan valid |
| KB Sheet tidak muncul | Jalankan fungsi `createKBSheet_()` secara manual dari Editor |
| File .evtx tidak terbaca | Ekspor file tersebut ke format `.xml` atau `.csv` dari Windows Event Viewer |
