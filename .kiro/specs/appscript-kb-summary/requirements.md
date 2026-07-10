# Requirements Document

## Introduction

Fitur ini menyempurnakan Event Viewer Analyzer (Google Apps Script Edition) dengan empat peningkatan utama:

1. **Knowledge Base Offline yang Diperkaya** — Memperluas database KB Windows Event ID dari ~60 entri menjadi 150+ entri dengan struktur kolom baru yang lebih kaya (`category`, `mitigation`, `mitre_tactic`, `source_log`, `os_version`), sehingga analisis offline lebih informatif dan kontekstual.
2. **Analisis Heuristik yang Disempurnakan** — Memanfaatkan kolom KB yang baru untuk menghasilkan laporan heuristik offline yang lebih kaya, termasuk mitigasi spesifik per Event ID dan pemetaan taktik MITRE ATT&CK.
3. **Fitur Summary per Event ID** — Tab baru "📋 Summary" yang menampilkan ringkasan per Event ID dari log yang dimuat: jumlah kemunculan (count), tingkat keparahan (severity), deskripsi dari KB, mitigation, serta kategori MITRE.
4. **Filter Berdasarkan Tanggal (Date Range Picker)** — Mengganti filter waktu relatif (dropdown 30m/1h/3h) menjadi date range picker (`tanggal mulai` – `tanggal akhir`) dengan tetap mempertahankan preset cepat sebagai shortcut.

Seluruh implementasi dalam ekosistem Google Apps Script (`.gs` + `Index.html`) tanpa library eksternal berbayar. Antarmuka dalam Bahasa Indonesia.

---

## Glossary

- **KB (Knowledge Base)**: Database Windows Event ID yang disimpan di Google Sheets sheet "WindowsEventDB". Menjadi sumber data utama untuk enrichment analisis offline.
- **KB_Entry**: Satu baris data dalam KB yang merepresentasikan satu Windows Event ID beserta metadata-nya.
- **HeuristicEngine**: Modul `HeuristicEngine.gs` yang menghasilkan laporan diagnostik offline ketika AI API tidak tersedia.
- **Summary_Tab**: Tab baru di UI (`tab-summary`) yang menampilkan ringkasan per Event ID dari log yang sedang aktif.
- **Date_Range_Filter**: Komponen UI berupa dua input `date` HTML5 untuk memfilter log berdasarkan rentang tanggal absolut.
- **Event_ID**: Nomor identifikasi unik sebuah entri Windows Event Log (contoh: 4625, 1116, 7034).
- **Severity**: Tingkat keparahan sebuah log: Critical, Error, Warning, Information.
- **MITRE_Tactic**: Kode taktik serangan dari framework MITRE ATT&CK (contoh: T1110, T1562).
- **Mitigation**: Langkah perbaikan atau penanggulangan spesifik untuk sebuah Event ID.
- **applyFilters**: Fungsi JavaScript klien yang memfilter `allLogs` dan memperbarui tampilan.
- **allLogs**: Array JavaScript sisi klien yang menyimpan semua log yang telah di-parse dari file.
- **filteredLogs**: Array JavaScript sisi klien hasil filter dari `allLogs`.

---

## Requirements

### Requirement 1: Penyempurnaan Struktur Knowledge Base

**User Story:** Sebagai analis keamanan, saya ingin Knowledge Base Windows Event ID memiliki kolom yang lebih kaya sehingga saya mendapatkan informasi mitigation dan konteks MITRE yang relevan tanpa perlu internet.

#### Acceptance Criteria

1. THE KB_Entry SHALL memiliki kolom: `event-id`, `legacy-event-id`, `criticality`, `summary`, `category`, `mitigation`, `mitre_tactic`, `source_log`, `os_version`.
2. WHEN fungsi `createKBSheet_()` dipanggil dan sheet "WindowsEventDB" belum ada, THE HeuristicEngine SHALL membuat sheet dengan 9 kolom header tersebut.
3. THE KB SHALL memuat minimal 150 entri Windows Event ID yang mencakup kategori: Auditing & Access, Defender Security, Code Integrity (WDAC), Service Failures, Application Crash, Hardware & Disk, Network & Firewalls, System Updates, dan AppLocker.
4. WHEN fungsi `lookupKBEntry(eventId)` dipanggil dengan Event ID yang ada di KB, THE KB SHALL mengembalikan objek KB_Entry dengan semua 9 kolom terisi (nilai kosong diperbolehkan untuk kolom opsional).
5. IF sheet "WindowsEventDB" sudah ada dengan kolom lama (4 kolom), THEN THE KB SHALL mengembalikan objek KB_Entry yang hanya berisi kolom lama (`event-id`, `legacy-event-id`, `criticality`, `summary`) dengan flag `isLegacyFormat: true`, sehingga pemanggil dapat membedakan format lama dan format baru.

---

### Requirement 2: Penyempurnaan Analisis Heuristik Offline

**User Story:** Sebagai analis keamanan, saya ingin laporan heuristik offline menampilkan langkah mitigasi spesifik per Event ID dari KB sehingga saya dapat segera mengambil tindakan tanpa koneksi internet.

#### Acceptance Criteria

1. WHEN fungsi `generateHeuristicReport()` dipanggil dan KB memiliki kolom `mitigation`, THE HeuristicEngine SHALL menyertakan kolom `mitigation` dari KB_Entry pada bagian "Knowledge Base Enrichment" di laporan.
2. WHEN fungsi `generateHeuristicReport()` dipanggil dan KB memiliki kolom `mitre_tactic`, THE HeuristicEngine SHALL menampilkan kolom `mitre_tactic` dari KB_Entry jika tidak kosong, pada bagian tersendiri "Pemetaan MITRE ATT&CK" di laporan.
3. WHEN fungsi `generateHeuristicReport()` dipanggil, THE HeuristicEngine SHALL mengelompokkan entri KB yang cocok berdasarkan `category` dari KB_Entry (bukan dari field `log.category`).
4. THE HeuristicEngine SHALL menampilkan maksimal 20 entri KB yang cocok (ditingkatkan dari batas 15 sebelumnya) dalam satu laporan, diurutkan berdasarkan urutan kritikalitas: Critical → High → Medium → Low.
5. WHILE KB memiliki kolom `mitigation` (format baru), THE HeuristicEngine SHALL menghasilkan laporan enhanced dengan bagian mitigation spesifik per Event ID. IF KB tidak memuat kolom `mitigation` (format lama, `isLegacyFormat: true`), THEN THE HeuristicEngine SHALL menghasilkan laporan format standar tanpa bagian mitigation, tanpa error.

---

### Requirement 3: Fitur Summary per Event ID

**User Story:** Sebagai analis keamanan, saya ingin melihat ringkasan per Event ID dari log yang dimuat — termasuk jumlah kemunculan, tingkat keparahan, deskripsi, dan mitigation dari KB — sehingga saya dapat dengan cepat mengidentifikasi Event ID mana yang paling sering muncul dan bagaimana cara mengatasinya.

#### Acceptance Criteria

1. THE Summary_Tab SHALL ditampilkan sebagai tab kelima di baris tab navigasi dengan label "📋 Summary" setelah tab "📊 Analitik".
2. WHEN tab "📋 Summary" diklik dan `filteredLogs` berisi data, THE Summary_Tab SHALL menampilkan tabel ringkasan dengan kolom: Event ID, Jumlah (count), Severity Tertinggi, Kategori, Deskripsi (dari KB), Mitigation (dari KB), MITRE Tactic (dari KB).
3. WHEN tab "📋 Summary" diklik dan `filteredLogs` kosong, THE Summary_Tab SHALL menampilkan pesan "Pilih file log terlebih dahulu" di dalam tabel.
4. THE Summary_Tab SHALL mengurutkan baris tabel berdasarkan Jumlah (count) secara menurun sebagai urutan default.
5. WHEN pengguna mengklik header kolom pada tabel Summary, THE Summary_Tab SHALL mengurutkan ulang tabel berdasarkan kolom yang diklik; klik pertama = ascending, klik kedua pada kolom yang sama = descending (toggle).
6. THE Summary_Tab SHALL menampilkan badge severity berwarna (Critical = merah, Error = oranye, Warning = kuning, Information = biru) pada kolom Severity Tertinggi. Severity Tertinggi dihitung dengan urutan prioritas: Critical > Error > Warning > Information — nilai tertinggi dari seluruh log dengan Event ID tersebut yang digunakan.
7. WHEN KB memiliki entri yang cocok untuk sebuah Event ID, THE Summary_Tab SHALL mengisi kolom Deskripsi, Mitigation, dan MITRE Tactic dari data KB.
8. IF KB tidak memiliki entri untuk sebuah Event ID, THEN THE Summary_Tab SHALL menampilkan teks "—" pada kolom Deskripsi, Mitigation, dan MITRE Tactic.
9. THE Summary_Tab SHALL menampilkan total jumlah Event ID unik di header kartu ("X Event ID Unik Terdeteksi").
10. WHEN filter tanggal atau filter severity di-update, THE Summary_Tab SHALL memperbarui datanya secara langsung (synchronous) berdasarkan `filteredLogs` yang aktif pada saat itu.
11. THE Summary_Tab SHALL menyediakan input pencarian yang memfilter baris tabel berdasarkan Event ID (prefix atau exact match) atau kata kunci yang muncul di kolom Deskripsi.
12. WHEN tab "📋 Summary" diklik sebelum file log dimuat, THE Summary_Tab SHALL memungkinkan pengguna tetap melihat daftar Event ID dari KB secara independen melalui tombol "Lihat Semua KB", menampilkan seluruh entri KB tanpa data count.

---

### Requirement 4: Filter Berdasarkan Tanggal (Date Range Picker)

**User Story:** Sebagai analis keamanan, saya ingin memfilter log berdasarkan rentang tanggal absolut (dari tanggal A hingga tanggal B) sehingga saya dapat menganalisis insiden yang terjadi pada periode waktu tertentu di masa lalu, tidak hanya "N jam terakhir".

#### Acceptance Criteria

1. THE Date_Range_Filter SHALL ditampilkan di baris filter yang sudah ada, menggantikan elemen `<select id="timeFilter">` yang hanya memiliki opsi relatif.
2. THE Date_Range_Filter SHALL terdiri dari: dua input bertipe `date` (tanggal mulai dan tanggal akhir), serta empat tombol preset: "30M", "1J", "3J", "Semua".
3. WHEN pengguna memilih tanggal mulai dan tanggal akhir yang valid, THE applyFilters SHALL memfilter `allLogs` sehingga hanya log dengan timestamp dalam rentang [tanggal mulai 00:00:00, tanggal akhir 23:59:59] yang masuk ke `filteredLogs`.
4. WHEN pengguna mengklik tombol preset "30M", THE Date_Range_Filter SHALL mengatur rentang waktu ke 30 menit terakhir dari log terbaru dan memperbarui `filteredLogs`.
5. WHEN pengguna mengklik tombol preset "1J", THE Date_Range_Filter SHALL mengatur rentang waktu ke 1 jam terakhir dari log terbaru dan memperbarui `filteredLogs`.
6. WHEN pengguna mengklik tombol preset "3J", THE Date_Range_Filter SHALL mengatur rentang waktu ke 3 jam terakhir dari log terbaru dan memperbarui `filteredLogs`.
7. WHEN pengguna mengklik tombol preset "Semua", THE Date_Range_Filter SHALL menghapus semua batasan waktu dan menampilkan semua log di `filteredLogs` (hanya dibatasi oleh filter severity dan keyword).
8. IF tanggal mulai yang dipilih lebih besar dari tanggal akhir, THEN THE Date_Range_Filter SHALL menampilkan pesan validasi "Tanggal mulai tidak boleh lebih besar dari tanggal akhir" dan TIDAK memperbarui `filteredLogs`.
9. WHEN file log baru dimuat (`allLogs` berubah), THE Date_Range_Filter SHALL secara otomatis mengisi input tanggal mulai dan tanggal akhir berdasarkan tanggal terlama dan terbaru yang ditemukan di log.
10. THE Date_Range_Filter SHALL mempertahankan kompatibilitas dengan label timeframe yang ditampilkan di header tabel log ("Timeframe: ..."), dengan menggunakan format "DD/MM/YYYY – DD/MM/YYYY" untuk rentang absolut.
11. WHILE preset "30M", "1J", atau "3J" aktif, THE Date_Range_Filter SHALL menampilkan tombol preset tersebut dalam kondisi aktif (highlighted). WHEN pengguna secara manual mengedit salah satu input tanggal, THE Date_Range_Filter SHALL secara otomatis menonaktifkan preset yang sedang aktif (tidak ada preset yang highlighted) dan menggunakan nilai tanggal yang diinput secara manual.
12. WHEN preset "Semua" diklik, THE Date_Range_Filter SHALL mengosongkan batasan waktu dan membiarkan kedua input tanggal tetap editable dan tidak terkunci.
