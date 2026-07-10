# Implementation Plan: appscript-kb-summary

## Overview

Implementasi dilakukan secara bertahap dalam tujuh kelompok tugas utama. Dimulai dari ekspansi skema KB dan penambahan 150+ entri ke Google Sheets, lalu pengkayaan laporan heuristik di `HeuristicEngine.gs`, kemudian lima fungsi CRUD baru di `Code.gs`, diikuti komponen UI baru di `Index.html` (Date Range Picker, tab Summary, tab KB), dan diakhiri dengan property-based tests untuk memverifikasi invariant kebenaran.

Semua kode menggunakan Google Apps Script (JavaScript ES5 kompatibel) untuk sisi server dan JavaScript vanilla untuk sisi klien di `Index.html`.

---

## Tasks

- [x] 1. Ekspansi Skema KB dan Seed 150+ Entri di `Code.gs`
  - [x] 1.1 Perbarui fungsi `createKBSheet_()` di `Code.gs` — tambahkan 5 kolom baru ke header row
    - Ganti baris `sheet.appendRow(["event-id", "legacy-event-id", "criticality", "summary"])` menjadi 9 kolom: `["event-id", "legacy-event-id", "criticality", "summary", "category", "mitigation", "mitre_tactic", "source_log", "os_version"]`
    - Perbarui array `essentialEntries` yang ada agar setiap baris memiliki 9 elemen (tambah 5 string kosong untuk kolom baru pada entri lama)
    - _Requirements: 1.1, 1.2_

  - [x] 1.2 Tambahkan 100+ entri baru dengan 9 kolom lengkap ke `createKBSheet_()` untuk mencapai minimal 150 total entri
    - Tambah entri baru dari kategori: Auditing & Access (Event ID 4656, 4658, 4663, 4670, 4698, 4702, 4703, 4704, 4705, 4706, 4707, 4713, 4714, 4715, 4716, 4717), Defender Security (1120, 1121, 2000, 2001, 2002, 2003, 2004, 5010, 5011, 5012, 5013, 5100, 5101), Code Integrity / WDAC (3010, 3033, 3034, 3040, 3041, 3064, 3065, 3066, 3076, 3077, 3080, 3082, 3089, 3090), Service Failures (7002, 7003, 7004, 7005, 7006, 7007, 7008, 7010, 7011, 7017, 7023, 7024, 7026, 7032, 7038, 7045), Application Crash (1000, 1001, 1002, 1005, 1026, 1033), Hardware & Disk (9, 10, 11, 15, 51, 52, 55, 57, 98, 129, 153, 157), Network & Firewalls (4946, 4947, 4948, 4949, 5025, 5031, 5152, 5153, 5156, 5157), System Updates (19, 20, 21, 22, 43), AppLocker (8000, 8003, 8006, 8007)
    - Isi kolom `mitigation` dengan langkah remediation spesifik dalam Bahasa Indonesia
    - Isi kolom `mitre_tactic` dengan kode MITRE ATT&CK yang relevan (contoh: T1110, T1562, T1059)
    - Isi kolom `category` secara konsisten (contoh: "Auditing & Access", "Defender Security", "Code Integrity", "Service Failures", "Application Crash", "Hardware & Disk", "Network & Firewalls", "System Updates", "AppLocker")
    - Isi kolom `source_log` dengan nama log Windows (Security, System, Application, Microsoft-Windows-CodeIntegrity/Operational, dsb.)
    - Isi kolom `os_version` jika relevan untuk versi Windows tertentu (kosong jika berlaku umum)
    - _Requirements: 1.1, 1.3_

  - [x] 1.3 Perbarui fungsi `loadKB_()` di `Code.gs` agar mendukung deteksi format lama vs baru
    - Setelah membangun objek `entry` dari header, cek apakah `headers` hanya memiliki 4 kolom (format lama)
    - Jika format lama terdeteksi, tambahkan flag `entry["isLegacyFormat"] = true` ke setiap entry
    - Jika format baru (9 kolom), flag tidak perlu ditambahkan (atau set `false`)
    - _Requirements: 1.4, 1.5_

- [ ] 2. Checkpoint — Verifikasi Skema KB
  - Jalankan `createKBSheet_()` di environment GAS lokal, pastikan sheet "WindowsEventDB" memiliki 9 kolom header dan minimal 150 baris data.
  - Pastikan `loadKB_()` mengembalikan array dengan objek yang memiliki key `category`, `mitigation`, `mitre_tactic`, `source_log`, `os_version`.
  - Tanyakan kepada pengguna jika ada pertanyaan sebelum lanjut.

- [ ] 3. Penyempurnaan `HeuristicEngine.gs` — Laporan Heuristik yang Diperkaya
  - [x] 3.1 Perbarui blok KB enrichment di `generateHeuristicReport()` agar menggunakan kolom baru
    - Ubah objek yang di-push ke `kbMatches` agar menyertakan: `category`, `mitigation`, `mitre_tactic` dari `kbEntry` (ambil nilai kosong jika tidak ada)
    - Ubah kunci objek kbMatches dari `{ eventId, criticality, summary }` menjadi `{ eventId, criticality, summary, category, mitigation, mitre_tactic }`
    - _Requirements: 2.1, 2.3_

  - [x] 3.2 Tambahkan sorting berdasarkan kritikalitas dan tingkatkan batas tampilan menjadi 20 entri
    - Setelah loop `kbMatches` selesai dibangun, sort array `kbMatches` dengan urutan: Critical → High → Medium → Low → Unknown
    - Definisikan map prioritas: `{ Critical: 0, High: 1, Medium: 2, Low: 3, Unknown: 4 }`
    - Gunakan `.slice(0, 20)` saat merender (naik dari 15)
    - _Requirements: 2.4_

  - [x] 3.3 Tambahkan bagian "Knowledge Base Enrichment" yang menampilkan `mitigation` per Event ID
    - Di dalam blok rendering `kbMatches`, untuk setiap entry: jika `k.mitigation` tidak kosong, tampilkan baris tambahan `  - 🛡️ Mitigasi: ${k.mitigation}`
    - Cek flag `isLegacyFormat` pada entry pertama kbMatches — jika format lama, lewati blok mitigation tanpa error
    - _Requirements: 2.1, 2.5_

  - [x] 3.4 Tambahkan bagian "Pemetaan MITRE ATT&CK" ke laporan jika terdapat kbMatches dengan `mitre_tactic` terisi
    - Setelah bagian KB Enrichment, kumpulkan semua nilai `mitre_tactic` unik dari `kbMatches` yang tidak kosong
    - Buat section baru bernomor: `N. **🎯 Pemetaan MITRE ATT&CK**\n`
    - Kelompokkan Event ID berdasarkan taktik yang sama, format: `- **${tactic}**: Event ID ${ids.join(", ")}`
    - _Requirements: 2.2, 2.3_

  - [ ]* 3.5 Tulis unit test untuk `generateHeuristicReport()` dengan KB format baru
    - Test bahwa bagian "Pemetaan MITRE ATT&CK" muncul ketika KB memiliki kolom `mitre_tactic` terisi
    - Test bahwa bagian "Mitigasi" per Event ID muncul saat format baru, dan tidak error saat format lama
    - Test bahwa maksimal 20 entri KB ditampilkan, diurutkan Critical di atas
    - _Requirements: 2.1, 2.2, 2.4, 2.5_

- [ ] 4. Checkpoint — Verifikasi HeuristicEngine
  - Jalankan analisis heuristik dengan data log contoh, periksa bahwa laporan HTML yang dihasilkan mengandung bagian "Pemetaan MITRE ATT&CK" dan baris "Mitigasi" per Event ID.
  - Tanyakan kepada pengguna jika ada pertanyaan sebelum lanjut.

- [x] 5. Tambahkan Lima Fungsi CRUD Server-Side ke `Code.gs`
  - [x] 5.1 Implementasikan fungsi `getKBEntries()` di `Code.gs`
    - Panggil `loadKB_()` untuk mendapatkan entries (memanfaatkan cache)
    - Kembalikan `JSON.stringify(entries)` — return `"[]"` jika terjadi exception, log error ke `Logger`
    - Jangan mutasi `KB_CACHE_` jika cache sudah warm
    - _Requirements: 1.4_

  - [x] 5.2 Implementasikan fungsi `addKBEntry(entryJson)` di `Code.gs`
    - Parse `entryJson`, validasi: `event-id` non-empty & digit-only regex `/^\d+$/`, `criticality` salah satu dari 5 nilai yang diizinkan, `summary` non-empty
    - Jalankan duplicate check dengan memanggil `loadKB_()` dan scan array untuk event-id yang sama
    - Jika lolos: ambil sheet via `PropertiesService`, `sheet.appendRow([...9 kolom...])`, set `KB_CACHE_ = null`
    - Kembalikan `JSON.stringify({ success: true, entry: entry })` atau `{ success: false, error: "..." }`
    - _Requirements: 1.1, 1.4_

  - [x] 5.3 Implementasikan fungsi `updateKBEntry(eventId, fieldsJson)` di `Code.gs`
    - Parse `fieldsJson`, ambil `data = sheet.getDataRange().getValues()`, scan baris untuk menemukan `rowIndex` berdasarkan kolom `event-id`
    - Jika tidak ditemukan: kembalikan `{ success: false, error: "Entry not found: X" }`
    - Untuk setiap key di `fields`: cari index kolom dari `headers`, panggil `sheet.getRange(rowIndex, colIndex).setValue(...)`
    - Set `KB_CACHE_ = null`, kembalikan `{ success: true }`
    - _Requirements: 1.4_

  - [x] 5.4 Implementasikan fungsi `deleteKBEntry(eventId)` di `Code.gs`
    - Ambil `data`, scan untuk menemukan baris dengan `event-id === eventId`
    - Jika tidak ditemukan: kembalikan `{ success: false, error: "Entry not found: X" }`
    - Panggil `sheet.deleteRow(rowIndex)`, set `KB_CACHE_ = null`, kembalikan `{ success: true }`
    - _Requirements: 1.4_

  - [x] 5.5 Implementasikan fungsi `refreshKBCache()` di `Code.gs`
    - Set `KB_CACHE_ = null`, panggil `loadKB_()` untuk re-populate cache dari sheet
    - Kembalikan `JSON.stringify({ success: true, count: entries.length })`
    - _Requirements: 1.7_

  - [ ]* 5.6 Tulis property test untuk **Property 1: Cache Consistency After Write** (validates Req 1.7)
    - **Property 1: Cache Consistency After Write**
    - **Validates: Requirements 1.7**
    - Setelah setiap fungsi write (`addKBEntry`, `updateKBEntry`, `deleteKBEntry`, `refreshKBCache`) berhasil, assert `KB_CACHE_ === null`
    - Gunakan fast-check (jika tersedia di test environment) atau manual generative test dengan berbagai input valid
    - _Requirements: 1.7_

  - [ ]* 5.7 Tulis property test untuk **Property 2: No Duplicate Event IDs** (validates Req 1.3)
    - **Property 2: No Duplicate Event IDs**
    - **Validates: Requirements 1.3**
    - Untuk arbitrary valid entry `e`, jika `addKBEntry(e)` mengembalikan `{ success: true }`, maka `getKBEntries()` harus mengandung tepat 1 entry dengan `event-id === e["event-id"]`
    - _Requirements: 1.3_

  - [ ]* 5.8 Tulis property test untuk **Property 3: Idempotent Delete** (validates Req 1.5)
    - **Property 3: Idempotent Delete**
    - **Validates: Requirements 1.5**
    - Memanggil `deleteKBEntry("99999-nonexistent")` harus mengembalikan `{ success: false }` dan jumlah baris sheet tidak berubah
    - _Requirements: 1.5_

- [ ] 6. Checkpoint — Verifikasi Fungsi CRUD Server-Side
  - Test setiap fungsi di Google Apps Script Editor menggunakan Run button, pastikan tidak ada exception.
  - Verifikasi bahwa `addKBEntry` menolak duplikat dan input tidak valid.
  - Tanyakan kepada pengguna jika ada pertanyaan sebelum lanjut.

- [ ] 7. Date Range Picker di `Index.html` — Ganti `<select id="timeFilter">`
  - [x] 7.1 Tambahkan CSS untuk Date Range Picker ke blok `<style>` di `Index.html`
    - Tambahkan style untuk `.date-range-picker` (wrapper flex), `.date-input` (input[type=date] styling), `.preset-btn` dan `.preset-btn.active` (tombol preset highlighted)
    - Gunakan CSS variables yang sudah ada (`--primary`, `--border`, `--card`, dsb.)
    - _Requirements: 4.1, 4.2_

- [x] 7.2 Ganti elemen `<select id="timeFilter">` di HTML dengan markup Date Range Picker
    - Hapus `<select id="timeFilter" ...>` dari filter-row
    - Tambahkan: dua input `<input type="date" id="dateStart">` dan `<input type="date" id="dateEnd">`, label pemisah "–"
    - Tambahkan empat tombol preset: `<button class="preset-btn" id="preset30m" onclick="applyPreset('30m')">30M</button>`, `1J`, `3J`, `Semua`
    - Tambahkan `<div id="dateRangeError" class="hidden" style="...">` untuk pesan validasi
    - _Requirements: 4.1, 4.2_

  - [x] 7.3 Implementasikan fungsi `applyPreset(type)` di blok `<script>` di `Index.html`
    - Untuk `'30m'`: cari log terbaru di `allLogs`, hitung `latestTime - 30*60*1000`, set `dateStart.value` dan `dateEnd.value` dalam format `YYYY-MM-DD`, highlight tombol 30M, panggil `applyFilters()`
    - Untuk `'1j'`: sama, tapi 60 menit
    - Untuk `'3j'`: sama, tapi 180 menit
    - Untuk `'all'`: kosongkan kedua input date, hilangkan semua highlight preset, panggil `applyFilters()`
    - Simpan active preset di var `activePreset`
    - _Requirements: 4.4, 4.5, 4.6, 4.7, 4.12_

  - [x] 7.4 Perbarui fungsi `applyFilters()` di `Index.html` untuk menggunakan Date Range sebagai ganti `timeFilter`
    - Baca `dateStart.value` dan `dateEnd.value`
    - Validasi: jika `dateStart` > `dateEnd` (keduanya terisi), tampilkan `dateRangeError`, return tanpa update `filteredLogs`
    - Jika keduanya kosong: tidak ada filter waktu (tampilkan semua, setara preset "Semua")
    - Jika terisi: filter `allLogs` sehingga hanya log dengan timestamp dalam `[dateStart 00:00:00, dateEnd 23:59:59]` yang lolos
    - Hapus semua referensi ke `document.getElementById("timeFilter").value`
    - _Requirements: 4.3, 4.8_

  - [x] 7.5 Implementasikan auto-population tanggal saat file baru dimuat
    - Di fungsi yang menangani selesainya parsing file (`processFiles` / worker `onmessage`), setelah `allLogs` diisi, cari `minDate` dan `maxDate` dari timestamps seluruh log
    - Set `dateStart.value = minDate` dan `dateEnd.value = maxDate` dalam format `YYYY-MM-DD`
    - Hilangkan highlight semua preset (set `activePreset = null`)
    - Panggil `applyFilters()`
    - _Requirements: 4.9_

  - [x] 7.6 Perbarui label `#timeframeLabel` dan listener input date untuk menon-aktifkan preset aktif saat edit manual
    - Tambahkan event `oninput` pada kedua input date: set `activePreset = null`, hapus class `active` dari semua preset-btn, hilangkan pesan error
    - Perbarui `updateTimeframeLabel()` (atau lokasi yang setara): jika rentang absolut, format sebagai `"DD/MM/YYYY – DD/MM/YYYY"`; jika preset aktif gunakan label preset
    - _Requirements: 4.10, 4.11_

  - [ ]* 7.7 Tulis unit test untuk logika Date Range Filter
    - Test validasi: `dateStart > dateEnd` → `filteredLogs` tidak berubah, pesan error muncul
    - Test preset "30M": `filteredLogs` hanya berisi log dalam 30 menit terakhir dari log terbaru
    - Test preset "Semua": semua log dari `allLogs` masuk ke `filteredLogs` (dibatasi filter severity/keyword saja)
    - Test auto-population: setelah file dimuat, `dateStart` dan `dateEnd` terisi dengan tanggal terlama dan terbaru
    - _Requirements: 4.3, 4.4, 4.7, 4.8, 4.9_

- [x] 8. Checkpoint — Verifikasi Date Range Picker
  - Buka aplikasi GAS, upload file log, verifikasi bahwa input tanggal terisi otomatis dan keempat tombol preset berfungsi.
  - Coba masukkan `dateStart > dateEnd`, pastikan pesan validasi muncul dan tabel tidak berubah.
  - Tanyakan kepada pengguna jika ada pertanyaan sebelum lanjut.

- [x] 9. Tab Summary di `Index.html` — Tab "📋 Summary"
- [x] 9.1 Tambahkan tab "📋 Summary" ke baris navigasi dan buat elemen `#tab-summary` di `Index.html`
    - Tambahkan `<div class="tab" data-tab="summary" onclick="switchTab('summary')">📋 Summary</div>` sebagai tab kelima (setelah Analitik)
    - Tambahkan `<div id="tab-summary" class="hidden">` di bawah `#tab-analytics`
    - Isi dengan: kartu counter "X Event ID Unik Terdeteksi" (`#summaryUniqueCount`), input search `#summarySearch`, tabel `#summaryTable` dengan kolom: Event ID, Jumlah, Severity Tertinggi, Kategori, Deskripsi, Mitigation, MITRE Tactic
    - Tambahkan tombol "Lihat Semua KB" (`#btnShowAllKB`) di dalam tab
    - Perbarui `switchTab()` agar menangani `"summary"` dan memanggil `renderSummaryTab()`
    - _Requirements: 3.1, 3.2, 3.3, 3.9, 3.12_

  - [x] 9.2 Implementasikan fungsi `buildSummaryData()` di `Index.html`
    - Aggregate `filteredLogs` per `eventId`: hitung `count`, tentukan `maxSeverity` (Critical > Error > Warning > Information)
    - Untuk setiap eventId unik, lookup KB dari array `kbEntries` (jika sudah dimuat) atau panggil `lookupKBEntryClient(eventId)` untuk mendapatkan `summary`, `mitigation`, `mitre_tactic`, `category`
    - Kembalikan array objek `{ eventId, count, maxSeverity, category, description, mitigation, mitreTactic }`
    - Default ke "—" untuk kolom KB jika tidak ada match
    - Sort default: `count` descending
    - _Requirements: 3.2, 3.4, 3.7, 3.8_

  - [x] 9.3 Implementasikan fungsi `renderSummaryTab()` di `Index.html`
    - Panggil `buildSummaryData()`, update `#summaryUniqueCount` dengan jumlah baris
    - Render `<tbody>` tabel dengan badge severity berwarna pada kolom "Severity Tertinggi"
    - Jika `filteredLogs` kosong: tampilkan baris "Pilih file log terlebih dahulu"
    - Terapkan filter `#summarySearch` (prefix/exact match pada Event ID, atau keyword di kolom Deskripsi)
    - _Requirements: 3.2, 3.3, 3.6, 3.11_

  - [x] 9.4 Implementasikan sortable columns untuk tabel Summary
    - Tambahkan `onclick="sortSummary('eventId')"` (dan kolom lain) ke setiap `<th>` di header tabel Summary
    - Implementasikan fungsi `sortSummary(col)`: toggle asc/desc jika kolom sama diklik dua kali, re-render tabel
    - Simpan state sort di variabel `summarySort = { col: 'count', dir: 'desc' }`
    - _Requirements: 3.5_

  - [x] 9.5 Implementasikan tombol "Lihat Semua KB" di tab Summary
    - Handler `#btnShowAllKB`: jika `kbEntries` sudah dimuat, render tabel Summary dengan semua entri KB (count = 0 atau "—")
    - Jika `kbEntries` belum dimuat, panggil `google.script.run.getKBEntries()` terlebih dahulu
    - _Requirements: 3.12_

  - [x] 9.6 Pastikan `renderSummaryTab()` dipanggil ulang setiap kali `applyFilters()` dieksekusi
    - Di akhir fungsi `applyFilters()`, tambahkan: `if (document.querySelector('[data-tab="summary"]').classList.contains("active")) renderSummaryTab();`
    - _Requirements: 3.10_

  - [ ]* 9.7 Tulis unit test untuk `buildSummaryData()` dan `renderSummaryTab()`
    - Test bahwa `maxSeverity` dihitung dengan urutan prioritas Critical > Error > Warning > Information yang benar
    - Test bahwa baris dengan Event ID yang tidak ada di KB menampilkan "—" di kolom Deskripsi/Mitigation/MITRE
    - Test bahwa `#summaryUniqueCount` selalu sama dengan jumlah Event ID unik di `filteredLogs`
    - _Requirements: 3.2, 3.6, 3.7, 3.8, 3.9_

- [x] 10. Checkpoint — Verifikasi Tab Summary
  - Buka tab Summary setelah log dimuat, verifikasi tabel terisi dengan kolom lengkap dan sort berfungsi.
  - Klik header kolom dua kali, pastikan toggle ascending/descending bekerja.
  - Tanyakan kepada pengguna jika ada pertanyaan sebelum lanjut.

- [x] 11. Tab KB di `Index.html` — Tab "📚 KB"
- [x] 11.1 Tambahkan tab "📚 KB" ke baris navigasi dan buat elemen `#tab-kb` di `Index.html`
    - Tambahkan `<div class="tab" data-tab="kb" onclick="switchTab('kb')">📚 KB</div>` sebagai tab keenam (setelah Summary)
    - Tambahkan CSS untuk: `.kb-stats-grid` (stats cards KB), `.kb-form` (add form), `.kb-modal` (edit modal), `.kb-error-banner`
    - Perbarui `switchTab()` agar menangani `"kb"` dan memanggil `loadKBTab()`
    - _Requirements: (desain — KB Tab UI)_

  - [x] 11.2 Buat markup HTML untuk tab KB: stats bar, filter, tabel, add form, edit modal
    - Stats bar: 6 kartu — Total, Critical, High, Medium, Low, Unknown (dengan ID `#kbStatTotal`, dll.)
    - Filter row: `<input type="text" id="kbSearch">` + `<select id="kbCritFilter">` (All, Critical, High, Medium, Low, Unknown) + tombol "🔄 Sync" (`onclick="syncKBCache()"`) + tombol "📥 JSON" (`onclick="exportKB('json')"`) + tombol "📥 CSV" (`onclick="exportKB('csv')"`)
    - Tabel `#kbTableBody` dengan kolom: Event ID, Criticality, Summary, Category, Mitigation, MITRE Tactic, Aksi (Edit/Hapus)
    - Add form (inline, hidden by default): input fields untuk semua 9 kolom KB + tombol Simpan/Batal
    - Edit modal (`.modal-overlay` pattern yang sudah ada): form dengan field yang sama + tombol Update/Batal
    - Error banner `#kbErrorBanner` (hidden by default)
    - _Requirements: (desain — KB Tab UI, Req 1.1-1.8)_

  - [x] 11.3 Implementasikan state management dan fungsi `loadKBTab()` di `Index.html`
    - Deklarasikan `var kbEntries = []; var kbFiltered = []; var kbLoaded = false;` di blok STATE
    - `loadKBTab()`: jika `kbLoaded === true`, return (guard untuk mencegah duplikasi load); panggil `google.script.run.withSuccessHandler(...).withFailureHandler(...).getKBEntries()`
    - Success handler: `kbEntries = JSON.parse(json); kbLoaded = true; applyKBFilters(); renderKBStats();`
    - Failure handler: tampilkan `#kbErrorBanner` dengan pesan error
    - _Requirements: (desain — loadKBTab, Performance Considerations)_

  - [x] 11.4 Implementasikan `renderKBStats()`, `applyKBFilters()`, dan `renderKBTable()` di `Index.html`
    - `renderKBStats()`: hitung dari `kbEntries` (bukan `kbFiltered`), update DOM `#kbStatTotal`, `#kbStatCritical`, dll.
    - `applyKBFilters()`: filter `kbEntries` berdasarkan `#kbSearch` (match pada event-id atau summary) dan `#kbCritFilter`, simpan ke `kbFiltered`, panggil `renderKBTable()`
    - `renderKBTable()`: render `#kbTableBody` dari `kbFiltered`; setiap baris punya tombol "✏️ Edit" (`onclick="openEditModal(entry['event-id'])"`) dan "🗑️ Hapus" (`onclick="deleteEntry(entry['event-id'])"`)
    - _Requirements: (desain — renderKBStats, applyKBFilters, Req 1.2, 1.6)_

  - [x] 11.5 Implementasikan `submitAddEntry()` — validasi client-side + panggil `addKBEntry` server
    - `openAddForm()`: tampilkan form inline (hapus `.hidden`)
    - `submitAddEntry()`: validasi `event-id` digit-only, `criticality` valid, `summary` non-empty; cek duplikat di `kbEntries` client-side; panggil `google.script.run.addKBEntry(JSON.stringify(entry))`
    - Success: `kbEntries.push(result.entry); applyKBFilters(); renderKBStats();`; sembunyikan form; reset field
    - Failure/error: tampilkan pesan error inline di form
    - _Requirements: (desain — submitAddEntry, Req 1.3, 1.4)_

  - [x] 11.6 Implementasikan `openEditModal(eventId)` dan `submitEditEntry()` di `Index.html`
    - `openEditModal(eventId)`: cari entry di `kbEntries`, populate field modal, tampilkan modal
    - `submitEditEntry()`: kumpulkan field yang berubah ke objek `fields`, panggil `google.script.run.updateKBEntry(eventId, JSON.stringify(fields))`
    - Success: patch `kbEntries` in-place, `applyKBFilters()`; tutup modal
    - Failure: tampilkan error di dalam modal
    - _Requirements: (desain — openEditModal, submitEditEntry)_

  - [x] 11.7 Implementasikan `deleteEntry(eventId)` dan `syncKBCache()` di `Index.html`
    - `deleteEntry(eventId)`: tampilkan `confirm("Hapus Event ID " + eventId + "?")`, jika OK panggil `google.script.run.deleteKBEntry(eventId)`
    - Success: `kbEntries = kbEntries.filter(...)`, `applyKBFilters()`, `renderKBStats()`
    - `syncKBCache()`: disable tombol Sync, panggil `google.script.run.refreshKBCache()`; success: `kbLoaded = false; loadKBTab();`; re-enable tombol
    - _Requirements: (desain — deleteEntry, syncKBCache, Req 1.5, 1.7)_

  - [x] 11.8 Implementasikan `exportKB(format)` di `Index.html`
    - `format = 'json'`: `content = JSON.stringify(kbEntries, null, 2)`, fileName `"kb-export.json"`, mimeType `"application/json"`
    - `format = 'csv'`: header `"event-id,legacy-event-id,criticality,summary,category,mitigation,mitre_tactic,source_log,os_version"`, escape setiap field (bungkus dengan `"` jika mengandung koma atau newline)
    - Buat `Blob`, `URL.createObjectURL`, trigger download via `<a>` element, revoke URL
    - _Requirements: (desain — exportKB, Req 1.8)_

  - [ ]* 11.9 Tulis property test untuk **Property 4: Stats Accuracy** (validates Req 1.2)
    - **Property 4: Stats Accuracy**
    - **Validates: Requirements 1.2**
    - `computeStats(kbEntries).total === kbEntries.length` harus selalu benar
    - `critical + high + medium + low + unknown === total` harus selalu benar
    - Test dengan berbagai kombinasi criticality value termasuk "Unknown"
    - _Requirements: 1.2_

  - [ ]* 11.10 Tulis property test untuk **Property 5: Export Completeness** (validates Req 1.8)
    - **Property 5: Export Completeness**
    - **Validates: Requirements 1.8**
    - CSV export: `exportedCSV.trim().split("\n").length === kbEntries.length + 1` (1 header + N baris)
    - JSON export: `JSON.parse(exportedJSON).length === kbEntries.length`
    - Test dengan `kbEntries` yang mengandung field berisi koma, newline, dan karakter khusus
    - _Requirements: 1.8_

  - [ ]* 11.11 Tulis property test untuk **Property 6: Filter Is a Subset** (validates Req 1.6)
    - **Property 6: Filter Is a Subset**
    - **Validates: Requirements 1.6**
    - `∀ query q, criticality c: applyKBFilters(q, c).length <= kbEntries.length`
    - Setiap entry di `kbFiltered` harus ada di `kbEntries` (subset property)
    - _Requirements: 1.6_

- [x] 12. Final Checkpoint — Integrasi Penuh dan Semua Tes Lulus
  - Jalankan semua property-based tests dan unit tests, pastikan tidak ada yang gagal.
  - Buka aplikasi GAS, navigasi ke tab KB, lakukan add/edit/delete/sync/export.
  - Buka tab Summary, verifikasi data KB terintegrasi pada kolom Deskripsi/Mitigation/MITRE.
  - Verifikasi Date Range Picker dan tab Summary saling terhubung (filter tanggal memperbarui Summary).
  - Tanyakan kepada pengguna jika ada pertanyaan sebelum melakukan deployment.

---

## Notes

- Task bertanda `*` bersifat opsional dan dapat dilewati untuk MVP yang lebih cepat
- Setiap task mereferensikan requirement spesifik untuk traceability
- Checkpoint memastikan validasi incremental sebelum lanjut ke fase berikutnya
- Property tests memvalidasi invariant universal yang tidak bisa ditangkap oleh unit test biasa
- Semua kode server menggunakan Google Apps Script (JavaScript ES5 kompatibel, tidak ada `const`/`let`/arrow function/template literal yang tidak didukung)
- Semua kode klien menggunakan JavaScript vanilla `var`-based sesuai pola yang sudah ada di `Index.html`
- `KB_CACHE_` adalah module-level variable yang diakses oleh fungsi baru sama persis seperti fungsi `loadKB_()` yang sudah ada

---

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["1.2", "1.3"] },
    { "id": 2, "tasks": ["3.1", "5.1"] },
    { "id": 3, "tasks": ["3.2", "3.3", "3.4", "5.2", "5.3", "5.4", "5.5", "7.1", "7.2"] },
    { "id": 4, "tasks": ["3.5", "5.6", "5.7", "5.8", "7.3", "7.4", "7.5"] },
    { "id": 5, "tasks": ["7.6", "9.1", "11.1"] },
    { "id": 6, "tasks": ["7.7", "9.2", "9.5", "11.2", "11.3"] },
    { "id": 7, "tasks": ["9.3", "9.4", "9.6", "11.4", "11.5"] },
    { "id": 8, "tasks": ["9.7", "11.6", "11.7", "11.8"] },
    { "id": 9, "tasks": ["11.9", "11.10", "11.11"] }
  ]
}
```
