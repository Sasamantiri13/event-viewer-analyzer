/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { DefenderErrorCode } from "../types";

export const defenderErrorCodes: DefenderErrorCode[] = [
  // Event IDs
  {
    code: "Event ID 1116",
    title: "Malware Detection",
    type: "Event ID",
    description: "Windows Defender Antivirus terdeteksi ancaman malware atau software berbahaya (PUA/LPI) pada perangkat ini.",
    recommendation: "Periksa jalur file yang terinfeksi di rincian log. Jalankan full scan dan pastikan file dikarantina atau dihapus.",
    link: "https://learn.microsoft.com/en-us/defender-endpoint/event-error-codes"
  },
  {
    code: "Event ID 1117",
    title: "Malware Action Taken",
    type: "Event ID",
    description: "Tindakan remediasi (karantina, hapus, atau bersihkan) berhasil dilakukan pada ancaman malware yang terdeteksi.",
    recommendation: "Ancaman telah berhasil diamankan. Tetap lakukan monitoring pada aktivitas file terkait untuk memastikan tidak ada infeksi ulang.",
    link: "https://learn.microsoft.com/en-us/defender-endpoint/event-error-codes"
  },
  {
    code: "Event ID 1118",
    title: "Malware Action Failed",
    type: "Event ID",
    description: "Windows Defender Antivirus gagal melakukan tindakan remediasi (karantina atau hapus) terhadap ancaman yang terdeteksi.",
    recommendation: "SEGERA lakukan tindakan manual! Reboot ke Safe Mode, gunakan Microsoft Defender Offline Scan, atau bersihkan file secara manual dengan hak administrator.",
    link: "https://learn.microsoft.com/en-us/defender-endpoint/event-error-codes"
  },
  {
    code: "Event ID 1119",
    title: "Remediation Signature Failed",
    type: "Event ID",
    description: "Remediasi kritis gagal karena tanda tangan/signature pemulihan tidak dapat dimuat atau mengalami kerusakan.",
    recommendation: "Perbarui Security Intelligence Defender ke versi terbaru menggunakan PowerShell 'Update-MpSignature', lalu jalankan kembali scan.",
    link: "https://learn.microsoft.com/en-us/defender-endpoint/event-error-codes"
  },
  {
    code: "Event ID 2000",
    title: "Endpoint Protection Platform Update Succeeded",
    type: "Event ID",
    description: "Pembaruan platform mesin pemindai (Engine) Microsoft Defender berhasil dipasang.",
    recommendation: "Tidak ada tindakan yang diperlukan. Sistem berjalan pada platform Defender versi terbaru yang stabil.",
    link: "https://learn.microsoft.com/en-us/defender-endpoint/event-error-codes"
  },
  {
    code: "Event ID 2001",
    title: "Endpoint Protection Platform Update Failed",
    type: "Event ID",
    description: "Gagal memperbarui platform mesin pemindai Microsoft Defender.",
    recommendation: "Periksa koneksi internet ke Microsoft Update. Reset Windows Update components jika diperlukan, atau instal secara manual via portal Catalog.",
    link: "https://learn.microsoft.com/en-us/defender-endpoint/event-error-codes"
  },
  {
    code: "Event ID 2010",
    title: "Security Intelligence Update Succeeded",
    type: "Event ID",
    description: "Definisi tanda tangan virus (security intelligence) berhasil diperbarui ke database lokal.",
    recommendation: "Sistem telah menggunakan proteksi definisi terbaru. Pastikan frekuensi update dilakukan secara berkala.",
    link: "https://learn.microsoft.com/en-us/defender-endpoint/event-error-codes"
  },
  {
    code: "Event ID 2011",
    title: "Security Intelligence Update Failed",
    type: "Event ID",
    description: "Gagal mengunduh atau menerapkan database tanda tangan virus terbaru.",
    recommendation: "Periksa error code (misal 0x80070643). Jalankan 'MpCmdRun.exe -SignatureUpdate' dari command prompt administrator untuk update manual.",
    link: "https://learn.microsoft.com/en-us/defender-endpoint/event-error-codes"
  },
  {
    code: "Event ID 3002",
    title: "Real-time Protection Blocked Event",
    type: "Event ID",
    description: "Fitur Proteksi Real-time atau Proteksi Jaringan berhasil memblokir akses ke URL jahat, eksploitasi, atau dokumen mencurigakan.",
    recommendation: "Akses berbahaya berhasil dicegah. Beritahu pengguna untuk menghindari situs atau file tersebut, dan audit log jaringan jika ada indikasi serangan lateral.",
    link: "https://learn.microsoft.com/en-us/defender-endpoint/event-error-codes"
  },
  {
    code: "Event ID 5001",
    title: "Real-time Protection Disabled",
    type: "Event ID",
    description: "Proteksi Real-time Windows Defender dinonaktifkan secara sengaja atau oleh pihak ketiga.",
    recommendation: "⚠️ KRITIS! Aktifkan kembali proteksi real-time segera melalui Windows Security UI atau jalankan command PowerShell: 'Set-MpPreference -DisableRealtimeMonitoring $false'.",
    link: "https://learn.microsoft.com/en-us/defender-endpoint/event-error-codes"
  },
  {
    code: "Event ID 5007",
    title: "Defender Configuration Changed",
    type: "Event ID",
    description: "Konfigurasi penting Microsoft Defender telah diubah (misal pengecualian folder baru ditambahkan, proteksi cloud dinonaktifkan).",
    recommendation: "Audit perubahan ini. Pastikan perubahan dilakukan oleh administrator yang sah dan bukan taktik bypass antivirus (Defense Evasion) oleh malware.",
    link: "https://learn.microsoft.com/en-us/defender-endpoint/event-error-codes"
  },
  {
    code: "Event ID 5008",
    title: "Real-time Protection Failed",
    type: "Event ID",
    description: "Proteksi real-time mengalami kegagalan fatal pada modul internal sehingga tidak dapat memantau aktivitas sistem.",
    recommendation: "Restart service Defender (Windefend). Jika masalah berlanjut, periksa adanya driver antivirus pihak ketiga yang tumpang tindih atau kerusakan sistem file.",
    link: "https://learn.microsoft.com/en-us/defender-endpoint/event-error-codes"
  },
  {
    code: "Event ID 5009",
    title: "Antivirus is Disabled",
    type: "Event ID",
    description: "Windows Defender Antivirus sepenuhnya dimatikan dan dinonaktifkan.",
    recommendation: "🚨 BAHAYA! Perangkat tidak memiliki proteksi aktif. Aktifkan kembali antivirus segera melalui Group Policy, Registry, atau periksa infeksi malware aktif yang mencoba melumpuhkan keamanan.",
    link: "https://learn.microsoft.com/en-us/defender-endpoint/event-error-codes"
  },
  {
    code: "Event ID 5010",
    title: "Defender Scan Stopped",
    type: "Event ID",
    description: "Pemindaian antivirus dihentikan secara paksa sebelum selesai dilakukan.",
    recommendation: "Jalankan ulang scan cepat (quick scan) atau scan penuh (full scan). Periksa apakah ada intervensi pengguna atau crash pada modul MpEngine.dll.",
    link: "https://learn.microsoft.com/en-us/defender-endpoint/event-error-codes"
  },
  {
    code: "Event ID 5011",
    title: "Real-time Protection State Changed",
    type: "Event ID",
    description: "Status proteksi real-time berubah (on/off). Log ini merekam transisi status.",
    recommendation: "Pastikan status akhir berada pada posisi AKTIF. Selidiki riwayat log jika transisi off terjadi di luar jendela maintenance.",
    link: "https://learn.microsoft.com/en-us/defender-endpoint/event-error-codes"
  },
  {
    code: "Event ID 1006",
    title: "Malware Blocked In Transit",
    type: "Event ID",
    description: "Unduhan file berbahaya dari internet atau drive eksternal berhasil dideteksi dan diblokir sebelum tereksekusi.",
    recommendation: "File telah terblokir aman. Bersihkan folder unduhan sementara dan ingatkan pengguna mengenai bahaya mengunduh file mencurigakan.",
    link: "https://learn.microsoft.com/en-us/defender-endpoint/event-error-codes"
  },
  {
    code: "Event ID 1015",
    title: "ASR Rule Triggered",
    type: "Event ID",
    description: "Aturan Attack Surface Reduction (ASR) mendeteksi dan memblokir aktivitas mencurigakan (misal: Office makro menjalankan child process).",
    recommendation: "Lakukan review kebijakan ASR. Jika ini adalah aplikasi bisnis yang sah, buat pengecualian khusus. Jika bukan, ini adalah indikasi percobaan intrusi.",
    link: "https://learn.microsoft.com/en-us/defender-endpoint/event-error-codes"
  },
  {
    code: "Event ID 3001",
    title: "Driver Load Blocked (Unsigned)",
    type: "Event ID",
    description: "Microsoft Windows Code Integrity memblokir pemuatan driver perangkat karena driver tersebut tidak memiliki tanda tangan digital yang valid atau tepercaya.",
    recommendation: "Mencegah serangan pemuatan driver rentan (Bring Your Own Vulnerable Driver - BYOVD). Verifikasi jalur file driver (.sys) di rincian log, dan pasang driver berlisensi resmi WHQL dari situs resmi vendor.",
    link: "https://learn.microsoft.com/en-us/windows-hardware/drivers/install/code-integrity"
  },
  {
    code: "Event ID 3002",
    title: "Image Hash Verification Failed",
    type: "Event ID",
    description: "Code Integrity tidak dapat memverifikasi hash gambar (image hash) dari file eksekusi atau pustaka DLL karena integritas file terganggu.",
    recommendation: "Ini mengindikasikan adanya file sistem atau pustaka aplikasi yang rusak atau dimodifikasi tanpa izin. Jalankan perintah 'sfc /scannow' atau instal ulang aplikasi terkait untuk memulihkan berkas biner asli.",
    link: "https://learn.microsoft.com/en-us/windows-hardware/drivers/install/code-integrity"
  },
  {
    code: "Event ID 3004",
    title: "Kernel-Mode Code Signing Violation",
    type: "Event ID",
    description: "Verifikasi tanda tangan digital tingkat kernel gagal untuk file driver sistem utama saat booting atau startup layanan.",
    recommendation: "Audit daftar driver sistem yang terpasang. Jalankan antivirus untuk memastikan tidak ada rootkit atau malware yang mencoba memuat driver tingkat rendah secara ilegal.",
    link: "https://learn.microsoft.com/en-us/windows-hardware/drivers/install/code-integrity"
  },
  {
    code: "Event ID 3091",
    title: "WDAC Policy Blocked Executive",
    type: "Event ID",
    description: "Windows Defender Application Control (WDAC) memblokir pemuatan file biner karena tidak memenuhi syarat kebijakan kontrol aplikasi.",
    recommendation: "Jika aplikasi ini sah untuk kebutuhan kantor, tambahkan aturan penerbit (publisher rule) atau hash rule pada konfigurasi WDAC Anda. Jika tidak dikenal, blokir ini menandakan pencegahan serangan siber yang sukses.",
    link: "https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/wdac"
  },
  {
    code: "Event ID 3097",
    title: "Code Integrity Signature Failure",
    type: "Event ID",
    description: "Code Integrity mendeteksi kegagalan tanda tangan digital yang tidak valid atau telah kedaluwarsa pada file sistem biner Windows yang krusial.",
    recommendation: "Jalankan Windows Update untuk memperbarui sertifikat otoritas akar (root certificates) dan jalankan verifikasi integritas 'DISM /Online /Cleanup-Image /RestoreHealth'.",
    link: "https://learn.microsoft.com/en-us/windows-hardware/drivers/install/code-integrity"
  },

  // HRESULT Error Codes
  {
    code: "0x80508015",
    title: "Scan or Threat Cleanup Error",
    type: "HRESULT",
    description: "Terjadi kesalahan internal ketika Defender mencoba membersihkan ancaman. Ini sering disebabkan oleh file target yang terkunci secara eksklusif oleh proses sistem lain.",
    recommendation: "Jalankan 'Microsoft Defender Offline Scan' sehingga sistem akan reboot ke lingkungan steril untuk membersihkan file tanpa intervensi OS aktif.",
    link: "https://learn.microsoft.com/en-us/defender-endpoint/event-error-codes"
  },
  {
    code: "0x80508001",
    title: "Real-time Protection Disabled Error",
    type: "HRESULT",
    description: "Kesalahan internal di mana mesin pemindaian tidak dapat mengaktifkan monitor real-time karena adanya konflik group policy atau service Windefend gagal berjalan.",
    recommendation: "Verifikasi Group Policy di 'Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus'. Pastikan tidak ada policy menonaktifkan antivirus.",
    link: "https://learn.microsoft.com/en-us/defender-endpoint/event-error-codes"
  },
  {
    code: "0x80508007",
    title: "Scan Cancelled by Policy",
    type: "HRESULT",
    description: "Operasi pemindaian dibatalkan secara paksa oleh administrator atau karena perubahan kebijakan daya (misalnya beralih ke baterai hemat daya).",
    recommendation: "Pastikan komputer terhubung ke daya AC saat menjalankan scan penuh, atau konfigurasikan ulang task scheduler agar mengizinkan pemindaian saat baterai aktif.",
    link: "https://learn.microsoft.com/en-us/defender-endpoint/event-error-codes"
  },
  {
    code: "0x80508016",
    title: "Scan Engine Initialization Failed",
    type: "HRESULT",
    description: "Mesin pemindai gagal diinisialisasi. Kemungkinan besar disebabkan oleh rusaknya file biner utama Defender (seperti MpEngine.dll) setelah update yang korup.",
    recommendation: "Jalankan perintah System File Checker: 'sfc /scannow' diikuti dengan 'DISM.exe /Online /Cleanup-image /Restorehealth' di Command Prompt Administrator untuk memperbaiki file sistem.",
    link: "https://learn.microsoft.com/en-us/defender-endpoint/event-error-codes"
  },
  {
    code: "0x80070005",
    title: "Access Denied (Akses Ditolak)",
    type: "HRESULT",
    description: "Operasi atau service Defender diblokir ketika mengakses file atau kunci Registry. Sering kali merupakan tanda aktivitas malware canggih (Rootkit) yang melumpuhkan izin akses antivirus.",
    recommendation: "Jalankan pemindaian dengan media bootable eksternal (Microsoft Defender Offline / Windows PE). Pulihkan hak akses folder dengan perintah icacls.",
    link: "https://learn.microsoft.com/en-us/defender-endpoint/event-error-codes"
  },
  {
    code: "0x80070422",
    title: "Service Disabled Error",
    type: "HRESULT",
    description: "Layanan utama Defender (Windefend atau Sense) berada dalam kondisi Dinonaktifkan (Disabled) di konfigurasi services.msc.",
    recommendation: "Jalankan Command Prompt Administrator dan ketik: 'sc config WinDefend start= auto' kemudian 'sc start WinDefend' untuk mengaktifkan kembali layanan.",
    link: "https://learn.microsoft.com/en-us/defender-endpoint/event-error-codes"
  },
  {
    code: "0x80041002",
    title: "WMI Namespace Provider Error",
    type: "HRESULT",
    description: "Namespace WMI untuk Microsoft Defender rusak. Hal ini membuat modul management internal GPO/SCCM/Intune tidak bisa mengontrol status proteksi.",
    recommendation: "Bangun kembali repositori WMI dengan menjalankan perintah: 'winmgmt /resetrepository' di Command Prompt dengan hak akses administrator.",
    link: "https://learn.microsoft.com/en-us/defender-endpoint/event-error-codes"
  },
  {
    code: "0x8007000e",
    title: "Out of Memory",
    type: "HRESULT",
    description: "Sistem kehabisan RAM atau memori virtual ketika melakukan pemindaian file yang sangat besar atau terkompresi berlapis-lapis.",
    recommendation: "Konfigurasikan pembatasan ukuran file maksimum yang dipindai, tambahkan RAM fisik, atau perluas ukuran Pagefile di pengaturan sistem Windows.",
    link: "https://learn.microsoft.com/en-us/defender-endpoint/event-error-codes"
  },
  {
    code: "0x80070057",
    title: "Invalid Parameter Passing",
    type: "HRESULT",
    description: "Pemanggilan executable MpCmdRun.exe atau PowerShell Security Module menggunakan argumen/parameter yang tidak valid.",
    recommendation: "Verifikasi sintaks skrip otomasi Anda. Gunakan command bawaan yang bersih seperti 'Start-MpScan -ScanType QuickScan' tanpa modifikasi parameter eksperimental.",
    link: "https://learn.microsoft.com/en-us/defender-endpoint/event-error-codes"
  },
  {
    code: "0x80508023",
    title: "Threat Remediated Or Missing",
    type: "HRESULT",
    description: "Upaya tindakan pembersihan gagal karena file ancaman sudah tidak ditemukan (kemungkinan telah dihapus oleh proteksi real-time, dihapus manual, atau dipindah ke karantina).",
    recommendation: "Aman. Ancaman sudah dinetralisir terlebih dahulu. Segarkan status Windows Security dashboard.",
    link: "https://learn.microsoft.com/en-us/defender-endpoint/event-error-codes"
  },
  {
    code: "0x80070643",
    title: "Fatal Installation / Update Error",
    type: "HRESULT",
    description: "Kesalahan kritis yang sangat umum terjadi saat proses instalasi database keamanan KB2267602 gagal diterapkan akibat konflik cache update yang rusak.",
    recommendation: "Jalankan troubleshoot Windows Update, hapus file cache di 'C:\\Windows\\SoftwareDistribution\\Download', lalu jalankan 'Update-MpSignature' di PowerShell Admin.",
    link: "https://learn.microsoft.com/en-us/defender-endpoint/event-error-codes"
  }
];

export function lookupErrorCode(codeOrId: string | number): DefenderErrorCode | undefined {
  const normalizedSearch = codeOrId.toString().toLowerCase().trim();
  
  return defenderErrorCodes.find(item => {
    // If searching Event ID (e.g., "1116" or "Event ID 1116")
    if (typeof codeOrId === "number" || /^\d+$/.test(normalizedSearch)) {
      const matchNum = normalizedSearch;
      return item.code.includes(matchNum) && item.type === "Event ID";
    }
    // If searching HRESULT code (e.g., "0x80508015")
    return item.code.toLowerCase() === normalizedSearch;
  });
}
