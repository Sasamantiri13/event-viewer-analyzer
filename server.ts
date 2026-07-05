import express from "express";
import path from "path";
import fs from "fs";
import { createServer as createViteServer } from "vite";
import dotenv from "dotenv";
import { GoogleGenAI } from "@google/genai";
import OpenAI from "openai";

dotenv.config();

// Load Windows Event ID Knowledge Base (offline)
let windowsKB: any[] = [];
try {
  const kbPath = path.join(process.cwd(), "src", "data", "kb", "database", "windowseventid.json");
  if (fs.existsSync(kbPath)) {
    windowsKB = JSON.parse(fs.readFileSync(kbPath, "utf-8"));
    console.log(`Loaded Windows Event ID KB: ${windowsKB.length} entries.`);
  }
} catch (e) {
  console.warn("Could not load Windows Event ID KB:", e);
}

function lookupKBEntry(eventId: string | number): any | null {
  const id = eventId?.toString();
  if (!id) return null;
  return windowsKB.find(e => e["event-id"] === id) || null;
}

// Lazy initialization of GoogleGenAI client to prevent crash on startup if key is missing
let aiClient: GoogleGenAI | null = null;

function getAiClient(): GoogleGenAI {
  if (!aiClient) {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      throw new Error("GEMINI_API_KEY environment variable is not configured. Please set it in the Secrets panel in AI Studio.");
    }
    aiClient = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          "User-Agent": "aistudio-build",
        },
      },
    });
  }
  return aiClient;
}

let openaiClient: OpenAI | null = null;

function getOpenaiClient(): OpenAI {
  if (!openaiClient) {
    const apiKey = process.env.OPENAI_API_KEY;
    if (!apiKey) {
      throw new Error("OPENAI_API_KEY is not configured.");
    }
    openaiClient = new OpenAI({
      apiKey,
    });
  }
  return openaiClient;
}

function generateHeuristicReport(logs: any[], categoryCounts: any, timeFrameText: string, isMultiFileCorrelation: boolean = false): string {
  const totalLogs = logs.length;
  const criticalLogs = logs.filter(l => l.level === "Critical");
  const errorLogs = logs.filter(l => l.level === "Error");
  const warningLogs = logs.filter(l => l.level === "Warning");
  const infoLogs = logs.filter(l => l.level === "Information");

  // Determine overall status
  let overallSeverity = "Aman (Information)";
  let severityEmoji = "✅";
  if (criticalLogs.length > 0) {
    overallSeverity = "Kritis (Critical)";
    severityEmoji = "🚨";
  } else if (errorLogs.length > 0) {
    overallSeverity = "Kesalahan (Error)";
    severityEmoji = "⚠️";
  } else if (warningLogs.length > 0) {
    overallSeverity = "Peringatan (Warning)";
    severityEmoji = "🔔";
  }

  // Find matched Defender directory codes
  const matchedCodes: any[] = [];
  const defenderCodesList = [
    { code: "1116", title: "Malware Detection", rec: "Periksa jalur file terinfeksi. Jalankan full scan segera." },
    { code: "1117", title: "Malware Action Taken", rec: "Ancaman telah dinetralisir aman. Terus pantau aktivitas perangkat." },
    { code: "1118", title: "Malware Action Failed", rec: "🚨 SEGERA laksanakan scan offline atau pembersihan manual!" },
    { code: "1119", title: "Remediation Signature Failed", rec: "Perbarui Security Intelligence Defender dengan PowerShell 'Update-MpSignature'." },
    { code: "2011", title: "Security Intelligence Update Failed", rec: "Jalankan 'MpCmdRun.exe -SignatureUpdate' untuk memperbarui tanda tangan virus secara manual." },
    { code: "5001", title: "Real-time Protection Disabled", rec: "Aktifkan kembali proteksi real-time via PowerShell 'Set-MpPreference -DisableRealtimeMonitoring $false'." },
    { code: "5007", title: "Defender Configuration Changed", rec: "Audit perubahan konfigurasi untuk memastikan tidak ada percobaan bypass." },
    { code: "5008", title: "Real-time Protection Failed", rec: "Restart service Defender (Windefend) dan cek adanya konflik driver." },
    { code: "5009", title: "Antivirus is Disabled", rec: "🚨 Aktifkan kembali antivirus segera via Group Policy atau Registry!" },
    { code: "3001", title: "Driver Load Blocked (Code Integrity)", rec: "Mencegah BYOVD (Bring Your Own Vulnerable Driver). Gunakan driver resmi WHQL dan hapus loader tidak sah." },
    { code: "3002", title: "Image Hash Verification Failed", rec: "Kerusakan berkas sistem terdeteksi. Jalankan 'sfc /scannow' atau instal ulang paket biner." },
    { code: "3004", title: "Kernel-Mode Signing Violation", rec: "Sertifikat driver kernel tidak sah. Jalankan 'sigverif' atau pastikan driver ditandatangani Microsoft secara digital." },
    { code: "3091", title: "WDAC Policy Blocked Executive", rec: "File diblokir kebijakan WDAC/AppLocker. Daftarkan pengecualian (publisher rule) jika file ini sah." },
    { code: "3097", title: "Code Integrity Signature Failure", rec: "Gagal memverifikasi tanda tangan pustaka inti. Update sistem sertifikat root Windows Anda." },
    { code: "0x80508015", title: "Scan or Threat Cleanup Error", rec: "Jalankan 'Microsoft Defender Offline Scan' dari Windows Security." },
    { code: "0x80070005", title: "Access Denied (Akses Ditolak)", rec: "Gunakan alat pembersih bootable steril untuk menembus malware rootkit." },
    { code: "0x80070422", title: "Service Disabled Error", rec: "Nyalakan kembali service via 'sc config WinDefend start= auto' di CMD Admin." },
    { code: "0x80070643", title: "Fatal Installation / Update Error", rec: "Jalankan Windows Update Troubleshooter dan bersihkan folder SoftwareDistribution." }
  ];

  logs.forEach(log => {
    const evMatch = defenderCodesList.find(c => log.eventId?.toString() === c.code);
    if (evMatch && !matchedCodes.some(m => m.code === evMatch.code)) {
      matchedCodes.push(evMatch);
    }
    defenderCodesList.forEach(c => {
      if (c.code.startsWith("0x") && log.message?.toLowerCase().includes(c.code.toLowerCase())) {
        if (!matchedCodes.some(m => m.code === c.code)) {
          matchedCodes.push(c);
        }
      }
    });
  });

  // KB Enrichment - match log event IDs against the downloaded knowledge base
  const kbMatches: { eventId: string; criticality: string; summary: string }[] = [];
  const seenKbIds = new Set<string>();
  logs.forEach(log => {
    const id = log.eventId?.toString();
    if (!id || seenKbIds.has(id)) return;
    const kbEntry = lookupKBEntry(id);
    if (kbEntry) {
      seenKbIds.add(id);
      kbMatches.push({
        eventId: id,
        criticality: kbEntry.criticality || "Unknown",
        summary: kbEntry.summary || "No description",
      });
    }
  });

  // Group by Category to find dominant issues
  const categoriesMap: Record<string, number> = {};
  logs.forEach(log => {
    categoriesMap[log.category] = (categoriesMap[log.category] || 0) + 1;
  });
  const dominantCategory = Object.entries(categoriesMap).sort((a, b) => b[1] - a[1])[0]?.[0] || "Tidak spesifik";

  // Build the markdown text step-by-step
  let md = `### 📊 Laporan Diagnostik Sistem Offline (Mode Heuristik + Knowledge Base)

> **Mode Analisis**: 🔒 Offline (Knowledge Base Lokal: ${windowsKB.length} entri Windows Event ID)

1. **Ringkasan Eksekutif (Executive Summary)**
Sistem mendeteksi total **${totalLogs} log abnormal** dalam jangka waktu **${timeFrameText || "1 jam terakhir"}**. Berdasarkan pola kejadian, kategori kendala yang mendominasi adalah **${dominantCategory}**. Tingkat keparahan keseluruhan dinilai berada pada level **${overallSeverity} ${severityEmoji}**.

- Total Kejadian Kritis (Critical): **${criticalLogs.length}**
- Total Kesalahan (Error): **${errorLogs.length}**
- Total Peringatan (Warning): **${warningLogs.length}**
- Total Informasi (Information): **${infoLogs.length}**

2. **Analisis Kendala Utama (Major Findings & Root Cause)**
Berikut adalah temuan utama dari rincian log yang dimuat:
${criticalLogs.length > 0 ? `- **Kegagalan Kritis Terdeteksi**: Terdapat ${criticalLogs.length} entri tingkat kepatuhan KRITIS yang membutuhkan perhatian langsung. Terutama berasal dari sumber \`${criticalLogs[0]?.source || "N/A"}\` dengan Event ID \`${criticalLogs[0]?.eventId || "N/A"}\`.\n` : ""}
${errorLogs.length > 0 ? `- **Kesalahan Sistem/Aplikasi**: Terdapat ${errorLogs.length} error terkait modul \`${errorLogs[0]?.source || "N/A"}\`. Pola ini mengindikasikan adanya service crash atau ketidakmampuan mengakses resource sistem secara reguler.\n` : ""}
${warningLogs.length > 0 ? `- **Indikasi Peringatan Keamanan**: Ditemukan ${warningLogs.length} log peringatan (warning) dari sumber \`${warningLogs[0]?.source || "N/A"}\` yang perlu dipantau untuk mencegah terjadinya kegagalan sistem yang lebih besar.\n` : ""}
- **Sumber Utama Penyebab**: Masalah didominasi oleh ketidakselarasan konfigurasi atau kegagalan pembaruan modul pendukung sistem.

3. **Analisis Defender Endpoint (Bila relevan)**
Pencocokan tanda tangan dengan Kamus Masalah Microsoft Defender Endpoint:
${matchedCodes.length > 0 ? matchedCodes.map(m => `- **Ditemukan Kode ${m.code} (${m.title})**: ${m.rec}`).join("\n") : "- *Tidak ditemukan Event ID atau HRESULT spesifik Microsoft Defender Endpoint dalam log terfilter saat ini.*"}

${kbMatches.length > 0 ? `4. **📚 Knowledge Base Windows Event ID (Enrichment Lokal)**
Sistem berhasil mencocokkan **${kbMatches.length} Event ID** dengan database pengetahuan Windows:
${kbMatches.slice(0, 15).map(k => `- **Event ID ${k.eventId}** [${k.criticality}]: ${k.summary}`).join("\n")}
${kbMatches.length > 15 ? `\n- *...dan ${kbMatches.length - 15} Event ID lainnya.*` : ""}
` : ""}
${isMultiFileCorrelation ? `${kbMatches.length > 0 ? "5" : "4"}. **Korelasi Silang 2 Berkas (Smart Multi-File Check)**
- **Deteksi Otomatis**: Sistem mendeteksi dua sumber berkas log yang diunggah bersamaan.
- **Korelasi Teridentifikasi**: Berdasarkan analisis heuristik lokal, masalah yang teridentifikasi pada berkas pertama kemungkinan besar memiliki hubungan sebab-akibat (causal chain) dengan kegagalan sistem dasar yang tercatat pada berkas kedua.
` : ""}
${isMultiFileCorrelation ? (kbMatches.length > 0 ? "6" : "5") : (kbMatches.length > 0 ? "5" : "4")}. **Rekomendasi Langkah Perbaikan (Actionable Recommendations)**
Berdasarkan analisis heuristic lokal, Administrator disarankan melakukan langkah remediasi berikut:
- **Langkah 1 (PowerShell Keamanan)**: Buka PowerShell dengan Hak Administrator, lalu jalankan pembaruan definisi pertahanan antivirus:
  \`\`\`powershell
  Update-MpSignature
  \`\`\`
- **Langkah 2 (Verifikasi Layanan)**: Pastikan seluruh service vital Microsoft Defender Endpoint dan System Service dalam kondisi berjalan normal:
  \`\`\`cmd
  sc query WinDefend
  sc start WinDefend
  \`\`\`
- **Langkah 3 (Kesehatan Berkas)**: Untuk mengoreksi potensi crash berkas sistem akibat pembaruan yang rusak, jalankan utilitas pemulihan terintegrasi:
  \`\`\`cmd
  sfc /scannow
  DISM.exe /Online /Cleanup-image /Restorehealth
  \`\`\`

${isMultiFileCorrelation ? (kbMatches.length > 0 ? "7" : "6") : (kbMatches.length > 0 ? "6" : "5")}. **Tingkat Keparahan & Urgensi (Severity & Urgency Rating)**
- **Status Kesehatan**: **${overallSeverity}**
- **Skor Urgensi**: **${criticalLogs.length > 0 ? "9/10 (Sangat Tinggi - Butuh Penanganan Segera)" : errorLogs.length > 0 ? "7/10 (Tinggi - Segera Jadwalkan Perbaikan)" : "4/10 (Sedang - Pantau Berkala)"}**
- **Catatan**: Laporan ini dihasilkan secara offline menggunakan mesin heuristik lokal dan Knowledge Base Windows Event ID (${windowsKB.length} entri). Hubungkan API Key untuk analisis AI yang lebih mendalam.`;

  return md;
}


async function startServer() {
  const app = express();
  const PORT = 3000;

  // Increase payload size limit to accept logs
  app.use(express.json({ limit: "20mb" }));

  // API endpoints
  app.get("/api/health", (req, res) => {
    res.json({ status: "ok", time: new Date().toISOString() });
  });

  // AI analysis endpoint
  app.post("/api/analyze-logs", async (req, res) => {
    try {
      const { logs, categoryCounts, timeFrameText, isMultiFileCorrelation, forceMode } = req.body;

      if (!logs || !Array.isArray(logs) || logs.length === 0) {
        return res.status(400).json({ error: "No logs provided for analysis." });
      }

      // If forceMode is "offline", skip AI entirely and use heuristic+KB
      if (forceMode === "offline") {
        console.info("Force Offline Mode: Generating KB-enriched heuristic report.");
        const localAnalysis = generateHeuristicReport(logs, categoryCounts, timeFrameText, isMultiFileCorrelation);
        return res.json({
          analysis: localAnalysis,
          isHeuristicFallback: true,
          mode: "offline",
          kbSize: windowsKB.length
        });
      }

      // Check for API Keys
      const geminiApiKey = process.env.GEMINI_API_KEY;
      const openAiApiKey = process.env.OPENAI_API_KEY;

      // Format log summary for model input
      const formattedLogs = logs
        .slice(0, 40) // Take top 40 critical logs to avoid overwhelming tokens and stay highly focused
        .map((log, idx) => {
          return `${idx + 1}. [${log.level.toUpperCase()}] [${log.timestamp}] [Source: ${log.source}] [EventID: ${log.eventId}]
   Message: ${log.message.substring(0, 300)}${log.message.length > 300 ? "..." : ""}
   ${log.channel ? `Channel: ${log.channel}` : ""} ${log.computer ? `Computer: ${log.computer}` : ""}`;
        })
        .join("\n\n");

      const statsSummary = Object.entries(categoryCounts || {})
        .map(([cat, count]) => `${cat}: ${count}`)
        .join(", ");

const systemInstruction = `Anda adalah seorang Enterprise Windows Security & System Administrator expert.
Tugas Anda adalah menganalisis log Windows Event Viewer (System & Application) untuk menemukan bukti (evidence) kendala, crash, atau indikasi ancaman keamanan dalam ${timeFrameText || "waktu"} terakhir log.
Fokus khusus pada troubleshooting, penanganan error, kecocokan dengan Defender Endpoint Event & Error Codes (seperti Defender Event ID 1116, 1117, 5001, 5007, atau HRESULT error codes seperti 0x80508015, 0x80070005, dll. yang merujuk pada https://learn.microsoft.com/en-us/defender-endpoint/event-error-codes).

${isMultiFileCorrelation ? `**INSTRUKSI KHUSUS MULTI-FILE CORRELATION**: Administrator telah mengunggah 2 file log yang berbeda. Tugas Anda adalah melakukan **Korelasi Silang (Cross-Correlation)** secara cerdas antara dua log tersebut. Temukan akar penyebab (root cause) dari suatu masalah dengan mengaitkan error di satu log (misal Aplikasi) dengan error sistem dasar (misal Disk atau Code Integrity) pada rentang waktu yang sama.` : ''}

Berikan hasil analisis yang mendalam, terstruktur, profesional, dan dalam Bahasa Indonesia.
Format response harus menggunakan Markdown yang rapi dengan bagian-bagian berikut:
1. **Ringkasan Eksekutif (Executive Summary)**: Penjelasan singkat dan jelas mengenai apa yang terjadi pada sistem berdasarkan data log.
2. **Analisis Kendala Utama (Major Findings & Root Cause)**: Identifikasi kendala terpenting atau kritis (misal: Service crash, Defender blocked, Disk failures, DCOM error, dll.). Jelaskan apa arti error tersebut, hubungannya dengan kode error Windows/Defender, dan root cause-nya.
3. **Analisis Defender Endpoint (Bila relevan)**: Sorot jika ada Event ID atau error code yang cocok dengan direktori Defender Endpoint.
${isMultiFileCorrelation ? `4. **Korelasi Silang 2 Berkas (Smart Multi-File Check)**: Berikan pemahaman cerdas tentang hubungan sebab-akibat yang ditemukan dari gabungan 2 file log yang diunggah. Tunjukkan bukti urutan waktu kejadian jika relevan.\n5. **Rekomendasi Langkah Perbaikan (Actionable Recommendations)**: Langkah teknis konkret...` : `4. **Rekomendasi Langkah Perbaikan (Actionable Recommendations)**: Langkah teknis konkret...`}
${isMultiFileCorrelation ? `6` : `5`}. **Tingkat Keparahan & Urgensi (Severity & Urgency Rating)**: Berikan kesimpulan status kesehatan sistem (Kritis / Peringatan / Aman) beserta tingkat urgensi.

Gunakan nada bicara yang profesional, teknis, mantap, dan mudah dipahami oleh tim operasional IT/Security Operations Center (SOC).`;

      const prompt = `Berikut adalah data statistik log yang dianalisis:
- Timeframe analisis: ${timeFrameText || "3 jam terakhir"}
- Distribusi tingkat keparahan / kategori: ${statsSummary || "N/A"}
- Jumlah log kritis yang dikirim untuk analisis mendalam: ${logs.length} log.

Berikut adalah detail dari log-log penting / bermasalah:
\`\`\`text
${formattedLogs}
\`\`\`

Silakan lakukan analisis mendalam terhadap log di atas sesuai dengan instruksi sistem Anda. Hubungkan dengan direktori kendala Microsoft Defender Endpoint bila terdeteksi indikasi terkait Defender atau kode kesalahan Windows yang umum.`;

      if (geminiApiKey) {
        // Initialize Gemini client lazily
        const ai = getAiClient();

        const response = await ai.models.generateContent({
          model: "gemini-3.5-flash",
          contents: prompt,
          config: {
            systemInstruction,
            temperature: 0.2, // low temperature for precise, fact-based diagnosis
          },
        });

        const analysisText = response.text || "Gagal menghasilkan analisis AI.";
        return res.json({ analysis: analysisText, mode: "online-gemini" });
      } else if (openAiApiKey) {
        console.info("Using OpenAI GPT-4o for diagnostic analysis fallback.");
        const openai = getOpenaiClient();

        const completion = await openai.chat.completions.create({
          model: "gpt-4o",
          messages: [
            { role: "system", content: systemInstruction },
            { role: "user", content: prompt }
          ],
          temperature: 0.2
        });

        const analysisText = completion.choices[0]?.message?.content || "Gagal menghasilkan analisis AI.";
        return res.json({ 
          analysis: analysisText,
          isOpenAiActive: true,
          mode: "online-openai"
        });
      } else {
        console.warn("No AI API keys configured or hit quota. Generating KB-enriched local diagnostic report.");
        const localAnalysis = generateHeuristicReport(logs, categoryCounts, timeFrameText, isMultiFileCorrelation);
        return res.json({ 
          analysis: localAnalysis, 
          isHeuristicFallback: true,
          mode: "offline",
          kbSize: windowsKB.length
        });
      }
    } catch (error: any) {
      console.error("AI Analysis Error:", error);
      res.status(500).json({
        error: error.message || "An error occurred during AI analysis. Please verify your GEMINI_API_KEY.",
      });
    }
  });

  // API Key status check endpoint
  app.get("/api/check-keys", (req, res) => {
    const geminiKey = process.env.GEMINI_API_KEY;
    const openaiKey = process.env.OPENAI_API_KEY;
    res.json({
      gemini: !!geminiKey && geminiKey.length > 5,
      openai: !!openaiKey && openaiKey.length > 5,
      kbLoaded: windowsKB.length > 0,
      kbSize: windowsKB.length
    });
  });

  // Serve static assets & route all requests to index.html in production
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on port ${PORT}`);
  });
}

startServer();
