/**
 * Event Viewer Analyzer — Google Apps Script Edition
 * Code.gs: Entry point, AI analysis, and server-side API functions
 */

/* ───────── Web App Entry Point ───────── */

function doGet() {
  var html = HtmlService.createHtmlOutputFromFile("Index")
    .setTitle("Event Viewer Analyzer")
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
  html.addMetaTag("viewport", "width=device-width, initial-scale=1");
  return html;
}

/* ───────── API Key Management ───────── */

function getGeminiApiKey_() {
  return PropertiesService.getScriptProperties().getProperty("GEMINI_API_KEY") || "";
}

function getOpenAiApiKey_() {
  return PropertiesService.getScriptProperties().getProperty("OPENAI_API_KEY") || "";
}

function checkApiKeys() {
  var gemini = getGeminiApiKey_();
  var openai = getOpenAiApiKey_();
  var kbSize = getKBSize();
  return {
    gemini: gemini.length > 5,
    openai: openai.length > 5,
    kbLoaded: kbSize > 0,
    kbSize: kbSize
  };
}

/* ───────── Knowledge Base from Google Sheets ───────── */

var KB_CACHE_ = null;

var DEFAULT_WINDOWS_KB = [
  {"event-id": "7", "criticality": "Critical", "summary": "Bad block on disk", "category": "Hardware & Disk", "mitigation": "Segera backup data dan ganti hard drive/SSD.", "mitre_tactic": ""},
  {"event-id": "11", "criticality": "High", "summary": "Disk controller error", "category": "Hardware & Disk", "mitigation": "Periksa kabel SATA/NVMe dan kesehatan disk.", "mitre_tactic": ""},
  {"event-id": "18", "criticality": "Critical", "summary": "WHEA Uncorrectable Error (Hardware)", "category": "Hardware & Disk", "mitigation": "Bisa menyebabkan BSOD. Cek suhu CPU, RAM (MemTest), atau PSU.", "mitre_tactic": ""},
  {"event-id": "41", "criticality": "Critical", "summary": "System rebooted without cleanly shutting down", "category": "Kernel-Power", "mitigation": "Gejala BSOD atau mati mendadak (Power failure). Cek minidump.", "mitre_tactic": ""},
  {"event-id": "51", "criticality": "Warning", "summary": "Paging operation error", "category": "Hardware & Disk", "mitigation": "Biasanya indikasi awal disk akan rusak atau kabel longgar.", "mitre_tactic": ""},
  {"event-id": "55", "criticality": "High", "summary": "NTFS File System Corruption", "category": "Hardware & Disk", "mitigation": "Jalankan 'chkdsk /f /r' segera untuk memperbaiki struktur file sistem.", "mitre_tactic": ""},
  {"event-id": "98", "criticality": "High", "summary": "NTFS volume requires online scan", "category": "Hardware & Disk", "mitigation": "Disk mulai bermasalah. Jadwalkan chkdsk saat reboot.", "mitre_tactic": ""},
  {"event-id": "153", "criticality": "High", "summary": "IO operation retried (Disk)", "category": "Hardware & Disk", "mitigation": "Disk mulai melambat atau controller bermasalah.", "mitre_tactic": ""},
  {"event-id": "1002", "criticality": "Medium", "summary": "Application Hang", "category": "Application Crash", "mitigation": "Aplikasi tidak merespon (Not Responding). Update aplikasi atau cek konflik memori.", "mitre_tactic": ""},
  {"event-id": "1014", "criticality": "Warning", "summary": "DNS Client Name Resolution Timeout", "category": "Network", "mitigation": "Cek koneksi internet, router, atau ganti DNS ke 8.8.8.8.", "mitre_tactic": ""},
  {"event-id": "6008", "criticality": "High", "summary": "Unexpected Shutdown", "category": "System", "mitigation": "Server/PC mati paksa sebelumnya. Periksa log Event 41.", "mitre_tactic": ""},
  {"event-id": "10016", "criticality": "Low", "summary": "DistributedCOM (DCOM) Permission Error", "category": "System", "mitigation": "Abaikan jika sistem berjalan normal. Cukup sering terjadi sebagai noise.", "mitre_tactic": ""},
  {"event-id": "1000", "criticality": "High", "summary": "Application Crash", "category": "Application", "mitigation": "Periksa dump file dan perbarui aplikasi yang bermasalah.", "mitre_tactic": "T1499"},
  {"event-id": "1001", "criticality": "Medium", "summary": "Windows Error Reporting", "category": "Application", "mitigation": "Analisis bucket fault pada event viewer.", "mitre_tactic": ""},
  {"event-id": "1026", "criticality": "High", "summary": ".NET Runtime Exception", "category": "Application", "mitigation": "Perbaiki kode .NET yang tidak menangani exception.", "mitre_tactic": ""},
  {"event-id": "104", "criticality": "Critical", "summary": "Log File Cleared", "category": "System", "mitigation": "Investigasi segera, indikasi penghapusan jejak (defense evasion).", "mitre_tactic": "T1070.001"},
  {"event-id": "1102", "criticality": "Critical", "summary": "Audit Log Cleared", "category": "Security", "mitigation": "Tindakan mencurigakan. Kunci akun yang melakukan pembersihan log.", "mitre_tactic": "T1070.001"},
  {"event-id": "1116", "criticality": "Critical", "summary": "Defender: Malware Detected", "category": "Security", "mitigation": "Isolasi host dan jalankan full scan.", "mitre_tactic": "T1204"},
  {"event-id": "1117", "criticality": "High", "summary": "Defender: Malware Action Taken", "category": "Security", "mitigation": "Malware berhasil dihapus/karantina. Pantau aktivitas host.", "mitre_tactic": ""},
  {"event-id": "1118", "criticality": "Critical", "summary": "Defender: Action Failed", "category": "Security", "mitigation": "SEGERA lakukan scan offline, malware aktif menolak pembersihan.", "mitre_tactic": "T1562.001"},
  {"event-id": "4624", "criticality": "Low", "summary": "Successful Logon", "category": "Authentication", "mitigation": "Aktivitas normal. Pantau jika terjadi di luar jam kerja.", "mitre_tactic": "T1078"},
  {"event-id": "4625", "criticality": "High", "summary": "Failed Logon", "category": "Authentication", "mitigation": "Jika berulang kali, waspadai serangan Brute Force. Kunci akun.", "mitre_tactic": "T1110"},
  {"event-id": "4634", "criticality": "Low", "summary": "Logoff", "category": "Authentication", "mitigation": "Aktivitas normal.", "mitre_tactic": ""},
  {"event-id": "4648", "criticality": "Medium", "summary": "Logon with Explicit Credentials", "category": "Authentication", "mitigation": "Sering digunakan oleh admin atau attacker untuk Pass-the-Hash.", "mitre_tactic": "T1550.002"},
  {"event-id": "4672", "criticality": "High", "summary": "Special Privileges Assigned", "category": "Privilege", "mitigation": "Periksa jika akun bukan Administrator seharusnya tidak mendapat hak khusus.", "mitre_tactic": "T1078.002"},
  {"event-id": "4688", "criticality": "Medium", "summary": "Process Created", "category": "Process", "mitigation": "Aktifkan command line logging. Pantau proses LOLBins (PowerShell, cmd).", "mitre_tactic": "T1059"},
  {"event-id": "4698", "criticality": "High", "summary": "Scheduled Task Created", "category": "Persistence", "mitigation": "Sering digunakan untuk persistensi. Hapus task yang tidak dikenal.", "mitre_tactic": "T1053.005"},
  {"event-id": "4703", "criticality": "High", "summary": "Token Right Adjusted", "category": "Privilege", "mitigation": "Indikasi Privilege Escalation. Periksa proses yang meminta hak.", "mitre_tactic": "T1134"},
  {"event-id": "4719", "criticality": "Critical", "summary": "System Audit Policy Changed", "category": "Security", "mitigation": "Attacker mungkin mencoba mematikan auditing.", "mitre_tactic": "T1562.001"},
  {"event-id": "4720", "criticality": "High", "summary": "User Account Created", "category": "Account", "mitigation": "Pastikan pembuatan akun memang sah oleh Administrator.", "mitre_tactic": "T1136.001"},
  {"event-id": "4722", "criticality": "High", "summary": "User Account Enabled", "category": "Account", "mitigation": "Periksa jika akun tamu atau admin lama tiba-tiba diaktifkan.", "mitre_tactic": "T1098"},
  {"event-id": "4724", "criticality": "High", "summary": "Password Reset Attempt", "category": "Account", "mitigation": "Jika dilakukan pada akun Admin oleh akun biasa, segera blokir.", "mitre_tactic": "T1098"},
  {"event-id": "4728", "criticality": "High", "summary": "Member Added to Security Group", "category": "Privilege", "mitigation": "Pantau penambahan ke grup Domain Admins.", "mitre_tactic": "T1098"},
  {"event-id": "4732", "criticality": "High", "summary": "Member Added to Local Group", "category": "Privilege", "mitigation": "Pantau penambahan ke grup Administrators lokal.", "mitre_tactic": "T1098"},
  {"event-id": "4768", "criticality": "Low", "summary": "Kerberos TGT Requested", "category": "Authentication", "mitigation": "Normal, kecuali diminta massal (Golden Ticket attempt).", "mitre_tactic": "T1558.001"},
  {"event-id": "4769", "criticality": "Low", "summary": "Kerberos Service Ticket Requested", "category": "Authentication", "mitigation": "Pantau potensi Kerberoasting jika banyak tiket di-request berturut-turut.", "mitre_tactic": "T1558.003"},
  {"event-id": "4776", "criticality": "Medium", "summary": "NTLM Authentication Attempt", "category": "Authentication", "mitigation": "NTLM rentan terhadap Pass-the-Hash. Pertimbangkan migrasi penuh ke Kerberos.", "mitre_tactic": "T1550.002"},
  {"event-id": "5001", "criticality": "Critical", "summary": "Defender: Real-time Protection Disabled", "category": "Security", "mitigation": "Aktifkan paksa menggunakan Group Policy atau Set-MpPreference.", "mitre_tactic": "T1562.001"},
  {"event-id": "5140", "criticality": "Medium", "summary": "Network Share Accessed", "category": "Network", "mitigation": "Pantau jika IPC$ atau ADMIN$ diakses dari host tak dikenal (Lateral Movement).", "mitre_tactic": "T1021.002"},
  {"event-id": "7000", "criticality": "High", "summary": "Service Failed to Start", "category": "System", "mitigation": "Periksa kredensial service atau file biner yang hilang/rusak.", "mitre_tactic": ""},
  {"event-id": "7009", "criticality": "Medium", "summary": "Service Timeout", "category": "System", "mitigation": "Service terlalu lama merespon. Restart service atau periksa resource CPU.", "mitre_tactic": ""},
  {"event-id": "7031", "criticality": "High", "summary": "Service Terminated Unexpectedly", "category": "System", "mitigation": "Indikasi crash (misal spoolsv.exe rentan PrintNightmare).", "mitre_tactic": ""},
  {"event-id": "7045", "criticality": "High", "summary": "New Service Installed", "category": "Persistence", "mitigation": "Attacker sering menggunakan psexec (meninggalkan service PSEXESVC).", "mitre_tactic": "T1543.003"},
  {"event-id": "8002", "criticality": "Medium", "summary": "AppLocker Policy Applied", "category": "Security", "mitigation": "Normal, sistem mengikuti aturan eksekusi.", "mitre_tactic": ""},
  {"event-id": "8003", "criticality": "Medium", "summary": "AppLocker Warning", "category": "Security", "mitigation": "File melanggar aturan tetapi dibiarkan jalan (Audit Mode).", "mitre_tactic": ""},
  {"event-id": "8004", "criticality": "High", "summary": "AppLocker Blocked Execution", "category": "Security", "mitigation": "File di-block. Periksa apakah itu malware atau false positive.", "mitre_tactic": ""}
];

function loadKB_() {
  if (KB_CACHE_) return KB_CACHE_;
  
  var props = PropertiesService.getScriptProperties();
  var sheetId = props.getProperty("KB_SHEET_ID");
  
  if (!sheetId) {
    try {
      // Try to find by name in the same Drive folder
      var files = DriveApp.getFilesByName("EventViewerAnalyzer_KB");
      if (files.hasNext()) {
        sheetId = files.next().getId();
        props.setProperty("KB_SHEET_ID", sheetId);
      } else {
        Logger.log("KB Sheet not found. Creating one...");
        sheetId = createKBSheet_();
      }
    } catch(e) {
      Logger.log("Error finding/creating KB sheet: " + e.toString());
    }
  }
  
  var entries = [];
  try {
    if (sheetId) {
      var ss = SpreadsheetApp.openById(sheetId);
      var sheet = ss.getSheetByName("WindowsEventDB");
      if (sheet) {
        var data = sheet.getDataRange().getValues();
        if (data.length > 1) {
          var headers = data[0];
          var isLegacy = headers.length <= 4;
          for (var i = 1; i < data.length; i++) {
            var row = data[i];
            var entry = {};
            for (var j = 0; j < headers.length; j++) {
              entry[headers[j]] = row[j] !== undefined ? String(row[j]) : "";
            }
            if (isLegacy) {
              entry["isLegacyFormat"] = true;
            }
            entries.push(entry);
          }
        }
      }
    }
  } catch (e) {
    Logger.log("Error loading KB: " + e.toString());
  }
  
  // Gabungkan dengan DEFAULT_WINDOWS_KB
  var merged = entries.slice();
  var existingIds = {};
  for (var k=0; k<merged.length; k++) { existingIds[merged[k]["event-id"]] = true; }
  
  for (var x=0; x<DEFAULT_WINDOWS_KB.length; x++) {
    if (!existingIds[DEFAULT_WINDOWS_KB[x]["event-id"]]) {
      merged.push(DEFAULT_WINDOWS_KB[x]);
    }
  }
  
  KB_CACHE_ = merged;
  return merged;
}

function getKBSize() {
  var kb = loadKB_();
  return kb.length;
}

/* ───────── AI Chat Assistant ───────── */

function handleAIChat(chatHistoryJson, contextStr) {
  try {
    var chatHistory = JSON.parse(chatHistoryJson);
    var geminiKey = getGeminiApiKey_();
    var openaiKey = getOpenAiApiKey_();
    
    var systemInstruction = "Anda adalah Asisten AI untuk Windows Event Viewer Analyzer. Anda membantu admin IT memecahkan masalah sistem. " + 
                            "Berikan jawaban yang bersahabat, ringkas, dan diformat dalam Markdown. Konteks Log saat ini:\n\n" + contextStr;

    if (geminiKey && geminiKey.length > 5) {
      return JSON.stringify({ success: true, response: callGeminiChatAPI_(geminiKey, systemInstruction, chatHistory), mode: 'gemini' });
    } else if (openaiKey && openaiKey.length > 5) {
      return JSON.stringify({ success: true, response: callOpenAiChatAPI_(openaiKey, systemInstruction, chatHistory), mode: 'openai' });
    } else {
      return JSON.stringify({ success: false, error: "API Key AI belum dikonfigurasi. Masukkan API Key Gemini atau OpenAI di menu '🔑 API Key'." });
    }
  } catch(e) {
    return JSON.stringify({ success: false, error: e.toString() });
  }
}

function callGeminiChatAPI_(apiKey, systemInstruction, chatHistory) {
  var url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=" + apiKey;
  
  var contents = chatHistory.map(function(msg) {
    return {
      role: msg.role === 'model' || msg.role === 'assistant' ? 'model' : 'user',
      parts: [{ text: msg.text }]
    };
  });

  var payload = {
    system_instruction: { parts: [{ text: systemInstruction }] },
    contents: contents,
    generationConfig: { temperature: 0.3 }
  };
  
  var options = {
    method: "post",
    contentType: "application/json",
    payload: JSON.stringify(payload),
    muteHttpExceptions: true
  };
  
  var response = UrlFetchApp.fetch(url, options);
  var json = JSON.parse(response.getContentText());
  
  if (json.error) throw new Error("Gemini Chat API Error: " + json.error.message);
  if (json.candidates && json.candidates[0] && json.candidates[0].content) {
    return json.candidates[0].content.parts[0].text;
  }
  throw new Error("Unexpected Gemini response format");
}

function callOpenAiChatAPI_(apiKey, systemInstruction, chatHistory) {
  var url = "https://api.openai.com/v1/chat/completions";
  
  var messages = [{ role: "system", content: systemInstruction }];
  chatHistory.forEach(function(msg) {
    messages.push({
      role: msg.role === 'model' || msg.role === 'assistant' ? 'assistant' : 'user',
      content: msg.text
    });
  });
  
  var payload = {
    model: "gpt-4o-mini",
    messages: messages,
    temperature: 0.3
  };
  
  var options = {
    method: "post",
    contentType: "application/json",
    headers: { "Authorization": "Bearer " + apiKey },
    payload: JSON.stringify(payload),
    muteHttpExceptions: true
  };
  
  var response = UrlFetchApp.fetch(url, options);
  var json = JSON.parse(response.getContentText());
  
  if (json.error) throw new Error("OpenAI API Error: " + json.error.message);
  if (json.choices && json.choices[0] && json.choices[0].message) {
    return json.choices[0].message.content;
  }
  throw new Error("Unexpected OpenAI response format");
}

function lookupKBEntry(eventId) {
  var kb = loadKB_();
  var id = String(eventId);
  for (var i = 0; i < kb.length; i++) {
    if (kb[i]["event-id"] === id) return kb[i];
  }
  return null;
}

/* ───────── KB CRUD Functions ───────── */

function getKBEntries() {
  try {
    var entries = loadKB_();
    return JSON.stringify(entries);
  } catch (e) {
    Logger.log("Error in getKBEntries: " + e.toString());
    return "[]";
  }
}

function addKBEntry(entryJson) {
  try {
    var entry = JSON.parse(entryJson);

    if (!entry["event-id"] || !/^\d+$/.test(entry["event-id"])) {
      return JSON.stringify({ success: false, error: "Invalid event-id: must be non-empty digits only" });
    }
    var validCrit = ["Critical", "High", "Medium", "Low", "Unknown"];
    if (validCrit.indexOf(entry["criticality"]) === -1) {
      return JSON.stringify({ success: false, error: "Invalid criticality value" });
    }
    if (!entry["summary"] || entry["summary"].trim() === "") {
      return JSON.stringify({ success: false, error: "Summary is required" });
    }

    var existing = loadKB_();
    for (var i = 0; i < existing.length; i++) {
      if (existing[i]["event-id"] === entry["event-id"]) {
        return JSON.stringify({ success: false, error: "Duplicate event-id: " + entry["event-id"] });
      }
    }

    var sheetId = PropertiesService.getScriptProperties().getProperty("KB_SHEET_ID");
    if (!sheetId) return JSON.stringify({ success: false, error: "KB sheet not configured" });
    var sheet = SpreadsheetApp.openById(sheetId).getSheetByName("WindowsEventDB");
    if (!sheet) return JSON.stringify({ success: false, error: "WindowsEventDB sheet not found" });

    sheet.appendRow([
      entry["event-id"] || "",
      entry["legacy-event-id"] || "",
      entry["criticality"] || "",
      entry["summary"] || "",
      entry["category"] || "",
      entry["mitigation"] || "",
      entry["mitre_tactic"] || "",
      entry["source_log"] || "",
      entry["os_version"] || ""
    ]);

    KB_CACHE_ = null;
    return JSON.stringify({ success: true, entry: entry });
  } catch (e) {
    Logger.log("Error in addKBEntry: " + e.toString());
    return JSON.stringify({ success: false, error: e.toString() });
  }
}

function updateKBEntry(eventId, fieldsJson) {
  try {
    var fields = JSON.parse(fieldsJson);
    var sheetId = PropertiesService.getScriptProperties().getProperty("KB_SHEET_ID");
    if (!sheetId) return JSON.stringify({ success: false, error: "KB sheet not configured" });
    var sheet = SpreadsheetApp.openById(sheetId).getSheetByName("WindowsEventDB");
    if (!sheet) return JSON.stringify({ success: false, error: "WindowsEventDB sheet not found" });

    var data = sheet.getDataRange().getValues();
    var headers = data[0];

    var rowIndex = -1;
    for (var i = 1; i < data.length; i++) {
      if (String(data[i][0]) === String(eventId)) {
        rowIndex = i + 1;
        break;
      }
    }

    if (rowIndex === -1) {
      return JSON.stringify({ success: false, error: "Entry not found: " + eventId });
    }

    for (var key in fields) {
      if (fields.hasOwnProperty(key)) {
        var colIndex = -1;
        for (var j = 0; j < headers.length; j++) {
          if (headers[j] === key) { colIndex = j + 1; break; }
        }
        if (colIndex > 0) {
          sheet.getRange(rowIndex, colIndex).setValue(fields[key]);
        }
      }
    }

    KB_CACHE_ = null;
    return JSON.stringify({ success: true });
  } catch (e) {
    Logger.log("Error in updateKBEntry: " + e.toString());
    return JSON.stringify({ success: false, error: e.toString() });
  }
}

function deleteKBEntry(eventId) {
  try {
    var sheetId = PropertiesService.getScriptProperties().getProperty("KB_SHEET_ID");
    if (!sheetId) return JSON.stringify({ success: false, error: "KB sheet not configured" });
    var sheet = SpreadsheetApp.openById(sheetId).getSheetByName("WindowsEventDB");
    if (!sheet) return JSON.stringify({ success: false, error: "WindowsEventDB sheet not found" });

    var data = sheet.getDataRange().getValues();
    var rowIndex = -1;
    for (var i = 1; i < data.length; i++) {
      if (String(data[i][0]) === String(eventId)) {
        rowIndex = i + 1;
        break;
      }
    }

    if (rowIndex === -1) {
      return JSON.stringify({ success: false, error: "Entry not found: " + eventId });
    }

    sheet.deleteRow(rowIndex);
    KB_CACHE_ = null;
    return JSON.stringify({ success: true });
  } catch (e) {
    Logger.log("Error in deleteKBEntry: " + e.toString());
    return JSON.stringify({ success: false, error: e.toString() });
  }
}

function refreshKBCache() {
  try {
    KB_CACHE_ = null;
    var entries = loadKB_();
    return JSON.stringify({ success: true, count: entries.length });
  } catch (e) {
    Logger.log("Error in refreshKBCache: " + e.toString());
    return JSON.stringify({ success: false, count: 0, error: e.toString() });
  }
}

function createKBSheet_() {
  var ss = SpreadsheetApp.create("EventViewerAnalyzer_KB");
  var sheet = ss.getActiveSheet();
  sheet.setName("WindowsEventDB");
  sheet.appendRow(["event-id", "legacy-event-id", "criticality", "summary", "category", "mitigation", "mitre_tactic", "source_log", "os_version"]);
  
  // Add some essential entries
  var essentialEntries = [
    ["1000", "", "Medium", "Application Error - An application has crashed or encountered a fatal error", "", "", "", "", ""],
    ["1001", "", "Medium", "Windows Error Reporting - Application fault bucket information", "", "", "", "", ""],
    ["1026", "", "Medium", ".NET Runtime Error - An unhandled exception occurred in a .NET application", "", "", "", "", ""],
    ["4624", "", "Low", "Successful Logon - An account was successfully logged on", "", "", "", "", ""],
    ["4625", "", "High", "Failed Logon - An account failed to log on", "", "", "", "", ""],
    ["4648", "", "Medium", "Explicit Credential Logon - A logon was attempted using explicit credentials", "", "", "", "", ""],
    ["4768", "", "Low", "Kerberos Authentication Ticket (TGT) Requested", "", "", "", "", ""],
    ["4769", "", "Low", "Kerberos Service Ticket Requested", "", "", "", "", ""],
    ["4776", "", "Medium", "NTLM Authentication - Domain controller attempted to validate credentials", "", "", "", "", ""],
    ["7000", "", "High", "Service Control Manager - A service failed to start", "", "", "", "", ""],
    ["7001", "", "High", "Service Control Manager - A service depends on another service that failed", "", "", "", "", ""],
    ["7009", "", "Medium", "Service Control Manager - A timeout was reached while waiting for a service", "", "", "", "", ""],
    ["7022", "", "High", "Service Control Manager - A service hung on starting", "", "", "", "", ""],
    ["7031", "", "High", "Service Control Manager - A service terminated unexpectedly", "", "", "", "", ""],
    ["7034", "", "High", "Service Control Manager - A service terminated unexpectedly (repeated)", "", "", "", "", ""],
    ["7036", "", "Low", "Service Control Manager - A service entered the stopped/running state", "", "", "", "", ""],
    ["1116", "", "Critical", "Windows Defender - Malware or potentially unwanted software detected", "", "", "", "", ""],
    ["1117", "", "High", "Windows Defender - Action taken against malware", "", "", "", "", ""],
    ["1118", "", "Critical", "Windows Defender - Failed to take action against malware", "", "", "", "", ""],
    ["5001", "", "Critical", "Windows Defender - Real-time protection is disabled", "", "", "", "", ""],
    ["5007", "", "High", "Windows Defender - Configuration changed", "", "", "", "", ""],
    ["3001", "", "High", "Code Integrity - Driver load blocked due to unsigned or invalid signature", "", "", "", "", ""],
    ["3002", "", "High", "Code Integrity - Image hash verification failed", "", "", "", "", ""],
    ["3004", "", "High", "Code Integrity - Kernel-mode signing violation", "", "", "", "", ""],
    ["19", "", "Low", "Windows Update - Installation successful", "", "", "", "", ""],
    ["20", "", "Medium", "Windows Update - Installation failure", "", "", "", "", ""],
    ["51", "", "High", "Disk - An error was detected on device during a paging operation", "", "", "", "", ""],
    ["55", "", "Critical", "NTFS - File system structure corruption detected", "", "", "", "", ""],
    ["7", "", "High", "Disk - Bad block detected", "", "", "", "", ""],
    ["11", "", "High", "Disk Controller - Driver detected a controller error", "", "", "", "", ""],
    ["4688", "", "Low", "Security - A new process has been created", "", "", "", "", ""],
    ["4689", "", "Low", "Security - A process has exited", "", "", "", "", ""],
    ["4634", "", "Low", "Security - An account was logged off", "", "", "", "", ""],
    ["4647", "", "Low", "Security - User initiated logoff", "", "", "", "", ""],
    ["4672", "", "Medium", "Security - Special privileges assigned to new logon", "", "", "", "", ""],
    ["4720", "", "Medium", "Security - A user account was created", "", "", "", "", ""],
    ["4722", "", "Medium", "Security - A user account was enabled", "", "", "", "", ""],
    ["4723", "", "Low", "Security - An attempt was made to change an account's password", "", "", "", "", ""],
    ["4724", "", "High", "Security - An attempt was made to reset an account's password", "", "", "", "", ""],
    ["4725", "", "Medium", "Security - A user account was disabled", "", "", "", "", ""],
    ["4726", "", "High", "Security - A user account was deleted", "", "", "", "", ""],
    ["4728", "", "Medium", "Security - A member was added to a security-enabled global group", "", "", "", "", ""],
    ["4732", "", "Medium", "Security - A member was added to a security-enabled local group", "", "", "", "", ""],
    ["4740", "", "High", "Security - A user account was locked out", "", "", "", "", ""],
    ["5136", "", "Medium", "Security - A directory service object was modified", "", "", "", "", ""],
    ["5140", "", "Low", "Security - A network share object was accessed", "", "", "", "", ""],
    ["5142", "", "Medium", "Security - A network share object was added", "", "", "", "", ""],
    ["1102", "", "Critical", "Security - The audit log was cleared (Defense Evasion)", "", "", "", "", ""],
    ["104", "", "Critical", "System - The system log was cleared (Defense Evasion)", "", "", "", "", ""],
    ["6005", "", "Low", "System - The Event log service was started (System Boot)", "", "", "", "", ""],
    ["6006", "", "Low", "System - The Event log service was stopped (System Shutdown)", "", "", "", "", ""],
    ["6008", "", "High", "System - The previous system shutdown was unexpected", "", "", "", "", ""],
    ["1074", "", "Medium", "System - System has been shutdown by a process or user", "", "", "", "", ""],
    ["41", "", "Critical", "Kernel-Power - The system has rebooted without cleanly shutting down first", "", "", "", "", ""],
    ["1002", "", "High", "Application Hang - An application stopped interacting with Windows", "", "", "", "", ""],
    ["1040", "", "Low", "MsiInstaller - Beginning a Windows Installer transaction", "", "", "", "", ""],
    ["1042", "", "Low", "MsiInstaller - Ending a Windows Installer transaction", "", "", "", "", ""],
    ["1534", "", "Low", "User Profile Service - Profile notification event", "", "", "", "", ""],
    ["1119", "", "High", "Windows Defender - Remediation failed for a critical threat", "", "", "", "", ""],
    ["2011", "", "High", "Windows Defender - Security Intelligence update failed", "", "", "", "", ""],
    ["1150", "", "Medium", "Windows Defender - Service configuration has changed", "", "", "", "", ""],
    ["1151", "", "Low", "Windows Defender - Service started", "", "", "", "", ""],
    ["8002", "", "Medium", "AppLocker - EXE or DLL was allowed to run", "", "", "", "", ""],
    ["8004", "", "High", "AppLocker - EXE or DLL was prevented from running", "", "", "", "", ""],
    ["1149", "", "Medium", "TerminalServices - User authentication succeeded", "", "", "", "", ""],

    // ───── Auditing & Access ─────
    ["4656", "560", "Medium", "A handle to an object was requested", "Auditing & Access", "Tinjau akun yang meminta akses ke objek sensitif; verifikasi bahwa akses sesuai dengan hak yang diberikan.", "T1530", "Security", ""],
    ["4658", "562", "Low", "The handle to an object was closed", "Auditing & Access", "Tidak ada tindakan darurat; gunakan untuk melacak durasi akses ke objek.", "", "Security", ""],
    ["4663", "567", "Medium", "An attempt was made to access an object", "Auditing & Access", "Periksa file atau objek yang diakses; jika sensitif, audit hak pengguna dan pertimbangkan pembatasan izin.", "T1530", "Security", ""],
    ["4670", "578", "High", "Permissions on an object were changed", "Auditing & Access", "Audit siapa yang mengubah izin; rollback ke konfigurasi semula jika perubahan tidak sah.", "T1222", "Security", ""],
    ["4698", "602", "High", "A scheduled task was created", "Auditing & Access", "Verifikasi pembuat scheduled task; hapus task jika tidak dikenal atau dibuat tanpa otorisasi.", "T1053.005", "Security", ""],
    ["4702", "602", "High", "A scheduled task was updated", "Auditing & Access", "Periksa perubahan yang dilakukan pada scheduled task; restore konfigurasi asli jika terindikasi manipulasi.", "T1053.005", "Security", ""],
    ["4703", "603", "Medium", "A user right was adjusted", "Auditing & Access", "Tinjau hak pengguna yang diubah; pastikan perubahan telah melalui proses change management.", "T1134", "Security", ""],
    ["4704", "608", "Medium", "A user right was assigned", "Auditing & Access", "Verifikasi bahwa pemberian hak pengguna sesuai kebijakan; cabut hak jika tidak diperlukan.", "T1134", "Security", ""],
    ["4705", "609", "Medium", "A user right was removed", "Auditing & Access", "Pastikan pencabutan hak pengguna sah dan terdokumentasi; restore jika tidak disengaja.", "T1134", "Security", ""],
    ["4706", "610", "High", "A new trust was created to a domain", "Auditing & Access", "Tinjau trust domain baru; verifikasi bahwa trust dibuat oleh admin yang berwenang dan sesuai kebijakan.", "T1484.002", "Security", ""],
    ["4707", "611", "High", "A trust to a domain was removed", "Auditing & Access", "Investigasi penghapusan domain trust; restore trust jika dihapus tanpa otorisasi.", "T1484.002", "Security", ""],
    ["4713", "617", "High", "Kerberos policy was changed", "Auditing & Access", "Audit perubahan kebijakan Kerberos; kembalikan ke konfigurasi aman jika dimodifikasi tanpa izin.", "T1558", "Security", ""],
    ["4714", "618", "Medium", "Encrypted data recovery policy was changed", "Auditing & Access", "Tinjau perubahan kebijakan EFS; pastikan kunci pemulihan tetap aman.", "", "Security", ""],
    ["4715", "619", "High", "The audit policy on an object was changed", "Auditing & Access", "Periksa siapa yang mengubah kebijakan audit; kembalikan ke pengaturan semula jika tidak sah.", "T1562.002", "Security", ""],
    ["4716", "620", "High", "Trusted domain information was modified", "Auditing & Access", "Audit modifikasi informasi trust; verifikasi bahwa perubahan sah dan sesuai kebijakan.", "T1484.002", "Security", ""],
    ["4717", "621", "Medium", "System security access was granted to an account", "Auditing & Access", "Tinjau akun yang mendapat akses keamanan sistem; pastikan sesuai kebijakan least privilege.", "T1134", "Security", ""],

    // ───── Defender Security ─────
    ["1120", "", "Critical", "Windows Defender - Malware scan failed to complete", "Defender Security", "Restart layanan Windows Defender; jalankan scan manual dari Safe Mode jika diperlukan.", "T1562.001", "Microsoft-Windows-Windows Defender/Operational", ""],
    ["1121", "", "Critical", "Windows Defender - Exploit Guard blocked an operation (Audit Mode)", "Defender Security", "Tinjau log detail Exploit Guard; aktifkan mode Enforce jika perlu untuk memblokir operasi serupa.", "T1203", "Microsoft-Windows-Windows Defender/Operational", ""],
    ["2000", "", "High", "Windows Defender - Antimalware platform expired", "Defender Security", "Perbarui platform Windows Defender segera melalui Windows Update; pastikan koneksi ke Microsoft Update tersedia.", "T1562.001", "Microsoft-Windows-Windows Defender/Operational", ""],
    ["2001", "", "High", "Windows Defender - Antimalware platform update failed", "Defender Security", "Periksa konektivitas jaringan ke server Microsoft Update; coba update manual dari Security Center.", "T1562.001", "Microsoft-Windows-Windows Defender/Operational", ""],
    ["2002", "", "Medium", "Windows Defender - Antimalware platform update successful", "Defender Security", "Platform berhasil diperbarui; tidak ada tindakan yang diperlukan.", "", "Microsoft-Windows-Windows Defender/Operational", ""],
    ["2003", "", "Medium", "Windows Defender - Antimalware engine update", "Defender Security", "Engine berhasil diperbarui; verifikasi bahwa versi engine terbaru terinstal.", "", "Microsoft-Windows-Windows Defender/Operational", ""],
    ["2004", "", "High", "Windows Defender - Antimalware engine update failed", "Defender Security", "Coba update engine secara manual; periksa apakah Defender diblokir oleh GPO atau software pihak ketiga.", "T1562.001", "Microsoft-Windows-Windows Defender/Operational", ""],
    ["5010", "", "Critical", "Windows Defender - Antimalware scan failed", "Defender Security", "Periksa integritas file Defender dengan 'sfc /scannow'; reinstall Defender jika scan terus gagal.", "T1562.001", "Microsoft-Windows-Windows Defender/Operational", ""],
    ["5011", "", "Critical", "Windows Defender - Antimalware scan failed to start", "Defender Security", "Verifikasi bahwa layanan WinDefend berjalan; restart layanan atau lakukan troubleshoot startup.", "T1562.001", "Microsoft-Windows-Windows Defender/Operational", ""],
    ["5012", "", "Critical", "Windows Defender - Antimalware scan was stopped before completion", "Defender Security", "Investigasi penyebab scan terhenti; pastikan tidak ada proses yang memaksa stop layanan Defender.", "T1562.001", "Microsoft-Windows-Windows Defender/Operational", ""],
    ["5013", "", "High", "Windows Defender - Protection was disabled", "Defender Security", "Aktifkan kembali perlindungan real-time segera; audit akun yang menonaktifkan Defender.", "T1562.001", "Microsoft-Windows-Windows Defender/Operational", ""],
    ["5100", "", "Critical", "Windows Defender Antivirus - An antimalware platform is expiring", "Defender Security", "Perbarui platform Windows Defender sesegera mungkin sebelum masa berlaku habis.", "T1562.001", "Microsoft-Windows-Windows Defender/Operational", ""],
    ["5101", "", "Critical", "Windows Defender Antivirus - An antimalware platform has expired", "Defender Security", "Segera perbarui atau reinstall Windows Defender; isolasi endpoint dari jaringan hingga proteksi dipulihkan.", "T1562.001", "Microsoft-Windows-Windows Defender/Operational", ""],

    // ───── Code Integrity / WDAC ─────
    ["3010", "", "High", "Code Integrity - The image is not WHQL signed", "Code Integrity", "Verifikasi legitimasi driver; jangan izinkan driver berjalan jika tidak ada signature WHQL yang valid.", "T1014", "Microsoft-Windows-CodeIntegrity/Operational", ""],
    ["3033", "", "High", "Code Integrity - A file does not meet the security requirements for Shared Sections", "Code Integrity", "Tinjau file yang melanggar kebijakan; hapus atau ganti file dengan versi yang ditandatangani secara sah.", "T1014", "Microsoft-Windows-CodeIntegrity/Operational", ""],
    ["3034", "", "High", "Code Integrity - A file does not meet the security requirements for Shared Sections (Audit)", "Code Integrity", "Gunakan event ini dalam mode audit; pertimbangkan migrasi ke mode Enforce setelah baseline ditetapkan.", "T1014", "Microsoft-Windows-CodeIntegrity/Operational", ""],
    ["3040", "", "Medium", "Code Integrity - WHQL enforcement is disabled for this session", "Code Integrity", "Audit mengapa WHQL enforcement dinonaktifkan; aktifkan kembali Secure Boot dan WHQL di BIOS/UEFI.", "T1014", "Microsoft-Windows-CodeIntegrity/Operational", ""],
    ["3041", "", "High", "Code Integrity - The Windows hardware abstraction layer (HAL) does not match the CPU", "Code Integrity", "Periksa integritas instalasi Windows; jalankan 'sfc /scannow' dan 'DISM /Online /Cleanup-Image /RestoreHealth'.", "", "Microsoft-Windows-CodeIntegrity/Operational", ""],
    ["3064", "", "High", "Code Integrity - A WDAC policy was loaded", "Code Integrity", "Verifikasi integritas kebijakan WDAC yang dimuat; pastikan hanya kebijakan yang diotorisasi yang aktif.", "T1553.006", "Microsoft-Windows-CodeIntegrity/Operational", "Windows 10/11"],
    ["3065", "", "Critical", "Code Integrity - A WDAC policy blocked a file from loading", "Code Integrity", "Tinjau file yang diblokir oleh WDAC; laporkan ke tim keamanan jika file mencurigakan.", "T1553.006", "Microsoft-Windows-CodeIntegrity/Operational", "Windows 10/11"],
    ["3066", "", "High", "Code Integrity - A WDAC policy would have blocked a file (Audit Mode)", "Code Integrity", "Gunakan informasi ini untuk memperbarui whitelist WDAC; pertimbangkan beralih ke mode Enforce.", "T1553.006", "Microsoft-Windows-CodeIntegrity/Operational", "Windows 10/11"],
    ["3076", "", "High", "Code Integrity - The file hash does not match a trusted file", "Code Integrity", "Hapus atau karantina file yang hash-nya tidak cocok; investigasi sumber file tersebut.", "T1553.002", "Microsoft-Windows-CodeIntegrity/Operational", ""],
    ["3077", "", "High", "Code Integrity - The file certificate is not valid (policy enforcement)", "Code Integrity", "Verifikasi sertifikat file; tolak eksekusi dan laporkan ke tim keamanan jika sertifikat tidak valid.", "T1553.002", "Microsoft-Windows-CodeIntegrity/Operational", ""],
    ["3080", "", "Medium", "Code Integrity - A WDAC policy was refreshed", "Code Integrity", "Verifikasi bahwa refresh kebijakan WDAC sah dan sesuai prosedur change management.", "T1553.006", "Microsoft-Windows-CodeIntegrity/Operational", "Windows 10/11"],
    ["3082", "", "High", "Code Integrity - A file is not authorized by a WDAC policy", "Code Integrity", "Blokir eksekusi file; audit dan perbarui kebijakan WDAC jika file tersebut memang dibutuhkan.", "T1553.006", "Microsoft-Windows-CodeIntegrity/Operational", "Windows 10/11"],
    ["3089", "", "Medium", "Code Integrity - A file was audited by a WDAC policy (AppID Tagging)", "Code Integrity", "Tinjau file yang di-audit; gunakan data ini untuk menyempurnakan kebijakan AppID Tagging.", "", "Microsoft-Windows-CodeIntegrity/Operational", "Windows 11"],
    ["3090", "", "High", "Code Integrity - A file was blocked by a WDAC policy (AppID Tagging)", "Code Integrity", "Investigasi file yang diblokir; update kebijakan WDAC jika file sah membutuhkan tag AppID.", "", "Microsoft-Windows-CodeIntegrity/Operational", "Windows 11"],
    ["3091", "", "Medium", "Code Integrity - A WDAC policy was partially applied", "Code Integrity", "Periksa error kebijakan WDAC; pastikan seluruh aturan dalam kebijakan berhasil diterapkan.", "T1553.006", "Microsoft-Windows-CodeIntegrity/Operational", "Windows 10/11"],
    ["3097", "", "High", "Code Integrity - A file does not meet the security requirements (Revoked)", "Code Integrity", "Hentikan penggunaan file yang sertifikatnya telah dicabut; ganti dengan versi yang valid.", "T1553.002", "Microsoft-Windows-CodeIntegrity/Operational", ""],

    // ───── Service Failures ─────
    ["7002", "", "High", "Service Control Manager - Service failed during startup and was reverted", "Service Failures", "Periksa log Application untuk error terkait; coba jalankan service secara manual dan analisis pesan error.", "", "System", ""],
    ["7003", "", "High", "Service Control Manager - Service cannot start due to dependency failure", "Service Failures", "Identifikasi dependensi service yang gagal; perbaiki atau restart dependensi tersebut terlebih dahulu.", "", "System", ""],
    ["7004", "", "High", "Service Control Manager - Service failure — executable not found", "Service Failures", "Verifikasi jalur executable service; reinstall aplikasi atau layanan yang terkait jika file tidak ditemukan.", "", "System", ""],
    ["7005", "", "High", "Service Control Manager - Service failure — error creating service event", "Service Failures", "Periksa integritas Event Log service; jalankan 'sfc /scannow' untuk memperbaiki file sistem.", "", "System", ""],
    ["7006", "", "High", "Service Control Manager - Service failed to execute start control", "Service Failures", "Restart service secara manual; periksa permission akun service dan log aplikasi untuk detail error.", "", "System", ""],
    ["7010", "", "Medium", "Service Control Manager - Service cannot be added to the group", "Service Failures", "Periksa konfigurasi grup service; verifikasi tidak ada konflik atau group yang penuh.", "", "System", ""],
    ["7011", "", "High", "Service Control Manager - Timeout waiting for transaction from a service", "Service Failures", "Tingkatkan batas timeout service jika perlu; investigasi mengapa service lambat merespons.", "", "System", ""],
    ["7017", "", "High", "Service Control Manager - Service sent an invalid response", "Service Failures", "Restart service; periksa apakah ada bug pada versi terbaru dan pertimbangkan rollback.", "", "System", ""],
    ["7023", "", "Critical", "Service Control Manager - A service terminated with an error", "Service Failures", "Kumpulkan crash dump service; analisis error code dan stack trace untuk identifikasi root cause.", "", "System", ""],
    ["7024", "", "Critical", "Service Control Manager - A service terminated with a service-specific error", "Service Failures", "Catat error code spesifik dan cari solusi di dokumentasi Microsoft; kontak vendor jika diperlukan.", "", "System", ""],
    ["7026", "", "High", "Service Control Manager - A boot-start or system-start driver failed to load", "Service Failures", "Periksa integritas driver dengan 'verifier'; rollback atau uninstall driver yang bermasalah.", "", "System", ""],
    ["7032", "", "High", "Service Control Manager - Service attempted to start but failed with a crash", "Service Failures", "Analisis crash dump yang dihasilkan; perbaiki kondisi error sebelum mengaktifkan restart otomatis.", "", "System", ""],
    ["7038", "", "High", "Service Control Manager - Service failed to log on with the configured account", "Service Failures", "Verifikasi kredensial akun service; reset password atau ubah ke akun layanan yang valid.", "T1078", "System", ""],
    ["7045", "", "High", "Service Control Manager - A new service was installed in the system", "Service Failures", "Verifikasi legitimasi service baru; hapus jika tidak dikenal atau dipasang tanpa otorisasi.", "T1543.003", "System", ""],

    // ───── Application Crash ─────
    ["1005", "", "Medium", "Application Error - Windows cannot access the file for one of the following reasons", "Application Crash", "Periksa hak akses file dan pastikan file tidak dikunci; coba jalankan ulang aplikasi dengan hak admin.", "", "Application", ""],
    ["1033", "", "Medium", "MsiInstaller - Product installation completed with errors", "Application Crash", "Tinjau log instalasi MSI; coba repair atau reinstall aplikasi dari media instalasi yang bersih.", "", "Application", ""],

    // ───── Hardware & Disk ─────
    ["9", "", "High", "Disk - The device reported an error on a request to write data", "Hardware & Disk", "Jalankan diagnostik disk (SMART check); backup data segera dan pertimbangkan penggantian drive.", "", "System", ""],
    ["10", "", "High", "Disk - The device reported an error on a request to read data", "Hardware & Disk", "Lakukan SMART scan dan 'chkdsk /r'; backup data penting segera sebelum drive gagal total.", "", "System", ""],
    ["15", "", "High", "Disk - The device is not ready for access yet", "Hardware & Disk", "Periksa koneksi fisik disk; coba restart sistem dan periksa apakah disk terdeteksi di BIOS.", "", "System", ""],
    ["52", "", "Critical", "Disk - Windows found errors on a disk", "Hardware & Disk", "Jalankan 'chkdsk /f /r' pada disk yang bermasalah; backup data segera dan rencanakan penggantian drive.", "", "System", ""],
    ["57", "", "High", "NTFS - Filesystem metadata write failed during flush", "Hardware & Disk", "Periksa kondisi disk dengan diagnostik SMART; pastikan volume tidak penuh dan cek integritas filesystem.", "", "System", ""],
    ["98", "", "High", "Disk - A disk was removed or became unavailable", "Hardware & Disk", "Periksa koneksi fisik dan kabel data; pastikan drive terpasang dengan benar di slot/konektor.", "", "System", ""],
    ["129", "", "High", "Disk - Reset to device was issued", "Hardware & Disk", "Investigasi penyebab reset controller disk; update firmware disk dan driver controller jika tersedia.", "", "System", ""],
    ["153", "", "High", "Disk - The IO operation failed due to a hardware error", "Hardware & Disk", "Lakukan pengecekan SMART; ganti drive jika ditemukan bad sector yang signifikan.", "", "System", ""],
    ["157", "", "High", "Disk - The disk was surprise removed", "Hardware & Disk", "Gunakan fitur 'Safely Remove Hardware' sebelum melepas disk; periksa apakah ada data corruption.", "", "System", ""],

    // ───── Network & Firewalls ─────
    ["4946", "", "Medium", "Windows Firewall - A rule was added to the Windows Firewall exception list", "Network & Firewalls", "Audit aturan firewall yang ditambahkan; hapus aturan jika tidak sesuai kebijakan keamanan.", "T1562.004", "Security", ""],
    ["4947", "", "Medium", "Windows Firewall - A change was made to the Windows Firewall exception list", "Network & Firewalls", "Tinjau perubahan aturan firewall; kembalikan ke konfigurasi semula jika perubahan tidak sah.", "T1562.004", "Security", ""],
    ["4948", "", "Medium", "Windows Firewall - A rule was deleted from the Windows Firewall exception list", "Network & Firewalls", "Periksa aturan firewall yang dihapus; restore aturan penting yang dihapus tanpa otorisasi.", "T1562.004", "Security", ""],
    ["4949", "", "Medium", "Windows Firewall - Windows Firewall settings were restored to the default values", "Network & Firewalls", "Audit siapa yang mereset firewall; konfigurasi ulang aturan yang diperlukan sesuai kebijakan.", "T1562.004", "Security", ""],
    ["5025", "", "Critical", "Windows Firewall - The Windows Firewall Service has been stopped", "Network & Firewalls", "Restart layanan Windows Firewall segera; investigasi penyebab layanan berhenti dan audit akun yang terlibat.", "T1562.004", "Security", ""],
    ["5031", "", "High", "Windows Firewall - Blocked an application from accepting incoming connections", "Network & Firewalls", "Tinjau aplikasi yang diblokir; jika sah, tambahkan pengecualian yang sesuai di kebijakan firewall.", "T1562.004", "Security", ""],
    ["5152", "", "Medium", "Windows Filtering Platform - A packet was blocked", "Network & Firewalls", "Analisis paket yang diblokir; pastikan aturan WFP sudah tepat dan tidak ada traffic sah yang terblokir.", "T1562.004", "Security", ""],
    ["5153", "", "Medium", "Windows Filtering Platform - A more restrictive Windows Filtering Platform filter has blocked a packet", "Network & Firewalls", "Tinjau filter WFP yang lebih ketat; pastikan filter tambahan tidak mengganggu operasi bisnis normal.", "T1562.004", "Security", ""],
    ["5156", "", "Low", "Windows Filtering Platform - The Windows Filtering Platform has permitted a connection", "Network & Firewalls", "Gunakan untuk audit koneksi yang diizinkan; analisis jika ada koneksi ke tujuan yang mencurigakan.", "", "Security", ""],
    ["5157", "", "Medium", "Windows Filtering Platform - The Windows Filtering Platform has blocked a connection", "Network & Firewalls", "Tinjau koneksi yang diblokir; investigasi jika endpoint mencoba koneksi ke IP/port yang tidak dikenal.", "T1041", "Security", ""],

    // ───── System Updates ─────
    ["21", "", "Low", "Windows Update - Installation started", "System Updates", "Tidak ada tindakan yang diperlukan; pantau hingga instalasi selesai berhasil.", "", "System", ""],
    ["22", "", "Low", "Windows Update - Installation completed", "System Updates", "Verifikasi bahwa update berhasil diinstal; restart sistem jika diperlukan untuk menerapkan perubahan.", "", "System", ""],
    ["43", "", "Medium", "Windows Update - Installation started for an update that requires restart", "System Updates", "Jadwalkan restart sistem pada waktu yang tepat; pastikan pengguna sudah menyimpan pekerjaan mereka.", "", "System", ""],

    // ───── AppLocker ─────
    ["8000", "", "High", "AppLocker - EXE/DLL rule was enforced and a file was allowed", "AppLocker", "Tinjau file yang diizinkan oleh AppLocker; verifikasi bahwa aturan allow sesuai kebijakan keamanan.", "T1059", "Microsoft-Windows-AppLocker/EXE and DLL", "Windows 7+"],
    ["8003", "", "Critical", "AppLocker - EXE/DLL rule was enforced and a file was blocked", "AppLocker", "Investigasi file yang diblokir; jika file berbahaya, laporkan ke tim keamanan dan isolasi endpoint.", "T1059", "Microsoft-Windows-AppLocker/EXE and DLL", "Windows 7+"],
    ["8006", "", "High", "AppLocker - Script rule was enforced and a script was allowed", "AppLocker", "Verifikasi skrip yang diizinkan AppLocker; pertimbangkan pengetatan aturan jika ada skrip yang tidak perlu diizinkan.", "T1059.001", "Microsoft-Windows-AppLocker/MSI and Script", "Windows 7+"],
    ["8007", "", "Critical", "AppLocker - Script rule was enforced and a script was blocked", "AppLocker", "Investigasi skrip yang diblokir; jika skrip berbahaya atau tidak dikenal, laporkan ke tim keamanan segera.", "T1059.001", "Microsoft-Windows-AppLocker/MSI and Script", "Windows 7+"]
  ];
  
  essentialEntries.forEach(function(row) {
    sheet.appendRow(row);
  });
  
  // Create Config sheet
  var configSheet = ss.insertSheet("Config");
  configSheet.appendRow(["key", "value"]);
  configSheet.appendRow(["ai_model", "gemini-2.0-flash"]);
  configSheet.appendRow(["max_logs_to_ai", "50"]);
  configSheet.appendRow(["version", "1.0.0"]);
  
  // Create History sheet
  var historySheet = ss.insertSheet("ServerHistoryDB");
  historySheet.appendRow(["timestamp", "computer", "event_id", "severity"]);
  
  Logger.log("Created KB Sheet: " + ss.getId());
  PropertiesService.getScriptProperties().setProperty("KB_SHEET_ID", ss.getId());
  return ss.getId();
}

/* ───────── Server History DB ───────── */

function logAnalysisHistory(computer, eventId, severity) {
  try {
    var sheetId = PropertiesService.getScriptProperties().getProperty("KB_SHEET_ID");
    if (!sheetId) return;
    var ss = SpreadsheetApp.openById(sheetId);
    var sheet = ss.getSheetByName("ServerHistoryDB");
    if (!sheet) {
      sheet = ss.insertSheet("ServerHistoryDB");
      sheet.appendRow(["timestamp", "computer", "event_id", "severity"]);
    }
    sheet.appendRow([new Date().toISOString(), computer, eventId, severity]);
  } catch (e) {
    Logger.log("Error logging history: " + e.toString());
  }
}

function getServerHistory(computer) {
  try {
    var sheetId = PropertiesService.getScriptProperties().getProperty("KB_SHEET_ID");
    if (!sheetId) return { count: 0, messages: [] };
    var ss = SpreadsheetApp.openById(sheetId);
    var sheet = ss.getSheetByName("ServerHistoryDB");
    if (!sheet) return { count: 0, messages: [] };
    
    var data = sheet.getDataRange().getValues();
    var count = 0;
    for (var i = 1; i < data.length; i++) {
      if (data[i][1] === computer) {
        count++;
      }
    }
    if (count > 1) {
      return { count: count, message: "⚠️ Peringatan: Komputer " + computer + " memiliki riwayat " + count + " masalah sebelumnya di database." };
    }
    return { count: count, message: "" };
  } catch (e) {
    return { count: 0, message: "" };
  }
}

/* ───────── AI Analysis (Gemini / OpenAI / Heuristic Fallback) ───────── */

function analyzeLogs(logsJson, categoryCountsJson, timeFrameText, isMultiFileCorrelation, enableAi) {
  var logs = JSON.parse(logsJson);
  var categoryCounts = JSON.parse(categoryCountsJson);
  
  if (!logs || logs.length === 0) {
    return JSON.stringify({ error: "No logs provided for analysis." });
  }
  
  var geminiKey = getGeminiApiKey_();
  var openaiKey = getOpenAiApiKey_();
  
  // Format log summary for model input (max 40 logs)
  var formattedLogs = logs.slice(0, 40).map(function(log, idx) {
    return (idx + 1) + ". [" + log.level.toUpperCase() + "] [" + log.timestamp + "] [Source: " + log.source + "] [EventID: " + log.eventId + "]\n" +
      "   Message: " + (log.message || "").substring(0, 300) + (log.message && log.message.length > 300 ? "..." : "") + "\n" +
      "   " + (log.channel ? "Channel: " + log.channel : "") + " " + (log.computer ? "Computer: " + log.computer : "");
  }).join("\n\n");
  
  var statsSummary = Object.keys(categoryCounts).map(function(cat) {
    return cat + ": " + categoryCounts[cat];
  }).join(", ");
  
  var eventIdMapForAI = {};
  logs.forEach(function(l) {
    if (l.eventId) {
      var eid = String(l.eventId);
      eventIdMapForAI[eid] = (eventIdMapForAI[eid] || 0) + 1;
    }
  });
  var top10EventIdsForAI = Object.keys(eventIdMapForAI).map(function(eid) {
    return { eid: eid, count: eventIdMapForAI[eid] };
  }).sort(function(a, b) {
    return b.count - a.count;
  }).slice(0, 10).map(function(e) {
    return "Event ID " + e.eid + ": " + e.count + " kejadian";
  }).join(", ");
  
  // --- 🧠 RAG CONTEXT BUILDING ---
  var uniqueEventIds = {};
  logs.forEach(function(l) { if (l.eventId) uniqueEventIds[l.eventId] = true; });
  var ragContextParts = [];
  
  Object.keys(uniqueEventIds).forEach(function(eid) {
    var kbEntry = lookupKBEntry(eid);
    if (kbEntry && kbEntry.summary) {
      ragContextParts.push("- Event ID " + eid + ": " + kbEntry.summary);
    }
    // Also check Defender Directory
    if (typeof lookupErrorCode !== "undefined") {
      var defMatch = lookupErrorCode(eid);
      if (defMatch) {
        ragContextParts.push("- [Defender] " + defMatch.code + " (" + defMatch.title + "): " + defMatch.description);
      }
    }
  });
  var ragContext = ragContextParts.length > 0 ? "REFERENSI KAMUS RESMI (RAG CONTEXT):\n" + ragContextParts.join("\n") : "";
  // -------------------------------
  
  var systemInstruction = buildSystemInstruction_(timeFrameText, isMultiFileCorrelation);
  var prompt = buildPrompt_(timeFrameText, statsSummary, logs.length, formattedLogs, ragContext, top10EventIdsForAI);
  
  // Log to history if there is a critical error
  var topComputer = logs[0] ? logs[0].computer : "Unknown";
  var topEventId = logs[0] ? logs[0].eventId : "Unknown";
  var topSeverity = logs[0] ? logs[0].level : "Information";
  if (topSeverity === "Critical" || topSeverity === "Error") {
    logAnalysisHistory(topComputer, topEventId, topSeverity);
  }
  
  // Try Gemini first
  if (enableAi && geminiKey && geminiKey.length > 5) {
    try {
      var analysis = callGeminiAPI_(geminiKey, systemInstruction, prompt);
      return JSON.stringify({ analysis: analysis, mode: "online-gemini" });
    } catch (e) {
      Logger.log("Gemini API failed: " + e.toString());
    }
  }
  
  // Fallback to OpenAI
  if (enableAi && openaiKey && openaiKey.length > 5) {
    try {
      var analysis = callOpenAiAPI_(openaiKey, systemInstruction, prompt);
      return JSON.stringify({ analysis: analysis, isOpenAiActive: true, mode: "online-openai" });
    } catch (e) {
      Logger.log("OpenAI API failed: " + e.toString());
    }
  }
  
  // Final fallback: Heuristic + KB
  var heuristicReport = generateHeuristicReport(logs, categoryCounts, timeFrameText, isMultiFileCorrelation);
  return JSON.stringify({
    analysis: heuristicReport,
    isHeuristicFallback: true,
    mode: "offline",
    kbSize: getKBSize()
  });
}

/* ───────── Dedicated Heuristic Report ───────── */
function generateLaporanKendala(logsStr, categoryCountsStr, timeFrameText, isMultiFileCorrelation, appsStr, resStr) {
  try {
    var logs = JSON.parse(logsStr);
    var categoryCounts = JSON.parse(categoryCountsStr);
    var apps = appsStr ? JSON.parse(appsStr) : [];
    var res = resStr ? JSON.parse(resStr) : {};
    var report = generateHeuristicReport(logs, categoryCounts, timeFrameText, isMultiFileCorrelation, apps, res);
    return JSON.stringify({ success: true, report: report });
  } catch (e) {
    return JSON.stringify({ success: false, error: e.toString() });
  }
}

/* ───────── Gemini REST API ───────── */

function callGeminiAPI_(apiKey, systemInstruction, prompt) {
  var url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=" + apiKey;
  
  var payload = {
    system_instruction: {
      parts: [{ text: systemInstruction }]
    },
    contents: [{
      parts: [{ text: prompt }]
    }],
    generationConfig: {
      temperature: 0.2
    }
  };
  
  var options = {
    method: "post",
    contentType: "application/json",
    payload: JSON.stringify(payload),
    muteHttpExceptions: true
  };
  
  var response = UrlFetchApp.fetch(url, options);
  var json = JSON.parse(response.getContentText());
  
  if (json.error) {
    throw new Error("Gemini API Error: " + json.error.message);
  }
  
  if (json.candidates && json.candidates[0] && json.candidates[0].content) {
    return json.candidates[0].content.parts[0].text;
  }
  
  throw new Error("Unexpected Gemini response format");
}

/* ───────── OpenAI REST API ───────── */

function callOpenAiAPI_(apiKey, systemInstruction, prompt) {
  var url = "https://api.openai.com/v1/chat/completions";
  
  var payload = {
    model: "gpt-4o",
    messages: [
      { role: "system", content: systemInstruction },
      { role: "user", content: prompt }
    ],
    temperature: 0.2
  };
  
  var options = {
    method: "post",
    contentType: "application/json",
    headers: { "Authorization": "Bearer " + apiKey },
    payload: JSON.stringify(payload),
    muteHttpExceptions: true
  };
  
  var response = UrlFetchApp.fetch(url, options);
  var json = JSON.parse(response.getContentText());
  
  if (json.error) {
    throw new Error("OpenAI API Error: " + json.error.message);
  }
  
  return json.choices[0].message.content;
}

/* ───────── Prompt Builders ───────── */

function buildSystemInstruction_(timeFrameText, isMultiFileCorrelation) {
  var instruction = "Anda adalah seorang Senior Security Analyst & Escalation Engineer dari tim Microsoft Security Response Center.\n" +
    "Tugas Anda adalah melakukan Root Cause Analysis (RCA) berdasarkan log Windows Event Viewer yang diberikan.\n\n" +
    "**INSTRUKSI CHAIN-OF-THOUGHT (CoT):**\n" +
    "1. Baca Referensi Kamus Resmi (RAG) terlebih dahulu sebelum menganalisis log.\n" +
    "2. Identifikasi Pemicu Awal (Root Cause) yang memulai rentetan kejadian.\n" +
    "3. Rekonstruksi Garis Waktu Kejadian (Sebab-Akibat).\n" +
    "4. Jangan menebak arti kode error jika tidak tahu, gunakan referensi RAG yang diberikan.\n\n";
  
  if (isMultiFileCorrelation) {
    instruction += "**INSTRUKSI KHUSUS MULTI-FILE CORRELATION**: Administrator telah mengunggah 2 file log yang berbeda. Lakukan Korelasi Silang secara cerdas.\n\n";
  }
  
  instruction += "Format response harus menggunakan Markdown yang rapi dengan bagian:\n" +
    "1. Ringkasan Eksekutif & Tingkat Keparahan (Cantumkan Confidence Level % Anda)\n" +
    "2. Rekonstruksi Timeline & Akar Masalah (Root Cause)\n" +
    "3. Analisis Teknis Mendalam (Hubungkan Event ID dengan bukti yang ada)\n" +
    (isMultiFileCorrelation ? "4. Korelasi Silang 2 Berkas\n5. Rekomendasi Mitigasi\n6. Skrip Remediasi Otomatis" :
      "4. Rekomendasi Mitigasi\n5. Skrip Remediasi Otomatis") + "\n\n" +
    "**PENTING UNTUK SKRIP REMEDIASI:**\n" +
    "Jika memungkinkan, berikan satu blok kode PowerShell yang jelas dan aman (menggunakan ```powershell ... ```) untuk mengatasi masalah (misal: mereset service, update signature, sfc scan, dll). Skrip ini akan diekstrak oleh sistem.\n\n" +
    "Gunakan nada bicara yang sangat teknis, analitis, profesional, dan dalam Bahasa Indonesia.";
  
  return instruction;
}

function buildPrompt_(timeFrameText, statsSummary, logCount, formattedLogs, ragContext, top10EventIdsForAI) {
  return "Berikut adalah data statistik log:\n" +
    "- Timeframe analisis: " + (timeFrameText || "3 jam terakhir") + "\n" +
    "- Distribusi kategori: " + (statsSummary || "N/A") + "\n" +
    "- Top 10 Event ID: " + (top10EventIdsForAI || "N/A") + "\n" +
    "- Jumlah log kritis yang diekstrak: " + logCount + " log.\n\n" +
    (ragContext ? ragContext + "\n\n" : "") +
    "Berikut adalah detail dari log-log berurutan waktu (urutan bisa dari terbaru ke terlama atau sebaliknya, harap periksa timestamp):\n```text\n" + formattedLogs + "\n```\n\n" +
    "Silakan lakukan Analisis Akar Masalah (RCA) mendalam berdasarkan data di atas.";
}

/* ───────── Utility: Save API Key ───────── */

function saveApiKey(keyName, keyValue) {
  PropertiesService.getScriptProperties().setProperty(keyName, keyValue);
  return { success: true, message: "API Key '" + keyName + "' berhasil disimpan." };
}

/* ───────── Utility: Get scenarios for client ───────── */

function getScenariosForClient() {
  return JSON.stringify(generateScenarios());
}

/* ───────── Enterprise Features: Export & Alerts ───────── */

function exportToGoogleDoc(markdownText) {
  try {
    var title = "Laporan Analisis Event Viewer - " + Utilities.formatDate(new Date(), "Asia/Jakarta", "yyyy-MM-dd HH:mm");
    var doc = DocumentApp.create(title);
    var body = doc.getBody();
    
    // Simple markdown to Google Docs formatting
    var lines = markdownText.split("\n");
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      if (line.indexOf("### ") === 0) {
        body.appendParagraph(line.substring(4)).setHeading(DocumentApp.ParagraphHeading.HEADING3);
      } else if (line.indexOf("## ") === 0) {
        body.appendParagraph(line.substring(3)).setHeading(DocumentApp.ParagraphHeading.HEADING2);
      } else if (line.indexOf("# ") === 0) {
        body.appendParagraph(line.substring(2)).setHeading(DocumentApp.ParagraphHeading.HEADING1);
      } else if (line.indexOf("- ") === 0) {
        body.appendListItem(line.substring(2)).setGlyphType(DocumentApp.GlyphType.BULLET);
      } else if (line.indexOf("1. ") === 0 || /^\d+\.\s/.test(line)) {
        body.appendListItem(line.replace(/^\d+\.\s/, "")).setGlyphType(DocumentApp.GlyphType.NUMBER);
      } else if (line.trim() !== "") {
        // Handle bold basic
        var p = body.appendParagraph(line.replace(/\*\*/g, ""));
        // A more advanced script would parse bold accurately, we do a simple append here
      }
    }
    
    doc.saveAndClose();
    return { success: true, url: doc.getUrl(), name: title };
  } catch (e) {
    return { success: false, error: e.toString() };
  }
}

function sendIncidentEmail(reportHtml, recipient, severity) {
  try {
    if (!recipient || recipient.indexOf("@") === -1) {
      throw new Error("Alamat email tidak valid.");
    }
    
    var subject = "[ALERT - " + severity + "] Insiden Keamanan / Sistem Terdeteksi";
    var bodyText = "Laporan analisis sistem menunjukkan adanya insiden.\n\nSilakan buka HTML viewer atau aplikasi Event Viewer Analyzer untuk membaca selengkapnya.";
    
    var finalHtml = "<div style='font-family:sans-serif;max-width:800px;margin:0 auto;border:1px solid #e2e8f0;border-radius:8px;padding:20px;background:#f8fafc'>" +
      "<h2 style='color:" + (severity === "Critical" ? "#dc2626" : "#ea580c") + "'>🚨 Peringatan Insiden Sistem</h2>" +
      "<div style='background:#fff;padding:16px;border-radius:6px;border:1px solid #e2e8f0;'>" + reportHtml + "</div>" +
      "<p style='font-size:11px;color:#64748b;margin-top:20px;text-align:center'>Dikirim secara otomatis dari Event Viewer Analyzer (Google Apps Script)</p>" +
      "</div>";

    MailApp.sendEmail({
      to: recipient,
      subject: subject,
      body: bodyText,
      htmlBody: finalHtml
    });
    
    return { success: true, message: "Email peringatan berhasil dikirim ke " + recipient };
  } catch (e) {
    return { success: false, error: e.toString() };
  }
}
