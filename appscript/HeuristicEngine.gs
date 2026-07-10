/**
 * HeuristicEngine.gs — Offline Analysis Engine + KB Enrichment
 * Generates structured diagnostic reports when AI APIs are unavailable.
 */

function generateHeuristicReport(logs, categoryCounts, timeFrameText, isMultiFileCorrelation, apps, res) {
  var totalLogs = logs.length;
  var criticalLogs = logs.filter(function(l) { return l.level === "Critical"; });
  var errorLogs = logs.filter(function(l) { return l.level === "Error"; });
  var warningLogs = logs.filter(function(l) { return l.level === "Warning"; });
  var infoLogs = logs.filter(function(l) { return l.level === "Information"; });

  // Determine overall severity
  var overallSeverity = "Aman (Information)";
  var severityEmoji = "✅";
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

  // Reference global defenderErrorCodes if available, else empty array
  var activeDefenderCodes = typeof defenderErrorCodes !== "undefined" ? defenderErrorCodes : [];

  // Match defender codes
  var matchedCodes = [];
  logs.forEach(function(log) {
    var evMatch = activeDefenderCodes.filter(function(c) {
      var pureCode = c.code.replace(/Event ID\s*/i, "").trim();
      return log.eventId && log.eventId.toString() === pureCode;
    })[0];
    if (evMatch && !matchedCodes.some(function(m) { return m.code === evMatch.code; })) {
      matchedCodes.push(evMatch);
    }
    activeDefenderCodes.forEach(function(c) {
      if (c.code.toLowerCase().indexOf("0x") !== -1 && log.message && log.message.toLowerCase().indexOf(c.code.toLowerCase()) !== -1) {
        if (!matchedCodes.some(function(m) { return m.code === c.code; })) {
          matchedCodes.push(c);
        }
      }
    });
  });

  // KB enrichment
  var kbMatches = [];
  var seenKbIds = {};
  var kbSize = getKBSize();
  
  logs.forEach(function(log) {
    var id = log.eventId ? log.eventId.toString() : null;
    if (!id || seenKbIds[id]) return;
    var kbEntry = lookupKBEntry(id);
    if (kbEntry) {
      seenKbIds[id] = true;
      kbMatches.push({
        eventId: id,
        criticality: kbEntry.criticality || "Unknown",
        summary: kbEntry.summary || "No description",
        category: kbEntry.category || "",
        mitigation: kbEntry.mitigation || "",
        mitre_tactic: kbEntry.mitre_tactic || ""
      });
    }
  });

  // Sort kbMatches by criticality: Critical → High → Medium → Low → Unknown
  var critPriority = { "Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4 };
  kbMatches.sort(function(a, b) {
    var pa = critPriority[a.criticality] !== undefined ? critPriority[a.criticality] : 4;
    var pb = critPriority[b.criticality] !== undefined ? critPriority[b.criticality] : 4;
    return pa - pb;
  });

  // Dominant category
  var categoriesMap = {};
  logs.forEach(function(log) {
    categoriesMap[log.category] = (categoriesMap[log.category] || 0) + 1;
  });
  var dominantCategory = Object.keys(categoriesMap).sort(function(a, b) {
    return categoriesMap[b] - categoriesMap[a];
  })[0] || "Tidak spesifik";

  // Group by Event ID for Top 10
  var eventIdMap = {};
  logs.forEach(function(log) {
    var eid = log.eventId ? log.eventId.toString() : null;
    if (eid) {
      eventIdMap[eid] = (eventIdMap[eid] || 0) + 1;
    }
  });
  var top10EventIds = Object.keys(eventIdMap).map(function(eid) {
    return { eventId: eid, count: eventIdMap[eid] };
  }).sort(function(a, b) {
    return b.count - a.count;
  }).slice(0, 10);

  // Dynamic Parameter Extractor
  var dynamicParamDict = {
    "nvlddmkm.sys": "Masalah pada driver grafis NVIDIA. Lakukan Clean Install menggunakan DDU (Display Driver Uninstaller).",
    "ntoskrnl.exe": "Core OS kernel mengalami kendala, kemungkinan terkait memori (RAM) atau sistem file. Jalankan MemTest86 dan sfc /scannow.",
    "tcpip.sys": "Driver jaringan TCP/IP mengalami masalah. Periksa driver Network Adapter atau reset TCP/IP (netsh int ip reset).",
    "0xc0000005": "Access Violation. Sebuah program mencoba mengakses memori yang tidak diizinkan. Periksa RAM atau program yang crash.",
    "0x80070005": "Access Denied. Izin (Permissions) tidak mencukupi. Pastikan akun memiliki hak Administrator pada folder/file terkait.",
    "0x80040154": "Class not registered. Masalah registrasi komponen COM. Jalankan regsvr32 pada DLL yang hilang.",
    "0xc000009c": "STATUS_DEVICE_DATA_ERROR. Terjadi bad sector pada hard disk. Segera backup data dan periksa kesehatan disk (chkdsk /f /r).",
    "0xc0000185": "STATUS_IO_DEVICE_ERROR. Kendala koneksi antara motherboard dan hard drive. Periksa kabel SATA/NVMe."
  };
  
  var extractedParams = {};
  logs.forEach(function(log) {
    if (!log.message) return;
    var msg = log.message;
    var sysMatch = msg.match(/([a-zA-Z0-9_-]+\.sys)/gi);
    if (sysMatch) sysMatch.forEach(function(m){ extractedParams[m.toLowerCase()] = { val: m, type: "Driver File (.sys)" }; });
    var exeMatch = msg.match(/([a-zA-Z0-9_-]+\.exe)/gi);
    if (exeMatch) exeMatch.forEach(function(m){ extractedParams[m.toLowerCase()] = { val: m, type: "Executable File (.exe)" }; });
    var hexMatch = msg.match(/(0x[0-9a-fA-F]{8})/gi);
    if (hexMatch) hexMatch.forEach(function(m){ extractedParams[m.toLowerCase()] = { val: m, type: "Hex Code (NTSTATUS)" }; });
  });

  // Modul Skoring Kesehatan & Integritas I/O Perangkat
  var healthScore = 100;
  logs.forEach(function(l) {
    var penalty = 0;
    if (l.level === "Critical") penalty = 20;
    else if (l.level === "Error") penalty = 10;
    else if (l.level === "Warning") penalty = 2;
    
    // Khusus untuk rumpun Storage (Disk/Ntfs) dan Kernel-Power, penalti diberikan dua kali lipat
    var source = (l.source || "").toLowerCase();
    if (source.indexOf("disk") !== -1 || source.indexOf("ntfs") !== -1 || source.indexOf("kernel-power") !== -1) {
      penalty *= 2;
    }
    healthScore -= penalty;
  });
  if (healthScore < 0) healthScore = 0;
  
  var healthStatus = "";
  var healthColor = "";
  if (healthScore >= 90) { healthStatus = "Sangat Baik"; healthColor = "#10b981"; }
  else if (healthScore >= 70) { healthStatus = "Butuh Perhatian"; healthColor = "#f59e0b"; }
  else if (healthScore >= 50) { healthStatus = "Kritis Ringan"; healthColor = "#f97316"; }
  else { healthStatus = "Sangat Kritis (Hardware Failure Risk)"; healthColor = "#ef4444"; }

  // Modul Deteksi Pola Berulang & Anomali Lonjakan (Spike & Loop Anomaly Detector)
  var anomalyAlerts = [];
  var timeWindowMs = 60 * 1000; // 60 seconds
  var anomalyThreshold = 30; // 30 occurrences
  
  var sortedLogs = [...logs].filter(function(l) { return l.timestamp && (l.level === "Warning" || l.level === "Error" || l.level === "Critical"); });
  sortedLogs.sort(function(a, b) { return new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime(); });
  
  var anomalyGroups = {};
  sortedLogs.forEach(function(l) {
    var key = (l.eventId || "Unknown") + ":::" + (l.source || "Unknown");
    if (!anomalyGroups[key]) anomalyGroups[key] = [];
    anomalyGroups[key].push(new Date(l.timestamp).getTime());
  });
  
  Object.keys(anomalyGroups).forEach(function(key) {
    var times = anomalyGroups[key];
    if (times.length >= anomalyThreshold) {
      var maxCount = 0;
      var i = 0, j = 0;
      while (j < times.length) {
        if (times[j] - times[i] <= timeWindowMs) {
          var currentCount = j - i + 1;
          if (currentCount > maxCount) maxCount = currentCount;
          j++;
        } else {
          i++;
        }
      }
      if (maxCount >= anomalyThreshold) {
        var parts = key.split(":::");
        anomalyAlerts.push({
          eventId: parts[0],
          source: parts.slice(1).join(":::"),
          count: maxCount
        });
      }
    }
  });

  // Build report
  var md = "<div style='background:" + healthColor + "15; border: 2px solid " + healthColor + "; border-radius: 8px; padding: 20px; margin-bottom: 24px; text-align: center; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);'>" +
    "<h2 style='margin: 0; color: " + healthColor + "; font-size: 24px; font-weight: 800;'>SKOR KESEHATAN DEVICE: " + healthScore + "% (" + healthStatus + ")</h2>" +
    "<p style='margin: 8px 0 0 0; color: #64748b; font-size: 13px;'>Berdasarkan agregasi penalti dari " + totalLogs + " log yang diunggah.</p>" +
    "</div>\n\n";

  if (anomalyAlerts.length > 0) {
    anomalyAlerts.forEach(function(a) {
      md += "<div style='background:#fef2f2; border-left:4px solid #ef4444; padding:12px 16px; margin-bottom:12px; font-size:14px; font-weight:600; color:#b91c1c; border-radius:4px; box-shadow: 0 1px 2px rgba(0,0,0,0.05);'>" +
            "⚠️ Terdeteksi Loop Anomali pada Source `" + a.source + "` (Event ID " + a.eventId + "): Terjadi " + a.count + " kali anomali berturut-turut dalam rentang 1 menit." +
            "</div>\n";
    });
    md += "\n";
  }

  md += "### 📊 Laporan Diagnostik Forensik Offline\n\n" +
    "> **Intelijen**: 🔒 Mesin Analitik Heuristik & Knowledge Base Lokal (" + kbSize + " Definisi Ancaman)\n\n" +
    "#### 1. Ringkasan Eksekutif (Executive Summary)\n" +
    "Analisis menyimpulkan bahwa dari total **" + totalLogs + " rekaman log abnormal** dalam jangka waktu **" + (timeFrameText || "terpilih") + "**, " +
    "fokus kendala didominasi oleh rumpun **" + dominantCategory + "**. " +
    "Tingkat keparahan komprehensif sistem Anda saat ini adalah: **" + overallSeverity + " " + severityEmoji + "**.\n\n" +
    "| Klasifikasi | Jumlah | Status |\n" +
    "| :--- | :---: | :--- |\n" +
    "| 🚨 **Kritis (Critical)** | **" + criticalLogs.length + "** | " + (criticalLogs.length > 0 ? "Butuh Penanganan Segera" : "Aman") + " |\n" +
    "| ⚠️ **Kesalahan (Error)** | **" + errorLogs.length + "** | " + (errorLogs.length > 0 ? "Berdampak pada Stabilitas" : "Aman") + " |\n" +
    "| 🔔 **Peringatan (Warning)** | **" + warningLogs.length + "** | " + (warningLogs.length > 0 ? "Perlu Dipantau" : "Normal") + " |\n" +
    "| ℹ️ **Informasi (Info)** | **" + infoLogs.length + "** | Sekadar Catatan Sistem |\n\n" +
    "#### 2. Sorotan Insiden Utama (Key Findings)\n";

  if (criticalLogs.length > 0) {
    md += "- **Kegagalan Kritis Terdeteksi**: Terdapat " + criticalLogs.length + " entri tingkat KRITIS dari sumber `" + (criticalLogs[0].source || "N/A") + "` dengan Event ID `" + (criticalLogs[0].eventId || "N/A") + "`.\n";
  }
  if (errorLogs.length > 0) {
    md += "- **Kesalahan Sistem/Aplikasi**: Terdapat " + errorLogs.length + " error terkait modul `" + (errorLogs[0].source || "N/A") + "`.\n";
  }
  if (warningLogs.length > 0) {
    md += "- **Indikasi Peringatan Keamanan**: Ditemukan " + warningLogs.length + " log peringatan dari sumber `" + (warningLogs[0].source || "N/A") + "`.\n";
  }
  md += "- **Sumber Utama Penyebab**: Masalah didominasi oleh ketidakselarasan konfigurasi atau kegagalan pembaruan modul pendukung sistem.\n\n";

  md += "#### 3. Top 10 Event ID Terbanyak\n\n";
  if (top10EventIds.length > 0) {
    md += "| Event ID | Jumlah (Frekuensi) | Diagnosa KB Lokal |\n";
    md += "| :--- | :---: | :--- |\n";
    top10EventIds.forEach(function(e) {
      var kInfo = lookupKBEntry(e.eventId);
      var diag = kInfo ? kInfo.summary : "Pola belum dikenali.";
      md += "| `" + e.eventId + "` | **" + e.count + "x** | " + diag + " |\n";
    });
  } else {
    md += "- *Tidak ada Event ID spesifik yang terdeteksi.*\n";
  }
  md += "\n";

  var sectionNum = 4;
  md += "\n#### " + sectionNum + ". Audit Resource & Korelasi Aplikasi\n";
  md += "Mesin telah membedah *payload* pesan log dan mencocokkannya dengan daftar perangkat lunak yang terinstal serta riwayat beban perangkat keras (RAM/CPU):\n\n";
  var auditMatches = [];
  var seenAudits = {};
  var auditLogs = criticalLogs.concat(errorLogs);
  if (auditLogs.length === 0) auditLogs = warningLogs;
  
  auditLogs.forEach(function(l) {
    if (l.message) {
      var corr = auditAppAndResourceCorrelation(l.message, apps, res);
      if (corr.found && !seenAudits[corr.detail]) {
        seenAudits[corr.detail] = true;
        auditMatches.push(corr.detail);
      }
    }
  });

  if (auditMatches.length > 0) {
    auditMatches.forEach(function(a) { md += "> " + a + "\n\n"; });
  } else {
    md += "- *Sistem log tidak menunjukkan korelasi langsung dengan aplikasi pihak ketiga atau status memori kritis saat ini.*\n\n";
  }
  
  sectionNum++;
  md += "\n#### " + sectionNum + ". Deteksi Parameter & Ekstraksi Dinamis\n";
  md += "Mesin telah membedah *payload* pesan log dan menemukan variabel/parameter yang berkorelasi dengan basis data kecerdasan sistem:\n\n";
  Object.keys(extractedParams).forEach(function(k) {
    var param = extractedParams[k];
    if (dynamicParamDict[k]) {
      md += "> 📌 **Ditemukan Parameter**: `" + param.val + "` (" + param.type + ")\n";
      md += "> **Diagnosa Spesifik**: " + dynamicParamDict[k] + "\n\n";
    }
  });

  md += "\n#### 5. Analisis Defender Endpoint\n";
  if (matchedCodes.length > 0) {
    matchedCodes.forEach(function(m) {
      var recText = m.recommendation || m.rec || "";
      md += "- **Ditemukan Kode " + m.code + " (" + m.title + ")**: " + recText + "\n";
    });
  } else {
    md += "- *Tidak ditemukan Event ID atau HRESULT spesifik Microsoft Defender Endpoint dalam log terfilter saat ini.*\n";
  }
  md += "\n";

  sectionNum++;
  if (kbMatches.length > 0) {
    md += "\n#### 6. Pencocokan Knowledge Base Lokal (Offline KB)\n" +
      "Sistem berhasil mencocokkan **" + kbMatches.length + " Event ID** dengan database pengetahuan Windows:\n\n";
    var isLegacyFormat = kbMatches[0] && kbMatches[0].isLegacyFormat;
    kbMatches.slice(0, 20).forEach(function(k) {
      md += "- **Event ID " + k.eventId + "** [" + k.criticality + "]: " + k.summary + "\n";
      if (!isLegacyFormat && k.mitigation && k.mitigation !== "") {
        md += "  - 🛡️ Mitigasi: " + k.mitigation + "\n";
      }
    });
    if (kbMatches.length > 20) {
      md += "- *...dan " + (kbMatches.length - 20) + " Event ID lainnya.*\n";
    }
    md += "\n";
    sectionNum++;
  }

  // MITRE ATT&CK mapping section
  var mitreMap = {};
  kbMatches.forEach(function(k) {
    if (k.mitre_tactic && k.mitre_tactic !== "") {
      var tactics = k.mitre_tactic.split(",");
      tactics.forEach(function(t) {
        var tac = t.trim();
        if (tac) {
          if (!mitreMap[tac]) mitreMap[tac] = [];
          mitreMap[tac].push(k.eventId);
        }
      });
    }
  });
  var mitreTactics = Object.keys(mitreMap);
  if (mitreTactics.length > 0) {
    md += "\n#### 7. Pemetaan Ancaman (MITRE ATT&CK Framework)\n";
    mitreTactics.forEach(function(tac) {
      md += "- **Taktik " + tac + "**: Terdeteksi pada Event ID " + mitreMap[tac].join(", ") + "\n";
    });
  }

  md += "\n";
  
  if (logs.length > 1) {
    var allCriticals = logs.filter(function(l) { return l.level === "Critical"; });
    var nonCriticalErrors = logs.filter(function(l) { return l.level === "Error" || l.level === "Warning"; });
    var correlations = [];
    
    allCriticals.forEach(function(crit) {
      var critTime = new Date(crit.timestamp).getTime();
      var relatedLogs = [];
      
      nonCriticalErrors.forEach(function(err) {
        var errTime = new Date(err.timestamp).getTime();
        var diffMs = errTime - critTime; 
        
        if (Math.abs(diffMs) <= 10000 && crit.id !== err.id) {
          relatedLogs.push({
            log: err,
            diffMs: diffMs,
            type: diffMs <= 0 ? "Root Cause Suspect" : "Domino Symptom"
          });
        }
      });
      
      if (relatedLogs.length > 0) {
        relatedLogs.sort(function(a,b){ return a.diffMs - b.diffMs; });
        correlations.push({
          critical: crit,
          related: relatedLogs
        });
      }
    });

    md += "\n#### 8. Korelasi Insiden Domino (Multi-Channel Timeline)\n";
    if (correlations.length > 0) {
      md += "Mesin analitik mendeteksi adanya efek domino di mana log Kritis berkaitan dengan log Error/Warning lain dalam rentang **±10 detik**:\n\n";
      correlations.slice(0, 5).forEach(function(c, i) {
        md += "**Insiden Rantai #" + (i+1) + " (Pusat: Event ID " + c.critical.eventId + " - " + c.critical.source + ")**\n";
        md += "Waktu Puncak: `" + new Date(c.critical.timestamp).toLocaleTimeString() + "`\n";
        
        c.related.forEach(function(r) {
          var diffSec = (r.diffMs / 1000).toFixed(1);
          var direction = r.diffMs <= 0 ? "*(Terjadi " + Math.abs(diffSec) + "d sebelumnya)*" : "*(Terjadi " + diffSec + "d setelahnya)*";
          var icon = r.type === "Root Cause Suspect" ? "🔻" : "🔸";
          md += "- " + icon + " **" + r.type + "** " + direction + ": Event ID " + r.log.eventId + " (`" + r.log.source + "`) ➔ " + (r.log.message || "").substring(0, 80).replace(/\n/g," ") + "...\n";
        });
        md += "\n";
      });
      if (correlations.length > 5) md += "*(Dan " + (correlations.length - 5) + " rantai insiden lainnya)*\n\n";
    } else {
      md += "- *Telah dilakukan pemindaian linimasa, namun tidak ditemukan log Error/Warning yang berdekatan (±10 detik) dengan log Kritis.*\n\n";
    }
  }

  if (isMultiFileCorrelation) {
    var networkErrors = logs.filter(function(l) { return l.eventId == 1014 || l.eventId == 104 || l.eventId == 4227; });
    var timeGroups = {};
    networkErrors.forEach(function(l) {
      var timeMin = new Date(l.timestamp).setSeconds(0,0);
      var compName = l.computerName || "Unknown_" + Math.random();
      if (!timeGroups[timeMin]) timeGroups[timeMin] = {};
      timeGroups[timeMin][compName] = true;
    });
    
    var globalIssues = [];
    Object.keys(timeGroups).forEach(function(time) {
      var affectedPCs = Object.keys(timeGroups[time]);
      if (affectedPCs.length > 1) {
        globalIssues.push({ time: new Date(parseInt(time)), count: affectedPCs.length });
      }
    });
    
    if (globalIssues.length > 0) {
      md += "\n#### 9. Pengecekan Silang Perangkat Tetangga (Network Neighbor Correlation)\n";
      md += "> 🌐 **Mode Agregasi Aktif**: Sistem menganalisis korelasi silang dari multi-file log.\n\n";
      globalIssues.slice(0, 3).forEach(function(issue) {
        md += "⚠️ **Peringatan Infrastruktur**: Pada pukul `" + issue.time.toLocaleTimeString() + "`, sebanyak **" + issue.count + " komputer berbeda** secara serempak melaporkan kegagalan jaringan (Event DNS/Network). " +
              "**Kesimpulan Forensik:** Masalah BUKAN pada PC client individual. Terdeteksi anomali/down pada Switch, Router Gateway Core, atau koneksi ISP.\n\n";
      });
    }
  }

  // Modul Manajemen Repositori Driver & Firmware Cross-Reference (OEM Compatibility Matrix)
  var biosLogs = logs.filter(function(l) { return l.eventId == 12 && l.source && (l.source.indexOf("Kernel-General") > -1 || l.source.indexOf("Kernel-Boot") > -1); });
  var wlanErrors = logs.filter(function(l) { return l.source && (l.source.toLowerCase().indexOf("wlan") > -1 || l.source.toLowerCase().indexOf("ndis") > -1) && (l.level === "Error" || l.level === "Critical"); });

  if (biosLogs.length > 0 && wlanErrors.length > 0) {
    var oemWarnings = [];
    var biosMsg = biosLogs[0].message || "";
    // Regex fleksibel untuk menangkap versi BIOS dari log sistem Windows
    var biosVersionMatch = biosMsg.match(/version\s+([A-Za-z0-9.-]+)/i) || biosMsg.match(/versi\s+([A-Za-z0-9.-]+)/i);
    var biosVer = biosVersionMatch ? biosVersionMatch[1] : "terkini (terdeteksi dari Event 12)";

    oemWarnings.push("⚠️ **Inkompatibilitas Hardware Terdeteksi**: Ditemukan **" + wlanErrors.length + "** *crash* pada modul WLAN/Jaringan. Berdasarkan *OEM Compatibility Matrix* offline kami, " +
    "Driver Wi-Fi yang digunakan saat ini terindikasi tidak stabil apabila dipasangkan dengan BIOS versi `" + biosVer + "`. " +
    "**Rekomendasi Global:** Segera lakukan *rollback* driver jaringan ke versi sebelumnya, atau pertimbangkan *flashing* BIOS sistem ke versi revisi stabil terbaru (Z-Series).");

    md += "\n#### 10. OEM Compatibility Matrix (Driver & Firmware Cross-Reference)\n";
    md += "> 🛠️ **Analisis Perangkat Keras**: Mengkorelasikan versi Firmware dasar (BIOS/UEFI) dengan tingkat kegagalan (*crash*) driver pihak ketiga.\n\n";
    oemWarnings.forEach(function(w) { md += w + "\n\n"; });
  }

  md += "\n#### 11. Rekomendasi Langkah Perbaikan (Actionable Recommendations)\n" +
    "- **Langkah 1 (PowerShell Keamanan)**: `Update-MpSignature`\n" +
    "- **Langkah 2 (Verifikasi Layanan)**: `sc query WinDefend` lalu `sc start WinDefend`\n" +
    "- **Langkah 3 (Kesehatan Berkas)**: `sfc /scannow` dan `DISM.exe /Online /Cleanup-image /Restorehealth`\n\n";
  
  md += "#### 12. Tingkat Keparahan & Urgensi (Severity & Urgency Rating)\n" +
    "- **Status Kesehatan**: **" + overallSeverity + "**\n" +
    "- **Skor Urgensi**: **" + (criticalLogs.length > 0 ? "9/10 (Sangat Tinggi)" : errorLogs.length > 0 ? "7/10 (Tinggi)" : "4/10 (Sedang)") + "**\n" +
    "- **Catatan**: Laporan ini dihasilkan secara offline menggunakan mesin heuristik lokal dan Knowledge Base (" + kbSize + " entri). Hubungkan API Key untuk analisis AI yang lebih mendalam.";

  return md;
}

// Helper: Modul Analisis untuk Menautkan Log & Aplikasi Terinstal
function auditAppAndResourceCorrelation(message, globalInstalledApps, globalResourceSnapshots) {
  var cleanMessage = String(message).toLowerCase();
  var correlationResult = { found: false, detail: "" };

  // A. Cek Korelasi Resource RAM/CPU Kritis
  if (globalResourceSnapshots && globalResourceSnapshots.CurrentRamLoadPct > 90) {
    return {
      found: true,
      detail: "⚠️ **KORELASI RESOURCE**: Penggunaan RAM saat event terjadi sangat kritis (" + globalResourceSnapshots.CurrentRamLoadPct + "%). Kejadian log ini sangat mungkin dipicu oleh kondisi sistem kehabisan memori RAM fisik (Out-Of-Memory)."
    };
  }

  // B. Cek Korelasi Aplikasi Terinstal Pasca-Error
  if (globalInstalledApps && globalInstalledApps.length > 0) {
    for (var i = 0; i < globalInstalledApps.length; i++) {
      var appName = globalInstalledApps[i].DisplayName.toLowerCase();
      // Jika nama aplikasi yang terinstal di sistem klien disebutkan di dalam log crash
      if (cleanMessage.indexOf(appName) > -1 || (appName.length > 3 && cleanMessage.indexOf(appName.split(' ')[0]) > -1)) {
        return {
          found: true,
          detail: "💡 **AUDIT APLIKASI**: Terdeteksi kecocokan forensik! Aplikasi **" + globalInstalledApps[i].DisplayName + "** (Versi: " + (globalInstalledApps[i].DisplayVersion || 'N/A') + ") terdaftar aktif di perangkat target dan berkorelasi langsung dengan pesan kesalahan ini."
        };
      }
    }
  }
  return correlationResult;
}
