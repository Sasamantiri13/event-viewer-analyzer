/**
 * ThreatMapper.gs — MITRE ATT&CK & System Health Evaluation Engine
 */

function evaluateThreats(logs) {
  var tactics = [];
  var hasKernelBypass = false;
  var hasServiceCrash = false;
  var hasIOExhaustion = false;
  var hasBruteForce = false;
  
  // Aggregate occurrences
  var counts = {};
  logs.forEach(function(l) {
    counts[l.eventId] = (counts[l.eventId] || 0) + 1;
  });

  // 1. T1014 Rootkit / T1068 Privilege Escalation (BYOVD / Kernel Bypass)
  if (counts["3033"] || counts["3004"] || counts["3001"] || counts["3097"]) {
    hasKernelBypass = true;
    tactics.push({
      id: "T1014 / T1068",
      name: "Rootkit & Defense Evasion (Kernel Bypass)",
      severity: "CRITICAL",
      desc: "Indikasi serangan Bring Your Own Vulnerable Driver (BYOVD) atau manipulasi Code Integrity untuk mengeksekusi kode tidak sah di tingkat Kernel."
    });
  }

  // 2. T1562 Impair Defenses (Service Manipulation)
  if (counts["7034"] || counts["7031"] || counts["5001"] || counts["5009"]) {
    hasServiceCrash = true;
    tactics.push({
      id: "T1562",
      name: "Impair Defenses (Service Termination)",
      severity: "HIGH",
      desc: "Layanan sistem kritis (kemungkinan Antivirus/EDR) dimatikan secara tidak wajar. Ini sering digunakan malware untuk membutakan sistem pemantauan."
    });
  }

  // 3. TA0040 Impact (Data Destruction / DoS / IO Errors)
  if (counts["11"] || counts["153"] || counts["129"] || counts["51"] || counts["55"] || counts["2004"]) {
    hasIOExhaustion = true;
    tactics.push({
      id: "TA0040",
      name: "Impact & IO Denial of Service",
      severity: "HIGH",
      desc: "Kemacetan parah pada Controller Disk atau memori. Dapat murni disebabkan oleh kerusakan perangkat keras atau serangan Ransomware/Wiper yang membebani I/O."
    });
  }

  // 4. T1110 Brute Force
  if (counts["4625"] >= 10) {
    hasBruteForce = true;
    tactics.push({
      id: "T1110",
      name: "Brute Force Authentication",
      severity: "MEDIUM",
      desc: "Terdeteksi banyak upaya login gagal dalam rentang waktu singkat."
    });
  }
  
  // Health Score Logic (0 - 100)
  var healthScore = 100;
  if (hasKernelBypass) healthScore -= 50;
  if (hasServiceCrash) healthScore -= 30;
  if (hasIOExhaustion) healthScore -= 40;
  if (hasBruteForce) healthScore -= 15;
  if (healthScore < 0) healthScore = 5; // minimum

  return {
    tactics: tactics,
    healthScore: healthScore
  };
}

// Client-side wrapper to be called from google.script.run
function analyzeThreatsAndHealth(logsJson) {
  try {
    var logs = JSON.parse(logsJson);
    return JSON.stringify(evaluateThreats(logs));
  } catch (e) {
    return JSON.stringify({ error: e.toString() });
  }
}
