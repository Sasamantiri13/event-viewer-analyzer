/**
 * Scenarios.gs — Demo incident scenarios for initial display
 * Converted from incidentScenarios.ts
 */

function generateScenarios() {
  var baseTime = new Date();
  
  function ts(minutesAgo, secondsOffset) {
    var ms = baseTime.getTime() - (minutesAgo * 60 * 1000) + (secondsOffset ? secondsOffset * 1000 : 0);
    return new Date(ms).toISOString();
  }

  return [
    {
      name: "Skenario: Serangan Ransomware Terdeteksi",
      description: "Simulasi deteksi ransomware oleh Windows Defender dengan eskalasi ke kegagalan layanan.",
      badge: "🚨 Critical",
      icon: "shield-alert",
      logs: [
        { id: "demo-1", timestamp: ts(5), level: "Critical", source: "Microsoft-Windows-Windows Defender", eventId: 1116, channel: "System", computer: "WORKSTATION-01", message: "Windows Defender Antivirus has detected malware. Name: Ransom:Win32/Tescrypt.A. Severity: Severe. Path: C:\\Users\\admin\\Downloads\\invoice.exe", category: "Defender Security" },
        { id: "demo-2", timestamp: ts(4), level: "Error", source: "Microsoft-Windows-Windows Defender", eventId: 1118, channel: "System", computer: "WORKSTATION-01", message: "Windows Defender Antivirus has encountered an error trying to take action on malware. Action: Quarantine. Error Code: 0x80508015", category: "Defender Security" },
        { id: "demo-3", timestamp: ts(3), level: "Critical", source: "Microsoft-Windows-Windows Defender", eventId: 5001, channel: "System", computer: "WORKSTATION-01", message: "Real-time protection is disabled. The malware may have tampered with Defender settings.", category: "Defender Security" },
        { id: "demo-4", timestamp: ts(2), level: "Error", source: "Service Control Manager", eventId: 7031, channel: "System", computer: "WORKSTATION-01", message: "The Windows Defender Antivirus Service terminated unexpectedly. It has done this 2 time(s).", category: "Service Failures" },
        // KORELASI 1: Crash app bertepatan dengan crash service
        { id: "demo-8", timestamp: ts(2, 2), level: "Error", source: "Application Error", eventId: 1000, channel: "Application", computer: "WORKSTATION-01", message: "Faulting application name: MsMpEng.exe. Faulting module name: ntdll.dll. Exception code: 0xc0000005", category: "Application Crash" },
        { id: "demo-5", timestamp: ts(1), level: "Warning", source: "Microsoft-Windows-CodeIntegrity", eventId: 3001, channel: "System", computer: "WORKSTATION-01", message: "Code Integrity determined that a process attempted to load a driver that did not meet the Microsoft signing level requirements.", category: "Code Integrity (WDAC)" },
        { id: "demo-6", timestamp: ts(55), level: "Information", source: "Microsoft-Windows-Security-Auditing", eventId: 4624, channel: "Security", computer: "WORKSTATION-01", message: "An account was successfully logged on. Logon Type: 10 (RemoteInteractive). Source Network Address: 192.168.1.105", category: "Auditing & Access" },
        { id: "demo-7", timestamp: ts(50), level: "Warning", source: "Microsoft-Windows-Security-Auditing", eventId: 4625, channel: "Security", computer: "WORKSTATION-01", message: "An account failed to log on. Failure Reason: Unknown user name or bad password. Source: 10.0.0.55", category: "Auditing & Access" }
      ]
    },
    {
      name: "Skenario: Kegagalan Pembaruan Sistem",
      description: "Simulasi kegagalan Windows Update dan dampaknya terhadap layanan sistem.",
      badge: "⚠️ Warning",
      icon: "alert-triangle",
      logs: [
        { id: "demo-u1", timestamp: ts(30), level: "Error", source: "Microsoft-Windows-WindowsUpdateClient", eventId: 20, channel: "System", computer: "SERVER-DC01", message: "Installation Failure: Windows failed to install the following update with error 0x80070643: Security Intelligence Update for Microsoft Defender Antivirus - KB2267602", category: "System Updates" },
        { id: "demo-u2", timestamp: ts(28), level: "Error", source: "Microsoft-Windows-Windows Defender", eventId: 2011, channel: "System", computer: "SERVER-DC01", message: "Security intelligence update failed. Error code: 0x80070643. Source: Microsoft Update Server", category: "Defender Security" },
        { id: "demo-u3", timestamp: ts(25), level: "Warning", source: "Microsoft-Windows-Windows Defender", eventId: 5007, channel: "System", computer: "SERVER-DC01", message: "Microsoft Defender Antivirus Configuration has changed. Old value: SignaturesLastUpdated = 2025-06-20T08:00:00Z", category: "Defender Security" },
        // Modifikasi menjadi Error agar masuk korelasi
        { id: "demo-u4", timestamp: ts(20), level: "Error", source: "disk", eventId: 51, channel: "System", computer: "SERVER-DC01", message: "An error was detected on device \\Device\\Harddisk0\\DR0 during a paging operation.", category: "Hardware & Disk" },
        // KORELASI 2: In-page I/O Error pada Aplikasi bertepatan dengan disk error System
        { id: "demo-u6", timestamp: ts(20, 1), level: "Error", source: "Application Error", eventId: 1000, channel: "Application", computer: "SERVER-DC01", message: "Faulting application name: update.exe, version: 10.0.19041.1, Exception code: 0xc0000006 (In-page I/O error).", category: "Application Crash" },
        { id: "demo-u5", timestamp: ts(15), level: "Information", source: "Service Control Manager", eventId: 7036, channel: "System", computer: "SERVER-DC01", message: "The Windows Update service entered the stopped state.", category: "Service Failures" }
      ]
    },
    {
      name: "Skenario: Kernel Bypass & IO Crash (BYOVD)",
      description: "Simulasi taktik T1014 (Rootkit) memuat driver rentan, mematikan layanan, dan memicu kemacetan IO/Disk.",
      badge: "🚨 Critical",
      icon: "cpu",
      logs: [
        { id: "demo-kb1", timestamp: ts(10), level: "Warning", source: "Microsoft-Windows-CodeIntegrity", eventId: 3033, channel: "System", computer: "SERVER-DC01", message: "Code Integrity determined that a process (cmd.exe) attempted to load RTCore64.sys that did not meet the Microsoft signing level requirements.", category: "Code Integrity (WDAC)" },
        { id: "demo-kb2", timestamp: ts(9), level: "Error", source: "Microsoft-Windows-CodeIntegrity", eventId: 3004, channel: "System", computer: "SERVER-DC01", message: "Windows is unable to verify the image integrity of the file RTCore64.sys because file hash could not be found on the system.", category: "Code Integrity (WDAC)" },
        { id: "demo-kb3", timestamp: ts(7), level: "Error", source: "Service Control Manager", eventId: 7034, channel: "System", computer: "SERVER-DC01", message: "The Windows Defender Advanced Threat Protection Service service terminated unexpectedly.  It has done this 1 time(s).", category: "Service Failures" },
        { id: "demo-kb4", timestamp: ts(5), level: "Error", source: "disk", eventId: 11, channel: "System", computer: "SERVER-DC01", message: "The driver detected a controller error on \\Device\\Harddisk1\\DR1.", category: "Hardware & Disk" },
        // KORELASI 3: Aplikasi Hang/Freeze persis saat disk controller error
        { id: "demo-kb7", timestamp: ts(5, 3), level: "Error", source: "Application Error", eventId: 1002, channel: "Application", computer: "SERVER-DC01", message: "The program Explorer.exe version 10.0.19041.1 stopped interacting with Windows and was closed. To see if more information about the problem is available...", category: "Application Crash" },
        { id: "demo-kb5", timestamp: ts(4), level: "Warning", source: "disk", eventId: 153, channel: "System", computer: "SERVER-DC01", message: "The IO operation at logical block address 0x4a3b2c for Disk 1 was retried.", category: "Hardware & Disk" },
        { id: "demo-kb6", timestamp: ts(3), level: "Warning", source: "Microsoft-Windows-Resource-Exhaustion-Detector", eventId: 2004, channel: "System", computer: "SERVER-DC01", message: "Windows successfully diagnosed a low virtual memory condition. The following programs consumed the most virtual memory: malware.exe (4502 MB).", category: "Hardware & Disk" }
      ]
    }
  ];
}
