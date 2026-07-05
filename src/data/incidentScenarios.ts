/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { EventLogEntry, IncidentScenario } from "../types";

// Helper to generate dynamic ISO timestamps relative to current time
function getRelativeTime(minutesAgo: number): string {
  const date = new Date();
  date.setMinutes(date.getMinutes() - minutesAgo);
  return date.toISOString().replace("Z", "+07:00"); // Standard Indonesian local-like offset
}

export function generateScenarios(): IncidentScenario[] {
  return [
    {
      name: "Serangan Malware & Proteksi Defender (ASR)",
      badge: "Security Alert",
      icon: "ShieldAlert",
      description: "Kasus serangan siber di mana terdeteksi malware Trojan, disusul pembatasan otomatis oleh Attack Surface Reduction (ASR) dan upaya modifikasi registry antivirus dalam 3 jam terakhir.",
      logs: [
        {
          id: "scen1-1",
          timestamp: getRelativeTime(10), // 10 mins ago
          level: "Warning",
          source: "Microsoft-Windows-Windows Defender",
          eventId: 5007,
          channel: "System",
          computer: "PROD-SRV-SOC01",
          message: "Windows Defender Antivirus Configuration has changed. User: NT AUTHORITY\\SYSTEM. Old Value: DisableRealtimeMonitoring = 0. New Value: DisableRealtimeMonitoring = 1. Upaya penonaktifan proteksi real-time terdeteksi namun dipulihkan otomatis oleh Tamper Protection.",
          category: "Security & Policy"
        },
        {
          id: "scen1-2",
          timestamp: getRelativeTime(25), // 25 mins ago
          level: "Information",
          source: "Microsoft-Windows-Windows Defender",
          eventId: 1117,
          channel: "Application",
          computer: "PROD-SRV-SOC01",
          message: "Windows Defender Antivirus has successfully taken action to protect this machine from threat. Threat Name: Trojan:Win32/Mimikatz.A. Path: C:\\Windows\\Temp\\lsass_dump.dmp. Action: Quarantine. Remediation was fully successful.",
          category: "Security & Policy"
        },
        {
          id: "scen1-3",
          timestamp: getRelativeTime(30), // 30 mins ago
          level: "Critical",
          source: "Microsoft-Windows-Windows Defender",
          eventId: 1116,
          channel: "Application",
          computer: "PROD-SRV-SOC01",
          message: "Windows Defender Antivirus has detected malware or other potentially unwanted software. Threat Name: Trojan:Win32/Mimikatz.A. Category: Credential Stealer. Severity: Critical. Path: C:\\Windows\\Temp\\lsass_dump.dmp. Detection Source: Real-time Protection.",
          category: "Security & Policy"
        },
        {
          id: "scen1-4",
          timestamp: getRelativeTime(50), // 50 mins ago
          level: "Warning",
          source: "Microsoft-Windows-Windows Defender",
          eventId: 1015,
          channel: "Application",
          computer: "PROD-SRV-SOC01",
          message: "Microsoft Defender Exploit Guard Attack Surface Reduction (ASR) blocked an action. Rule ID: d1e49fe6-a450-428f-8341-f60402f6b4fc. Process: powershell.exe. Affected Path: C:\\Windows\\System32\\cmd.exe. Action: Blocked execution of system utility by script.",
          category: "Security & Policy"
        },
        {
          id: "scen1-5",
          timestamp: getRelativeTime(75), // 1 hour 15 mins ago
          level: "Warning",
          source: "Microsoft-Windows-Windows Defender",
          eventId: 3002,
          channel: "System",
          computer: "PROD-SRV-SOC01",
          message: "Microsoft Defender Network Protection blocked connection to suspicious IP address: 185.220.101.4 (Tor Exit Node). Process path: C:\\Windows\\Temp\\update_agent.exe. Port: 443.",
          category: "Network & Firewalls"
        },
        {
          id: "scen1-6",
          timestamp: getRelativeTime(110), // 1 hour 50 mins ago
          level: "Error",
          source: "Service Control Manager",
          eventId: 7031,
          channel: "System",
          computer: "PROD-SRV-SOC01",
          message: "The WinRM (Windows Remote Management) service terminated unexpectedly. This has occurred 1 time(s). The following corrective action will be taken in 60000 milliseconds: Restart the service.",
          category: "Service Failures"
        },
        {
          id: "scen1-7",
          timestamp: getRelativeTime(150), // 2 hours 30 mins ago
          level: "Information",
          source: "Microsoft-Windows-Security-Auditing",
          eventId: 4624,
          channel: "Security",
          computer: "PROD-SRV-SOC01",
          message: "An account was successfully logged on. Subject: Security ID: NULL SID, Account Name: -, Logon Type: 3 (Network logon), New Logon: Security ID: NT AUTHORITY\\ANONYMOUS LOGON, Account Name: ANONYMOUS LOGON, Source Network Address: 10.0.8.55.",
          category: "Auditing & Access"
        },
        {
          id: "scen1-8",
          timestamp: getRelativeTime(220), // 3 hours 40 mins ago (OUTSIDE 3 hours window)
          level: "Information",
          source: "Microsoft-Windows-WindowsUpdateClient",
          eventId: 19,
          channel: "System",
          computer: "PROD-SRV-SOC01",
          message: "Installation Successful: Windows successfully installed the following update: Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.413.444.0).",
          category: "System Updates"
        }
      ]
    },
    {
      name: "Kegagalan Sistem Database & Sektor Disk Corrupt",
      badge: "System & Hardware Failure",
      icon: "DatabaseBackup",
      description: "Kasus kegagalan database MSSQLSERVER akibat bad block pada sektor harddisk fisik Harddisk0, mengakibatkan kerusakan sistem file NTFS dan unhandled exceptions.",
      logs: [
        {
          id: "scen2-1",
          timestamp: getRelativeTime(5), // 5 mins ago
          level: "Critical",
          source: "ntfs",
          eventId: 55,
          channel: "System",
          computer: "DB-SQL-CORE01",
          message: "The file system structure on the volume C: is corrupt and unusable. Please run the chkdsk utility on the volume C:. A corruption was detected in a system index block.",
          category: "Hardware & Disk"
        },
        {
          id: "scen2-2",
          timestamp: getRelativeTime(15), // 15 mins ago
          level: "Error",
          source: "Service Control Manager",
          eventId: 7034,
          channel: "System",
          computer: "DB-SQL-CORE01",
          message: "The Microsoft SQL Server (MSSQLSERVER) service terminated unexpectedly. It has done this 3 time(s). The system service control manager will retry starting in 2 minutes.",
          category: "Service Failures"
        },
        {
          id: "scen2-3",
          timestamp: getRelativeTime(20), // 20 mins ago
          level: "Error",
          source: ".NET Runtime",
          eventId: 1026,
          channel: "Application",
          computer: "DB-SQL-CORE01",
          message: "Application: sqlservr.exe. Framework Version: v4.0.30319. Description: The process was terminated due to an unhandled exception. Exception Info: System.IO.FileLoadException, Message: Disk I/O failure during read on C:\\Program Files\\Microsoft SQL Server\\MSSQL15.MSSQLSERVER\\MSSQL\\DATA\\tempdb.mdf.",
          category: "Application Crash"
        },
        {
          id: "scen2-4",
          timestamp: getRelativeTime(45), // 45 mins ago
          level: "Error",
          source: "disk",
          eventId: 7,
          channel: "System",
          computer: "DB-SQL-CORE01",
          message: "The device, \\Device\\Harddisk0\\DR0, has a bad block. A read operation to block sector 44295128 failed after 5 retries.",
          category: "Hardware & Disk"
        },
        {
          id: "scen2-5",
          timestamp: getRelativeTime(80), // 1 hour 20 mins ago
          level: "Warning",
          source: "disk",
          eventId: 51,
          channel: "System",
          computer: "DB-SQL-CORE01",
          message: "An error was detected on device \\Device\\Harddisk0\\DR0 during a paging operation. Data block write retried successfully.",
          category: "Hardware & Disk"
        },
        {
          id: "scen2-6",
          timestamp: getRelativeTime(130), // 2 hours 10 mins ago
          level: "Information",
          source: "MSSQLSERVER",
          eventId: 17137,
          channel: "Application",
          computer: "DB-SQL-CORE01",
          message: "Starting up database 'tempdb'. Ready for connection. Service level state is initialized.",
          category: "Database Events"
        },
        {
          id: "scen2-7",
          timestamp: getRelativeTime(240), // 4 hours ago (OUTSIDE 3 hours window)
          level: "Information",
          source: "Service Control Manager",
          eventId: 7036,
          channel: "System",
          computer: "DB-SQL-CORE01",
          message: "The SQL Server Distributed Replay Client service entered the running state.",
          category: "Service Failures"
        }
      ]
    },
    {
      name: "Update Antivirus Gagal & Layanan Defender Menggantung",
      badge: "Update & Services Hang",
      icon: "ServerCrash",
      description: "Kasus gangguan layanan Windows Defender Antivirus yang menggantung pada status startup (hang), disusul dengan kegagalan fatal instalasi update KB2267602 dengan HRESULT error code.",
      logs: [
        {
          id: "scen3-1",
          timestamp: getRelativeTime(12), // 12 mins ago
          level: "Error",
          source: "Microsoft-Windows-WindowsUpdateClient",
          eventId: 2011, // Defender update failed
          channel: "System",
          computer: "DESKTOP-FIN042",
          message: "Installation Failed: Windows failed to install the following update with error 0x80070643: Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.413.444.0).",
          category: "System Updates"
        },
        {
          id: "scen3-2",
          timestamp: getRelativeTime(35), // 35 mins ago
          level: "Error",
          source: "Service Control Manager",
          eventId: 7022,
          channel: "System",
          computer: "DESKTOP-FIN042",
          message: "The Microsoft Defender Antivirus Service service hung on starting. The service has not responded to the control request in a timely fashion.",
          category: "Service Failures"
        },
        {
          id: "scen3-3",
          timestamp: getRelativeTime(65), // 1 hour 5 mins ago
          level: "Warning",
          source: "Microsoft-Windows-Windows Defender",
          eventId: 5008,
          channel: "Application",
          computer: "DESKTOP-FIN042",
          message: "Windows Defender Antivirus Real-time Protection feature failed to start. Error code: 0x80508016. Check system drivers and verify no other third-party security agents are conflicting.",
          category: "Security & Policy"
        },
        {
          id: "scen3-4",
          timestamp: getRelativeTime(95), // 1 hour 35 mins ago
          level: "Warning",
          source: "Microsoft-Windows-WinHTTP",
          eventId: 1014,
          channel: "System",
          computer: "DESKTOP-FIN042",
          message: "Name resolution for the name dns.msftncsi.com timed out after no response from the configured DNS servers. Internet connection dropped temporarily during update retrieval.",
          category: "Network & Firewalls"
        },
        {
          id: "scen3-5",
          timestamp: getRelativeTime(140), // 2 hours 20 mins ago
          level: "Error",
          source: "Microsoft-Windows-GroupPolicy",
          eventId: 1058,
          channel: "System",
          computer: "DESKTOP-FIN042",
          message: "The processing of Group Policy failed. Windows attempted to read the file \\\\domain.local\\sysvol\\domain.local\\Policies\\{31B2F340}\\gpt.ini from a domain controller and was not successful. (Access Denied error 0x80070005).",
          category: "Security & Policy"
        },
        {
          id: "scen3-6",
          timestamp: getRelativeTime(200), // 3 hours 20 mins ago (OUTSIDE 3 hours window)
          level: "Information",
          source: "Microsoft-Windows-User Profiles Service",
          eventId: 2,
          channel: "Application",
          computer: "DESKTOP-FIN042",
          message: "User Profile Service started successfully. Interactive logon session established for domain\\user_ops.",
          category: "Auditing & Access"
        }
      ]
    },
    {
      name: "Blokir Driver Tidak Sah & Kegagalan Code Integrity (BYOVD)",
      badge: "Code Integrity & WDAC",
      icon: "ShieldAlert",
      description: "Kasus deteksi pemuatan driver ilegal (Bring Your Own Vulnerable Driver) yang diblokir oleh Code Integrity, memicu kegagalan layanan (System Log), crash aplikasi (Application Log), dan peringatan Defender.",
      logs: [
        {
          id: "scen4-1",
          timestamp: getRelativeTime(8), // 8 mins ago
          level: "Critical",
          source: "Microsoft-Windows-CodeIntegrity",
          eventId: 3001,
          channel: "Code Integrity",
          computer: "SEC-CLNT-HR02",
          message: "Code Integrity determined that a process (C:\\Temp\\loader.exe) attempted to load an unsigned kernel-mode driver C:\\Temp\\inpoutx64.sys. The driver was blocked from loading due to system signature enforcement policies.",
          category: "Code Integrity (WDAC)"
        },
        {
          id: "scen4-2",
          timestamp: getRelativeTime(11), // 11 mins ago
          level: "Error",
          source: "Application Error",
          eventId: 1000,
          channel: "Application",
          computer: "SEC-CLNT-HR02",
          message: "Faulting application name: loader.exe, version: 1.0.0.0, time stamp: 0x60c2b1a1\nFaulting module name: loader.exe, version: 1.0.0.0, time stamp: 0x60c2b1a1\nException code: 0xc0000005\nFault offset: 0x000000000001a4f0\nFaulting process id: 0x2e4a\nDescription: The application crashed because its critical kernel-mode driver dependency (inpoutx64.sys) was blocked from loading.",
          category: "Application Crash"
        },
        {
          id: "scen4-3",
          timestamp: getRelativeTime(15), // 15 mins ago
          level: "Warning",
          source: "Microsoft-Windows-Windows Defender",
          eventId: 1116,
          channel: "Application",
          computer: "SEC-CLNT-HR02",
          message: "Windows Defender Antivirus has detected malware or other potentially unwanted software.\nThreat Name: HackTool:Win64/ByovdLoader.A\nCategory: Riskware\nPath: C:\\Temp\\loader.exe\nDetection Source: Real-time Protection.",
          category: "Defender Security"
        },
        {
          id: "scen4-4",
          timestamp: getRelativeTime(30), // 30 mins ago
          level: "Error",
          source: "Service Control Manager",
          eventId: 7000,
          channel: "System",
          computer: "SEC-CLNT-HR02",
          message: "The InpOut Driver Service failed to start due to the following error:\nAn unsigned driver was blocked from loading on this machine (HRESULT error 0x80070241 / Code Integrity).",
          category: "Service Failures"
        },
        {
          id: "scen4-5",
          timestamp: getRelativeTime(55), // 55 mins ago
          level: "Warning",
          source: "Microsoft-Windows-CodeIntegrity",
          eventId: 3091,
          channel: "Code Integrity",
          computer: "SEC-CLNT-HR02",
          message: "Code Integrity detected that a file (C:\\Temp\\untrusted_helper.dll) did not meet the Windows Defender Application Control (WDAC) security requirements. The file was prevented from loading into loader.exe.",
          category: "Code Integrity (WDAC)"
        },
        {
          id: "scen4-6",
          timestamp: getRelativeTime(85), // 1 hour 25 mins ago
          level: "Warning",
          source: "Microsoft-Windows-CodeIntegrity",
          eventId: 3002,
          channel: "Code Integrity",
          computer: "SEC-CLNT-HR02",
          message: "Code Integrity was unable to verify the image hash of the system file C:\\Windows\\System32\\drivers\\old_usb_filter.sys. The file hash is invalid or corrupt.",
          category: "Code Integrity (WDAC)"
        }
      ]
    }
  ];
}
