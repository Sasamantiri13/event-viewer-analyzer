/**
 * LogParser.gs — Server-side log parsing utilities
 * computeCategory is shared between client and server
 */

function computeCategory(source, eventId, message) {
  var src = (source || "").toLowerCase();
  var msg = (message || "").toLowerCase();

  // Code Integrity & WDAC Policies
  if (src.indexOf("codeintegrity") !== -1 || src.indexOf("code integrity") !== -1 ||
      src.indexOf("microsoft-windows-codeintegrity") !== -1 ||
      [3001, 3002, 3003, 3004, 3091, 3097].indexOf(eventId) !== -1) {
    return "Code Integrity (WDAC)";
  }

  // Microsoft Defender & Endpoint Security
  if (src.indexOf("defender") !== -1 || src.indexOf("microsoft-windows-windows defender") !== -1 ||
      src.indexOf("security-mitigation") !== -1 || src.indexOf("sense") !== -1 ||
      [1116, 1117, 1118, 1119, 2000, 2001, 2010, 2011, 3002, 5001, 5007, 5008, 5009, 5010, 1006, 1015].indexOf(eventId) !== -1) {
    return "Defender Security";
  }

  // Windows Remote Access / Networking / Firewalls
  if (src.indexOf("winrm") !== -1 || src.indexOf("tcpip") !== -1 || src.indexOf("dns") !== -1 ||
      src.indexOf("dhcp") !== -1 || src.indexOf("firewall") !== -1 || src.indexOf("schannel") !== -1 ||
      msg.indexOf("network") !== -1 || msg.indexOf("connection timed out") !== -1) {
    return "Network & Firewalls";
  }

  // Hardware or Disk Failures
  if (src.indexOf("disk") !== -1 || src.indexOf("ntfs") !== -1 || src.indexOf("ftdisk") !== -1 ||
      src.indexOf("volmgr") !== -1 || msg.indexOf("bad block") !== -1 || msg.indexOf("corrupt") !== -1 ||
      msg.indexOf("io error") !== -1 || eventId === 7 || eventId === 55 || eventId === 51) {
    return "Hardware & Disk";
  }

  // Service Control Manager & Service crashes
  if (src.indexOf("service control manager") !== -1 ||
      [7000, 7001, 7009, 7022, 7031, 7034, 7036].indexOf(eventId) !== -1) {
    return "Service Failures";
  }

  // Application Crashes / Runtime
  if (src.indexOf(".net runtime") !== -1 || src.indexOf("application error") !== -1 ||
      src.indexOf("application hang") !== -1 || msg.indexOf("unhandled exception") !== -1 ||
      msg.indexOf("crash") !== -1 || eventId === 1000 || eventId === 1001 || eventId === 1026) {
    return "Application Crash";
  }

  // Active Directory / Logon Auditing
  if (src.indexOf("security-auditing") !== -1 || msg.indexOf("logon") !== -1 ||
      msg.indexOf("login") !== -1 || [4624, 4625, 4768, 4769, 4776].indexOf(eventId) !== -1) {
    return "Auditing & Access";
  }

  // System Updates
  if (src.indexOf("windowsupdateclient") !== -1 || src.indexOf("wusa") !== -1 ||
      msg.indexOf("kb226") !== -1 || msg.indexOf("security intelligence") !== -1 ||
      [19, 20, 2011].indexOf(eventId) !== -1) {
    return "System Updates";
  }

  return "General System";
}
