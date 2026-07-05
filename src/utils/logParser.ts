/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { EventLogEntry } from "../types";

// Clean string helpers
function cleanValue(val: string | null): string {
  if (!val) return "";
  return val.replace(/^["']|["']$/g, "").trim();
}

/**
 * Parses XML output exported from Windows Event Viewer
 */
export function parseEventXml(xmlContent: string, fastScanMode: boolean = false): EventLogEntry[] {
  const logs: EventLogEntry[] = [];
  try {
    const parser = new DOMParser();
    const xmlDoc = parser.parseFromString(xmlContent, "text/xml");
    
    // Check for parser errors
    const parserError = xmlDoc.querySelector("parsererror");
    if (parserError) {
      throw new Error("Invalid XML structure");
    }

    const eventNodes = xmlDoc.getElementsByTagName("Event");
    
    for (let i = 0; i < eventNodes.length; i++) {
      const eventNode = eventNodes[i];
      const systemNode = eventNode.getElementsByTagName("System")[0];
      
      if (!systemNode) continue;

      // 1. Get Event ID
      const eventIdNode = systemNode.getElementsByTagName("EventID")[0];
      const eventId = eventIdNode ? parseInt(eventIdNode.textContent || "0", 10) : 0;

      // 2. Get Source / Provider
      const providerNode = systemNode.getElementsByTagName("Provider")[0];
      const source = providerNode ? providerNode.getAttribute("Name") || "Unknown Source" : "Unknown Source";

      // 3. Get Timestamp
      const timeNode = systemNode.getElementsByTagName("TimeCreated")[0];
      const timestamp = timeNode ? timeNode.getAttribute("SystemTime") || new Date().toISOString() : new Date().toISOString();

      // 4. Get Level
      const levelNode = systemNode.getElementsByTagName("Level")[0];
      const rawLevel = levelNode ? levelNode.textContent : "4";
      let level: "Critical" | "Error" | "Warning" | "Information" | "Unknown" = "Information";
      
      if (rawLevel === "1") level = "Critical";
      else if (rawLevel === "2") level = "Error";
      else if (rawLevel === "3") level = "Warning";
      else if (rawLevel === "4") level = "Information";

      // 5. Get Channel
      const channelNode = systemNode.getElementsByTagName("Channel")[0];
      let channel: "System" | "Application" | "Security" | "Code Integrity" | "Unknown" = "Unknown";
      const rawChannel = channelNode ? channelNode.textContent?.toLowerCase() : "";
      if (rawChannel?.includes("system")) channel = "System";
      else if (rawChannel?.includes("application")) channel = "Application";
      else if (rawChannel?.includes("security")) channel = "Security";
      else if (rawChannel?.includes("codeintegrity") || rawChannel?.includes("code integrity")) channel = "Code Integrity";

      // 6. Get Computer
      const computerNode = systemNode.getElementsByTagName("Computer")[0];
      const computer = computerNode ? computerNode.textContent || "localhost" : "localhost";

      // 7. Get Message / EventData
      const eventDataNode = eventNode.getElementsByTagName("EventData")[0];
      let message = "";
      
      if (eventDataNode) {
        const dataNodes = eventDataNode.getElementsByTagName("Data");
        const dataParts: string[] = [];
        for (let j = 0; j < dataNodes.length; j++) {
          const name = dataNodes[j].getAttribute("Name");
          const val = dataNodes[j].textContent;
          if (name) {
            dataParts.push(`${name}: ${val}`);
          } else if (val) {
            dataParts.push(val);
          }
        }
        message = dataParts.join("\n") || "No detailed event data available.";
      } else {
        // Fallback to rendering entire node text content or specific child elements
        const renderingInfoNode = eventNode.getElementsByTagName("RenderingInfo")[0];
        if (renderingInfoNode) {
          const messageNode = renderingInfoNode.getElementsByTagName("Message")[0];
          message = messageNode ? messageNode.textContent || "" : "";
        }
        if (!message) {
          message = eventNode.textContent?.trim().substring(0, 500) || "No message available.";
        }
      }

      // Compute simple category
      const category = computeCategory(source, eventId, message);

      if (fastScanMode && level === "Information") {
        continue;
      }

      logs.push({
        id: `xml-${i}-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
        timestamp,
        level,
        source,
        eventId,
        channel,
        computer,
        message,
        category,
        raw: eventNode.outerHTML
      });
    }
  } catch (err) {
    console.error("Error parsing Event Log XML:", err);
  }
  return logs;
}

/**
 * Parses CSV exported from Windows Event Viewer
 */
export function parseEventCsv(csvContent: string, fastScanMode: boolean = false): EventLogEntry[] {
  const logs: EventLogEntry[] = [];
  try {
    const lines = csvContent.split(/\r?\n/);
    if (lines.length < 2) return [];

    // Parse headers to understand columns dynamically
    const headerLine = lines[0];
    const headers = parseCsvRow(headerLine).map(h => h.toLowerCase());

    const levelIdx = headers.indexOf("level");
    const timeIdx = headers.indexOf("date and time") !== -1 ? headers.indexOf("date and time") : headers.findIndex(h => h.includes("date") || h.includes("time"));
    const sourceIdx = headers.indexOf("source") !== -1 ? headers.indexOf("source") : headers.indexOf("provider");
    const idIdx = headers.indexOf("event id") !== -1 ? headers.indexOf("event id") : headers.findIndex(h => h.includes("id"));
    const msgIdx = headers.indexOf("description") !== -1 ? headers.indexOf("description") : (headers.indexOf("information") !== -1 ? headers.indexOf("information") : headers.length - 1);
    
    for (let i = 1; i < lines.length; i++) {
      if (!lines[i].trim()) continue;
      const columns = parseCsvRow(lines[i]);
      if (columns.length < 2) continue;

      const rawLevel = levelIdx !== -1 ? cleanValue(columns[levelIdx]) : "Information";
      let level: "Critical" | "Error" | "Warning" | "Information" | "Unknown" = "Information";
      if (/critical/i.test(rawLevel)) level = "Critical";
      else if (/error/i.test(rawLevel)) level = "Error";
      else if (/warning/i.test(rawLevel)) level = "Warning";
      else if (/info/i.test(rawLevel)) level = "Information";

      // ISO Timestamp fallback
      let timestamp = new Date().toISOString();
      if (timeIdx !== -1 && columns[timeIdx]) {
        try {
          const parsedDate = new Date(cleanValue(columns[timeIdx]));
          if (!isNaN(parsedDate.getTime())) {
            timestamp = parsedDate.toISOString();
          }
        } catch {
          // keep default
        }
      }

      const source = sourceIdx !== -1 && columns[sourceIdx] ? cleanValue(columns[sourceIdx]) : "System Source";
      const eventId = idIdx !== -1 && columns[idIdx] ? parseInt(cleanValue(columns[idIdx]), 10) || 0 : 0;
      const message = msgIdx !== -1 && columns[msgIdx] ? cleanValue(columns[msgIdx]) : "No details.";

      // Infer channel from source/level
      let channel: "System" | "Application" | "Security" | "Code Integrity" | "Unknown" = "System";
      if (/codeintegrity/i.test(source) || /code integrity/i.test(source) || /code integrity/i.test(message)) {
        channel = "Code Integrity";
      } else if (/security/i.test(source)) {
        channel = "Security";
      } else if (/application/i.test(source) || /app error/i.test(source)) {
        channel = "Application";
      }
      const category = computeCategory(source, eventId, message);

      if (fastScanMode && level === "Information") {
        continue;
      }

      logs.push({
        id: `csv-${i}-${Date.now()}`,
        timestamp,
        level,
        source,
        eventId,
        channel,
        computer: "localhost",
        message,
        category
      });
    }
  } catch (err) {
    console.error("Error parsing Event Log CSV:", err);
  }
  return logs;
}

/**
 * Regex CSV Parser to handle double-quoted values correctly
 */
function parseCsvRow(row: string): string[] {
  const result: string[] = [];
  let current = "";
  let inQuotes = false;

  for (let i = 0; i < row.length; i++) {
    const char = row[i];
    if (char === '"') {
      inQuotes = !inQuotes;
    } else if (char === ',' && !inQuotes) {
      result.push(current);
      current = "";
    } else {
      current += char;
    }
  }
  result.push(current);
  return result;
}

/**
 * Fallback Plain Text log parser
 */
export function parseEventText(textContent: string, fastScanMode: boolean = false): EventLogEntry[] {
  const logs: EventLogEntry[] = [];
  try {
    // Try dividing into logical events based on timestamps
    const regex = /(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^\n]*)/g;
    const parts = textContent.split(regex);
    
    let currentLog: Partial<EventLogEntry> | null = null;
    let count = 0;

    for (let part of parts) {
      part = part.trim();
      if (!part) continue;

      // Check if this part is a timestamp line matching
      const isDate = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}/.test(part) || /^\d{1,2}\/\d{1,2}\/\d{4}/.test(part);
      
      if (isDate) {
        if (currentLog && currentLog.timestamp && currentLog.message) {
          if (!(fastScanMode && currentLog.level === "Information")) {
            logs.push(currentLog as EventLogEntry);
          }
        }
        
        let level: "Critical" | "Error" | "Warning" | "Information" | "Unknown" = "Information";
        if (/error/i.test(part)) level = "Error";
        else if (/warning/i.test(part)) level = "Warning";
        else if (/critical/i.test(part)) level = "Critical";

        const idMatch = part.match(/(?:eventId|event id|id|ID)[:\s]+(\d+)/i) || part.match(/EventID\s+(\d+)/) || part.match(/ID:\s*(\d+)/);
        const eventId = idMatch ? parseInt(idMatch[1], 10) : 0;

        const sourceMatch = part.match(/(?:source|source name|provider)[:\s]+([^\s,]+)/i);
        const source = sourceMatch ? sourceMatch[1] : "System TextLog";

        currentLog = {
          id: `text-${count++}-${Date.now()}`,
          timestamp: new Date(part.substring(0, 24)).toISOString() || new Date().toISOString(),
          level,
          source,
          eventId,
          channel: "System",
          computer: "localhost",
          message: part,
          category: "General TextLog"
        };
      } else if (currentLog) {
        currentLog.message += "\n" + part;
        currentLog.category = computeCategory(currentLog.source || "", currentLog.eventId || 0, currentLog.message);
      }
    }
    if (currentLog && currentLog.timestamp) {
      if (!(fastScanMode && currentLog.level === "Information")) {
        logs.push(currentLog as EventLogEntry);
      }
    }
  } catch (err) {
    console.error("Error parsing text log:", err);
  }
  return logs;
}

/**
 * Computes an automated, high-fidelity category based on log metadata
 */
export function computeCategory(source: string, eventId: number, message: string): string {
  const src = source.toLowerCase();
  const msg = message.toLowerCase();

  // Code Integrity & WDAC Policies
  if (
    src.includes("codeintegrity") || 
    src.includes("code integrity") ||
    src.includes("microsoft-windows-codeintegrity") ||
    [3001, 3002, 3003, 3004, 3091, 3097].includes(eventId)
  ) {
    return "Code Integrity (WDAC)";
  }

  // Microsoft Defender & Endpoint Security
  if (
    src.includes("defender") || 
    src.includes("microsoft-windows-windows defender") ||
    src.includes("security-mitigation") ||
    src.includes("sense") || 
    [1116, 1117, 1118, 1119, 2000, 2001, 2010, 2011, 3002, 5001, 5007, 5008, 5009, 5010, 1006, 1015].includes(eventId)
  ) {
    return "Defender Security";
  }

  // Windows Remote Access / Networking / Firewalls
  if (
    src.includes("winrm") || 
    src.includes("tcpip") || 
    src.includes("dns") || 
    src.includes("dhcp") || 
    src.includes("firewall") || 
    src.includes("schannel") ||
    msg.includes("network") || 
    msg.includes("connection timed out")
  ) {
    return "Network & Firewalls";
  }

  // Hardware or Disk Failures
  if (
    src.includes("disk") || 
    src.includes("ntfs") || 
    src.includes("ftdisk") || 
    src.includes("volmgr") || 
    msg.includes("bad block") || 
    msg.includes("corrupt") || 
    msg.includes("io error") ||
    eventId === 7 || eventId === 55 || eventId === 51
  ) {
    return "Hardware & Disk";
  }

  // Service Control Manager & Service crashes
  if (
    src.includes("service control manager") || 
    eventId === 7000 || eventId === 7001 || eventId === 7009 || eventId === 7022 || eventId === 7031 || eventId === 7034 || eventId === 7036
  ) {
    return "Service Failures";
  }

  // Application Crashes / Runtime
  if (
    src.includes(".net runtime") || 
    src.includes("application error") || 
    src.includes("application hang") || 
    msg.includes("unhandled exception") || 
    msg.includes("crash") || 
    eventId === 1000 || eventId === 1001 || eventId === 1026
  ) {
    return "Application Crash";
  }

  // Active Directory / Logon Auditing
  if (
    src.includes("security-auditing") || 
    msg.includes("logon") || 
    msg.includes("login") || 
    [4624, 4625, 4768, 4769, 4776].includes(eventId)
  ) {
    return "Auditing & Access";
  }

  // System Updates
  if (
    src.includes("windowsupdateclient") || 
    src.includes("wusa") || 
    msg.includes("kb226") || 
    msg.includes("security intelligence") ||
    [19, 20, 2011].includes(eventId)
  ) {
    return "System Updates";
  }

  return "General System";
}
