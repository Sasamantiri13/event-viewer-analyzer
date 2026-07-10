/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { EventLogEntry } from "../types";
import { parseEvtxFile } from "winevtx";

// Clean string helpers
function cleanValue(val: string | null): string {
  if (!val) return "";
  return val.replace(/^["']|["']$/g, "").trim();
}

/**
 * Parses XML output exported from Windows Event Viewer
 */
export async function parseEventXml(xmlContent: string, fastScanMode: boolean = false, onProgress?: (progress: number) => void): Promise<EventLogEntry[]> {
  const logs: EventLogEntry[] = [];
  try {
    const parser = new DOMParser();
    let start = 0;
    let i = 0;
    while (true) {
      start = xmlContent.indexOf("<Event", start);
      if (start === -1) break;
      const end = xmlContent.indexOf("</Event>", start);
      if (end === -1) break;
      
      const eventStr = xmlContent.slice(start, end + 8);
      start = end + 8;
      
      if (i > 0 && i % 2000 === 0) {
        if (onProgress) onProgress(Math.round((start / xmlContent.length) * 100));
        await new Promise(r => setTimeout(r, 0));
      }
      
      const xmlDoc = parser.parseFromString(eventStr, "text/xml");
      const eventNode = xmlDoc.documentElement;
      if (!eventNode || (eventNode.localName !== "Event" && eventNode.nodeName !== "Event")) continue;

      const elements = eventNode.getElementsByTagName("*");
      
      const getElem = (name: string) => {
        for (let j = 0; j < elements.length; j++) {
          if (elements[j].localName === name || elements[j].nodeName === name) return elements[j];
        }
        return null;
      };

      const systemNode = getElem("System");
      if (!systemNode) continue;

      const eventIdNode = getElem("EventID");
      const eventId = eventIdNode ? parseInt(eventIdNode.textContent || "0", 10) : 0;

      const providerNode = getElem("Provider");
      const source = providerNode ? providerNode.getAttribute("Name") || "Unknown Source" : "Unknown Source";

      const timeNode = getElem("TimeCreated");
      const timestamp = timeNode ? timeNode.getAttribute("SystemTime") || new Date().toISOString() : new Date().toISOString();

      const levelNode = getElem("Level");
      const rawLevel = levelNode ? levelNode.textContent : "4";
      let level: "Critical" | "Error" | "Warning" | "Information" | "Unknown" = "Information";
      if (rawLevel === "1") level = "Critical";
      else if (rawLevel === "2") level = "Error";
      else if (rawLevel === "3") level = "Warning";
      else if (rawLevel === "4") level = "Information";

      const channelNode = getElem("Channel");
      let channel: "System" | "Application" | "Security" | "Code Integrity" | "Unknown" = "Unknown";
      const rawChannel = channelNode ? channelNode.textContent?.toLowerCase() : "";
      if (rawChannel?.includes("system")) channel = "System";
      else if (rawChannel?.includes("application")) channel = "Application";
      else if (rawChannel?.includes("security")) channel = "Security";
      else if (rawChannel?.includes("codeintegrity") || rawChannel?.includes("code integrity")) channel = "Code Integrity";

      const computerNode = getElem("Computer");
      const computer = computerNode ? computerNode.textContent || "localhost" : "localhost";

      const eventDataNode = getElem("EventData");
      let message = "";
      
      if (eventDataNode) {
        const dataNodes = eventDataNode.getElementsByTagName("*");
        const dataParts: string[] = [];
        for (let j = 0; j < dataNodes.length; j++) {
          if (dataNodes[j].localName === "Data" || dataNodes[j].nodeName === "Data") {
            const name = dataNodes[j].getAttribute("Name");
            const val = dataNodes[j].textContent;
            if (name) dataParts.push(`${name}: ${val}`);
            else if (val) dataParts.push(val);
          }
        }
        message = dataParts.join("\n") || "No detailed event data available.";
      } else {
        const renderingInfoNode = getElem("RenderingInfo");
        if (renderingInfoNode) {
          const messageNodes = renderingInfoNode.getElementsByTagName("*");
          for (let j = 0; j < messageNodes.length; j++) {
             if (messageNodes[j].localName === "Message" || messageNodes[j].nodeName === "Message") {
                message = messageNodes[j].textContent || "";
                break;
             }
          }
        }
        if (!message) {
          message = eventNode.textContent?.trim().substring(0, 500) || "No message available.";
        }
      }

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
        raw: eventStr
      });
      i++;
    }
  } catch (err) {
    console.error("Error parsing Event Log XML:", err);
  }
  return logs;
}

/**
 * Parses CSV exported from Windows Event Viewer
 */
export async function parseEventCsv(csvContent: string, fastScanMode: boolean = false, onProgress?: (progress: number) => void): Promise<EventLogEntry[]> {
  const logs: EventLogEntry[] = [];
  try {
    let start = 0;
    let end = csvContent.indexOf('\n');
    if (end === -1) return [];

    const headerLine = csvContent.slice(start, end).trim();
    const headers = parseCsvRow(headerLine).map(h => h.toLowerCase());

    const levelIdx = headers.indexOf("level");
    const timeIdx = headers.indexOf("date and time") !== -1 ? headers.indexOf("date and time") : headers.findIndex(h => h.includes("date") || h.includes("time"));
    const sourceIdx = headers.indexOf("source") !== -1 ? headers.indexOf("source") : headers.indexOf("provider");
    const idIdx = headers.indexOf("event id") !== -1 ? headers.indexOf("event id") : headers.findIndex(h => h.includes("id"));
    const msgIdx = headers.indexOf("description") !== -1 ? headers.indexOf("description") : (headers.indexOf("information") !== -1 ? headers.indexOf("information") : headers.length - 1);
    
    start = end + 1;
    let i = 1;
    
    while (start < csvContent.length) {
      end = csvContent.indexOf('\n', start);
      if (end === -1) end = csvContent.length;
      
      const line = csvContent.slice(start, end).trim();
      start = end + 1;
      i++;
      
      if (i % 5000 === 0) {
        if (onProgress) onProgress(Math.round((start / csvContent.length) * 100));
        await new Promise(r => setTimeout(r, 0));
      }
      
      if (!line) continue;
      const columns = parseCsvRow(line);
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
export async function parseEventText(textContent: string, fastScanMode: boolean = false, onProgress?: (progress: number) => void): Promise<EventLogEntry[]> {
  const logs: EventLogEntry[] = [];
  try {
    // Try dividing into logical events based on timestamps
    const regex = /(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^\n]*)/g;
    const parts = textContent.split(regex);
    
    let currentLog: Partial<EventLogEntry> | null = null;
    let count = 0;
    const totalParts = parts.length;

    for (let i = 0; i < parts.length; i++) {
      let part = parts[i].trim();
      
      if (i % 3000 === 0) {
        if (onProgress) onProgress(Math.round((i / totalParts) * 100));
        await new Promise(r => setTimeout(r, 0));
      }
      
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

/**
 * Parses binary EVTX files directly in the browser
 */
export async function parseEventEvtx(buffer: ArrayBuffer, fastScanMode: boolean = false, onProgress?: (progress: number) => void): Promise<EventLogEntry[]> {
  const logs: EventLogEntry[] = [];
  try {
    const uint8Array = new Uint8Array(buffer);
    const records = parseEvtxFile(uint8Array as any);
    
    let i = 0;
    const totalRecords = records.length;
    for (const record of records) {
      if (i > 0 && i % 2000 === 0) {
        if (onProgress) onProgress(Math.round((i / totalRecords) * 100));
        await new Promise(r => setTimeout(r, 0));
      }
      i++;
      
      const recEvent = record.event as any;
      if (!record || !recEvent || !recEvent.Event) continue;
      
      const eventNode = recEvent.Event;
      const systemNode = eventNode.System;
      if (!systemNode) continue;

      // Extract details from the parsed object
      const eventId = systemNode.EventID ? parseInt(systemNode.EventID._text || systemNode.EventID, 10) : 0;
      const source = systemNode.Provider?._Name || "Unknown Source";
      
      let timestamp = new Date().toISOString();
      if (systemNode.TimeCreated && systemNode.TimeCreated._SystemTime) {
        timestamp = systemNode.TimeCreated._SystemTime;
      } else if (record.timestamp) {
        timestamp = new Date(record.timestamp * 1000).toISOString();
      }

      const rawLevel = systemNode.Level;
      let level: "Critical" | "Error" | "Warning" | "Information" | "Unknown" = "Information";
      if (rawLevel == 1) level = "Critical";
      else if (rawLevel == 2) level = "Error";
      else if (rawLevel == 3) level = "Warning";
      else if (rawLevel == 4) level = "Information";

      const channelNode = systemNode.Channel || "";
      const rawChannel = channelNode.toLowerCase ? channelNode.toLowerCase() : String(channelNode).toLowerCase();
      let channel: "System" | "Application" | "Security" | "Code Integrity" | "Unknown" = "Unknown";
      if (rawChannel.includes("system")) channel = "System";
      else if (rawChannel.includes("application")) channel = "Application";
      else if (rawChannel.includes("security")) channel = "Security";
      else if (rawChannel.includes("codeintegrity") || rawChannel.includes("code integrity")) channel = "Code Integrity";

      const computer = systemNode.Computer || "localhost";

      let message = "";
      const eventDataNode = eventNode.EventData;
      if (eventDataNode && eventDataNode.Data) {
        if (Array.isArray(eventDataNode.Data)) {
          message = eventDataNode.Data.map((d: any) => {
            if (typeof d === 'object') {
              return (d._Name ? `${d._Name}: ` : '') + (d._text || JSON.stringify(d));
            }
            return String(d);
          }).join("\n");
        } else if (typeof eventDataNode.Data === 'object') {
          message = (eventDataNode.Data._Name ? `${eventDataNode.Data._Name}: ` : '') + (eventDataNode.Data._text || JSON.stringify(eventDataNode.Data));
        } else {
          message = String(eventDataNode.Data);
        }
      } else if (eventNode.RenderingInfo && eventNode.RenderingInfo.Message) {
        message = typeof eventNode.RenderingInfo.Message === 'object' 
          ? (eventNode.RenderingInfo.Message._text || JSON.stringify(eventNode.RenderingInfo.Message))
          : String(eventNode.RenderingInfo.Message);
      }
      
      if (!message) {
        message = "No message available.";
      }

      const category = computeCategory(source, eventId, message);

      if (fastScanMode && level === "Information") {
        continue;
      }

      logs.push({
        id: `evtx-${record.recordID}-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
        timestamp,
        level,
        source,
        eventId,
        channel,
        computer,
        message,
        category,
        raw: JSON.stringify(eventNode)
      });
    }
  } catch (err) {
    console.error("Error parsing EVTX binary log:", err);
  }
  return logs;
}
