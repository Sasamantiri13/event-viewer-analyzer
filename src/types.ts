/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export interface EventLogEntry {
  id: string;
  timestamp: string; // ISO string or readable format
  level: "Critical" | "Error" | "Warning" | "Information" | "Unknown";
  source: string;
  eventId: number;
  channel: "System" | "Application" | "Security" | "Code Integrity" | "Unknown";
  computer: string;
  message: string;
  category: string; // Dynamic or parsed category
  raw?: string; // Original raw XML or text
}

export interface IncidentScenario {
  name: string;
  description: string;
  badge: string;
  icon: string;
  logs: EventLogEntry[];
}

export interface DefenderErrorCode {
  code: string; // e.g., "0x80508015", "Event ID 1116"
  title: string;
  type: "HRESULT" | "Event ID" | "Service Code";
  description: string;
  recommendation: string;
  link: string;
}
