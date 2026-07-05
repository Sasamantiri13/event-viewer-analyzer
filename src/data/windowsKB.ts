/**
 * Windows Event ID Knowledge Base
 * Sourced from: https://github.com/adulau/windows-event-id-database (CC0-1.0)
 * This module provides offline enrichment of log events using a local KB database.
 */

import windowsEventDb from "./kb/database/windowseventid.json";

export interface KBEntry {
  eventId: string;
  legacyEventId: string | null;
  criticality: string;
  summary: string;
}

// Build a fast lookup map indexed by event-id
const kbMap = new Map<string, KBEntry>();

(windowsEventDb as any[]).forEach((entry) => {
  const id = entry["event-id"];
  if (id && id !== "-" && id !== null) {
    kbMap.set(id.toString(), {
      eventId: id.toString(),
      legacyEventId: entry["legacy-event-id"],
      criticality: entry["criticality"] || "Unknown",
      summary: entry["summary"] || "",
    });
  }
});

/**
 * Lookup a single Event ID from the offline KB
 */
export function lookupKB(eventId: string | number): KBEntry | undefined {
  return kbMap.get(eventId.toString());
}

/**
 * Enrich a batch of log entries with KB context, returning matched entries
 */
export function enrichLogsWithKB(
  logs: { eventId: number | string; level: string; source: string; message: string }[]
): { log: typeof logs[0]; kb: KBEntry }[] {
  const results: { log: typeof logs[0]; kb: KBEntry }[] = [];
  const seen = new Set<string>();

  for (const log of logs) {
    const id = log.eventId?.toString();
    if (!id || seen.has(id)) continue;

    const kb = kbMap.get(id);
    if (kb) {
      seen.add(id);
      results.push({ log, kb });
    }
  }

  return results;
}

/**
 * Get total KB entries count
 */
export function getKBSize(): number {
  return kbMap.size;
}

/**
 * Get all KB entries (for directory display)
 */
export function getAllKBEntries(): KBEntry[] {
  return Array.from(kbMap.values());
}
