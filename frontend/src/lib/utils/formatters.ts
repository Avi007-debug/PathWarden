// PathWarden Formatting and Display Utilities

import { IncidentSeverity, ReachabilityRelationshipType } from "../api/types";

export function formatNumber(num: number): string {
  if (num >= 1_000_000_000) {
    return (num / 1_000_000_000).toFixed(1) + "B";
  }
  if (num >= 1_000_000) {
    return (num / 1_000_000).toFixed(1) + "M";
  }
  if (num >= 1_000) {
    return (num / 1_000).toFixed(1) + "K";
  }
  return num.toLocaleString();
}

export function formatExactNumber(num: number): string {
  return num.toLocaleString();
}

export function formatBytes(bytes: number): string {
  if (bytes >= 1024 * 1024 * 1024) {
    return (bytes / (1024 * 1024 * 1024)).toFixed(2) + " GB";
  }
  if (bytes >= 1024 * 1024) {
    return (bytes / (1024 * 1024)).toFixed(1) + " MB";
  }
  if (bytes >= 1024) {
    return (bytes / 1024).toFixed(1) + " KB";
  }
  return bytes + " B";
}

export function formatDuration(seconds: number): string {
  if (seconds < 60) {
    return `${Math.round(seconds)}s`;
  }
  const mins = Math.floor(seconds / 60);
  const remSecs = Math.round(seconds % 60);
  if (mins < 60) {
    return `${mins}m ${remSecs}s`;
  }
  const hours = Math.floor(mins / 60);
  const remMins = mins % 60;
  return `${hours}h ${remMins}m`;
}

export function formatTimestamp(isoString: string): string {
  try {
    const d = new Date(isoString);
    return d.toISOString().replace("T", " ").replace("Z", " UTC");
  } catch {
    return isoString;
  }
}

export function formatTimeOnly(isoString: string): string {
  try {
    const d = new Date(isoString);
    return d.toISOString().substring(11, 19) + " UTC";
  } catch {
    return isoString;
  }
}

export function getSeverityStyle(severity: IncidentSeverity) {
  switch (severity) {
    case "CRITICAL":
      return {
        bg: "bg-red-500/15 border-red-500/50 text-red-400",
        badge: "bg-red-950/80 text-red-300 border-red-600/80 font-mono",
        dot: "bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.8)]",
        label: "CRITICAL",
      };
    case "HIGH":
      return {
        bg: "bg-amber-500/15 border-amber-500/50 text-amber-400",
        badge: "bg-amber-950/80 text-amber-300 border-amber-600/80 font-mono",
        dot: "bg-amber-500 shadow-[0_0_8px_rgba(245,158,11,0.8)]",
        label: "HIGH",
      };
    case "MEDIUM":
      return {
        bg: "bg-yellow-500/15 border-yellow-500/50 text-yellow-400",
        badge: "bg-yellow-950/80 text-yellow-300 border-yellow-600/80 font-mono",
        dot: "bg-yellow-400",
        label: "MEDIUM",
      };
    case "LOW":
      return {
        bg: "bg-teal-500/15 border-teal-500/50 text-teal-400",
        badge: "bg-teal-950/80 text-teal-300 border-teal-600/80 font-mono",
        dot: "bg-teal-400",
        label: "LOW",
      };
    case "INFORMATIONAL":
    default:
      return {
        bg: "bg-blue-500/15 border-blue-500/50 text-blue-400",
        badge: "bg-blue-950/80 text-blue-300 border-blue-600/80 font-mono",
        dot: "bg-blue-400",
        label: "INFO",
      };
  }
}

export function getReachabilityStyle(type: ReachabilityRelationshipType) {
  switch (type) {
    case "OBSERVED_SESSION":
      return {
        badge: "bg-[#B7FF3C]/15 border-[#B7FF3C]/60 text-[#B7FF3C]",
        border: "border-[#B7FF3C]",
        text: "text-[#B7FF3C]",
        label: "OBSERVED ACCESS (CONFIRMED)",
        description: "Confirmed logon session or execution recorded in telemetry",
      };
    case "NETWORK_REACHABLE":
      return {
        badge: "bg-[#00C8FF]/15 border-[#00C8FF]/60 text-[#00C8FF]",
        border: "border-[#00C8FF] border-dashed",
        text: "text-[#00C8FF]",
        label: "POTENTIAL (NETWORK REACHABLE)",
        description: "Open routing / firewall egress; no session verified",
      };
    case "PRIVILEGE_RELATIONSHIP":
      return {
        badge: "bg-amber-400/15 border-amber-400/60 text-amber-300",
        border: "border-amber-400 border-dotted",
        text: "text-amber-300",
        label: "POTENTIAL (PRIVILEGE EXPOSURE)",
        description: "Harvested credentials hold rights on target; no session yet",
      };
  }
}

