"use client";

import React from "react";
import Link from "next/link";
import { IncidentDetail } from "@/lib/api/types";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { formatTimestamp } from "@/lib/utils/formatters";
import { Radio, AlertTriangle } from "lucide-react";

interface InvestigationHeaderProps {
  incident: IncidentDetail;
}

export function InvestigationHeader({ incident }: InvestigationHeaderProps) {
  return (
    <div className="border-b-2 border-[var(--border-color)] bg-[var(--bg-surface)] p-5 flex flex-col gap-4 font-mono select-none shadow-[0_2px_0px_rgba(0,0,0,0.1)]">
      {/* Top line: Incident ID, Severity, Status, Actions */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <Badge variant={incident.severity === "CRITICAL" ? "critical" : "warning"} size="md">
            {incident.severity}
          </Badge>
          <h1 className="text-base sm:text-lg font-black text-[var(--text-primary)] tracking-wider">
            {incident.incident_id}
          </h1>
          <span className="hidden sm:inline text-xs px-2 py-0.5 bg-[var(--bg-surface-elevated)] border-2 border-[var(--border-color)] text-[var(--text-muted)] font-bold shadow-[1px_1px_0px_var(--border-color)] uppercase">
            {incident.status.replace(/_/g, " ")}
          </span>
          {incident.is_planted_match && (
            <span className="text-[10px] bg-[#B7FF3C] text-black border border-black px-2 py-0.5 font-extrabold shadow-[2px_2px_0px_#000] uppercase tracking-wider">
              PLANTED ATTACK BENCHMARK
            </span>
          )}
        </div>

        <div className="flex items-center gap-2.5">
          <Link href="/reachability">
            <Button variant="secondary" size="sm" icon={<Radio className="w-3.5 h-3.5 text-[#00C8FF]" />}>
              Reachability View
            </Button>
          </Link>
          <Link href="/incidents">
            <Button variant="ghost" size="sm">
              All Incidents
            </Button>
          </Link>
        </div>
      </div>

      {/* Title & Summary */}
      <div>
        <h2 className="text-sm font-black text-[var(--text-primary)] mb-1">
          {incident.title}
        </h2>
        <p className="text-xs text-[var(--text-muted)] leading-relaxed font-medium">
          {incident.summary}
        </p>
      </div>

      {/* Key Investigation Metadata Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3 pt-3 border-t-2 border-[var(--border-subtle)] text-xs">
        <div className="p-2 border border-[var(--border-color)] bg-[var(--bg-surface-elevated)] shadow-[1px_1px_0px_var(--border-color)]">
          <span className="text-[10px] text-[var(--text-dim)] uppercase block font-bold">{"// CONFIDENCE"}</span>
          <span className="text-[#00C8FF] font-black text-sm block mt-0.5">{(incident.confidence * 100).toFixed(0)}% Supported</span>
        </div>
        <div className="p-2 border border-[var(--border-color)] bg-[var(--bg-surface-elevated)] shadow-[1px_1px_0px_var(--border-color)]">
          <span className="text-[10px] text-[var(--text-dim)] uppercase block font-bold">{"// FIRST SEEN"}</span>
          <span className="text-[var(--text-primary)] font-bold text-[11px] block mt-0.5">{formatTimestamp(incident.first_seen)}</span>
        </div>
        <div className="p-2 border border-[var(--border-color)] bg-[var(--bg-surface-elevated)] shadow-[1px_1px_0px_var(--border-color)]">
          <span className="text-[10px] text-[var(--text-dim)] uppercase block font-bold">{"// LAST SEEN"}</span>
          <span className="text-[var(--text-primary)] font-bold text-[11px] block mt-0.5">{formatTimestamp(incident.last_seen)}</span>
        </div>
        <div className="p-2 border border-[var(--border-color)] bg-[var(--bg-surface-elevated)] shadow-[1px_1px_0px_var(--border-color)]">
          <span className="text-[10px] text-[var(--text-dim)] uppercase block font-bold">{`// HOSTS (${incident.hosts_involved.length})`}</span>
          <span className="text-[var(--text-primary)] truncate block font-bold text-[11px] mt-0.5" title={incident.hosts_involved.join(", ")}>
            {incident.hosts_involved.join(", ")}
          </span>
        </div>
        <div className="p-2 border border-[var(--border-color)] bg-[var(--bg-surface-elevated)] shadow-[1px_1px_0px_var(--border-color)]">
          <span className="text-[10px] text-[var(--text-dim)] uppercase block font-bold">{`// USERS (${incident.users_involved.length})`}</span>
          <span className="text-[var(--text-primary)] truncate block font-bold text-[11px] mt-0.5" title={incident.users_involved.join(", ")}>
            {incident.users_involved.join(", ")}
          </span>
        </div>
        <div className="p-2 border border-[var(--border-color)] bg-[var(--bg-surface-elevated)] shadow-[1px_1px_0px_var(--border-color)]">
          <span className="text-[10px] text-[var(--text-dim)] uppercase block font-bold">{"// ATTACK STEPS"}</span>
          <span className="text-[#86D400] dark:text-[#B7FF3C] font-black text-sm block mt-0.5">{incident.steps_count} Reconstructed</span>
        </div>
      </div>

      {/* Data Quality Caveats Warning Bar (if any) */}
      {incident.dq_caveats && incident.dq_caveats.length > 0 && (
        <div className="p-3 bg-amber-500/10 border-2 border-amber-500/50 text-amber-500 text-xs flex items-center gap-2 shadow-[2px_2px_0px_#FFB800]">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <div className="flex-1 flex flex-wrap items-center gap-2">
            <span className="font-black uppercase tracking-wider text-[10px]">{"// DATA QUALITY CAVEAT:"}</span>
            <span className="font-medium">{incident.dq_caveats[0].description}</span>
          </div>
        </div>
      )}
    </div>
  );
}
