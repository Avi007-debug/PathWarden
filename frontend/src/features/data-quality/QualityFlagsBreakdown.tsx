"use client";

import React from "react";
import { DataQualityReport } from "@/lib/api/types";
import { formatNumber } from "@/lib/utils/formatters";
import { AlertTriangle } from "lucide-react";

interface QualityFlagsBreakdownProps {
  report: DataQualityReport;
}

export function QualityFlagsBreakdown({ report }: QualityFlagsBreakdownProps) {
  const flags = Object.entries(report.flags_summary);

  return (
    <div className="border-2 border-[var(--border-color)] bg-[var(--bg-surface)] p-5 font-mono flex flex-col gap-4 shadow-[4px_4px_0px_var(--border-color)] hover:shadow-[6px_6px_0px_var(--border-color)] transition-all select-none">
      <div className="pb-3 border-b-2 border-[var(--border-color)]">
        <h2 className="text-sm font-black uppercase tracking-wider text-[var(--text-primary)]">
          Telemetry Quality Flags & Caveats
        </h2>
        <span className="text-xs text-[var(--text-muted)] font-medium">
          Non-terminal attributes tracked across events to prevent uncertain evidence from asserting false definitive claims.
        </span>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
        {flags.map(([flag, count]) => (
          <div
            key={flag}
            className="p-3 border-2 border-[var(--border-color)] bg-[var(--bg-surface-elevated)] shadow-[2px_2px_0px_var(--border-color)] hover:border-amber-500 hover:shadow-[4px_4px_0px_#FFB800] hover:-translate-x-[1px] hover:-translate-y-[1px] transition-all flex flex-col justify-between"
          >
            <div className="flex items-center gap-1.5 text-amber-500 mb-2 font-bold">
              <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
              <span className="text-[10px] uppercase truncate" title={flag}>
                {flag.replace(/_/g, " ")}
              </span>
            </div>
            <div>
              <span className="text-xl font-black text-[var(--text-primary)] block">
                {formatNumber(count)}
              </span>
              <span className="text-[10px] text-[var(--text-dim)] font-semibold">Affected Records</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
