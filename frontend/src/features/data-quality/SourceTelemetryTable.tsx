"use client";

import React from "react";
import { DataQualitySourceMetric } from "@/lib/api/types";
import { formatNumber } from "@/lib/utils/formatters";
import { Server } from "lucide-react";

interface SourceTelemetryTableProps {
  sources: DataQualitySourceMetric[];
}

export function SourceTelemetryTable({ sources }: SourceTelemetryTableProps) {
  return (
    <div className="border-2 border-[var(--border-color)] bg-[var(--bg-surface)] shadow-[4px_4px_0px_var(--border-color)] hover:shadow-[6px_6px_0px_var(--border-color)] transition-all overflow-hidden font-mono text-xs select-none">
      <div className="px-5 py-3.5 border-b-2 border-[var(--border-color)] bg-[var(--bg-surface-elevated)] flex items-center justify-between">
        <h3 className="font-black text-xs uppercase tracking-wider text-[var(--text-primary)]">
          Source Ingestion & Parser Breakdown
        </h3>
        <span className="text-[10px] font-bold text-[var(--text-muted)] uppercase bg-[var(--bg-surface)] px-2 py-0.5 border border-[var(--border-color)]">
          {sources.length} Adapters
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b-2 border-[var(--border-color)] bg-[var(--bg-surface-elevated)] text-[10px] uppercase text-[var(--text-dim)] tracking-wider font-black">
              <th className="py-3 px-4">Telemetry Source</th>
              <th className="py-3 px-4">Format Type</th>
              <th className="py-3 px-4 text-right">Records Read</th>
              <th className="py-3 px-4 text-right">Parse Success</th>
              <th className="py-3 px-4 text-right">Eligible</th>
              <th className="py-3 px-4 text-right">Excluded</th>
              <th className="py-3 px-4 text-right">Inferred Hosts</th>
            </tr>
          </thead>
          <tbody className="divide-y-2 divide-[var(--border-subtle)]">
            {sources.map((src) => (
              <tr key={src.source_name} className="hover:bg-[var(--bg-surface-elevated)] transition-colors">
                <td className="py-3.5 px-4 font-bold text-[var(--text-primary)] flex items-center gap-2">
                  <Server className="w-3.5 h-3.5 text-[#00C8FF]" />
                  <span>{src.source_name}</span>
                </td>
                <td className="py-3.5 px-4 text-[11px] text-[var(--text-muted)] font-semibold">
                  {src.source_type}
                </td>
                <td className="py-3.5 px-4 text-right font-black text-[var(--text-primary)]">
                  {formatNumber(src.records_read)}
                </td>
                <td className="py-3.5 px-4 text-right">
                  <span className="text-[#86D400] dark:text-[#B7FF3C] font-black">
                    {src.parse_success_rate_pct.toFixed(2)}%
                  </span>
                </td>
                <td className="py-3.5 px-4 text-right text-[#00C8FF] font-black">
                  {formatNumber(src.eligible)}
                </td>
                <td className="py-3.5 px-4 text-right text-[var(--text-muted)] font-semibold">
                  {formatNumber(src.valid_excluded)}
                </td>
                <td className="py-3.5 px-4 text-right text-amber-500 font-bold">
                  {src.inferred_hosts_count > 0 ? formatNumber(src.inferred_hosts_count) : "0"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
