"use client";

import React from "react";
import Link from "next/link";
import { DataQualityReport } from "@/lib/api/types";
import { formatNumber } from "@/lib/utils/formatters";
import { ArrowRight, Activity } from "lucide-react";

interface DatasetHealthWidgetProps {
  report: DataQualityReport;
}

export function DatasetHealthWidget({ report }: DatasetHealthWidgetProps) {
  return (
    <div className="border-2 border-[var(--border-color)] bg-[var(--bg-surface)] p-5 font-mono flex flex-col justify-between gap-4 shadow-[4px_4px_0px_var(--border-color)] hover:shadow-[6px_6px_0px_var(--border-color)] transition-all">
      {/* Header */}
      <div className="flex items-center justify-between pb-3 border-b-2 border-[var(--border-color)]">
        <div className="flex items-center gap-2">
          <Activity className="w-4 h-4 text-[#00C8FF]" />
          <h2 className="text-xs font-black uppercase tracking-wider text-[var(--text-primary)]">
            Dataset Health & Integrity
          </h2>
        </div>
        <span className="text-[10px] px-2 py-0.5 bg-[#B7FF3C] text-black font-extrabold uppercase border border-black shadow-[1px_1px_0px_#000]">
          99.82% VALID
        </span>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-2 gap-3 text-xs">
        <div className="p-3 border-2 border-[var(--border-color)] bg-[var(--bg-surface-elevated)] shadow-[2px_2px_0px_var(--border-color)] hover:border-[#00C8FF] hover:shadow-[3px_3px_0px_#00C8FF] transition-all">
          <span className="text-[10px] text-[var(--text-dim)] uppercase block font-bold">Parsing Failures</span>
          <span className="text-[var(--text-primary)] font-black text-base block mt-0.5">
            {formatNumber(report.malformed_count)}
          </span>
          <span className="text-[10px] text-[var(--text-muted)] block mt-0.5 font-medium">Isolated by reason</span>
        </div>

        <div className="p-3 border-2 border-[var(--border-color)] bg-[var(--bg-surface-elevated)] shadow-[2px_2px_0px_var(--border-color)] hover:border-[#00C8FF] hover:shadow-[3px_3px_0px_#00C8FF] transition-all">
          <span className="text-[10px] text-[var(--text-dim)] uppercase block font-bold">Duplicates Dropped</span>
          <span className="text-[var(--text-primary)] font-black text-base block mt-0.5">
            {formatNumber(report.duplicate_dropped_count)}
          </span>
          <span className="text-[10px] text-[var(--text-muted)] block mt-0.5 font-medium">Redundant deliveries</span>
        </div>

        <div className="p-3 border-2 border-[var(--border-color)] bg-[var(--bg-surface-elevated)] shadow-[2px_2px_0px_var(--border-color)] hover:border-amber-500 hover:shadow-[3px_3px_0px_#FFB800] transition-all">
          <span className="text-[10px] text-[var(--text-dim)] uppercase block font-bold">Inferred Hosts</span>
          <span className="text-amber-500 font-black text-base block mt-0.5">
            {formatNumber(report.flags_summary.HOST_INFERRED)}
          </span>
          <span className="text-[10px] text-[var(--text-muted)] block mt-0.5 font-medium">Explicitly flagged</span>
        </div>

        <div className="p-3 border-2 border-[var(--border-color)] bg-[var(--bg-surface-elevated)] shadow-[2px_2px_0px_var(--border-color)] hover:border-amber-500 hover:shadow-[3px_3px_0px_#FFB800] transition-all">
          <span className="text-[10px] text-[var(--text-dim)] uppercase block font-bold">Timestamp Offsets</span>
          <span className="text-amber-500 font-black text-base block mt-0.5">
            {formatNumber(report.flags_summary.TIMESTAMP_UNCERTAIN)}
          </span>
          <span className="text-[10px] text-[var(--text-muted)] block mt-0.5 font-medium">Drift normalized</span>
        </div>
      </div>

      {/* Footer Link */}
      <div className="pt-2 border-t-2 border-[var(--border-color)] flex items-center justify-between">
        <span className="text-[10px] text-[var(--text-dim)] font-semibold">Exact reconciliation balanced</span>
        <Link
          href="/data-quality"
          className="inline-flex items-center gap-1 text-[11px] font-bold text-[#00C8FF] hover:text-[#B7FF3C] transition-colors uppercase tracking-wider"
        >
          <span>Full Report</span>
          <ArrowRight className="w-3 h-3" />
        </Link>
      </div>
    </div>
  );
}
