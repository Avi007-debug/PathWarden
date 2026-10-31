"use client";

import React from "react";
import { DataQualityReport } from "@/lib/api/types";
import { formatNumber } from "@/lib/utils/formatters";
import { ShieldCheck, AlertOctagon, CopyX, CheckSquare } from "lucide-react";

interface TerminalDispositionsChartProps {
  report: DataQualityReport;
}

export function TerminalDispositionsChart({ report }: TerminalDispositionsChartProps) {
  const total = report.total_records_read;
  const eligiblePct = ((report.eligible_count / total) * 100).toFixed(1);
  const excludedPct = ((report.valid_excluded_count / total) * 100).toFixed(1);
  const duplicatePct = ((report.duplicate_dropped_count / total) * 100).toFixed(1);
  const malformedPct = ((report.malformed_count / total) * 100).toFixed(2);

  return (
    <div className="border-2 border-[var(--border-color)] bg-[var(--bg-surface)] p-5 font-mono flex flex-col gap-4 shadow-[4px_4px_0px_var(--border-color)] hover:shadow-[6px_6px_0px_var(--border-color)] transition-all select-none">
      <div className="flex items-center justify-between pb-3 border-b-2 border-[var(--border-color)]">
        <div>
          <h2 className="text-sm font-black uppercase tracking-wider text-[var(--text-primary)]">
            Terminal Dispositions Reconciliation
          </h2>
          <span className="text-xs text-[var(--text-muted)] font-medium">
            Strict non-overlapping categorization: records_read = malformed + duplicate + valid_excluded + eligible
          </span>
        </div>
      </div>

      {/* Visual Multi-Segment Proportional Bar */}
      <div className="flex flex-col gap-1.5">
        <div className="w-full h-3.5 bg-[#050B14] border-2 border-[var(--border-color)] flex overflow-hidden">
          <div
            style={{ width: `${excludedPct}%` }}
            className="h-full bg-slate-500 hover:opacity-90 transition-opacity"
            title={`VALID_EXCLUDED: ${excludedPct}%`}
          />
          <div
            style={{ width: `${eligiblePct}%` }}
            className="h-full bg-[#00C8FF] hover:opacity-90 transition-opacity"
            title={`ELIGIBLE: ${eligiblePct}%`}
          />
          <div
            style={{ width: `${duplicatePct}%` }}
            className="h-full bg-[#FFB800] hover:opacity-90 transition-opacity"
            title={`DUPLICATE_DROPPED: ${duplicatePct}%`}
          />
          <div
            style={{ width: `${malformedPct}%` }}
            className="h-full bg-red-500 hover:opacity-90 transition-opacity"
            title={`MALFORMED: ${malformedPct}%`}
          />
        </div>
        <div className="flex justify-between text-[10px] text-[var(--text-dim)] font-bold">
          <span>0%</span>
          <span>100% INGESTED VOLUME ({formatNumber(total)} RECORDS)</span>
        </div>
      </div>

      {/* Disposition Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 pt-2">
        {/* Eligible */}
        <div className="p-3 border-2 border-[#00C8FF] bg-[#00C8FF]/10 shadow-[2px_2px_0px_#00C8FF] hover:shadow-[4px_4px_0px_#00C8FF] hover:-translate-x-[1px] hover:-translate-y-[1px] transition-all flex flex-col justify-between">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] font-black text-[#00C8FF] uppercase">{"// ELIGIBLE"}</span>
            <CheckSquare className="w-4 h-4 text-[#00C8FF]" />
          </div>
          <div>
            <span className="text-xl sm:text-2xl font-black text-[var(--text-primary)] block">
              {formatNumber(report.eligible_count)}
            </span>
            <span className="text-[10px] text-[var(--text-dim)] font-bold">
              {eligiblePct}% • Evaluated by rules
            </span>
          </div>
        </div>

        {/* Valid Excluded */}
        <div className="p-3 border-2 border-[var(--border-color)] bg-[var(--bg-surface-elevated)] shadow-[2px_2px_0px_var(--border-color)] hover:shadow-[4px_4px_0px_var(--border-color)] hover:-translate-x-[1px] hover:-translate-y-[1px] transition-all flex flex-col justify-between">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] font-black text-slate-400 uppercase">{"// VALID_EXCLUDED"}</span>
            <ShieldCheck className="w-4 h-4 text-slate-400" />
          </div>
          <div>
            <span className="text-xl sm:text-2xl font-black text-[var(--text-primary)] block">
              {formatNumber(report.valid_excluded_count)}
            </span>
            <span className="text-[10px] text-[var(--text-dim)] font-bold">
              {excludedPct}% • Benign volume pruned
            </span>
          </div>
        </div>

        {/* Duplicate Dropped */}
        <div className="p-3 border-2 border-amber-500 bg-amber-500/10 shadow-[2px_2px_0px_#FFB800] hover:shadow-[4px_4px_0px_#FFB800] hover:-translate-x-[1px] hover:-translate-y-[1px] transition-all flex flex-col justify-between">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] font-black text-amber-500 uppercase">{"// DUPLICATE_DROPPED"}</span>
            <CopyX className="w-4 h-4 text-amber-500" />
          </div>
          <div>
            <span className="text-xl sm:text-2xl font-black text-[var(--text-primary)] block">
              {formatNumber(report.duplicate_dropped_count)}
            </span>
            <span className="text-[10px] text-[var(--text-dim)] font-bold">
              {duplicatePct}% • Exact delivery duplicates
            </span>
          </div>
        </div>

        {/* Malformed */}
        <div className="p-3 border-2 border-red-500 bg-red-500/10 shadow-[2px_2px_0px_#FF334B] hover:shadow-[4px_4px_0px_#FF334B] hover:-translate-x-[1px] hover:-translate-y-[1px] transition-all flex flex-col justify-between">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] font-black text-red-400 uppercase">{"// MALFORMED"}</span>
            <AlertOctagon className="w-4 h-4 text-red-400" />
          </div>
          <div>
            <span className="text-xl sm:text-2xl font-black text-[var(--text-primary)] block">
              {formatNumber(report.malformed_count)}
            </span>
            <span className="text-[10px] text-[var(--text-dim)] font-bold">
              {malformedPct}% • Parsing syntax failures
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
