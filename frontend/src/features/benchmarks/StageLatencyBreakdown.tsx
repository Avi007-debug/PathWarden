"use client";

import React from "react";
import { BenchmarkStageMetric } from "@/lib/api/types";
import { formatDuration } from "@/lib/utils/formatters";
import { CheckCircle2 } from "lucide-react";

interface StageLatencyBreakdownProps {
  stages: BenchmarkStageMetric[];
}

export function StageLatencyBreakdown({ stages }: StageLatencyBreakdownProps) {
  return (
    <div className="border-2 border-[var(--border-color)] bg-[var(--bg-surface)] shadow-[4px_4px_0px_var(--border-color)] hover:shadow-[6px_6px_0px_var(--border-color)] transition-all overflow-hidden font-mono text-xs select-none">
      <div className="px-5 py-3.5 border-b-2 border-[var(--border-color)] bg-[var(--bg-surface-elevated)] flex items-center justify-between">
        <h3 className="font-black text-xs uppercase tracking-wider text-[var(--text-primary)]">
          Stage-Level Latency & Throughput Breakdown
        </h3>
        <span className="text-[10px] font-bold text-[var(--text-muted)] uppercase bg-[var(--bg-surface)] px-2 py-0.5 border border-[var(--border-color)]">
          {stages?.length || 5} Pipeline Stages
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b-2 border-[var(--border-color)] bg-[var(--bg-surface-elevated)] text-[10px] uppercase text-[var(--text-dim)] tracking-wider font-black">
              <th className="py-3 px-4">Pipeline Stage</th>
              <th className="py-3 px-4 text-right">Measured Time</th>
              <th className="py-3 px-4 text-right">Target Ceiling</th>
              <th className="py-3 px-4 text-right">Throughput</th>
              <th className="py-3 px-4 text-right">Performance Status</th>
            </tr>
          </thead>
          <tbody className="divide-y-2 divide-[var(--border-subtle)]">
            {stages.map((stg) => (
              <tr key={stg.stage_name} className="hover:bg-[var(--bg-surface-elevated)] transition-colors">
                <td className="py-3 px-4 font-bold text-[var(--text-primary)]">
                  {stg.stage_name}
                </td>
                <td className="py-3 px-4 text-right font-black text-[#00C8FF]">
                  {formatDuration(stg.measured_seconds)}
                </td>
                <td className="py-3 px-4 text-right text-[var(--text-dim)] font-bold">
                  {formatDuration(stg.target_seconds)}
                </td>
                <td className="py-3 px-4 text-right text-[var(--text-muted)] font-bold">
                  {stg.measured_throughput_mbs
                    ? `${stg.measured_throughput_mbs.toFixed(1)} MB/s`
                    : "-"}
                </td>
                <td className="py-3 px-4 text-right">
                  <span className="inline-flex items-center gap-1 text-[10px] font-extrabold px-2 py-0.5 bg-[#B7FF3C] text-black border border-black shadow-[1px_1px_0px_#000] uppercase">
                    <CheckCircle2 className="w-3 h-3" />
                    {stg.status.replace(/_/g, " ")}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
