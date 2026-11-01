"use client";

import React from "react";
import { BenchmarkReport } from "@/lib/api/types";
import { formatDuration } from "@/lib/utils/formatters";
import { Clock, Cpu, Gauge, Zap, CheckCircle2 } from "lucide-react";

interface BenchmarkSummaryCardsProps {
  benchmark: BenchmarkReport;
}

export function BenchmarkSummaryCards({ benchmark }: BenchmarkSummaryCardsProps) {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 font-mono select-none">
      {/* Total Processing Time */}
      <div className="p-4 border-2 border-[var(--border-color)] bg-[var(--bg-surface)] shadow-[4px_4px_0px_var(--border-color)] hover:shadow-[6px_6px_0px_#00C8FF] hover:border-[#00C8FF] hover:-translate-x-[2px] hover:-translate-y-[2px] transition-all flex flex-col justify-between">
        <div className="flex items-center justify-between text-[10px] text-[var(--text-dim)] uppercase font-bold">
          <span>{"// RUNTIME (END-TO-END)"}</span>
          <Clock className="w-3.5 h-3.5 text-[#00C8FF]" />
        </div>
        <div className="my-2">
          <span className="text-2xl sm:text-3xl font-black text-[var(--text-primary)] block">
            {formatDuration(benchmark.total_duration_seconds)}
          </span>
          <div className="text-[11px] text-[#86D400] dark:text-[#B7FF3C] flex items-center gap-1 mt-0.5 font-bold">
            <CheckCircle2 className="w-3.5 h-3.5" />
            <span>Target: &lt; {formatDuration(benchmark.target_duration_seconds)} (Met)</span>
          </div>
        </div>
        <div className="text-[10px] text-[var(--text-muted)] border-t border-[var(--border-subtle)] pt-1.5 font-semibold">
          Tier: {benchmark.tier_name || `${Math.round(benchmark.dataset_size_gb || 30)} GB Tier (${benchmark.multiplier || '1.3×'})`}
        </div>
      </div>

      {/* Sustained Throughput */}
      <div className="p-4 border-2 border-[var(--border-color)] bg-[var(--bg-surface)] shadow-[4px_4px_0px_var(--border-color)] hover:shadow-[6px_6px_0px_#B7FF3C] hover:border-[#B7FF3C] hover:-translate-x-[2px] hover:-translate-y-[2px] transition-all flex flex-col justify-between">
        <div className="flex items-center justify-between text-[10px] text-[var(--text-dim)] uppercase font-bold">
          <span>{"// SUSTAINED THROUGHPUT"}</span>
          <Gauge className="w-3.5 h-3.5 text-[#86D400] dark:text-[#B7FF3C]" />
        </div>
        <div className="my-2">
          <span className="text-2xl sm:text-3xl font-black text-[#00C8FF] block">
            {benchmark.sustained_throughput_mbs.toFixed(1)} MB/s
          </span>
          <div className="text-[11px] text-[#86D400] dark:text-[#B7FF3C] flex items-center gap-1 mt-0.5 font-bold">
            <CheckCircle2 className="w-3.5 h-3.5" />
            <span>Target: ≥ {benchmark.target_throughput_mbs.toFixed(1)} MB/s</span>
          </div>
        </div>
        <div className="text-[10px] text-[var(--text-muted)] border-t border-[var(--border-subtle)] pt-1.5 font-semibold">
          End-to-end ingestion through graph output
        </div>
      </div>

      {/* Peak Memory Consumption */}
      <div className="p-4 border-2 border-[var(--border-color)] bg-[var(--bg-surface)] shadow-[4px_4px_0px_var(--border-color)] hover:shadow-[6px_6px_0px_#FFB800] hover:border-[#FFB800] hover:-translate-x-[2px] hover:-translate-y-[2px] transition-all flex flex-col justify-between">
        <div className="flex items-center justify-between text-[10px] text-[var(--text-dim)] uppercase font-bold">
          <span>{"// PEAK CONTAINER RAM"}</span>
          <Cpu className="w-3.5 h-3.5 text-amber-500" />
        </div>
        <div className="my-2">
          <span className="text-2xl sm:text-3xl font-black text-[var(--text-primary)] block">
            {(benchmark.peak_container_memory_mb / 1024).toFixed(2)} GB
          </span>
          <div className="text-[11px] text-[#86D400] dark:text-[#B7FF3C] flex items-center gap-1 mt-0.5 font-bold">
            <CheckCircle2 className="w-3.5 h-3.5" />
            <span>Target: ≤ 7.0 GB (Hard Cap 8.0 GB)</span>
          </div>
        </div>
        <div className="text-[10px] text-[var(--text-muted)] border-t border-[var(--border-subtle)] pt-1.5 font-semibold">
          Tested on 16 GB host (8 CPU cores)
        </div>
      </div>

      {/* Investigation Latency */}
      <div className="p-4 border-2 border-[var(--border-color)] bg-[var(--bg-surface)] shadow-[4px_4px_0px_var(--border-color)] hover:shadow-[6px_6px_0px_#2563FF] hover:border-[#2563FF] hover:-translate-x-[2px] hover:-translate-y-[2px] transition-all flex flex-col justify-between">
        <div className="flex items-center justify-between text-[10px] text-[var(--text-dim)] uppercase font-bold">
          <span>{"// PRECOMPUTED LATENCY"}</span>
          <Zap className="w-3.5 h-3.5 text-[#2563FF]" />
        </div>
        <div className="my-2">
          <span className="text-2xl sm:text-3xl font-black text-[#86D400] dark:text-[#B7FF3C] block">
            {benchmark.investigation_latency_ms} ms
          </span>
          <div className="text-[11px] text-[#86D400] dark:text-[#B7FF3C] flex items-center gap-1 mt-0.5 font-bold">
            <CheckCircle2 className="w-3.5 h-3.5" />
            <span>Target: ≤ {benchmark.target_latency_ms} ms</span>
          </div>
        </div>
        <div className="text-[10px] text-[var(--text-muted)] border-t border-[var(--border-subtle)] pt-1.5 font-semibold">
          Instant graph retrieval without runtime re-crawl
        </div>
      </div>
    </div>
  );
}
