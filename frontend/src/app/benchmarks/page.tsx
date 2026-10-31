"use client";

import React, { useEffect, useState } from "react";
import { pathWardenApi } from "@/lib/api/client";
import { BenchmarkReport } from "@/lib/api/types";
import { useApp } from "@/lib/context/AppContext";
import { BenchmarkSummaryCards } from "@/features/benchmarks/BenchmarkSummaryCards";
import { AccuracyMetricsCard } from "@/features/benchmarks/AccuracyMetricsCard";
import { StageLatencyBreakdown } from "@/features/benchmarks/StageLatencyBreakdown";
import { Gauge, RefreshCw, Cpu, HardDrive } from "lucide-react";
import { Button } from "@/components/ui/Button";

export default function BenchmarksPage() {
  const { isDemoMode } = useApp();
  const [report, setReport] = useState<BenchmarkReport | null>(null);
  const [loading, setLoading] = useState(true);

  const loadBenchmark = React.useCallback(() => {
    setLoading(true);
    pathWardenApi
      .getBenchmark(isDemoMode)
      .then((data) => {
        setReport(data);
        setLoading(false);
      })
      .catch(() => {
        setLoading(false);
      });
  }, [isDemoMode]);

  useEffect(() => {
    loadBenchmark();
  }, [loadBenchmark]);

  return (
    <div className="flex-1 p-6 flex flex-col gap-6 max-w-7xl mx-auto w-full font-mono select-none">
      {/* Page Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b-2 border-[var(--border-color)]">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Gauge className="w-5 h-5 text-[#00C8FF]" />
            <h1 className="font-heading text-xl font-black uppercase tracking-tight text-[var(--text-primary)]">
              Performance Benchmarks & Accuracy Scorer
            </h1>
          </div>
          <p className="text-xs text-[var(--text-muted)] font-medium">
            Measured execution results against the 30 GB Advanced Tier competition targets on 16 GB RAM / 8-core hardware.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <Button
            variant="secondary"
            size="sm"
            onClick={loadBenchmark}
            icon={<RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />}
          >
            Refresh
          </Button>
        </div>
      </div>

      {loading || !report ? (
        <div className="p-12 border-2 border-[var(--border-color)] bg-[var(--bg-surface)] shadow-[4px_4px_0px_var(--border-color)] text-center text-xs text-[var(--text-muted)] font-bold">
          RETRIEVING BENCHMARK METRICS...
        </div>
      ) : (
        <>
          {/* Hardware & Target Profile Callout */}
          <div className="p-4 border-2 border-[var(--border-color)] bg-[var(--bg-surface-elevated)] shadow-[4px_4px_0px_var(--border-color)] hover:shadow-[6px_6px_0px_var(--border-color)] transition-all flex flex-wrap items-center justify-between gap-4 text-xs">
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-1.5 text-[var(--text-primary)] font-bold">
                <Cpu className="w-4 h-4 text-[#86D400] dark:text-[#B7FF3C]" />
                <span>Target Hardware: 8 Cores • 16 GB RAM • 8 GB Container Cap</span>
              </div>
              <span className="text-[var(--text-dim)] hidden sm:inline">|</span>
              <div className="flex items-center gap-1.5 text-[var(--text-muted)] font-semibold">
                <HardDrive className="w-4 h-4 text-[#00C8FF]" />
                <span>Dataset: 30 GB Advanced Tier (1.3× Multiplier)</span>
              </div>
            </div>
            <span className="text-[10px] px-2.5 py-1 bg-[#B7FF3C] text-black font-extrabold border border-black shadow-[2px_2px_0px_#000] uppercase tracking-wider">
              STATUS: {report.status}
            </span>
          </div>

          {/* Benchmark Cards */}
          <BenchmarkSummaryCards benchmark={report} />

          {/* Accuracy Metrics */}
          <AccuracyMetricsCard metrics={report.metrics} />

          {/* Pipeline Stage Latencies */}
          <StageLatencyBreakdown stages={report.stages} />
        </>
      )}
    </div>
  );
}
