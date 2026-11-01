"use client";

import React, { useEffect, useState } from "react";
import { pathWardenApi } from "@/lib/api/client";
import { BenchmarkReport, ProcessingStatusResponse } from "@/lib/api/types";
import { useApp } from "@/lib/context/AppContext";
import { BenchmarkSummaryCards } from "@/features/benchmarks/BenchmarkSummaryCards";
import { AccuracyMetricsCard } from "@/features/benchmarks/AccuracyMetricsCard";
import { StageLatencyBreakdown } from "@/features/benchmarks/StageLatencyBreakdown";
import { CompetitionTargetMatrix } from "@/features/benchmarks/CompetitionTargetMatrix";
import { DetectionRuleConfigEditor } from "@/features/benchmarks/DetectionRuleConfigEditor";
import { Gauge, RefreshCw, Cpu, HardDrive } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Footer } from "@/components/layout/Footer";

export default function BenchmarksPage() {
  const { isDemoMode } = useApp();
  const [report, setReport] = useState<BenchmarkReport | null>(null);
  const [status, setStatus] = useState<ProcessingStatusResponse | null>(null);
  const [loading, setLoading] = useState(true);

  const loadData = React.useCallback(() => {
    setLoading(true);
    Promise.all([
      pathWardenApi.getBenchmark(isDemoMode),
      pathWardenApi.getStatus(isDemoMode),
    ])
      .then(([benchData, statusData]) => {
        setReport(benchData);
        setStatus(statusData);
        setLoading(false);
      })
      .catch(() => {
        setLoading(false);
      });
  }, [isDemoMode]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  return (
    <div className="flex-1 flex flex-col justify-between min-h-full">
      <div className="p-6 flex flex-col gap-6 max-w-7xl mx-auto w-full font-mono select-none flex-1">
        {/* Page Header */}
        <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b-2 border-[var(--border-color)]">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <Gauge className="w-5 h-5 text-[#00C8FF]" />
              <h1 className="font-heading text-xl font-black uppercase tracking-tight text-[var(--text-primary)]">
                Performance Benchmarks & Competition Target Matrix
              </h1>
            </div>
            <p className="text-xs text-[var(--text-muted)] font-medium">
              {report?.tier_name || `${Math.round(report?.dataset_size_gb || 30)} GB Tier (${report?.multiplier || '1.3×'})`} measured against planted attacks • Evaluated on host specifications
            </p>
          </div>

          <div className="flex items-center gap-2.5">
            <Button
              variant="secondary"
              size="sm"
              onClick={loadData}
              icon={<RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />}
            >
              Refresh Telemetry
            </Button>
          </div>
        </div>

        {loading || !report ? (
          <div className="p-12 border-2 border-[var(--border-color)] bg-[var(--bg-surface)] shadow-[4px_4px_0px_var(--border-color)] text-center text-xs text-[var(--text-muted)] font-bold">
            RETRIEVING BENCHMARK & SYSTEM SPECIFICATIONS...
          </div>
        ) : (
          <>
            {/* Target Matrix & Hardware Specs (From Competition Screenshot 1) */}
            <CompetitionTargetMatrix
              targets={status?.target_matrix}
              machineSpecs={status?.machine_specifications}
            />

            {/* Hardware & Target Profile Callout */}
            <div className="p-4 border-2 border-[var(--border-color)] bg-[var(--bg-surface-elevated)] shadow-[4px_4px_0px_var(--border-color)] hover:shadow-[6px_6px_0px_var(--border-color)] transition-all flex flex-wrap items-center justify-between gap-4 text-xs">
              <div className="flex items-center gap-4">
                <div className="flex items-center gap-1.5 text-[var(--text-primary)] font-bold">
                  <Cpu className="w-4 h-4 text-[#86D400] dark:text-[#B7FF3C]" />
                  <span>
                    Hardware Budget: {status?.machine_specifications?.cpu_cores ?? 8} Cores • {status?.machine_specifications?.total_ram_gb ?? 16} GB RAM • 8 GB Cap
                  </span>
                </div>
                <span className="text-[var(--text-dim)] hidden sm:inline">|</span>
                <div className="flex items-center gap-1.5 text-[var(--text-muted)] font-semibold">
                  <HardDrive className="w-4 h-4 text-[#00C8FF]" />
                  <span>Dataset: {report.tier_name || `${Math.round(report.dataset_size_gb || 30)} GB Tier (${report.multiplier || '1.3×'})`}</span>
                </div>
              </div>
              <span className="text-[10px] px-2.5 py-1 bg-[#B7FF3C] text-black font-extrabold border border-black shadow-[2px_2px_0px_#000] uppercase tracking-wider">
                STATUS: {report.status}
              </span>
            </div>

            {/* Bonus B-4: Detection Rules Config Editor (YAML/Sigma) */}
            <DetectionRuleConfigEditor />

            {/* Benchmark Cards */}
            <BenchmarkSummaryCards benchmark={report} />

            {/* Accuracy Metrics */}
            <AccuracyMetricsCard metrics={report.metrics} />

            {/* Pipeline Stage Latencies */}
            <StageLatencyBreakdown stages={report.stages} />
          </>
        )}
      </div>
      <Footer />
    </div>
  );
}
