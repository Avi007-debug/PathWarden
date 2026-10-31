"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { pathWardenApi } from "@/lib/api/client";
import {
  Incident,
  DataQualityReport,
} from "@/lib/api/types";
import { useApp } from "@/lib/context/AppContext";
import { MetricsOverview } from "@/features/overview/MetricsOverview";
import { FunnelReconciliation } from "@/features/data-quality/FunnelReconciliation";
import { RecentIncidentsTable } from "@/features/overview/RecentIncidentsTable";
import { DatasetHealthWidget } from "@/features/overview/DatasetHealthWidget";
import { RunAnalysisModal } from "@/features/overview/RunAnalysisModal";
import { Button } from "@/components/ui/Button";
import {
  PlayCircle,
  RefreshCw,
  GitFork,
  Radio,
  FileCheck2,
  Gauge,
} from "lucide-react";

export default function OverviewDashboardPage() {
  const { isDemoMode } = useApp();

  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [dqReport, setDqReport] = useState<DataQualityReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [runModalOpen, setRunModalOpen] = useState(false);

  const loadDashboardData = React.useCallback(async () => {
    setLoading(true);
    try {
      const [incs, dq] = await Promise.all([
        pathWardenApi.getIncidents(isDemoMode),
        pathWardenApi.getDataQuality(isDemoMode),
      ]);
      setIncidents(incs);
      setDqReport(dq);
    } catch {
      // Handled
    } finally {
      setLoading(false);
    }
  }, [isDemoMode]);

  useEffect(() => {
    loadDashboardData();
  }, [loadDashboardData]);

  const criticalCount = incidents.filter((i) => i.severity === "CRITICAL").length;
  const attackStepsCount = dqReport?.total_attack_steps || 84;

  return (
    <div className="flex-1 p-6 flex flex-col gap-6 max-w-7xl mx-auto w-full font-mono">
      {/* Overview Header & Actions */}
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-[var(--border-color)]">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <h1 className="font-heading text-2xl font-black uppercase tracking-tight text-[var(--text-primary)]">
              Investigation Overview
            </h1>
            <span className="text-xs px-2 py-0.5 bg-[#2563FF]/15 text-[#2563FF] border border-[#2563FF]/30 font-bold uppercase">
              Operational SOC
            </span>
          </div>
          <p className="text-xs text-[var(--text-muted)]">
            Correlated attack graph reconstruction & evidence reconciliation for the active dataset enclave.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <Button
            variant="cyan"
            size="md"
            icon={<PlayCircle className="w-4 h-4" />}
            onClick={() => setRunModalOpen(true)}
          >
            Run Pipeline
          </Button>
          <Button
            variant="secondary"
            size="md"
            icon={<RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />}
            onClick={loadDashboardData}
          >
            Sync Telemetry
          </Button>
        </div>
      </div>

      {loading && !dqReport ? (
        <div className="p-16 border border-[var(--border-color)] bg-[var(--bg-surface)] text-center text-xs text-[var(--text-muted)]">
          <div className="w-8 h-8 border-2 border-[#00C8FF] border-t-transparent animate-spin mx-auto mb-3" />
          <span>LOADING INVESTIGATION DASHBOARD & EVENT METRICS...</span>
        </div>
      ) : (
        <>
          {/* Key Metrics Row */}
          <MetricsOverview
            recordsProcessed={dqReport?.total_records_read || 142850400}
            eligibleEvents={dqReport?.eligible_count || 18410000}
            detectionsCount={dqReport?.total_detections || 4892}
            incidentsCount={incidents.length}
            criticalIncidentsCount={criticalCount}
            attackStepsCount={attackStepsCount}
          />

          {/* Processing Funnel */}
          {dqReport && <FunnelReconciliation report={dqReport} />}

          {/* Asymmetrical 2-Column Split: Incidents Table + Dataset Health */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Left 2 Cols: Recent Incidents */}
            <div className="lg:col-span-2">
              <RecentIncidentsTable incidents={incidents} />
            </div>

            {/* Right 1 Col: Dataset Health & Fast Nav */}
            <div className="flex flex-col gap-6">
              {dqReport && <DatasetHealthWidget report={dqReport} />}

              {/* Fast Jump Card */}
              <div className="p-4 border-2 border-[var(--border-color)] bg-[var(--bg-surface)] shadow-[4px_4px_0px_var(--border-color)] hover:shadow-[6px_6px_0px_var(--border-color)] transition-all flex flex-col gap-3 font-mono text-xs">
                <span className="font-extrabold text-[10px] uppercase tracking-wider text-[var(--text-dim)] pb-2 border-b-2 border-[var(--border-color)]">
                  {"// QUICK HUD ROUTING"}
                </span>
                <div className="grid grid-cols-2 gap-2.5">
                  <Link
                    href="/incidents/INC-2026-0841"
                    className="p-3 border-2 border-[var(--border-color)] bg-[var(--bg-surface-elevated)] shadow-[2px_2px_0px_var(--border-color)] hover:border-[#00C8FF] hover:shadow-[4px_4px_0px_#00C8FF] hover:-translate-x-[1px] hover:-translate-y-[1px] transition-all flex flex-col gap-1"
                  >
                    <GitFork className="w-3.5 h-3.5 text-[#00C8FF]" />
                    <span className="font-bold text-[var(--text-primary)]">Planted Path</span>
                    <span className="text-[10px] text-[var(--text-dim)]">INC-2026-0841</span>
                  </Link>

                  <Link
                    href="/reachability"
                    className="p-3 border-2 border-[var(--border-color)] bg-[var(--bg-surface-elevated)] shadow-[2px_2px_0px_var(--border-color)] hover:border-[#B7FF3C] hover:shadow-[4px_4px_0px_#B7FF3C] hover:-translate-x-[1px] hover:-translate-y-[1px] transition-all flex flex-col gap-1"
                  >
                    <Radio className="w-3.5 h-3.5 text-[#86D400] dark:text-[#B7FF3C]" />
                    <span className="font-bold text-[var(--text-primary)]">Reachability</span>
                    <span className="text-[10px] text-[var(--text-dim)]">Observed Access</span>
                  </Link>

                  <Link
                    href="/data-quality"
                    className="p-3 border-2 border-[var(--border-color)] bg-[var(--bg-surface-elevated)] shadow-[2px_2px_0px_var(--border-color)] hover:border-[#FFB800] hover:shadow-[4px_4px_0px_#FFB800] hover:-translate-x-[1px] hover:-translate-y-[1px] transition-all flex flex-col gap-1"
                  >
                    <FileCheck2 className="w-3.5 h-3.5 text-[#FFB800]" />
                    <span className="font-bold text-[var(--text-primary)]">Data Quality</span>
                    <span className="text-[10px] text-[var(--text-dim)]">Reconciliation</span>
                  </Link>

                  <Link
                    href="/benchmarks"
                    className="p-3 border-2 border-[var(--border-color)] bg-[var(--bg-surface-elevated)] shadow-[2px_2px_0px_var(--border-color)] hover:border-[#2563FF] hover:shadow-[4px_4px_0px_#2563FF] hover:-translate-x-[1px] hover:-translate-y-[1px] transition-all flex flex-col gap-1"
                  >
                    <Gauge className="w-3.5 h-3.5 text-[#2563FF]" />
                    <span className="font-bold text-[var(--text-primary)]">Benchmarks</span>
                    <span className="text-[10px] text-[var(--text-dim)]">30 GB Target</span>
                  </Link>
                </div>
              </div>
            </div>
          </div>
        </>
      )}

      {/* Ingestion & Analysis Run Modal */}
      <RunAnalysisModal isOpen={runModalOpen} onClose={() => setRunModalOpen(false)} />
    </div>
  );
}
