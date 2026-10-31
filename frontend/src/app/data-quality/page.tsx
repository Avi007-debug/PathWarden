"use client";

import React, { useEffect, useState } from "react";
import { pathWardenApi } from "@/lib/api/client";
import { DataQualityReport } from "@/lib/api/types";
import { useApp } from "@/lib/context/AppContext";
import { FunnelReconciliation } from "@/features/data-quality/FunnelReconciliation";
import { TerminalDispositionsChart } from "@/features/data-quality/TerminalDispositionsChart";
import { QualityFlagsBreakdown } from "@/features/data-quality/QualityFlagsBreakdown";
import { SourceTelemetryTable } from "@/features/data-quality/SourceTelemetryTable";
import { FileCheck2, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/Button";

export default function DataQualityPage() {
  const { isDemoMode } = useApp();
  const [report, setReport] = useState<DataQualityReport | null>(null);
  const [loading, setLoading] = useState(true);

  const loadDataQuality = React.useCallback(() => {
    setLoading(true);
    pathWardenApi
      .getDataQuality(isDemoMode)
      .then((data) => {
        setReport(data);
        setLoading(false);
      })
      .catch(() => {
        setLoading(false);
      });
  }, [isDemoMode]);

  useEffect(() => {
    loadDataQuality();
  }, [loadDataQuality]);

  return (
    <div className="flex-1 p-6 flex flex-col gap-6 max-w-7xl mx-auto w-full font-mono select-none">
      {/* Page Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b-2 border-[var(--border-color)]">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <FileCheck2 className="w-5 h-5 text-[#86D400] dark:text-[#B7FF3C]" />
            <h1 className="font-heading text-xl font-black uppercase tracking-tight text-[var(--text-primary)]">
              Data Quality & Processing Observability
            </h1>
          </div>
          <p className="text-xs text-[var(--text-muted)] font-medium">
            Full record reconciliation accounting from raw stream decompression through correlated incident outputs.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <Button
            variant="secondary"
            size="sm"
            onClick={loadDataQuality}
            icon={<RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />}
          >
            Refresh
          </Button>
        </div>
      </div>

      {loading || !report ? (
        <div className="p-12 border-2 border-[var(--border-color)] bg-[var(--bg-surface)] shadow-[4px_4px_0px_var(--border-color)] text-center text-xs text-[var(--text-muted)] font-bold">
          RECONCILING INGESTED LOG VOLUMES...
        </div>
      ) : (
        <>
          {/* Funnel */}
          <FunnelReconciliation report={report} />

          {/* Terminal Dispositions */}
          <TerminalDispositionsChart report={report} />

          {/* Quality Flags Breakdown */}
          <QualityFlagsBreakdown report={report} />

          {/* Source Breakdown Table */}
          <SourceTelemetryTable sources={report.sources} />
        </>
      )}
    </div>
  );
}
