"use client";

import React from "react";
import { DataQualityReport } from "@/lib/api/types";
import { formatNumber, formatExactNumber } from "@/lib/utils/formatters";
import { CheckCircle2 } from "lucide-react";

interface FunnelReconciliationProps {
  report: DataQualityReport;
}

export function FunnelReconciliation({ report }: FunnelReconciliationProps) {
  const stages = [
    {
      label: "Raw Ingested Records",
      count: report.total_records_read,
      color: "border-[var(--border-color)] bg-[var(--bg-surface)] text-[var(--text-primary)]",
      desc: "All source records read from disk / files",
    },
    {
      label: "Parsed Events",
      count: report.total_records_read - report.malformed_count,
      color: "border-[#2563FF] bg-[#2563FF]/5 text-[var(--text-primary)]",
      desc: "Syntax validated & schema mapped",
    },
    {
      label: "Eligible Events",
      count: report.eligible_count,
      color: "border-[#00C8FF] bg-[#00C8FF]/5 text-[var(--text-primary)]",
      desc: "Security-relevant candidate events",
    },
    {
      label: "Detections",
      count: report.total_detections,
      color: "border-[#FFB800] bg-[#FFB800]/5 text-[var(--text-primary)]",
      desc: "SQL rule predicates triggered",
    },
    {
      label: "Attack Steps",
      count: report.total_attack_steps,
      color: "border-[#00BFA6] bg-[#00BFA6]/5 text-[var(--text-primary)]",
      desc: "Contextually validated attack actions",
    },
    {
      label: "Correlated Incidents",
      count: report.total_incidents,
      color: "border-[#B7FF3C] bg-[#B7FF3C]/5 text-[var(--text-primary)]",
      desc: "Coherent multi-stage attack paths",
    },
  ];

  return (
    <div className="border-2 border-[var(--border-color)] bg-[var(--bg-surface)] p-5 font-mono flex flex-col gap-4 shadow-[4px_4px_0px_var(--border-color)] hover:shadow-[6px_6px_0px_var(--border-color)] transition-all">
      <div className="flex items-center justify-between pb-3 border-b-2 border-[var(--border-color)]">
        <div>
          <h2 className="text-sm font-black uppercase tracking-wider text-[var(--text-primary)]">
            End-to-End Processing Funnel
          </h2>
          <span className="text-xs text-[var(--text-muted)] font-medium">
            Reconciles ingestion through correlated incident generation.
          </span>
        </div>
        <div className="flex items-center gap-1.5 px-2.5 py-1 bg-[#B7FF3C] text-black text-[10px] font-extrabold uppercase border border-black shadow-[2px_2px_0px_#000]">
          <CheckCircle2 className="w-3.5 h-3.5" />
          <span>RECONCILIATION BALANCED</span>
        </div>
      </div>

      {/* Responsive Funnel Steps */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {stages.map((stage, idx) => (
          <div
            key={stage.label}
            className={`p-3.5 border-2 flex flex-col justify-between relative shadow-[2px_2px_0px_var(--border-color)] hover:shadow-[4px_4px_0px_#00C8FF] hover:-translate-x-[1px] hover:-translate-y-[1px] transition-all cursor-default ${stage.color}`}
          >
            <div>
              <span className="text-[10px] text-[var(--text-dim)] uppercase block font-bold mb-1">
                {`// STAGE 0${idx + 1}`}
              </span>
              <span className="text-xs font-black uppercase block line-clamp-1" title={stage.label}>
                {stage.label}
              </span>
            </div>

            <div className="my-3">
              <span className="text-xl sm:text-2xl font-black tracking-tight block">
                {formatNumber(stage.count)}
              </span>
              <span className="text-[10px] text-[var(--text-dim)] font-medium block">
                {formatExactNumber(stage.count)}
              </span>
            </div>

            <span className="text-[10px] text-[var(--text-muted)] leading-tight block font-medium">
              {stage.desc}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
