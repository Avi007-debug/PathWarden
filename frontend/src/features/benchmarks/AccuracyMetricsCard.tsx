"use client";

import React from "react";
import { BenchmarkReport } from "@/lib/api/types";
import { ShieldCheck, Target, Crosshair, AlertCircle } from "lucide-react";

interface AccuracyMetricsCardProps {
  metrics: BenchmarkReport["metrics"];
}

export function AccuracyMetricsCard({ metrics }: AccuracyMetricsCardProps) {
  const cards = [
    {
      label: "Detection Recall",
      measured: metrics.detection_recall_pct,
      target: metrics.target_recall_pct,
      desc: "Planted attack steps detected / total planted steps",
      color: "text-[#00C8FF]",
      icon: Target,
    },
    {
      label: "ATT&CK Label Accuracy",
      measured: metrics.label_accuracy_pct,
      target: metrics.target_label_accuracy_pct,
      desc: "Technique labels matching ground truth contract",
      color: "text-[#86D400] dark:text-[#B7FF3C]",
      icon: ShieldCheck,
    },
    {
      label: "Attack Path Reconstruction",
      measured: metrics.path_reconstruction_pct,
      target: metrics.target_path_reconstruction_pct,
      desc: "Planted attacks reconstructed with required steps and order",
      color: "text-[#2563FF]",
      icon: Crosshair,
    },
    {
      label: "False Alarm Rate",
      measured: metrics.false_alarm_rate_pct,
      target: metrics.target_false_alarm_pct,
      desc: "Unplanted generated incidents / all generated incidents",
      color: "text-amber-500",
      icon: AlertCircle,
      isLowerBetter: true,
    },
  ];

  return (
    <div className="border-2 border-[var(--border-color)] bg-[var(--bg-surface)] p-5 font-mono flex flex-col gap-4 shadow-[4px_4px_0px_var(--border-color)] hover:shadow-[6px_6px_0px_var(--border-color)] transition-all select-none">
      <div className="pb-3 border-b-2 border-[var(--border-color)]">
        <h2 className="text-sm font-black uppercase tracking-wider text-[var(--text-primary)]">
          Evaluation Scorer Accuracy Metrics
        </h2>
        <span className="text-xs text-[var(--text-muted)] font-medium">
          Evaluated strictly in isolated evaluation mode without ground truth leaking into the detection engine.
        </span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {cards.map((c) => (
          <div
            key={c.label}
            className="p-4 border-2 border-[var(--border-color)] bg-[var(--bg-surface-elevated)] shadow-[2px_2px_0px_var(--border-color)] hover:shadow-[4px_4px_0px_#00C8FF] hover:border-[#00C8FF] hover:-translate-x-[1px] hover:-translate-y-[1px] transition-all flex flex-col justify-between"
          >
            <div>
              <div className="flex items-center justify-between text-[10px] text-[var(--text-dim)] uppercase mb-2">
                <span className="font-extrabold">{c.label}</span>
                <c.icon className={`w-3.5 h-3.5 ${c.color}`} />
              </div>
              <span className={`text-2xl sm:text-3xl font-black ${c.color} block`}>
                {c.measured.toFixed(1)}%
              </span>
            </div>

            <div className="mt-3 pt-2 border-t border-[var(--border-subtle)] text-[10px] text-[var(--text-muted)] font-medium">
              <span className="font-bold">
                Target: {c.isLowerBetter ? "≤ " : "≥ "}
                {c.target.toFixed(1)}% (
                {c.isLowerBetter ? (c.measured <= c.target ? "Met" : "Not Met") : c.measured >= c.target ? "Met" : "Not Met"})
              </span>
              <p className="mt-1 text-[var(--text-dim)] leading-tight">{c.desc}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
