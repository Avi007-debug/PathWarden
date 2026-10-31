"use client";

import React from "react";
import { formatNumber } from "@/lib/utils/formatters";
import {
  FileText,
  Filter,
  AlertTriangle,
  GitFork,
  ShieldAlert,
  Flame,
} from "lucide-react";

interface MetricsOverviewProps {
  recordsProcessed: number;
  eligibleEvents: number;
  detectionsCount: number;
  incidentsCount: number;
  criticalIncidentsCount: number;
  attackStepsCount: number;
}

export function MetricsOverview({
  recordsProcessed,
  eligibleEvents,
  detectionsCount,
  incidentsCount,
  criticalIncidentsCount,
  attackStepsCount,
}: MetricsOverviewProps) {
  const metrics = [
    {
      label: "Records Ingested",
      value: formatNumber(recordsProcessed),
      subtext: `${formatNumber(recordsProcessed)} records analyzed`,
      icon: FileText,
      accent: "text-[#2563FF]",
      borderClass: "border-l-4 border-l-[#2563FF]",
      hoverShadow: "hover:shadow-[6px_6px_0px_#2563FF] hover:border-[#2563FF]",
    },
    {
      label: "Eligible Events",
      value: formatNumber(eligibleEvents),
      subtext: `${formatNumber(eligibleEvents)} security candidates`,
      icon: Filter,
      accent: "text-[#00C8FF]",
      borderClass: "border-l-4 border-l-[#00C8FF]",
      hoverShadow: "hover:shadow-[6px_6px_0px_#00C8FF] hover:border-[#00C8FF]",
    },
    {
      label: "Suspicious Detections",
      value: formatNumber(detectionsCount),
      subtext: `${formatNumber(detectionsCount)} rule predicates triggered`,
      icon: AlertTriangle,
      accent: "text-[#FFB800]",
      borderClass: "border-l-4 border-l-[#FFB800]",
      hoverShadow: "hover:shadow-[6px_6px_0px_#FFB800] hover:border-[#FFB800]",
    },
    {
      label: "Attack Steps",
      value: formatNumber(attackStepsCount),
      subtext: `${formatNumber(attackStepsCount)} validated attack actions`,
      icon: GitFork,
      accent: "text-[#00BFA6]",
      borderClass: "border-l-4 border-l-[#00BFA6]",
      hoverShadow: "hover:shadow-[6px_6px_0px_#00BFA6] hover:border-[#00BFA6]",
    },
    {
      label: "Correlated Incidents",
      value: formatNumber(incidentsCount),
      subtext: `${formatNumber(incidentsCount)} isolated attack clusters`,
      icon: ShieldAlert,
      accent: "text-[#86D400] dark:text-[#B7FF3C]",
      borderClass: "border-l-4 border-l-[#B7FF3C]",
      hoverShadow: "hover:shadow-[6px_6px_0px_#B7FF3C] hover:border-[#B7FF3C]",
    },
    {
      label: "Planted Intrusions",
      value: formatNumber(criticalIncidentsCount),
      subtext: `${formatNumber(criticalIncidentsCount)} priority compromises`,
      icon: Flame,
      accent: "text-red-500",
      borderClass: "border-l-4 border-l-red-500",
      hoverShadow: "hover:shadow-[6px_6px_0px_#FF334B] hover:border-[#FF334B]",
    },
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3.5 font-mono select-none">
      {metrics.map((m) => (
        <div
          key={m.label}
          className={`relative p-3.5 border-2 border-[var(--border-color)] bg-[var(--bg-surface)] flex flex-col justify-between shadow-[4px_4px_0px_var(--border-color)] transition-all duration-150 hover:-translate-x-[2px] hover:-translate-y-[2px] cursor-default group ${m.borderClass} ${m.hoverShadow}`}
        >
          {/* Subtle Corner Reticle */}
          <span className="absolute -top-[5px] -right-[5px] font-mono text-[9px] text-[var(--text-dim)] group-hover:text-[#00C8FF] pointer-events-none select-none font-bold">
            +
          </span>

          <div className="flex items-center justify-between text-[10px] text-[var(--text-dim)] uppercase mb-2">
            <span className="truncate pr-1 font-bold tracking-wider" title={m.label}>
              {m.label}
            </span>
            <m.icon className={`w-3.5 h-3.5 ${m.accent} shrink-0 transition-transform group-hover:scale-110`} />
          </div>

          <div>
            <span className="text-xl sm:text-2xl font-black text-[var(--text-primary)] block tracking-tight">
              {m.value}
            </span>
            <span
              className="text-[10px] text-[var(--text-muted)] line-clamp-1 mt-0.5 tracking-tight font-medium"
              title={m.subtext}
            >
              {m.subtext}
            </span>
          </div>
        </div>
      ))}
    </div>
  );
}
