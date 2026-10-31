"use client";

import React from "react";
import Link from "next/link";
import { Incident } from "@/lib/api/types";
import { Badge } from "@/components/ui/Badge";
import { ShieldAlert, Server, User, ArrowRight } from "lucide-react";

interface RecentIncidentsTableProps {
  incidents: Incident[];
}

export function RecentIncidentsTable({ incidents }: RecentIncidentsTableProps) {
  return (
    <div className="border-2 border-[var(--border-color)] bg-[var(--bg-surface)] shadow-[4px_4px_0px_var(--border-color)] hover:shadow-[6px_6px_0px_var(--border-color)] transition-all font-mono text-xs flex flex-col justify-between">
      {/* Table Header Bar */}
      <div className="px-5 py-3.5 border-b-2 border-[var(--border-color)] bg-[var(--bg-surface-elevated)] flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-[#2563FF]" />
          <h2 className="font-extrabold text-xs uppercase tracking-wider text-[var(--text-primary)]">
            Correlated High-Priority Incidents
          </h2>
        </div>
        <Link
          href="/incidents"
          className="text-[11px] font-bold text-[#00C8FF] hover:text-[#B7FF3C] flex items-center gap-1 transition-colors uppercase tracking-wider"
        >
          <span>View All ({incidents.length})</span>
          <ArrowRight className="w-3 h-3" />
        </Link>
      </div>

      <div className="divide-y-2 divide-[var(--border-subtle)]">
        {incidents.slice(0, 4).map((inc) => {
          return (
            <div
              key={inc.incident_id}
              className="p-4 bg-[var(--bg-surface)] hover:bg-[var(--bg-surface-elevated)] transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-3 group"
            >
              <div className="flex flex-col gap-1.5 flex-1 max-w-xl">
                <div className="flex items-center gap-2">
                  <Badge
                    variant={
                      inc.severity === "CRITICAL"
                        ? "critical"
                        : inc.severity === "HIGH"
                        ? "warning"
                        : "default"
                    }
                  >
                    {inc.severity}
                  </Badge>
                  <Link
                    href={`/incidents/${inc.incident_id}`}
                    className="font-bold text-[var(--text-primary)] hover:text-[#00C8FF] transition-colors tracking-wider"
                  >
                    {inc.incident_id}
                  </Link>
                  {inc.is_planted_match && (
                    <span className="text-[9px] bg-[#B7FF3C] text-black border border-black px-1.5 py-0.2 font-extrabold shadow-[1px_1px_0px_#000] uppercase tracking-wider">
                      PLANTED BENCHMARK
                    </span>
                  )}
                </div>

                <Link
                  href={`/incidents/${inc.incident_id}`}
                  className="font-bold text-sm text-[var(--text-primary)] group-hover:text-[#00C8FF] transition-colors line-clamp-1"
                >
                  {inc.title}
                </Link>

                <div className="flex flex-wrap items-center gap-3 text-[10px] text-[var(--text-dim)]">
                  <span className="flex items-center gap-1 font-semibold">
                    <Server className="w-3 h-3 text-[#00C8FF]" />
                    {inc.hosts_involved.join(", ")}
                  </span>
                  <span className="flex items-center gap-1 font-semibold">
                    <User className="w-3 h-3 text-[#86D400] dark:text-[#B7FF3C]" />
                    {inc.users_involved.join(", ")}
                  </span>
                  <span>|</span>
                  <span className="font-bold text-[var(--text-muted)]">
                    Confidence: {(inc.confidence * 100).toFixed(0)}%
                  </span>
                </div>
              </div>

              <div className="flex items-center gap-4 shrink-0">
                <div className="text-right hidden md:block">
                  <span className="font-black text-[#00C8FF] block text-base">
                    {inc.steps_count} Steps
                  </span>
                  <span className="text-[10px] text-[var(--text-dim)] font-bold">
                    {inc.detection_count} Detections
                  </span>
                </div>

                <Link
                  href={`/incidents/${inc.incident_id}`}
                  className="inline-flex items-center gap-1 px-3.5 py-1.5 text-xs font-bold border-2 border-[var(--border-color)] text-[var(--text-primary)] bg-[var(--bg-surface)] shadow-[2px_2px_0px_var(--border-color)] hover:shadow-[3px_3px_0px_#00C8FF] hover:border-[#00C8FF] hover:text-[#00C8FF] hover:-translate-x-[1px] hover:-translate-y-[1px] active:translate-x-[1px] active:translate-y-[1px] active:shadow-none transition-all uppercase"
                >
                  <span>Trace Path</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </Link>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
