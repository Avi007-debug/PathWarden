"use client";

import React from "react";
import Link from "next/link";
import { Incident } from "@/lib/api/types";
import { Badge } from "@/components/ui/Badge";
import { formatTimestamp } from "@/lib/utils/formatters";
import { ShieldAlert, Server, User, ArrowRight } from "lucide-react";

interface IncidentTableProps {
  incidents: Incident[];
}

export function IncidentTable({ incidents }: IncidentTableProps) {
  if (incidents.length === 0) {
    return (
      <div className="p-12 border-2 border-[var(--border-color)] bg-[var(--bg-surface)] text-center font-mono shadow-[4px_4px_0px_var(--border-color)] select-none">
        <ShieldAlert className="w-8 h-8 text-[var(--text-dim)] mx-auto mb-3" />
        <h4 className="text-sm font-black text-[var(--text-primary)] uppercase">No Matching Incidents Found</h4>
        <p className="text-xs text-[var(--text-muted)] mt-1 font-medium">
          Adjust search criteria or filter thresholds to inspect available correlated events.
        </p>
      </div>
    );
  }

  return (
    <div className="border-2 border-[var(--border-color)] bg-[var(--bg-surface)] shadow-[4px_4px_0px_var(--border-color)] hover:shadow-[6px_6px_0px_var(--border-color)] transition-all overflow-hidden font-mono text-xs select-none">
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b-2 border-[var(--border-color)] bg-[var(--bg-surface-elevated)] text-[10px] uppercase text-[var(--text-dim)] tracking-wider font-extrabold">
              <th className="py-3 px-4">Severity / Incident</th>
              <th className="py-3 px-4 text-center">Risk (B-1)</th>
              <th className="py-3 px-4">Attack Summary & Narrative (B-2)</th>
              <th className="py-3 px-4">Hosts & Entities</th>
              <th className="py-3 px-4 text-center">Steps</th>
              <th className="py-3 px-4 text-center">Confidence</th>
              <th className="py-3 px-4">Time Window</th>
              <th className="py-3 px-4 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y-2 divide-[var(--border-subtle)]">
            {incidents.map((incident, index) => {
              const risk = incident.risk_score ?? 75;
              return (
                <tr
                  key={incident.incident_id}
                  className="hover:bg-[var(--bg-surface-elevated)] transition-colors group"
                >
                  {/* Severity & ID */}
                  <td className="py-3.5 px-4 align-top">
                    <div className="flex flex-col gap-1.5">
                      <div className="flex items-center gap-2">
                        <Badge
                          variant={
                            incident.severity === "CRITICAL"
                              ? "critical"
                              : incident.severity === "HIGH"
                              ? "warning"
                              : "default"
                          }
                        >
                          {incident.severity}
                        </Badge>
                        {incident.is_planted_match && (
                          <span className="text-[9px] bg-[#B7FF3C] text-black border border-black px-1.5 py-0.2 font-extrabold shadow-[1px_1px_0px_#000] uppercase tracking-wider">
                            PLANTED
                          </span>
                        )}
                      </div>
                      <Link
                        href={`/incidents/${incident.incident_id}`}
                        className="font-bold text-[var(--text-primary)] hover:text-[#00C8FF] transition-colors tracking-wider"
                      >
                        {incident.incident_id}
                      </Link>
                    </div>
                  </td>

                  {/* Bonus B-1: Risk Score (0-100) */}
                  <td className="py-3.5 px-4 text-center align-top">
                    <div className="flex flex-col items-center">
                      <span
                        className={`text-xs px-2 py-0.5 font-black border shadow-[1px_1px_0px_#000] ${
                          risk >= 85
                            ? "bg-red-500/20 text-red-400 border-red-500"
                            : risk >= 65
                            ? "bg-amber-500/20 text-amber-400 border-amber-500"
                            : "bg-blue-500/20 text-blue-400 border-blue-500"
                        }`}
                      >
                        {risk}/100
                      </span>
                      {index === 0 && (
                        <span className="text-[8px] bg-red-500 text-white font-extrabold px-1 mt-1 rounded uppercase tracking-wider">
                          Top Risk
                        </span>
                      )}
                    </div>
                  </td>

                  {/* Summary & Plain English Report (Bonus B-2) */}
                  <td className="py-3.5 px-4 max-w-md align-top">
                    <div className="flex flex-col gap-1.5">
                      <Link
                        href={`/incidents/${incident.incident_id}`}
                        className="font-bold text-sm text-[var(--text-primary)] hover:text-[#00C8FF] transition-colors line-clamp-1"
                      >
                        {incident.title}
                      </Link>
                      <p className="text-[11px] text-[var(--text-muted)] line-clamp-2 leading-relaxed font-medium">
                        {incident.summary}
                      </p>
                      {incident.plain_english_report && (
                        <div className="p-1.5 bg-[var(--bg-surface-elevated)] border border-[var(--border-color)] text-[10px] text-[var(--text-dim)] italic line-clamp-2">
                          <span className="font-bold not-italic text-[#00C8FF]">Auto Report: </span>
                          {incident.plain_english_report}
                        </div>
                      )}
                      <div className="flex flex-wrap gap-1.5 mt-1">
                        {incident.tactics.slice(0, 4).map((t) => (
                          <span
                            key={t}
                            className="text-[9px] px-1.5 py-0.5 bg-[var(--bg-surface-elevated)] border border-[var(--border-color)] text-[var(--text-muted)] font-bold uppercase tracking-wider shadow-[1px_1px_0px_var(--border-color)]"
                          >
                            {t}
                          </span>
                        ))}
                        {incident.tactics.length > 4 && (
                          <span className="text-[9px] text-[var(--text-dim)] font-bold self-center">
                            +{incident.tactics.length - 4} MORE
                          </span>
                        )}
                      </div>
                    </div>
                  </td>

                  {/* Hosts & Users */}
                  <td className="py-3.5 px-4 align-top">
                    <div className="flex flex-col gap-1 text-[11px]">
                      <div className="flex items-center gap-1.5 text-[var(--text-primary)] font-bold">
                        <Server className="w-3.5 h-3.5 text-[#00C8FF] shrink-0" />
                        <span className="truncate max-w-[140px]" title={incident.hosts_involved.join(", ")}>
                          {incident.hosts_involved.join(", ")}
                        </span>
                      </div>
                      <div className="flex items-center gap-1.5 text-[var(--text-muted)] font-semibold">
                        <User className="w-3.5 h-3.5 text-[#86D400] dark:text-[#B7FF3C] shrink-0" />
                        <span className="truncate max-w-[140px]" title={incident.users_involved.join(", ")}>
                          {incident.users_involved.join(", ")}
                        </span>
                      </div>
                    </div>
                  </td>

                  {/* Steps */}
                  <td className="py-3.5 px-4 text-center align-top font-black text-sm text-[#00C8FF]">
                    {incident.steps_count}
                  </td>

                  {/* Confidence */}
                  <td className="py-3.5 px-4 text-center align-top font-black text-sm text-[#86D400] dark:text-[#B7FF3C]">
                    {(incident.confidence * 100).toFixed(0)}%
                  </td>

                  {/* Time Window */}
                  <td className="py-3.5 px-4 align-top text-[11px] text-[var(--text-muted)] font-medium">
                    <div>{formatTimestamp(incident.first_seen)}</div>
                    <div className="text-[var(--text-dim)]">TO {formatTimestamp(incident.last_seen)}</div>
                  </td>

                  {/* Action Link */}
                  <td className="py-3.5 px-4 text-right align-top">
                    <Link
                      href={`/incidents/${incident.incident_id}`}
                      className="inline-flex items-center gap-1 px-3 py-1.5 text-[11px] font-bold border-2 border-[var(--border-color)] text-[var(--text-primary)] bg-[var(--bg-surface)] shadow-[2px_2px_0px_var(--border-color)] hover:shadow-[3px_3px_0px_#00C8FF] hover:border-[#00C8FF] hover:text-[#00C8FF] hover:-translate-x-[1px] hover:-translate-y-[1px] active:translate-x-[1px] active:translate-y-[1px] active:shadow-none transition-all uppercase"
                    >
                      <span>Investigate</span>
                      <ArrowRight className="w-3 h-3" />
                    </Link>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
