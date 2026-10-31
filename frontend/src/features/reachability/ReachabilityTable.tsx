"use client";

import React from "react";
import { ReachabilityItem } from "@/lib/api/types";
import { getReachabilityStyle } from "@/lib/utils/formatters";
import { Server, Database, Shield, FileSearch } from "lucide-react";

interface ReachabilityTableProps {
  items: ReachabilityItem[];
  onInspectEvidence: (evidenceUids: string[]) => void;
}

export function ReachabilityTable({ items, onInspectEvidence }: ReachabilityTableProps) {
  return (
    <div className="border-2 border-[var(--border-color)] bg-[var(--bg-surface)] shadow-[4px_4px_0px_var(--border-color)] hover:shadow-[6px_6px_0px_var(--border-color)] transition-all overflow-hidden font-mono text-xs select-none">
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b-2 border-[var(--border-color)] bg-[var(--bg-surface-elevated)] text-[10px] uppercase text-[var(--text-dim)] tracking-wider font-black">
              <th className="py-3.5 px-4">Relationship Category</th>
              <th className="py-3.5 px-4">Source Entity</th>
              <th className="py-3.5 px-4">Target System</th>
              <th className="py-3.5 px-4 text-center">Hops</th>
              <th className="py-3.5 px-4">Rationale & Justification</th>
              <th className="py-3.5 px-4">Assumptions / Missing Data</th>
              <th className="py-3.5 px-4 text-right">Evidence</th>
            </tr>
          </thead>
          <tbody className="divide-y-2 divide-[var(--border-subtle)]">
            {items.map((item) => {
              const style = getReachabilityStyle(item.relationship_type);

              return (
                <tr key={item.id} className="hover:bg-[var(--bg-surface-elevated)] transition-colors">
                  {/* Category Badge */}
                  <td className="py-3.5 px-4 align-top">
                    <span
                      className={`inline-block px-2 py-0.5 border-2 text-[10px] font-black tracking-wider uppercase shadow-[1px_1px_0px_var(--border-color)] ${style.badge}`}
                    >
                      {item.relationship_type.replace(/_/g, " ")}
                    </span>
                  </td>

                  {/* Source */}
                  <td className="py-3.5 px-4 align-top">
                    <div className="flex items-center gap-1.5 font-bold text-[var(--text-primary)]">
                      <Server className="w-3.5 h-3.5 text-[#00C8FF]" />
                      <span>{item.source_entity}</span>
                    </div>
                  </td>

                  {/* Target & Target Type */}
                  <td className="py-3.5 px-4 align-top">
                    <div className="flex flex-col gap-0.5">
                      <div className="flex items-center gap-1.5 font-bold text-[var(--text-primary)]">
                        {item.target_type === "DATABASE" ? (
                          <Database className="w-3.5 h-3.5 text-amber-500" />
                        ) : item.target_type === "DOMAIN_CONTROLLER" ? (
                          <Shield className="w-3.5 h-3.5 text-red-500" />
                        ) : (
                          <Server className="w-3.5 h-3.5 text-[#86D400] dark:text-[#B7FF3C]" />
                        )}
                        <span>{item.target_entity}</span>
                      </div>
                      <span className="text-[10px] text-[var(--text-dim)] uppercase font-bold">
                        [{item.target_type.replace(/_/g, " ")}]
                      </span>
                    </div>
                  </td>

                  {/* Hops */}
                  <td className="py-3.5 px-4 text-center align-top font-black text-sm text-[#00C8FF]">
                    {item.hops} {item.hops === 1 ? "Hop" : "Hops"}
                  </td>

                  {/* Rationale */}
                  <td className="py-3.5 px-4 align-top max-w-sm">
                    <p className="text-[11px] text-[var(--text-muted)] leading-relaxed font-medium">
                      {item.rationale}
                    </p>
                    {item.privilege_level && (
                      <div className="mt-1 text-[10px] text-[var(--text-dim)] font-bold">
                        PRIVILEGE: <span className="text-[var(--text-primary)]">{item.privilege_level}</span>
                      </div>
                    )}
                  </td>

                  {/* Assumptions */}
                  <td className="py-3.5 px-4 align-top max-w-xs">
                    {item.assumptions && item.assumptions.length > 0 ? (
                      <ul className="list-disc list-inside text-[10px] text-amber-500 font-semibold leading-tight flex flex-col gap-1">
                        {item.assumptions.map((asm, idx) => (
                          <li key={idx}>{asm}</li>
                        ))}
                      </ul>
                    ) : (
                      <span className="text-[10px] text-[var(--text-dim)] font-semibold">None (Observed in logs)</span>
                    )}
                  </td>

                  {/* Evidence inspect */}
                  <td className="py-3.5 px-4 text-right align-top">
                    {item.evidence_event_uids && item.evidence_event_uids.length > 0 ? (
                      <button
                        onClick={() => onInspectEvidence(item.evidence_event_uids)}
                        className="inline-flex items-center gap-1 px-3 py-1 text-[11px] font-bold border-2 border-[var(--border-color)] text-[var(--text-primary)] bg-[var(--bg-surface)] shadow-[2px_2px_0px_var(--border-color)] hover:shadow-[3px_3px_0px_#00C8FF] hover:border-[#00C8FF] hover:text-[#00C8FF] hover:-translate-x-[1px] hover:-translate-y-[1px] active:translate-x-[1px] active:translate-y-[1px] active:shadow-none transition-all uppercase cursor-pointer"
                      >
                        <FileSearch className="w-3 h-3" />
                        <span>Inspect ({item.evidence_event_uids.length})</span>
                      </button>
                    ) : (
                      <span className="text-[10px] text-[var(--text-dim)] font-bold">N/A</span>
                    )}
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
