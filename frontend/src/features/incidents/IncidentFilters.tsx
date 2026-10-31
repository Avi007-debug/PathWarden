"use client";

import React from "react";
import { Search, X } from "lucide-react";

interface IncidentFiltersProps {
  searchQuery: string;
  onSearchChange: (q: string) => void;
  selectedSeverity: string;
  onSeverityChange: (s: string) => void;
  selectedTactic: string;
  onTacticChange: (t: string) => void;
  onClearFilters: () => void;
}

export function IncidentFilters({
  searchQuery,
  onSearchChange,
  selectedSeverity,
  onSeverityChange,
  selectedTactic,
  onTacticChange,
  onClearFilters,
}: IncidentFiltersProps) {
  const hasActiveFilters =
    searchQuery !== "" || selectedSeverity !== "ALL" || selectedTactic !== "ALL";

  return (
    <div className="p-4 border-2 border-[var(--border-color)] bg-[var(--bg-surface)] shadow-[4px_4px_0px_var(--border-color)] hover:shadow-[6px_6px_0px_var(--border-color)] transition-all flex flex-wrap items-center justify-between gap-3 font-mono text-xs select-none">
      {/* Search Input */}
      <div className="relative flex-1 min-w-[240px]">
        <Search className="w-3.5 h-3.5 text-[var(--text-dim)] absolute left-3 top-1/2 -translate-y-1/2" />
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => onSearchChange(e.target.value)}
          placeholder="SEARCH INCIDENT ID, HOST, USER, OR ATT&CK TECHNIQUE..."
          className="w-full bg-[var(--bg-main)] border-2 border-[var(--border-color)] shadow-[2px_2px_0px_var(--border-color)] pl-9 pr-8 py-1.5 text-xs text-[var(--text-primary)] placeholder-[var(--text-dim)] outline-none focus:border-[#00C8FF] focus:shadow-[3px_3px_0px_#00C8FF] transition-all font-mono"
        />
        {searchQuery && (
          <button
            onClick={() => onSearchChange("")}
            className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[var(--text-dim)] hover:text-[#FF334B] cursor-pointer"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        )}
      </div>

      {/* Severity Filter */}
      <div className="flex items-center gap-2">
        <span className="text-[10px] uppercase text-[var(--text-dim)] font-bold">{"// SEVERITY:"}</span>
        <select
          value={selectedSeverity}
          onChange={(e) => onSeverityChange(e.target.value)}
          className="bg-[var(--bg-main)] border-2 border-[var(--border-color)] shadow-[2px_2px_0px_var(--border-color)] px-2.5 py-1.5 text-xs font-bold text-[var(--text-primary)] outline-none cursor-pointer focus:border-[#00C8FF] hover:border-[#00C8FF] transition-all"
        >
          <option value="ALL">ALL SEVERITIES</option>
          <option value="CRITICAL">CRITICAL</option>
          <option value="HIGH">HIGH</option>
          <option value="MEDIUM">MEDIUM</option>
          <option value="LOW">LOW</option>
        </select>
      </div>

      {/* MITRE Tactic Filter */}
      <div className="flex items-center gap-2">
        <span className="text-[10px] uppercase text-[var(--text-dim)] font-bold">{"// TACTIC:"}</span>
        <select
          value={selectedTactic}
          onChange={(e) => onTacticChange(e.target.value)}
          className="bg-[var(--bg-main)] border-2 border-[var(--border-color)] shadow-[2px_2px_0px_var(--border-color)] px-2.5 py-1.5 text-xs font-bold text-[var(--text-primary)] outline-none cursor-pointer focus:border-[#00C8FF] hover:border-[#00C8FF] transition-all"
        >
          <option value="ALL">ALL TACTICS</option>
          <option value="Initial Access">INITIAL ACCESS</option>
          <option value="Execution">EXECUTION</option>
          <option value="Persistence">PERSISTENCE</option>
          <option value="Privilege Escalation">PRIVILEGE ESCALATION</option>
          <option value="Defense Evasion">DEFENSE EVASION</option>
          <option value="Credential Access">CREDENTIAL ACCESS</option>
          <option value="Discovery">DISCOVERY</option>
          <option value="Lateral Movement">LATERAL MOVEMENT</option>
          <option value="Command and Control">COMMAND AND CONTROL</option>
          <option value="Impact">IMPACT</option>
        </select>
      </div>

      {/* Clear Filters */}
      {hasActiveFilters && (
        <button
          onClick={onClearFilters}
          className="flex items-center gap-1 text-[10px] font-bold text-[#FF334B] border-2 border-[#FF334B] px-2.5 py-1 bg-red-500/10 shadow-[2px_2px_0px_#FF334B] hover:shadow-[3px_3px_0px_#FF334B] hover:-translate-x-[1px] hover:-translate-y-[1px] active:translate-x-[1px] active:translate-y-[1px] active:shadow-none transition-all cursor-pointer uppercase"
        >
          <X className="w-3 h-3" />
          <span>RESET FILTERS</span>
        </button>
      )}
    </div>
  );
}
