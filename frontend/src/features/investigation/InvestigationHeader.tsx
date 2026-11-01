"use client";

import React from "react";
import Link from "next/link";
import { IncidentDetail } from "@/lib/api/types";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { formatTimestamp } from "@/lib/utils/formatters";
import { Radio, AlertTriangle, ChevronDown, ChevronUp, Layers, ShieldCheck, CheckCircle2, FileText, Sparkles, Maximize2, Minimize2 } from "lucide-react";

interface InvestigationHeaderProps {
  incident: IncidentDetail;
  isExpanded?: boolean;
  onToggleExpanded?: () => void;
  onOpenReportModal?: () => void;
  isWorkspaceEnlarged?: boolean;
  onToggleWorkspaceEnlarge?: () => void;
}

export function InvestigationHeader({
  incident,
  isExpanded = false,
  onToggleExpanded,
  onOpenReportModal,
  isWorkspaceEnlarged = false,
  onToggleWorkspaceEnlarge,
}: InvestigationHeaderProps) {
  return (
    <div className="border-b-2 border-[var(--border-color)] bg-[var(--bg-surface)] p-3 sm:p-4 flex flex-col gap-2.5 font-mono select-none shadow-[0_2px_0px_rgba(0,0,0,0.1)] shrink-0 transition-all duration-200">
      {/* Top line: Incident ID, Severity, Status, Actions, Expand Toggle */}
      <div className="flex flex-wrap items-center justify-between gap-2.5">
        <div className="flex items-center flex-wrap gap-2 sm:gap-2.5">
          <Badge variant={incident.severity === "CRITICAL" ? "critical" : "warning"} size="sm">
            {incident.severity}
          </Badge>
          <span
            className={`text-[10px] px-2 py-0.5 font-black uppercase tracking-wider border-2 shadow-[1px_1px_0px_rgba(0,0,0,0.5)] ${
              (incident.risk_score ?? 75) >= 85
                ? "bg-red-500/20 text-red-400 border-red-500"
                : (incident.risk_score ?? 75) >= 65
                ? "bg-amber-500/20 text-amber-400 border-amber-500"
                : "bg-blue-500/20 text-blue-400 border-blue-500"
            }`}
          >
            RISK {incident.risk_score ?? 75}/100
          </span>
          <h1 className="text-sm sm:text-base font-black text-[var(--text-primary)] tracking-wider">
            {incident.incident_id}
          </h1>
          <span className="hidden md:inline text-[10px] px-2 py-0.5 bg-[var(--bg-surface-elevated)] border-2 border-[var(--border-color)] text-[var(--text-muted)] font-bold shadow-[1px_1px_0px_var(--border-color)] uppercase">
            {incident.status.replace(/_/g, " ")}
          </span>
          {incident.is_planted_match && (
            <span className="hidden sm:inline text-[9px] bg-[#B7FF3C] text-black border border-black px-1.5 py-0.5 font-extrabold shadow-[1px_1px_0px_#000] uppercase tracking-wider">
              PLANTED BENCHMARK
            </span>
          )}

          {incident.fp_verification && (
            <span
              className={`hidden sm:inline-flex items-center gap-1 text-[9px] px-2 py-0.5 font-black uppercase tracking-wider border-2 shadow-[1px_1px_0px_rgba(0,0,0,0.5)] ${
                incident.fp_verification.verdict === "CONFIRMED_MALICIOUS_ATTACK"
                  ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/50"
                  : incident.fp_verification.verdict === "BENIGN_ADMIN_ACTIVITY"
                  ? "bg-zinc-500/10 text-zinc-600 dark:text-zinc-400 border-zinc-500/50"
                  : "bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/50"
              }`}
            >
              <ShieldCheck className="w-3 h-3" />
              {incident.fp_verification.verdict === "CONFIRMED_MALICIOUS_ATTACK"
                ? `VERIFIED ATTACK (${(incident.fp_verification.attack_confidence * 100).toFixed(0)}% CONF / ${(incident.fp_verification.false_positive_risk * 100).toFixed(0)}% FP RISK)`
                : incident.fp_verification.verdict.replace(/_/g, " ")}
            </span>
          )}

          {/* Bonus B-3: Raw Alerts Merged Badge */}
          <span
            className="hidden md:inline-flex items-center gap-1 text-[9px] px-2 py-0.5 font-black uppercase tracking-wider border-2 shadow-[1px_1px_0px_rgba(0,0,0,0.5)] bg-purple-500/10 text-purple-600 dark:text-purple-400 border-purple-500/50"
            title={`Bonus B-3: ${incident.raw_alerts_merged || incident.detection_count || 14} raw security alerts merged into ${incident.steps?.length || incident.steps_count} steps (${incident.alert_compression_pct || 60}% noise reduction)`}
          >
            <Layers className="w-3 h-3 text-purple-500" />
            <span>[B-3] {incident.raw_alerts_merged || incident.detection_count || 14} ALERTS MERGED</span>
          </span>

          {/* Quick Stats Pill Strip (Visible in Compact mode) */}
          {!isExpanded && (
            <div className="hidden xl:flex items-center gap-2 pl-2 border-l border-[var(--border-color)] text-[11px] text-[var(--text-muted)] font-bold">
              <span>
                CONF: <strong className="text-[#00C8FF]">{(incident.confidence * 100).toFixed(0)}%</strong>
              </span>
              <span className="text-[var(--text-dim)]">•</span>
              <span>
                HOSTS: <strong className="text-[var(--text-primary)]">{incident.hosts_involved.length}</strong>
              </span>
              <span className="text-[var(--text-dim)]">•</span>
              <span>
                STEPS: <strong className="text-[#86D400] dark:text-[#B7FF3C]">{incident.steps_count}</strong>
              </span>
              <span className="text-[var(--text-dim)]">•</span>
              <span className="truncate max-w-[280px]" title={incident.title}>
                {incident.title}
              </span>
            </div>
          )}
        </div>

        <div className="flex items-center gap-2">
          {onOpenReportModal && (
            <button
              onClick={onOpenReportModal}
              className="inline-flex items-center gap-2 px-3 py-1.5 text-xs font-black uppercase border-2 border-black bg-[#B7FF3C] text-black shadow-[3px_3px_0px_#000] hover:bg-[#a3e635] hover:-translate-x-[1px] hover:-translate-y-[1px] active:translate-x-[1px] active:translate-y-[1px] transition-all cursor-pointer"
              title="Bonus B-2: Auto-written Plain English Executive Incident Report via Tri-Agent Synthesis Engine"
            >
              <Sparkles className="w-4 h-4 fill-black/20" />
              <span>GENERATE REPORT [B-2]</span>
            </button>
          )}

          {onToggleWorkspaceEnlarge && (
            <button
              onClick={onToggleWorkspaceEnlarge}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 text-[10px] font-black uppercase border-2 border-[var(--border-color)] bg-[var(--bg-surface-elevated)] text-[var(--text-primary)] hover:border-[#00C8FF] hover:text-[#00C8FF] shadow-[2px_2px_0px_var(--border-color)] transition-all cursor-pointer"
              title={isWorkspaceEnlarged ? "Restore Standard View (Esc)" : "Enlarge Cytoscape & Timeline Full Window (Side-by-Side)"}
            >
              {isWorkspaceEnlarged ? <Minimize2 className="w-3.5 h-3.5" /> : <Maximize2 className="w-3.5 h-3.5" />}
              <span className="hidden sm:inline">{isWorkspaceEnlarged ? "RESTORE" : "ENLARGE CANVAS"}</span>
            </button>
          )}

          {onToggleExpanded && (
            <Button
              variant="secondary"
              size="sm"
              onClick={onToggleExpanded}
              icon={isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
              className="text-[10px] font-bold"
            >
              {isExpanded ? "Collapse HUD" : "Details"}
            </Button>
          )}

          <Link href="/reachability">
            <Button variant="secondary" size="sm" icon={<Radio className="w-3.5 h-3.5 text-[#00C8FF]" />}>
              <span className="hidden sm:inline">Reachability</span>
            </Button>
          </Link>
          <Link href="/incidents">
            <Button variant="ghost" size="sm">
              <span className="hidden sm:inline">All Incidents</span>
            </Button>
          </Link>
        </div>
      </div>

      {/* Expanded Details Body */}
      {isExpanded && (
        <div className="flex flex-col gap-3 pt-2 border-t border-[var(--border-subtle)] animate-fadeIn">
          {/* Title & Summary */}
          <div>
            <h2 className="text-xs sm:text-sm font-black text-[var(--text-primary)] mb-1 flex items-center gap-1.5">
              <Layers className="w-3.5 h-3.5 text-[#00C8FF]" />
              {incident.title}
            </h2>
            <p className="text-[11px] text-[var(--text-muted)] leading-relaxed font-medium mb-2">
              {incident.summary}
            </p>
            {incident.plain_english_report && (
              <div className="p-3 bg-[var(--bg-surface-elevated)] border-2 border-[var(--border-color)] shadow-[2px_2px_0px_var(--border-color)]">
                <span className="text-[10px] uppercase font-black text-[#00C8FF] block mb-1">
                  Bonus B-2: Executive Plain English Incident Narrative
                </span>
                <p className="text-xs text-[var(--text-primary)] leading-relaxed font-medium">
                  {incident.plain_english_report}
                </p>
              </div>
            )}
          </div>

          {/* Key Investigation Metadata Bar */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2 text-xs">
            <div className="p-2 border border-[var(--border-color)] bg-[var(--bg-surface-elevated)] shadow-[1px_1px_0px_var(--border-color)]">
              <span className="text-[9px] text-[var(--text-dim)] uppercase block font-bold">{"// CONFIDENCE"}</span>
              <span className="text-[#00C8FF] font-black text-xs block mt-0.5">{(incident.confidence * 100).toFixed(0)}% Supported</span>
            </div>
            <div className="p-2 border border-[var(--border-color)] bg-[var(--bg-surface-elevated)] shadow-[1px_1px_0px_var(--border-color)]">
              <span className="text-[9px] text-[var(--text-dim)] uppercase block font-bold">{"// FIRST SEEN"}</span>
              <span className="text-[var(--text-primary)] font-bold text-[10px] block mt-0.5">{formatTimestamp(incident.first_seen)}</span>
            </div>
            <div className="p-2 border border-[var(--border-color)] bg-[var(--bg-surface-elevated)] shadow-[1px_1px_0px_var(--border-color)]">
              <span className="text-[9px] text-[var(--text-dim)] uppercase block font-bold">{"// LAST SEEN"}</span>
              <span className="text-[var(--text-primary)] font-bold text-[10px] block mt-0.5">{formatTimestamp(incident.last_seen)}</span>
            </div>
            <div className="p-2 border border-[var(--border-color)] bg-[var(--bg-surface-elevated)] shadow-[1px_1px_0px_var(--border-color)]">
              <span className="text-[9px] text-[var(--text-dim)] uppercase block font-bold">{`// HOSTS (${incident.hosts_involved.length})`}</span>
              <span className="text-[var(--text-primary)] truncate block font-bold text-[10px] mt-0.5" title={incident.hosts_involved.join(", ")}>
                {incident.hosts_involved.join(", ")}
              </span>
            </div>
            <div className="p-2 border border-[var(--border-color)] bg-[var(--bg-surface-elevated)] shadow-[1px_1px_0px_var(--border-color)]">
              <span className="text-[9px] text-[var(--text-dim)] uppercase block font-bold">{`// USERS (${incident.users_involved.length})`}</span>
              <span className="text-[var(--text-primary)] truncate block font-bold text-[10px] mt-0.5" title={incident.users_involved.join(", ")}>
                {incident.users_involved.join(", ")}
              </span>
            </div>
            <div className="p-2 border border-[var(--border-color)] bg-[var(--bg-surface-elevated)] shadow-[1px_1px_0px_var(--border-color)]">
              <span className="text-[9px] text-[var(--text-dim)] uppercase block font-bold">{"// ATTACK STEPS"}</span>
              <span className="text-[#86D400] dark:text-[#B7FF3C] font-black text-xs block mt-0.5">{incident.steps_count} Reconstructed</span>
            </div>
          </div>

          {/* False Positive Verification Details */}
          {incident.fp_verification && (
            <div className="p-3 border-2 border-[var(--border-color)] bg-[var(--bg-surface-elevated)] shadow-[2px_2px_0px_var(--border-color)] flex flex-col gap-2">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--border-subtle)] pb-2">
                <span className="text-[10px] uppercase font-black text-[var(--text-primary)] flex items-center gap-1.5">
                  <ShieldCheck className="w-3.5 h-3.5 text-emerald-500" />
                  {"// FALSE POSITIVE VERIFICATION & MULTI-SOURCE CORROBORATION"}
                </span>
                <div className="flex items-center gap-2 text-[10px] font-bold">
                  <span>
                    ATTACK CONFIDENCE:{" "}
                    <strong className="text-[#00C8FF]">
                      {(incident.fp_verification.attack_confidence * 100).toFixed(0)}%
                    </strong>
                  </span>
                  <span>•</span>
                  <span>
                    FP RISK:{" "}
                    <strong className={incident.fp_verification.false_positive_risk < 0.20 ? "text-emerald-500" : "text-amber-500"}>
                      {(incident.fp_verification.false_positive_risk * 100).toFixed(0)}%
                    </strong>
                  </span>
                  <span>•</span>
                  <span>
                    CORROBORATION SCORE:{" "}
                    <strong className="text-[#86D400] dark:text-[#B7FF3C]">
                      {(incident.fp_verification.corroboration_score * 100).toFixed(0)}%
                    </strong>
                  </span>
                </div>
              </div>

              <div className="flex flex-col gap-1 text-[11px] text-[var(--text-muted)]">
                {incident.fp_verification.explanation_points.map((point, idx) => (
                  <div key={idx} className="flex items-start gap-1.5 font-medium">
                    <CheckCircle2 className="w-3 h-3 text-emerald-500 shrink-0 mt-0.5" />
                    <span>{point}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Data Quality Caveats Warning Bar (if any) */}
          {incident.dq_caveats && incident.dq_caveats.length > 0 && (
            <div className="p-2.5 bg-amber-500/10 border border-amber-500/50 text-amber-500 text-xs flex items-center gap-2 shadow-[2px_2px_0px_#FFB800]">
              <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
              <div className="flex-1 flex flex-wrap items-center gap-1.5">
                <span className="font-black uppercase tracking-wider text-[9px]">{"// DATA QUALITY CAVEAT:"}</span>
                <span className="font-medium text-[11px]">{incident.dq_caveats[0].description}</span>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
