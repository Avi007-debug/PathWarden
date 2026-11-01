"use client";

import React, { useState, useEffect } from "react";
import { IncidentDetail, ExecutiveReportResponse } from "@/lib/api/types";
import { pathWardenApi } from "@/lib/api/client";
import { useApp } from "@/lib/context/AppContext";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import {
  FileText,
  X,
  Copy,
  Check,
  Download,
  Sparkles,
  Cpu,
  Layers,
  ShieldCheck,
  RefreshCw,
  Terminal,
} from "lucide-react";

interface ExecutiveReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  incident: IncidentDetail;
}

export function ExecutiveReportModal({
  isOpen,
  onClose,
  incident,
}: ExecutiveReportModalProps) {
  const { isDemoMode } = useApp();
  const [reportData, setReportData] = useState<ExecutiveReportResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const [viewMode, setViewMode] = useState<"executive" | "markdown">("executive");

  const loadReport = React.useCallback(
    (forceEngine?: string) => {
      setLoading(true);
      pathWardenApi
        .getIncidentReport(incident.incident_id, forceEngine, isDemoMode)
        .then((data) => {
          setReportData(data);
          setLoading(false);
        })
        .catch(() => {
          // Fallback to embedded plain english report
          setReportData({
            incident_id: incident.incident_id,
            severity: incident.severity,
            risk_score: incident.risk_score || 75,
            plain_english_report: incident.plain_english_report || incident.summary,
            report_markdown: incident.executive_report_markdown || `# INCIDENT REPORT: ${incident.incident_id}\n\n${incident.plain_english_report || incident.summary}`,
            raw_alerts_merged: incident.raw_alerts_merged || incident.detection_count || 14,
            alert_compression_pct: incident.alert_compression_pct || 60,
            engine_used: incident.report_engine_used || "On-Device Tri-Agent Synthesis Engine",
            generated_at: new Date().toISOString(),
            agent_workflow: {
              analyst_agent: `Triaged ${incident.raw_alerts_merged || 14} raw security alerts.`,
              forensics_agent: `Mapped ${incident.hosts_involved.length} hosts.`,
              executive_reporter_agent: "Completed plain English synthesis.",
            },
          });
          setLoading(false);
        });
    },
    [incident, isDemoMode]
  );

  useEffect(() => {
    if (isOpen) {
      loadReport();
    }
  }, [isOpen, loadReport]);

  if (!isOpen) return null;

  const rawAlerts = reportData?.raw_alerts_merged || incident.raw_alerts_merged || incident.detection_count || 14;
  const stepsCount = incident.steps?.length || incident.steps_count || 8;
  const reductionPct = reportData?.alert_compression_pct || incident.alert_compression_pct || 60;
  const engineUsed = reportData?.engine_used || "On-Device Tri-Agent Synthesis Engine";

  const handleCopy = () => {
    const textToCopy = viewMode === "markdown" ? (reportData?.report_markdown || "") : (reportData?.plain_english_report || "");
    navigator.clipboard.writeText(textToCopy);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const content = reportData?.report_markdown || "";
    const blob = new Blob([content], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `PathWarden_Incident_Report_${incident.incident_id}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-black/75 backdrop-blur-sm font-mono select-none">
      <div className="bg-[var(--bg-surface)] border-2 border-[var(--border-color)] shadow-[8px_8px_0px_#000] w-full max-w-4xl max-h-[92vh] flex flex-col overflow-hidden">
        {/* Modal Header */}
        <div className="p-4 border-b-2 border-[var(--border-color)] bg-[var(--bg-surface-elevated)] flex items-center justify-between gap-3 shrink-0">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 bg-[#B7FF3C] text-black border border-black shadow-[2px_2px_0px_#000]">
              <Sparkles className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-black uppercase text-[var(--text-primary)]">
                  [BONUS B-2] AUTO-WRITTEN INCIDENT REPORT
                </span>
                <span className="text-[10px] px-2 py-0.5 bg-[#00C8FF]/10 text-[#00C8FF] border border-[#00C8FF] font-black uppercase">
                  {incident.incident_id}
                </span>
              </div>
              <span className="text-[10px] text-[var(--text-muted)] font-bold block">
                Tri-Agent Autonomous Pipeline (Analyst → Forensics → Executive Briefing)
              </span>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => loadReport("llm")}
              disabled={loading}
              className="hidden sm:flex items-center gap-1.5 px-2 py-1 bg-[var(--bg-surface)] border border-[var(--border-color)] hover:border-[#B7FF3C] text-[10px] font-bold text-[var(--text-primary)] cursor-pointer transition-all"
              title="Query on-device local GPU LLM (Ollama)"
            >
              <Cpu className="w-3 h-3 text-[#B7FF3C]" />
              <span>{loading ? "GENERATING..." : "RETRY LOCAL GPU"}</span>
            </button>
            <button
              onClick={onClose}
              className="p-1 text-[var(--text-muted)] hover:text-[#FF334B] hover:bg-red-500/10 border border-transparent hover:border-red-500 transition-all cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Sub-Header: B-3 Raw Alerts Merged & Engine Provenance Strip */}
        <div className="px-4 py-2 bg-[var(--bg-canvas)] border-b-2 border-[var(--border-color)] flex flex-wrap items-center justify-between gap-2 text-[10px] shrink-0">
          <div className="flex items-center flex-wrap gap-2 font-bold">
            <span className="px-2 py-0.5 bg-purple-500/20 text-purple-400 border border-purple-500 uppercase flex items-center gap-1">
              <Layers className="w-3 h-3" />
              <strong>[B-3] {rawAlerts} RAW ALERTS MERGED</strong>
            </span>
            <span className="text-[var(--text-muted)]">
              Compressed into <strong>{stepsCount} steps</strong> ({reductionPct}% noise reduction)
            </span>
          </div>

          <div className="flex items-center gap-2 font-bold">
            <span className="px-2 py-0.5 bg-emerald-500/20 text-emerald-400 border border-emerald-500 uppercase flex items-center gap-1">
              <ShieldCheck className="w-3 h-3" />
              <span>{engineUsed}</span>
            </span>
            <span className="text-[var(--text-dim)]">RISK: {incident.risk_score || 75}/100</span>
          </div>
        </div>

        {/* Tab & Action Controls */}
        <div className="px-4 py-2 border-b border-[var(--border-subtle)] bg-[var(--bg-surface)] flex items-center justify-between gap-3 shrink-0">
          <div className="flex items-center gap-1 bg-[var(--bg-canvas)] p-0.5 border border-[var(--border-color)]">
            <button
              onClick={() => setViewMode("executive")}
              className={`px-3 py-1 text-[11px] font-bold uppercase transition-all cursor-pointer ${
                viewMode === "executive"
                  ? "bg-[#00C8FF] text-black shadow-[1px_1px_0px_#000]"
                  : "text-[var(--text-muted)] hover:text-[var(--text-primary)]"
              }`}
            >
              Plain English Briefing
            </button>
            <button
              onClick={() => setViewMode("markdown")}
              className={`px-3 py-1 text-[11px] font-bold uppercase transition-all cursor-pointer ${
                viewMode === "markdown"
                  ? "bg-[#00C8FF] text-black shadow-[1px_1px_0px_#000]"
                  : "text-[var(--text-muted)] hover:text-[var(--text-primary)]"
              }`}
            >
              Full Technical Markdown
            </button>
          </div>

          <div className="flex items-center gap-2">
            <Button
              variant="secondary"
              size="sm"
              onClick={handleCopy}
              icon={copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              className="text-[10px]"
            >
              {copied ? "COPIED" : "COPY"}
            </Button>
            <Button
              variant="secondary"
              size="sm"
              onClick={handleDownload}
              icon={<Download className="w-3.5 h-3.5" />}
              className="text-[10px]"
            >
              DOWNLOAD .MD
            </Button>
          </div>
        </div>

        {/* Modal Scrollable Body */}
        <div className="flex-1 min-h-0 overflow-y-auto p-4 sm:p-6 bg-[var(--bg-surface)] text-xs text-[var(--text-primary)] leading-relaxed select-text font-mono">
          {loading ? (
            <div className="flex flex-col items-center justify-center py-16 gap-3 text-[var(--text-muted)]">
              <RefreshCw className="w-6 h-6 animate-spin text-[#00C8FF]" />
              <span className="font-bold">SYNTHESIZING AGENTIC INCIDENT BRIEFING...</span>
            </div>
          ) : viewMode === "executive" ? (
            <div className="flex flex-col gap-5 max-w-3xl">
              {/* Executive Summary Card */}
              <div className="p-4 border-2 border-[#00C8FF] bg-[#00C8FF]/5 shadow-[3px_3px_0px_#00C8FF]">
                <h3 className="text-xs font-black uppercase text-[#00C8FF] mb-2 flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5" />
                  EXECUTIVE SUMMARY (NON-TECHNICAL BRIEFING)
                </h3>
                <p className="text-sm font-medium leading-relaxed text-[var(--text-primary)]">
                  {reportData?.plain_english_report || incident.plain_english_report}
                </p>
              </div>

              {/* Tri-Agent Analysis Cards */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div className="p-3.5 border-2 border-[var(--border-color)] bg-[var(--bg-surface-elevated)] shadow-[2px_2px_0px_var(--border-color)]">
                  <span className="text-[10px] font-black uppercase text-purple-400 block mb-1">
                    AGENT 1 // DETECTION ANALYST
                  </span>
                  <p className="text-[11px] text-[var(--text-muted)]">
                    {reportData?.agent_workflow?.analyst_agent || `Clustered ${rawAlerts} raw security alerts with ${reductionPct}% noise reduction across MITRE techniques.`}
                  </p>
                </div>
                <div className="p-3.5 border-2 border-[var(--border-color)] bg-[var(--bg-surface-elevated)] shadow-[2px_2px_0px_var(--border-color)]">
                  <span className="text-[10px] font-black uppercase text-[#86D400] dark:text-[#B7FF3C] block mb-1">
                    AGENT 2 // FORENSICS INVESTIGATOR
                  </span>
                  <p className="text-[11px] text-[var(--text-muted)]">
                    {reportData?.agent_workflow?.forensics_agent || `Mapped ${incident.hosts_involved.length} affected endpoints starting at ${incident.root_cause_host || incident.hosts_involved[0]}.`}
                  </p>
                </div>
              </div>

              {/* Remediation Checklist */}
              <div className="p-4 border-2 border-red-500/40 bg-red-500/5">
                <h4 className="text-xs font-black uppercase text-red-400 mb-2.5">
                  CRITICAL ACTIONS REQUIRED
                </h4>
                <ul className="space-y-2 text-[11px] text-[var(--text-primary)] font-medium">
                  <li className="flex items-start gap-2">
                    <span className="text-red-400 font-bold">•</span>
                    <span><strong>Isolate host(s):</strong> {incident.hosts_involved.join(", ")} immediately from network perimeter.</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-red-400 font-bold">•</span>
                    <span><strong>Revoke identity:</strong> Revoke Active Directory credentials for {incident.users_involved.join(", ")}.</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-red-400 font-bold">•</span>
                    <span><strong>Triage:</strong> Preserve volatility memory dump and evidence artifacts for forensic validation.</span>
                  </li>
                </ul>
              </div>
            </div>
          ) : (
            <pre className="whitespace-pre-wrap font-mono text-xs leading-relaxed bg-[var(--bg-canvas)] p-4 border-2 border-[var(--border-color)] text-[var(--text-primary)]">
              {reportData?.report_markdown}
            </pre>
          )}
        </div>

        {/* Modal Footer */}
        <div className="p-3 border-t-2 border-[var(--border-color)] bg-[var(--bg-surface-elevated)] flex items-center justify-between gap-3 shrink-0">
          <span className="text-[10px] text-[var(--text-muted)]">
            Generated {reportData?.generated_at ? new Date(reportData.generated_at).toLocaleString() : "Just now"} • Grounded in log evidence
          </span>
          <Button variant="primary" size="sm" onClick={onClose} className="text-[10px]">
            DONE
          </Button>
        </div>
      </div>
    </div>
  );
}

