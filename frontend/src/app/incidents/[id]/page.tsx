"use client";

import React, { useEffect, useState, useCallback, Suspense } from "react";
import { useParams } from "next/navigation";
import { pathWardenApi } from "@/lib/api/client";
import { IncidentDetail, AttackStep, AttackEdge } from "@/lib/api/types";
import { useApp } from "@/lib/context/AppContext";
import { InvestigationHeader } from "@/features/investigation/InvestigationHeader";
import { AttackGraphView } from "@/features/investigation/AttackGraphView";
import { ChronologicalTimeline } from "@/features/investigation/ChronologicalTimeline";
import { AttackStepDetail } from "@/features/investigation/AttackStepDetail";
import { EvidenceDrawer } from "@/features/investigation/EvidenceDrawer";
import { ExecutiveReportModal } from "@/features/investigation/ExecutiveReportModal";
import { Badge } from "@/components/ui/Badge";
import { GitFork, Clock, AlertCircle, FileSearch, X, Maximize2, Minimize2, Sparkles } from "lucide-react";

function IncidentInvestigationContent() {
  const params = useParams();
  const id = (params?.id as string) || "INC-001";
  const { isDemoMode, setSelectedIncidentId } = useApp();

  const [incident, setIncident] = useState<IncidentDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Selection states
  const [selectedStep, setSelectedStep] = useState<AttackStep | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<AttackEdge | null>(null);
  const [evidenceDrawerOpen, setEvidenceDrawerOpen] = useState(false);
  const [headerExpanded, setHeaderExpanded] = useState(false);
  const [isTimelineOpen, setIsTimelineOpen] = useState(true);
  const [isWorkspaceEnlarged, setIsWorkspaceEnlarged] = useState(false);
  const [reportModalOpen, setReportModalOpen] = useState(false);

  // Tab switch for mobile
  const [activeTab, setActiveTab] = useState<"graph" | "timeline">("graph");

  // Global ESC key listener to exit enlarged workspace or modal
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        if (reportModalOpen) {
          setReportModalOpen(false);
        } else if (isWorkspaceEnlarged) {
          setIsWorkspaceEnlarged(false);
        }
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [reportModalOpen, isWorkspaceEnlarged]);

  useEffect(() => {
    setSelectedIncidentId(id);
    let isMounted = true;
    setLoading(true);
    setError(null);

    pathWardenApi
      .getIncident(id, isDemoMode)
      .then((data) => {
        if (isMounted) {
          setIncident(data);
          // Default selection to first step
          if (data.steps && data.steps.length > 0) {
            setSelectedStep(data.steps[0]);
          }
          setLoading(false);
        }
      })
      .catch((err) => {
        if (isMounted) {
          setError(err.message || "Failed to load incident investigation details");
          setLoading(false);
        }
      });

    return () => {
      isMounted = false;
    };
  }, [id, isDemoMode, setSelectedIncidentId]);

  const handleInspectStepEvidence = useCallback((step: AttackStep) => {
    setSelectedStep(step);
    setSelectedEdge(null);
    setEvidenceDrawerOpen(true);
  }, []);

  const handleInspectEdgeEvidence = useCallback((edge: AttackEdge | null) => {
    setSelectedEdge(edge);
    setSelectedStep(null);
    if (edge) {
      setEvidenceDrawerOpen(true);
    }
  }, []);

  const handleSelectStep = useCallback((step: AttackStep | null) => {
    setSelectedStep(step);
    setSelectedEdge(null);
  }, []);

  const handleToggleTimeline = useCallback(() => {
    setIsTimelineOpen((prev) => !prev);
  }, []);

  if (loading) {
    return (
      <div className="flex-1 flex items-center justify-center font-mono text-xs text-[var(--text-muted)]">
        <div className="flex flex-col items-center gap-3">
          <div className="w-8 h-8 border-2 border-[#00C8FF] border-t-transparent animate-spin" />
          <span>RECONSTRUCTING ATTACK GRAPH & TIMELINE...</span>
        </div>
      </div>
    );
  }

  if (error || !incident) {
    return (
      <div className="flex-1 p-8 flex items-center justify-center font-mono">
        <div className="max-w-md p-6 border border-red-500/50 bg-red-500/10 text-red-400 flex flex-col gap-3">
          <div className="flex items-center gap-2 font-bold">
            <AlertCircle className="w-5 h-5 text-red-500" />
            <span>INCIDENT INVESTIGATION ERROR</span>
          </div>
          <p className="text-xs text-[var(--text-muted)] leading-relaxed">
            {error || "Incident details could not be retrieved from the API."}
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col flex-1 h-full min-h-0 overflow-hidden">
      {/* Top Incident Summary Bar */}
      <InvestigationHeader
        incident={incident}
        isExpanded={headerExpanded}
        onToggleExpanded={() => setHeaderExpanded(!headerExpanded)}
        onOpenReportModal={() => setReportModalOpen(true)}
        isWorkspaceEnlarged={isWorkspaceEnlarged}
        onToggleWorkspaceEnlarge={() => setIsWorkspaceEnlarged(!isWorkspaceEnlarged)}
      />

      {/* Fullscreen Side-by-Side Canvas Overlay (Opens Cytoscape & Timeline in Full Window) */}
      {isWorkspaceEnlarged && (
        <div className="fixed inset-0 z-50 bg-[var(--bg-canvas)] flex flex-col p-2.5 sm:p-3 font-mono select-none overflow-hidden animate-fadeIn">
          {/* Fullscreen Workspace Header Bar */}
          <div className="p-3 bg-[var(--bg-surface)] border-2 border-[var(--border-color)] shadow-[4px_4px_0px_#000] flex items-center justify-between gap-3 mb-2.5 shrink-0">
            <div className="flex items-center flex-wrap gap-2 sm:gap-2.5">
              <span className="px-2.5 py-0.5 bg-[#B7FF3C] text-black font-black text-xs uppercase border border-black shadow-[1px_1px_0px_#000]">
                CANVAS ENLARGED
              </span>
              <span className="font-black text-sm text-[var(--text-primary)]">
                {incident.incident_id}
              </span>
              <Badge variant={incident.severity === "CRITICAL" ? "critical" : "warning"} size="sm">
                {incident.severity}
              </Badge>
              <span className="text-xs px-2 py-0.5 bg-red-500/10 text-red-400 border border-red-500/50 font-bold uppercase">
                RISK: {incident.risk_score || 75}/100
              </span>
              <span className="hidden sm:inline-flex items-center gap-1 text-[10px] px-2 py-0.5 bg-purple-500/15 text-purple-400 border border-purple-500/40 font-bold uppercase">
                [B-3] {incident.raw_alerts_merged || incident.detection_count || 14} ALERTS MERGED
              </span>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => setReportModalOpen(true)}
                className="hidden sm:inline-flex items-center gap-1.5 px-3 py-1 text-xs font-black uppercase border-2 border-black bg-[#B7FF3C] text-black shadow-[2px_2px_0px_#000] cursor-pointer hover:bg-[#a3e635] transition-all"
              >
                <Sparkles className="w-3.5 h-3.5" />
                <span>[B-2] REPORT</span>
              </button>
              <button
                onClick={() => setIsWorkspaceEnlarged(false)}
                className="flex items-center gap-1.5 px-3 py-1 bg-[#FF334B] hover:bg-[#e02b41] text-white font-mono text-xs font-black uppercase border-2 border-black shadow-[3px_3px_0px_#000] cursor-pointer transition-all active:translate-x-[1px] active:translate-y-[1px]"
                title="Exit Fullscreen (Esc)"
              >
                <Minimize2 className="w-4 h-4" />
                <span>EXIT FULLSCREEN [ESC]</span>
              </button>
            </div>
          </div>

          {/* Fullscreen Side-by-Side Main Area */}
          <div className="flex-1 min-h-0 flex flex-col lg:flex-row gap-2.5 overflow-hidden">
            {/* Left Side: Expanded Cytoscape Graph */}
            <div className="flex-1 min-w-0 min-h-0 h-full relative">
              <AttackGraphView
                steps={incident.steps}
                edges={incident.edges}
                selectedStepUid={selectedStep?.step_uid || null}
                selectedEdgeId={selectedEdge?.edge_id || null}
                onSelectStep={handleSelectStep}
                onSelectEdge={handleInspectEdgeEvidence}
                isTimelineOpen={true}
                isWorkspaceEnlarged={true}
                onToggleWorkspaceEnlarge={() => setIsWorkspaceEnlarged(false)}
              />
            </div>

            {/* Right Side: Step Inspector + Full-Height Timeline */}
            <div className="w-full lg:w-[460px] xl:w-[520px] shrink-0 h-full flex flex-col min-h-0 border-2 border-[var(--border-color)] bg-[var(--bg-surface)] shadow-[4px_4px_0px_var(--border-color)] overflow-hidden">
              {selectedStep && (
                <div className="shrink-0 max-h-[45%] overflow-y-auto border-b-2 border-[var(--border-color)]">
                  <AttackStepDetail
                    step={selectedStep}
                    onClose={() => setSelectedStep(null)}
                    onInspectEvidence={handleInspectStepEvidence}
                  />
                </div>
              )}
              <div className="flex-1 min-h-0 overflow-y-auto">
                <ChronologicalTimeline
                  steps={incident.steps}
                  selectedStepUid={selectedStep?.step_uid || null}
                  onSelectStep={handleSelectStep}
                  onInspectEvidence={handleInspectStepEvidence}
                  isEnlarged={true}
                  onToggleEnlarge={() => setIsWorkspaceEnlarged(false)}
                />
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Mobile Tab Switcher */}
      <div className="flex lg:hidden border-b border-[var(--border-color)] bg-[var(--bg-surface-elevated)] font-mono text-xs shrink-0">
        <button
          onClick={() => setActiveTab("graph")}
          className={`flex-1 py-2 flex items-center justify-center gap-2 border-b-2 font-bold cursor-pointer ${
            activeTab === "graph"
              ? "border-[#00C8FF] text-[#00C8FF] bg-[var(--bg-surface)]"
              : "border-transparent text-[var(--text-muted)]"
          }`}
        >
          <GitFork className="w-3.5 h-3.5" />
          ATTACK GRAPH
        </button>
        <button
          onClick={() => setActiveTab("timeline")}
          className={`flex-1 py-2 flex items-center justify-center gap-2 border-b-2 font-bold cursor-pointer ${
            activeTab === "timeline"
              ? "border-[#00C8FF] text-[#00C8FF] bg-[var(--bg-surface)]"
              : "border-transparent text-[var(--text-muted)]"
          }`}
        >
          <Clock className="w-3.5 h-3.5" />
          CHRONOLOGICAL TIMELINE ({incident.steps.length})
        </button>
      </div>

      {/* Standard Investigation Split Pane Workspace */}
      <div className="flex-1 min-h-0 min-w-0 flex flex-col lg:flex-row overflow-hidden relative">
        {/* Left / Center: Interactive Attack Graph */}
        <div
          className={`flex-1 min-w-0 min-h-0 h-full flex flex-col relative ${
            activeTab === "graph" ? "flex" : "hidden lg:flex"
          }`}
        >
          <AttackGraphView
            steps={incident.steps}
            edges={incident.edges}
            selectedStepUid={selectedStep?.step_uid || null}
            selectedEdgeId={selectedEdge?.edge_id || null}
            onSelectStep={handleSelectStep}
            onSelectEdge={handleInspectEdgeEvidence}
            isTimelineOpen={isTimelineOpen}
            onToggleTimeline={handleToggleTimeline}
            isWorkspaceEnlarged={isWorkspaceEnlarged}
            onToggleWorkspaceEnlarge={() => setIsWorkspaceEnlarged(!isWorkspaceEnlarged)}
          />

          {/* Mobile Step Selection Drawer / Pill */}
          {selectedStep && activeTab === "graph" && (
            <div className="lg:hidden absolute bottom-3 left-3 right-3 z-30 bg-[var(--bg-surface)] border-2 border-[var(--border-color)] p-3 shadow-[4px_4px_0px_#000] font-mono text-xs flex items-center justify-between">
              <div className="min-w-0 flex-1 pr-2">
                <div className="flex items-center gap-2 mb-0.5">
                  <Badge variant={selectedStep.severity === "CRITICAL" ? "critical" : "warning"}>
                    STEP #{selectedStep.order_index}
                  </Badge>
                  <span className="font-bold text-[var(--text-primary)] truncate">{selectedStep.mitre.technique_name}</span>
                </div>
                <span className="text-[10px] text-[var(--text-muted)] block truncate">{selectedStep.host_name} // {selectedStep.user_name}</span>
              </div>
              <div className="flex items-center gap-1.5 shrink-0">
                <button
                  onClick={() => setActiveTab("timeline")}
                  className="px-2 py-1 bg-[#00C8FF] text-black font-bold text-[10px] uppercase border border-black cursor-pointer"
                >
                  VIEW TIMELINE
                </button>
                <button
                  onClick={() => handleInspectStepEvidence(selectedStep)}
                  className="px-2 py-1 bg-[#2563FF] text-white font-bold text-[10px] uppercase border border-black cursor-pointer"
                >
                  EVIDENCE
                </button>
                <button
                  onClick={() => setSelectedStep(null)}
                  className="p-1 text-[var(--text-muted)] hover:text-[#FF334B] cursor-pointer"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Right Pane: Chronological Timeline + Selected Step Details */}
        {isTimelineOpen && (
          <div
            className={`w-full lg:w-[380px] xl:w-[440px] border-l-2 border-[var(--border-color)] flex flex-col shrink-0 h-full min-h-0 overflow-hidden ${
              activeTab === "timeline" ? "flex" : "hidden lg:flex"
            }`}
          >
            {/* Docked Inspector Panel */}
            {selectedStep ? (
              <div className="shrink-0 max-h-[48%] overflow-y-auto border-b-2 border-[var(--border-color)]">
                <AttackStepDetail
                  step={selectedStep}
                  onClose={() => setSelectedStep(null)}
                  onInspectEvidence={handleInspectStepEvidence}
                />
              </div>
            ) : selectedEdge ? (
              <div className="shrink-0 border-b-2 border-[var(--border-color)] bg-[var(--bg-surface)] p-3.5 font-mono text-xs flex flex-col gap-2 shadow-[2px_2px_0px_var(--border-color)]">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-1.5 font-black text-[var(--text-primary)]">
                    <GitFork className="w-3.5 h-3.5 text-[#00C8FF]" />
                    <span>EDGE INSPECTION // {selectedEdge.edge_id}</span>
                  </div>
                  <button onClick={() => setSelectedEdge(null)} className="p-0.5 text-[var(--text-muted)] hover:text-[#FF334B] cursor-pointer">
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>
                <div className="text-[11px] font-bold text-[#00C8FF] uppercase">
                  {selectedEdge.relationship_type.replace(/_/g, " ")}
                </div>
                <p className="text-[11px] text-[var(--text-muted)] leading-relaxed">{selectedEdge.explanation}</p>
                <div className="flex items-center justify-between text-[10px] pt-1.5 border-t border-[var(--border-subtle)]">
                  <span className="font-bold text-[var(--text-dim)]">
                    CONFIDENCE: {selectedEdge.confidence_category} ({((selectedEdge.relationship_score || 0.85) * 100).toFixed(0)}%)
                  </span>
                  <button
                    onClick={() => handleInspectEdgeEvidence(selectedEdge)}
                    className="text-[#00C8FF] hover:underline font-bold flex items-center gap-1 cursor-pointer"
                  >
                    <FileSearch className="w-3 h-3" />
                    <span>EVIDENCE ({selectedEdge.evidence_event_uids?.length || 0})</span>
                  </button>
                </div>
              </div>
            ) : (
              <div className="p-3 border-b-2 border-[var(--border-color)] bg-[var(--bg-surface-elevated)] flex items-center justify-between font-mono text-xs shrink-0 select-none">
                <div className="flex items-center gap-2">
                  <FileSearch className="w-3.5 h-3.5 text-[#00C8FF]" />
                  <span className="font-bold text-[var(--text-muted)] text-[10px] tracking-wide">
                    CLICK ANY STEP OR NODE TO INSPECT DETAILS
                  </span>
                </div>
                <span className="text-[9px] text-[var(--text-dim)] uppercase bg-[var(--bg-surface)] px-1.5 py-0.5 border border-[var(--border-color)] font-bold">
                  INSPECTOR READY
                </span>
              </div>
            )}

            {/* Chronological Timeline */}
            <div className="flex-1 min-h-0 overflow-y-auto">
              <ChronologicalTimeline
                steps={incident.steps}
                selectedStepUid={selectedStep?.step_uid || null}
                onSelectStep={handleSelectStep}
                onInspectEvidence={handleInspectStepEvidence}
                isEnlarged={false}
                onToggleEnlarge={() => setIsWorkspaceEnlarged(true)}
              />
            </div>
          </div>
        )}
      </div>

      {/* Evidence Inspection Drawer */}
      <EvidenceDrawer
        isOpen={evidenceDrawerOpen}
        onClose={() => setEvidenceDrawerOpen(false)}
        selectedStep={selectedStep}
        selectedEdge={selectedEdge}
      />

      {/* Bonus B-2: Executive Report Modal */}
      <ExecutiveReportModal
        isOpen={reportModalOpen}
        onClose={() => setReportModalOpen(false)}
        incident={incident}
      />
    </div>
  );
}

export default function IncidentInvestigationPage() {
  return (
    <Suspense
      fallback={
        <div className="flex-1 flex items-center justify-center font-mono text-xs text-[var(--text-muted)]">
          LOADING INCIDENT WORKSPACE...
        </div>
      }
    >
      <IncidentInvestigationContent />
    </Suspense>
  );
}
