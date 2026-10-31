"use client";

import React, { useEffect, useState, Suspense } from "react";
import { useParams } from "next/navigation";
import { pathWardenApi } from "@/lib/api/client";
import { IncidentDetail, AttackStep, AttackEdge } from "@/lib/api/types";
import { useApp } from "@/lib/context/AppContext";
import { InvestigationHeader } from "@/features/investigation/InvestigationHeader";
import { AttackGraphView } from "@/features/investigation/AttackGraphView";
import { ChronologicalTimeline } from "@/features/investigation/ChronologicalTimeline";
import { AttackStepDetail } from "@/features/investigation/AttackStepDetail";
import { EvidenceDrawer } from "@/features/investigation/EvidenceDrawer";
import { GitFork, Clock, AlertCircle } from "lucide-react";

function IncidentInvestigationContent() {
  const params = useParams();
  const id = (params?.id as string) || "INC-2026-0841";
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

  // Tab switch for mobile
  const [activeTab, setActiveTab] = useState<"graph" | "timeline">("graph");

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

  const handleInspectStepEvidence = (step: AttackStep) => {
    setSelectedStep(step);
    setSelectedEdge(null);
    setEvidenceDrawerOpen(true);
  };

  const handleInspectEdgeEvidence = (edge: AttackEdge | null) => {
    setSelectedEdge(edge);
    setSelectedStep(null);
    if (edge) {
      setEvidenceDrawerOpen(true);
    }
  };

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
      {/* Top Incident Summary Bar (Collapsible to maximize graph workspace) */}
      <InvestigationHeader
        incident={incident}
        isExpanded={headerExpanded}
        onToggleExpanded={() => setHeaderExpanded(!headerExpanded)}
      />

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

      {/* Main Investigation Split Pane Workspace */}
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
            onSelectStep={(step) => {
              setSelectedStep(step);
              setSelectedEdge(null);
            }}
            onSelectEdge={handleInspectEdgeEvidence}
            isTimelineOpen={isTimelineOpen}
            onToggleTimeline={() => setIsTimelineOpen(!isTimelineOpen)}
          />
        </div>

        {/* Right Pane: Chronological Timeline + Selected Step Details */}
        {isTimelineOpen && (
          <div
            className={`w-full lg:w-[380px] xl:w-[440px] border-l-2 border-[var(--border-color)] flex flex-col shrink-0 h-full min-h-0 overflow-hidden ${
              activeTab === "timeline" ? "flex" : "hidden lg:flex"
            }`}
          >
            {/* Selected Step Detail Panel (Docked at top of right rail if step is selected) */}
            {selectedStep && (
              <div className="shrink-0 max-h-[45%] overflow-y-auto border-b-2 border-[var(--border-color)]">
                <AttackStepDetail
                  step={selectedStep}
                  onClose={() => setSelectedStep(null)}
                  onInspectEvidence={handleInspectStepEvidence}
                />
              </div>
            )}

            {/* Chronological Timeline */}
            <div className="flex-1 min-h-0 overflow-y-auto">
              <ChronologicalTimeline
                steps={incident.steps}
                selectedStepUid={selectedStep?.step_uid || null}
                onSelectStep={(step) => {
                  setSelectedStep(step);
                  setSelectedEdge(null);
                }}
                onInspectEvidence={handleInspectStepEvidence}
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
