"use client";

import React, { useEffect, useState } from "react";
import { pathWardenApi } from "@/lib/api/client";
import { ReachabilityItem, AttackEdge } from "@/lib/api/types";
import { useApp } from "@/lib/context/AppContext";
import { ObservedVsPotentialExplainer } from "@/features/reachability/ObservedVsPotentialExplainer";
import { ReachabilityTable } from "@/features/reachability/ReachabilityTable";
import { EvidenceDrawer } from "@/features/investigation/EvidenceDrawer";
import { Radio, RefreshCw, Filter } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Footer } from "@/components/layout/Footer";

export default function ReachabilityPage() {
  const { isDemoMode, selectedIncidentId } = useApp();
  const [items, setItems] = useState<ReachabilityItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterType, setFilterType] = useState<string>("ALL");

  // Evidence Drawer state
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [activeEvidenceUids, setActiveEvidenceUids] = useState<string[]>([]);

  const loadReachability = React.useCallback(() => {
    setLoading(true);
    pathWardenApi
      .getReachability(selectedIncidentId, isDemoMode)
      .then((data) => {
        setItems(data);
        setLoading(false);
      })
      .catch(() => {
        setLoading(false);
      });
  }, [selectedIncidentId, isDemoMode]);

  useEffect(() => {
    loadReachability();
  }, [loadReachability]);

  const filteredItems = items.filter((item) => {
    if (filterType !== "ALL" && item.relationship_type !== filterType) {
      return false;
    }
    return true;
  });

  const handleInspectEvidence = (uids: string[]) => {
    setActiveEvidenceUids(uids);
    setDrawerOpen(true);
  };

  // Mock edge object for evidence drawer
  const mockEdge: AttackEdge = {
    edge_id: "REACHABILITY_PATH",
    incident_id: selectedIncidentId,
    source_step_uid: "COMPROMISED_HOST",
    target_step_uid: "TARGET_SYSTEM",
    relationship_type: "lateral_movement",
    relationship_score: 0.95,
    confidence_category: "STRONG",
    evidence_event_uids: activeEvidenceUids,
    explanation: "Observed network authentication or RPC session connection supporting reachability assessment.",
    is_inferred: false,
  };

  return (
    <div className="flex-1 flex flex-col justify-between min-h-full">
      <div className="p-6 flex flex-col gap-6 max-w-7xl mx-auto w-full font-mono select-none flex-1">
        {/* Page Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b-2 border-[var(--border-color)]">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Radio className="w-5 h-5 text-[#00C8FF]" />
            <h1 className="font-heading text-xl font-black uppercase tracking-tight text-[var(--text-primary)]">
              Reachability & Blast Radius Assessment
            </h1>
          </div>
          <p className="text-xs text-[var(--text-muted)] font-medium">
            Evidence-grounded reachability analysis strictly differentiating confirmed observed access from inferred potential reachability.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <Button
            variant="secondary"
            size="sm"
            onClick={loadReachability}
            icon={<RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />}
          >
            Refresh
          </Button>
        </div>
      </div>

      {/* Explainer Banners */}
      <ObservedVsPotentialExplainer />

      {/* Filters Bar */}
      <div className="p-3.5 border-2 border-[var(--border-color)] bg-[var(--bg-surface)] shadow-[3px_3px_0px_var(--border-color)] hover:shadow-[4px_4px_0px_var(--border-color)] transition-all flex items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-2">
          <Filter className="w-3.5 h-3.5 text-[var(--text-dim)]" />
          <span className="text-[10px] uppercase text-[var(--text-dim)] font-black">{"// FILTER RELATIONSHIP:"}</span>
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="bg-[var(--bg-main)] border-2 border-[var(--border-color)] shadow-[2px_2px_0px_var(--border-color)] px-2.5 py-1 text-xs text-[var(--text-primary)] font-bold outline-none cursor-pointer focus:border-[#00C8FF]"
          >
            <option value="ALL">ALL RELATIONSHIPS ({items.length})</option>
            <option value="OBSERVED_SESSION">OBSERVED SESSIONS (CONFIRMED)</option>
            <option value="NETWORK_REACHABLE">NETWORK REACHABLE (POTENTIAL)</option>
            <option value="PRIVILEGE_RELATIONSHIP">PRIVILEGE EXPOSURE (POTENTIAL)</option>
          </select>
        </div>

        <span className="text-[11px] text-[var(--text-muted)] font-bold">
          TARGET INCIDENT: <strong className="text-[#00C8FF]">{selectedIncidentId}</strong>
        </span>
      </div>

      {/* Reachability Table */}
      {loading ? (
        <div className="p-12 border-2 border-[var(--border-color)] bg-[var(--bg-surface)] shadow-[4px_4px_0px_var(--border-color)] text-center text-xs text-[var(--text-muted)] font-bold">
          LOADING REACHABILITY ASSESSMENT PATHS...
        </div>
      ) : (
        <ReachabilityTable items={filteredItems} onInspectEvidence={handleInspectEvidence} />
      )}

        {/* Evidence Drawer */}
        <EvidenceDrawer
          isOpen={drawerOpen}
          onClose={() => setDrawerOpen(false)}
          selectedStep={null}
          selectedEdge={mockEdge}
        />
      </div>
      <Footer />
    </div>
  );
}
