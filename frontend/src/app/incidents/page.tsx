"use client";

import React, { useEffect, useState } from "react";
import { pathWardenApi } from "@/lib/api/client";
import { Incident } from "@/lib/api/types";
import { useApp } from "@/lib/context/AppContext";
import { IncidentFilters } from "@/features/incidents/IncidentFilters";
import { IncidentTable } from "@/features/incidents/IncidentTable";
import { ShieldAlert, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/Button";

export default function IncidentsPage() {
  const { isDemoMode } = useApp();
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filter state
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedSeverity, setSelectedSeverity] = useState("ALL");
  const [selectedTactic, setSelectedTactic] = useState("ALL");

  const loadIncidents = React.useCallback(() => {
    setLoading(true);
    setError(null);
    pathWardenApi
      .getIncidents(isDemoMode)
      .then((data) => {
        setIncidents(data);
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message || "Failed to load incidents list");
        setLoading(false);
      });
  }, [isDemoMode]);

  useEffect(() => {
    loadIncidents();
  }, [loadIncidents]);

  // Client-side filtering
  const filteredIncidents = incidents.filter((incident) => {
    if (selectedSeverity !== "ALL" && incident.severity !== selectedSeverity) {
      return false;
    }
    if (selectedTactic !== "ALL" && !incident.tactics.includes(selectedTactic)) {
      return false;
    }
    if (searchQuery.trim() !== "") {
      const q = searchQuery.toLowerCase();
      const matchId = incident.incident_id.toLowerCase().includes(q);
      const matchTitle = incident.title.toLowerCase().includes(q);
      const matchSummary = incident.summary.toLowerCase().includes(q);
      const matchHost = incident.hosts_involved.some((h) => h.toLowerCase().includes(q));
      const matchUser = incident.users_involved.some((u) => u.toLowerCase().includes(q));
      const matchTactic = incident.tactics.some((t) => t.toLowerCase().includes(q));
      if (!matchId && !matchTitle && !matchSummary && !matchHost && !matchUser && !matchTactic) {
        return false;
      }
    }
    return true;
  });

  return (
    <div className="flex-1 p-6 flex flex-col gap-5 max-w-7xl mx-auto w-full font-mono select-none">
      {/* Page Title & Controls */}
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b-2 border-[var(--border-color)]">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <ShieldAlert className="w-5 h-5 text-[#2563FF]" />
            <h1 className="font-heading text-xl font-black uppercase tracking-tight text-[var(--text-primary)]">
              Incident Explorer
            </h1>
          </div>
          <p className="text-xs text-[var(--text-muted)] font-medium">
            Correlated attack paths and multi-stage intrusions identified across the ingested telemetry stream.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <Button
            variant="secondary"
            size="sm"
            onClick={loadIncidents}
            icon={<RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />}
          >
            Refresh
          </Button>
        </div>
      </div>

      {/* Filter Controls */}
      <IncidentFilters
        searchQuery={searchQuery}
        onSearchChange={setSearchQuery}
        selectedSeverity={selectedSeverity}
        onSeverityChange={setSelectedSeverity}
        selectedTactic={selectedTactic}
        onTacticChange={setSelectedTactic}
        onClearFilters={() => {
          setSearchQuery("");
          setSelectedSeverity("ALL");
          setSelectedTactic("ALL");
        }}
      />

      {/* Table Display */}
      {loading ? (
        <div className="p-12 border-2 border-[var(--border-color)] bg-[var(--bg-surface)] shadow-[4px_4px_0px_var(--border-color)] text-center text-xs text-[var(--text-muted)] font-bold">
          <div className="w-6 h-6 border-2 border-[#00C8FF] border-t-transparent animate-spin mx-auto mb-2" />
          <span>QUERYING CORRELATED INCIDENT CLUSTERS...</span>
        </div>
      ) : error ? (
        <div className="p-6 border-2 border-red-500 bg-red-500/10 text-red-400 text-xs font-bold shadow-[4px_4px_0px_#FF334B]">
          Failed to load incidents: {error}
        </div>
      ) : (
        <IncidentTable incidents={filteredIncidents} />
      )}
    </div>
  );
}
