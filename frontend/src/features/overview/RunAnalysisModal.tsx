"use client";

import React, { useState } from "react";
import { Modal } from "@/components/ui/Modal";
import { Button } from "@/components/ui/Button";
import { pathWardenApi } from "@/lib/api/client";
import { useApp } from "@/lib/context/AppContext";
import { PlayCircle, Cpu } from "lucide-react";

interface RunAnalysisModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export function RunAnalysisModal({ isOpen, onClose }: RunAnalysisModalProps) {
  const { isDemoMode } = useApp();
  const [datasetPath, setDatasetPath] = useState("c:\\Coding\\PathWarden\\edr_events.json");
  const [tier, setTier] = useState<"CORE_15GB" | "ADVANCED_30GB" | "EXTREME_50GB">("ADVANCED_30GB");
  const [duckdbMemory, setDuckdbMemory] = useState(3);
  const [workers, setWorkers] = useState(3);
  const [running, setRunning] = useState(false);
  const [responseMsg, setResponseMsg] = useState<string | null>(null);

  const handleStartRun = async () => {
    setRunning(true);
    setResponseMsg(null);
    try {
      const res = await pathWardenApi.startRun(
        {
          dataset_path: datasetPath,
          tier,
          duckdb_memory_limit_gb: duckdbMemory,
          parser_workers: workers,
          max_container_memory_gb: 8,
        },
        isDemoMode
      );
      setResponseMsg(`Run ${res.run_id} initiated successfully. Pipeline status: ${res.status}`);
      setRunning(false);
    } catch (err: unknown) {
      const error = err as Error;
      setResponseMsg(`Error initiating run: ${error.message}`);
      setRunning(false);
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Execute Ingestion & Reconstruction Run">
      <div className="flex flex-col gap-4 font-mono text-xs select-none">
        <p className="text-[var(--text-muted)] leading-relaxed font-medium">
          Configure the bounded-memory pipeline parameters to ingest raw logs, execute DuckDB normalization,
          evaluate SQL detection rules, and generate precomputed attack paths.
        </p>

        {/* Dataset Path */}
        <div>
          <label className="text-[10px] uppercase font-black text-[var(--text-dim)] block mb-1.5">
            {"// DATASET SOURCE LOCATION"}
          </label>
          <input
            type="text"
            value={datasetPath}
            onChange={(e) => setDatasetPath(e.target.value)}
            className="w-full bg-[var(--bg-main)] border-2 border-[var(--border-color)] shadow-[2px_2px_0px_var(--border-color)] px-3 py-2 text-xs text-[var(--text-primary)] font-bold outline-none focus:border-[#00C8FF]"
          />
        </div>

        {/* Competition Tier Selection */}
        <div>
          <label className="text-[10px] uppercase font-black text-[var(--text-dim)] block mb-1.5">
            {"// TARGET COMPETITION TIER"}
          </label>
          <select
            value={tier}
            onChange={(e) => setTier(e.target.value as "CORE_15GB" | "ADVANCED_30GB" | "EXTREME_50GB")}
            className="w-full bg-[var(--bg-main)] border-2 border-[var(--border-color)] shadow-[2px_2px_0px_var(--border-color)] px-3 py-2 text-xs text-[var(--text-primary)] font-bold outline-none cursor-pointer focus:border-[#00C8FF]"
          >
            <option value="CORE_15GB">CORE TIER (15 GB) • 1.0× MULTIPLIER</option>
            <option value="ADVANCED_30GB">ADVANCED TIER (30 GB) • 1.3× MULTIPLIER (TARGET)</option>
            <option value="EXTREME_50GB">EXTREME TIER (50 GB) • 1.6× MULTIPLIER (SPILL OVER)</option>
          </select>
        </div>

        {/* Resource Allocation Sliders */}
        <div className="grid grid-cols-2 gap-3 p-3.5 bg-[var(--bg-surface-elevated)] border-2 border-[var(--border-color)] shadow-[2px_2px_0px_var(--border-color)]">
          <div>
            <div className="flex justify-between text-[10px] text-[var(--text-dim)] uppercase font-bold mb-1">
              <span>DuckDB Memory</span>
              <span className="text-[#00C8FF]">{duckdbMemory} GB</span>
            </div>
            <input
              type="range"
              min="2"
              max="5"
              step="1"
              value={duckdbMemory}
              onChange={(e) => setDuckdbMemory(Number(e.target.value))}
              className="w-full accent-[#00C8FF] cursor-pointer"
            />
          </div>

          <div>
            <div className="flex justify-between text-[10px] text-[var(--text-dim)] uppercase font-bold mb-1">
              <span>Parser Workers</span>
              <span className="text-[#86D400] dark:text-[#B7FF3C]">{workers} Threads</span>
            </div>
            <input
              type="range"
              min="1"
              max="6"
              step="1"
              value={workers}
              onChange={(e) => setWorkers(Number(e.target.value))}
              className="w-full accent-[#00C8FF] cursor-pointer"
            />
          </div>
        </div>

        {/* Container Hard Cap Warning */}
        <div className="p-3 bg-[#B7FF3C]/10 border-2 border-[#B7FF3C]/50 text-[#86D400] dark:text-[#B7FF3C] text-[11px] font-bold flex items-center gap-2 shadow-[2px_2px_0px_#B7FF3C]">
          <Cpu className="w-4 h-4 shrink-0" />
          <span>Container hard cap enforced at 8.0 GB RAM. Out-of-core spill directory active.</span>
        </div>

        {responseMsg && (
          <div className="p-3 bg-[var(--bg-main)] border-2 border-[var(--border-color)] text-[11px] font-bold text-[var(--text-primary)]">
            {responseMsg}
          </div>
        )}

        <div className="pt-2 flex items-center justify-end gap-2.5">
          <Button variant="ghost" size="sm" onClick={onClose} disabled={running}>
            Cancel
          </Button>
          <Button
            variant="cyan"
            size="md"
            onClick={handleStartRun}
            disabled={running}
            icon={<PlayCircle className="w-4 h-4" />}
          >
            {running ? "Initiating Pipeline..." : "Trigger Processing Run"}
          </Button>
        </div>
      </div>
    </Modal>
  );
}
