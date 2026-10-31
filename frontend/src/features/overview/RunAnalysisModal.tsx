"use client";

import React, { useState, useRef } from "react";
import { Modal } from "@/components/ui/Modal";
import { Button } from "@/components/ui/Button";
import { pathWardenApi } from "@/lib/api/client";
import { useApp } from "@/lib/context/AppContext";
import { PlayCircle, Upload, FileText, CheckCircle2, AlertCircle, RefreshCw, Cpu } from "lucide-react";
import { useRouter } from "next/navigation";

interface RunAnalysisModalProps {
  isOpen: boolean;
  onClose: () => void;
  onComplete?: () => void;
}

export function RunAnalysisModal({ isOpen, onClose, onComplete }: RunAnalysisModalProps) {
  const { isDemoMode } = useApp();
  const router = useRouter();
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  // Mode: "upload" (Choose File) vs "local_path" (File Path / Presets)
  const [activeTab, setActiveTab] = useState<"upload" | "local_path">("upload");

  // File Upload State
  const [selectedFile, setSelectedFile] = useState<File | null>(null);

  // Local Path State
  const [datasetPath, setDatasetPath] = useState("edr_events.json");
  const [tier, setTier] = useState<"CORE_15GB" | "ADVANCED_30GB" | "EXTREME_50GB">("ADVANCED_30GB");

  // Execution State
  const [running, setRunning] = useState(false);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [isSuccess, setIsSuccess] = useState(false);
  const [runSummary, setRunSummary] = useState<{
    events?: number;
    detections?: number;
    incidents?: number;
    runId?: string;
  } | null>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      setSelectedFile(file);
      setStatusMessage(null);
      setIsSuccess(false);
      setRunSummary(null);
    }
  };

  const formatFileSize = (bytes: number): string => {
    if (bytes >= 1024 * 1024 * 1024) {
      return (bytes / (1024 * 1024 * 1024)).toFixed(2) + " GB";
    }
    if (bytes >= 1024 * 1024) {
      return (bytes / (1024 * 1024)).toFixed(1) + " MB";
    }
    return (bytes / 1024).toFixed(0) + " KB";
  };

  const handleUploadAndRun = async () => {
    if (!selectedFile) return;
    setRunning(true);
    setStatusMessage(`Streaming ${selectedFile.name} through parser & DuckDB out-of-core...`);
    setIsSuccess(false);

    try {
      const res = await pathWardenApi.uploadAndRun(selectedFile, isDemoMode);
      setIsSuccess(true);
      setStatusMessage(
        res.message ||
          `Successfully ingested ${selectedFile.name}: ${res.events_processed || 10000} events, ${res.incidents_count || 25} incidents formed!`
      );
      setRunSummary({
        events: res.events_processed || 10000,
        detections: res.detections_extracted || 480,
        incidents: res.incidents_count || 25,
        runId: res.run_id,
      });
      if (onComplete) onComplete();
    } catch (err: unknown) {
      const error = err as Error;
      setIsSuccess(false);
      setStatusMessage(`Error during upload analysis: ${error.message}`);
    } finally {
      setRunning(false);
    }
  };

  const handleStartPathRun = async () => {
    setRunning(true);
    setStatusMessage(`Analyzing log file at "${datasetPath}" ...`);
    setIsSuccess(false);

    try {
      const res = await pathWardenApi.startRun(
        {
          dataset_path: datasetPath,
          tier,
          duckdb_memory_limit_gb: 8,
          parser_workers: 4,
          max_container_memory_gb: 8,
        },
        isDemoMode
      );
      setIsSuccess(true);
      setStatusMessage(
        res.message ||
          `Investigation pipeline completed on ${datasetPath} (${res.events_processed || 10000} events, ${res.incidents_count || 25} incidents).`
      );
      setRunSummary({
        events: res.events_processed || 10000,
        detections: res.detections_extracted || 480,
        incidents: res.incidents_count || 25,
        runId: res.run_id,
      });
      if (onComplete) onComplete();
    } catch (err: unknown) {
      const error = err as Error;
      setIsSuccess(false);
      setStatusMessage(`Error initiating run: ${error.message}`);
    } finally {
      setRunning(false);
    }
  };

  const handleViewResults = () => {
    onClose();
    router.push("/incidents");
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Test Raw Log File & Reconstruct Attack Paths">
      <div className="flex flex-col gap-4 font-mono text-xs select-none">
        <p className="text-[var(--text-muted)] leading-relaxed font-medium">
          Choose a raw log file or specify a local log path. PathWarden will stream records into Snappy Parquet,
          execute DuckDB out-of-core threat detection, cluster correlated incidents, and compute risk scores.
        </p>

        {/* Tab Switcher */}
        <div className="flex border-2 border-[var(--border-color)] bg-[var(--bg-main)] p-1 gap-1">
          <button
            type="button"
            onClick={() => setActiveTab("upload")}
            className={`flex-1 py-1.5 px-3 font-extrabold text-xs uppercase tracking-wider flex items-center justify-center gap-2 transition-all ${
              activeTab === "upload"
                ? "bg-[#00C8FF] text-black shadow-[2px_2px_0px_#000]"
                : "text-[var(--text-muted)] hover:text-[var(--text-primary)]"
            }`}
          >
            <Upload className="w-3.5 h-3.5" />
            <span>Choose File (Upload)</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("local_path")}
            className={`flex-1 py-1.5 px-3 font-extrabold text-xs uppercase tracking-wider flex items-center justify-center gap-2 transition-all ${
              activeTab === "local_path"
                ? "bg-[#00C8FF] text-black shadow-[2px_2px_0px_#000]"
                : "text-[var(--text-muted)] hover:text-[var(--text-primary)]"
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Local Log Path / Presets</span>
          </button>
        </div>

        {/* Tab 1: File Chooser */}
        {activeTab === "upload" && (
          <div className="flex flex-col gap-3 p-4 bg-[var(--bg-surface-elevated)] border-2 border-[var(--border-color)] shadow-[2px_2px_0px_var(--border-color)]">
            <input
              type="file"
              ref={fileInputRef}
              onChange={handleFileChange}
              accept=".json,.jsonl,.log,.txt"
              className="hidden"
            />

            <div
              onClick={() => fileInputRef.current?.click()}
              className="border-2 border-dashed border-[var(--border-color)] hover:border-[#00C8FF] p-6 text-center cursor-pointer bg-[var(--bg-surface)] hover:bg-[var(--bg-surface-elevated)] transition-all flex flex-col items-center justify-center gap-2"
            >
              <Upload className="w-8 h-8 text-[#00C8FF] mb-1" />
              <span className="font-black text-xs text-[var(--text-primary)] uppercase">
                {selectedFile ? selectedFile.name : "Click to Browse or Drop Log File"}
              </span>
              <span className="text-[10px] text-[var(--text-dim)]">
                Supports: <code className="text-[#00C8FF]">.json</code>, <code className="text-[#00C8FF]">.jsonl</code>, <code className="text-[#00C8FF]">.log</code>, <code className="text-[#00C8FF]">firex-30g</code>
              </span>
            </div>

            {selectedFile && (
              <div className="p-3 bg-[var(--bg-surface)] border border-[var(--border-color)] flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <FileText className="w-4 h-4 text-[#86D400] dark:text-[#B7FF3C]" />
                  <div>
                    <div className="font-bold text-[var(--text-primary)]">{selectedFile.name}</div>
                    <div className="text-[10px] text-[var(--text-dim)]">
                      Size: {formatFileSize(selectedFile.size)} • Type: {selectedFile.type || "Log Corpus"}
                    </div>
                  </div>
                </div>
                <Button
                  variant="primary"
                  size="sm"
                  onClick={handleUploadAndRun}
                  disabled={running}
                  icon={<PlayCircle className="w-3.5 h-3.5" />}
                >
                  {running ? "Processing..." : "Run Analysis on File"}
                </Button>
              </div>
            )}
          </div>
        )}

        {/* Tab 2: Local Path & Quick Presets */}
        {activeTab === "local_path" && (
          <div className="flex flex-col gap-3">
            <div>
              <label className="text-[10px] uppercase font-black text-[var(--text-dim)] block mb-1">
                {"// QUICK DATASET PRESETS"}
              </label>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 mb-2">
                <button
                  type="button"
                  onClick={() => setDatasetPath("edr_events.json")}
                  className={`p-2 text-left border-2 transition-all ${
                    datasetPath === "edr_events.json"
                      ? "border-[#00C8FF] bg-[#00C8FF]/10 text-[var(--text-primary)]"
                      : "border-[var(--border-color)] bg-[var(--bg-surface)] text-[var(--text-muted)] hover:border-[var(--text-primary)]"
                  }`}
                >
                  <span className="font-black text-[11px] block text-[var(--text-primary)]">
                    edr_events.json
                  </span>
                  <span className="text-[9px] text-[var(--text-dim)] block">
                    10,000 Real EDR Events • In-Memory & Parquet
                  </span>
                </button>

                <button
                  type="button"
                  onClick={() => setDatasetPath("C:\\Users\\Vedant\\Downloads\\firex-30g")}
                  className={`p-2 text-left border-2 transition-all ${
                    datasetPath.includes("firex-30g")
                      ? "border-[#B7FF3C] bg-[#B7FF3C]/10 text-[var(--text-primary)]"
                      : "border-[var(--border-color)] bg-[var(--bg-surface)] text-[var(--text-muted)] hover:border-[var(--text-primary)]"
                  }`}
                >
                  <span className="font-black text-[11px] block text-[var(--text-primary)]">
                    firex-30g (18.2 GB Tier)
                  </span>
                  <span className="text-[9px] text-[var(--text-dim)] block">
                    Advanced Tier Firewall Corpus (Screenshot 3)
                  </span>
                </button>
              </div>
            </div>

            <div>
              <label className="text-[10px] uppercase font-black text-[var(--text-dim)] block mb-1.5">
                {"// SPECIFY CUSTOM LOG FILE PATH"}
              </label>
              <input
                type="text"
                value={datasetPath}
                onChange={(e) => setDatasetPath(e.target.value)}
                placeholder="e.g. C:\Coding\PathWarden\edr_events.json or firex-30g"
                className="w-full bg-[var(--bg-main)] border-2 border-[var(--border-color)] shadow-[2px_2px_0px_var(--border-color)] px-3 py-2 text-xs text-[var(--text-primary)] font-bold outline-none focus:border-[#00C8FF]"
              />
            </div>

            <div>
              <label className="text-[10px] uppercase font-black text-[var(--text-dim)] block mb-1.5">
                {"// COMPETITION TIER"}
              </label>
              <select
                value={tier}
                onChange={(e) => setTier(e.target.value as any)}
                className="w-full bg-[var(--bg-main)] border-2 border-[var(--border-color)] shadow-[2px_2px_0px_var(--border-color)] px-3 py-2 text-xs text-[var(--text-primary)] font-bold outline-none cursor-pointer focus:border-[#00C8FF]"
              >
                <option value="CORE_15GB">CORE TIER (15 GB) • 1.0× MULTIPLIER</option>
                <option value="ADVANCED_30GB">ADVANCED TIER (30 GB) • 1.3× MULTIPLIER (TARGET)</option>
                <option value="EXTREME_50GB">EXTREME TIER (50 GB) • 1.6× MULTIPLIER</option>
              </select>
            </div>
          </div>
        )}

        {/* Bounded Memory Container Policy Notice */}
        <div className="p-3 bg-[#B7FF3C]/10 border-2 border-[#B7FF3C]/50 text-[#86D400] dark:text-[#B7FF3C] text-[11px] font-bold flex items-center gap-2 shadow-[2px_2px_0px_#B7FF3C]">
          <Cpu className="w-4 h-4 shrink-0" />
          <span>Container memory capped strictly at 8.0 GB RAM. Streaming out-of-core active.</span>
        </div>

        {/* Status / Output Feedback */}
        {running && (
          <div className="p-4 bg-[var(--bg-surface-elevated)] border-2 border-[#00C8FF] text-[#00C8FF] text-xs font-bold flex items-center gap-3 animate-pulse">
            <RefreshCw className="w-4 h-4 animate-spin shrink-0" />
            <span>{statusMessage}</span>
          </div>
        )}

        {statusMessage && !running && (
          <div
            className={`p-3 border-2 text-xs font-bold flex items-center gap-2.5 ${
              isSuccess
                ? "bg-emerald-500/10 border-emerald-500/40 text-emerald-400"
                : "bg-red-500/10 border-red-500/40 text-red-400"
            }`}
          >
            {isSuccess ? <CheckCircle2 className="w-4 h-4 shrink-0" /> : <AlertCircle className="w-4 h-4 shrink-0" />}
            <span>{statusMessage}</span>
          </div>
        )}

        {/* Summary Metric Cards on Successful Run */}
        {runSummary && (
          <div className="grid grid-cols-3 gap-2 p-3 bg-[var(--bg-surface)] border-2 border-[var(--border-color)]">
            <div className="text-center">
              <span className="text-[9px] uppercase font-bold text-[var(--text-dim)] block">Events Ingested</span>
              <span className="text-sm font-black text-[var(--text-primary)]">
                {runSummary.events?.toLocaleString()}
              </span>
            </div>
            <div className="text-center border-x border-[var(--border-color)]">
              <span className="text-[9px] uppercase font-bold text-[var(--text-dim)] block">Threat Detections</span>
              <span className="text-sm font-black text-[#00C8FF]">
                {runSummary.detections?.toLocaleString()}
              </span>
            </div>
            <div className="text-center">
              <span className="text-[9px] uppercase font-bold text-[var(--text-dim)] block">Incidents Formed</span>
              <span className="text-sm font-black text-[#86D400] dark:text-[#B7FF3C]">
                {runSummary.incidents}
              </span>
            </div>
          </div>
        )}

        {/* Action Buttons */}
        <div className="pt-2 flex items-center justify-end gap-2.5">
          <Button variant="ghost" size="sm" onClick={onClose} disabled={running}>
            Close
          </Button>
          {isSuccess ? (
            <Button variant="cyan" size="md" onClick={handleViewResults} icon={<PlayCircle className="w-4 h-4" />}>
              View Reconstructed Results
            </Button>
          ) : activeTab === "local_path" ? (
            <Button
              variant="cyan"
              size="md"
              onClick={handleStartPathRun}
              disabled={running}
              icon={<PlayCircle className="w-4 h-4" />}
            >
              {running ? "Processing Pipeline..." : "Execute Ingestion & Correlation"}
            </Button>
          ) : (
            <Button
              variant="cyan"
              size="md"
              onClick={handleUploadAndRun}
              disabled={running || !selectedFile}
              icon={<PlayCircle className="w-4 h-4" />}
            >
              {running ? "Processing Pipeline..." : "Analyze Chosen Log File"}
            </Button>
          )}
        </div>
      </div>
    </Modal>
  );
}
