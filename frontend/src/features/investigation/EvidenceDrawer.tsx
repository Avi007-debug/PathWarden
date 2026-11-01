"use client";

import React, { useEffect, useState } from "react";
import { Drawer } from "@/components/ui/Drawer";
import { AttackStep, AttackEdge, RawEvidenceRecord } from "@/lib/api/types";
import { pathWardenApi } from "@/lib/api/client";
import { useApp } from "@/lib/context/AppContext";
import { Badge } from "@/components/ui/Badge";
import { formatTimestamp } from "@/lib/utils/formatters";
import {
  FileCode,
  Copy,
  Check,
} from "lucide-react";

interface EvidenceDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  selectedStep: AttackStep | null;
  selectedEdge: AttackEdge | null;
}

export function EvidenceDrawer({
  isOpen,
  onClose,
  selectedStep,
  selectedEdge,
}: EvidenceDrawerProps) {
  const { isDemoMode } = useApp();
  const [activeEvidenceUid, setActiveEvidenceUid] = useState<string | null>(null);
  const [evidenceRecord, setEvidenceRecord] = useState<RawEvidenceRecord | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [copied, setCopied] = useState<boolean>(false);

  // Evidence UIDs available
  const evidenceUids = React.useMemo(() => {
    return selectedStep
      ? selectedStep.evidence_event_uids || []
      : selectedEdge
      ? selectedEdge.evidence_event_uids || []
      : [];
  }, [selectedStep, selectedEdge]);

  useEffect(() => {
    if (evidenceUids.length > 0) {
      setActiveEvidenceUid(evidenceUids[0]);
    } else {
      setActiveEvidenceUid(null);
      setEvidenceRecord(null);
    }
  }, [evidenceUids]);

  useEffect(() => {
    if (!activeEvidenceUid) return;

    let isMounted = true;
    setLoading(true);

    pathWardenApi
      .getEvidence(activeEvidenceUid, 5, isDemoMode)
      .then((record) => {
        if (isMounted) {
          setEvidenceRecord(record);
          setLoading(false);
        }
      })
      .catch(() => {
        if (isMounted) {
          setLoading(false);
        }
      });

    return () => {
      isMounted = false;
    };
  }, [activeEvidenceUid, isDemoMode]);

  const handleCopyRaw = () => {
    if (evidenceRecord?.raw_log_snippet) {
      navigator.clipboard.writeText(evidenceRecord.raw_log_snippet);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const title = selectedStep
    ? `Step Evidence: ${selectedStep.step_uid}`
    : selectedEdge
    ? `Relationship Evidence: ${selectedEdge.edge_id}`
    : "Evidence Inspector";

  const subtitle = selectedStep
    ? `${selectedStep.mitre.technique_id} - ${selectedStep.mitre.technique_name}`
    : selectedEdge
    ? `Causal link between ${selectedEdge.source_step_uid} and ${selectedEdge.target_step_uid}`
    : undefined;

  return (
    <Drawer isOpen={isOpen} onClose={onClose} title={title} subtitle={subtitle} width="xl">
      <div className="flex flex-col gap-5 font-mono text-xs select-none">
        {/* Step or Edge Context Summary Box */}
        <div className="p-4 border-2 border-[var(--border-color)] bg-[var(--bg-surface-elevated)] shadow-[3px_3px_0px_var(--border-color)] flex flex-col gap-2">
          <div className="flex items-center justify-between">
            <span className="font-black text-[var(--text-primary)] uppercase tracking-wider text-[11px]">
              {selectedStep ? "// DETECTION EXPLANATION" : "// CORRELATION JUSTIFICATION"}
            </span>
            {selectedStep && (
              <Badge variant="cyan">Confidence: {(selectedStep.detection_confidence * 100).toFixed(0)}%</Badge>
            )}
            {selectedEdge && (
              <Badge variant="green">Score: {(selectedEdge.relationship_score ?? 0.85).toFixed(2)}</Badge>
            )}
          </div>
          <p className="text-[var(--text-muted)] text-xs leading-relaxed font-medium">
            {selectedStep ? selectedStep.explanation : selectedEdge?.explanation}
          </p>

          {selectedStep?.command_line && (
            <div className="mt-2 p-2.5 bg-[var(--bg-main)] border-2 border-[var(--border-color)] text-[11px] break-all">
              <span className="text-[var(--text-dim)] block text-[10px] uppercase font-bold mb-1">{"// COMMAND LINE"}</span>
              <code className="text-[#00C8FF] font-bold">{selectedStep.command_line}</code>
            </div>
          )}
        </div>

        {/* Supporting Evidence UIDs Selector */}
        <div>
          <span className="text-[10px] uppercase tracking-wider text-[var(--text-dim)] font-black block mb-2">
            {`// SUPPORTING TELEMETRY RECORDS (${evidenceUids.length})`}
          </span>
          <div className="flex flex-wrap gap-2">
            {evidenceUids.map((uid) => (
              <button
                key={uid}
                onClick={() => setActiveEvidenceUid(uid)}
                className={`px-3 py-1.5 border-2 text-xs font-mono font-bold uppercase transition-all cursor-pointer shadow-[2px_2px_0px_var(--border-color)] active:translate-x-[1px] active:translate-y-[1px] active:shadow-none ${
                  activeEvidenceUid === uid
                    ? "bg-[#2563FF] text-white border-black shadow-[3px_3px_0px_#00C8FF]"
                    : "bg-[var(--bg-surface-elevated)] text-[var(--text-muted)] border-[var(--border-color)] hover:border-[#00C8FF] hover:text-[var(--text-primary)]"
                }`}
              >
                {uid}
              </button>
            ))}
          </div>
        </div>

        {/* Evidence Record Details */}
        {loading ? (
          <div className="p-8 border-2 border-[var(--border-color)] text-center text-[var(--text-muted)] font-bold">
            LOADING EVIDENCE TELEMETRY...
          </div>
        ) : evidenceRecord ? (
          <div className="flex flex-col gap-4">
            {/* Normalized Attributes Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 p-3.5 border-2 border-[var(--border-color)] bg-[var(--bg-surface)] shadow-[3px_3px_0px_var(--border-color)]">
              <div>
                <span className="text-[10px] text-[var(--text-dim)] uppercase block font-bold">{"// SOURCE TYPE"}</span>
                <span className="text-[var(--text-primary)] font-bold">{evidenceRecord.source_type}</span>
              </div>
              <div>
                <span className="text-[10px] text-[var(--text-dim)] uppercase block font-bold">{"// SOURCE FILE"}</span>
                <span className="text-[var(--text-primary)] font-bold truncate block" title={evidenceRecord.source_file_id}>
                  {evidenceRecord.source_file_id}
                </span>
              </div>
              <div>
                <span className="text-[10px] text-[var(--text-dim)] uppercase block font-bold">{"// TIMESTAMP"}</span>
                <span className="text-[var(--text-primary)] font-bold">{formatTimestamp(evidenceRecord.event_ts)}</span>
              </div>
              <div>
                <span className="text-[10px] text-[var(--text-dim)] uppercase block font-bold">{"// HOST"}</span>
                <span className="text-[#00C8FF] font-black">{evidenceRecord.host_name || "N/A"}</span>
              </div>
              <div>
                <span className="text-[10px] text-[var(--text-dim)] uppercase block font-bold">{"// USER"}</span>
                <span className="text-[#86D400] dark:text-[#B7FF3C] font-black">{evidenceRecord.user_name || "N/A"}</span>
              </div>
              <div>
                <span className="text-[10px] text-[var(--text-dim)] uppercase block font-bold">{"// ACTION / OUTCOME"}</span>
                <span className="text-[var(--text-primary)] font-bold">
                  {evidenceRecord.action} ({evidenceRecord.outcome})
                </span>
              </div>
            </div>

            {/* Raw Log Excerpt */}
            <div className="flex flex-col border-2 border-[var(--border-color)] bg-[var(--bg-main)] shadow-[3px_3px_0px_var(--border-color)]">
              <div className="px-3.5 py-2 border-b-2 border-[var(--border-color)] bg-[var(--bg-surface-elevated)] flex items-center justify-between">
                <span className="text-[11px] font-black text-[var(--text-primary)] uppercase tracking-wider flex items-center gap-1.5">
                  <FileCode className="w-3.5 h-3.5 text-[#00C8FF]" />
                  Raw Telemetry Excerpt
                </span>
                <button
                  onClick={handleCopyRaw}
                  className="flex items-center gap-1 text-[10px] font-bold text-[var(--text-muted)] hover:text-[#00C8FF] border border-transparent hover:border-[#00C8FF] px-2 py-0.5 cursor-pointer uppercase transition-all"
                >
                  {copied ? <Check className="w-3 h-3 text-[#B7FF3C]" /> : <Copy className="w-3 h-3" />}
                  {copied ? "COPIED" : "COPY RAW"}
                </button>
              </div>
              <pre className="p-3 text-[11px] leading-relaxed overflow-x-auto text-[var(--text-primary)] font-mono selection:bg-[#00C8FF]/30 select-text">
                {evidenceRecord.raw_log_snippet}
              </pre>
            </div>
          </div>
        ) : (
          <div className="p-6 border-2 border-dashed border-[var(--border-color)] text-center text-[var(--text-muted)] font-bold">
            Select an evidence identifier to inspect raw log telemetry.
          </div>
        )}
      </div>
    </Drawer>
  );
}
