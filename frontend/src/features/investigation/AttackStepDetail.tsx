"use client";

import React from "react";
import { AttackStep } from "@/lib/api/types";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { formatTimestamp } from "@/lib/utils/formatters";
import {
  Server,
  User,
  Terminal,
  FileSearch,
  AlertTriangle,
  X,
} from "lucide-react";

interface AttackStepDetailProps {
  step: AttackStep;
  onClose: () => void;
  onInspectEvidence: (step: AttackStep) => void;
}

export function AttackStepDetail({
  step,
  onClose,
  onInspectEvidence,
}: AttackStepDetailProps) {
  return (
    <div className="border-2 border-[var(--border-color)] bg-[var(--bg-surface)] shadow-[4px_4px_0px_var(--border-color)] hover:shadow-[6px_6px_0px_var(--border-color)] transition-all flex flex-col font-mono text-xs select-none">
      {/* Header */}
      <div className="p-3.5 border-b-2 border-[var(--border-color)] bg-[var(--bg-surface-elevated)] flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Badge variant={step.severity === "CRITICAL" ? "critical" : "warning"}>
            STEP #{step.order_index}
          </Badge>
          <span className="font-black text-[var(--text-primary)] tracking-wider">{step.step_uid}</span>
        </div>
        <button
          onClick={onClose}
          className="p-1 text-[var(--text-muted)] hover:text-[#FF334B] border border-transparent hover:border-[#FF334B] cursor-pointer transition-all"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Content */}
      <div className="p-4 flex flex-col gap-4 overflow-y-auto max-h-[380px]">
        {/* Technique Title & Tactic */}
        <div>
          <div className="flex items-center gap-2 text-sm font-black text-[var(--text-primary)] mb-1">
            <span className="text-[#00C8FF]">{step.mitre.technique_id}</span>
            <span>{step.mitre.technique_name}</span>
          </div>
          <div className="flex items-center gap-2 text-[11px] text-[var(--text-muted)] font-bold">
            <span>TACTIC: {step.mitre.tactic}</span>
            <span>•</span>
            <span>KILL CHAIN: {step.kill_chain_stage}</span>
          </div>
        </div>

        {/* Rule Explanation */}
        <div className="p-3 bg-[var(--bg-main)] border-2 border-[var(--border-color)] shadow-[2px_2px_0px_var(--border-color)]">
          <span className="text-[10px] uppercase font-black text-[var(--text-dim)] block mb-1">
            {`// DETECTION LOGIC: ${step.rule_name}`}
          </span>
          <p className="text-[var(--text-muted)] leading-relaxed font-medium">{step.explanation}</p>
        </div>

        {/* Entities Grid */}
        <div className="grid grid-cols-2 gap-2 text-[11px]">
          <div className="p-2.5 border-2 border-[var(--border-color)] bg-[var(--bg-surface-elevated)] shadow-[2px_2px_0px_var(--border-color)]">
            <span className="text-[10px] text-[var(--text-dim)] block uppercase font-bold">{"// HOST"}</span>
            <span className="text-[var(--text-primary)] font-bold flex items-center gap-1.5 mt-0.5">
              <Server className="w-3.5 h-3.5 text-[#00C8FF]" />
              {step.host_name}
            </span>
          </div>
          <div className="p-2.5 border-2 border-[var(--border-color)] bg-[var(--bg-surface-elevated)] shadow-[2px_2px_0px_var(--border-color)]">
            <span className="text-[10px] text-[var(--text-dim)] block uppercase font-bold">{"// USER ACCOUNT"}</span>
            <span className="text-[var(--text-primary)] font-bold flex items-center gap-1.5 mt-0.5">
              <User className="w-3.5 h-3.5 text-[#86D400] dark:text-[#B7FF3C]" />
              {step.user_name}
            </span>
          </div>
          {step.process_name && (
            <div className="p-2.5 border-2 border-[var(--border-color)] bg-[var(--bg-surface-elevated)] shadow-[2px_2px_0px_var(--border-color)]">
              <span className="text-[10px] text-[var(--text-dim)] block uppercase font-bold">{"// PROCESS (PID)"}</span>
              <span className="text-[var(--text-primary)] font-bold flex items-center gap-1.5 mt-0.5 truncate">
                <Terminal className="w-3.5 h-3.5 text-[#FFB800]" />
                {step.process_name} {step.process_id ? `(${step.process_id})` : ""}
              </span>
            </div>
          )}
          <div className="p-2.5 border-2 border-[var(--border-color)] bg-[var(--bg-surface-elevated)] shadow-[2px_2px_0px_var(--border-color)]">
            <span className="text-[10px] text-[var(--text-dim)] block uppercase font-bold">{"// TIMESTAMP"}</span>
            <span className="text-[var(--text-primary)] font-bold mt-0.5 block truncate">
              {formatTimestamp(step.timestamp)}
            </span>
          </div>
        </div>

        {/* Data Quality Caveats */}
        {step.dq_flags && step.dq_flags.length > 0 && (
          <div className="p-2.5 bg-amber-500/10 border-2 border-amber-500/40 text-amber-500 flex items-start gap-2 shadow-[2px_2px_0px_#FFB800]">
            <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
            <div>
              <span className="font-black block text-[10px] uppercase">{"// DATA QUALITY FLAG"}</span>
              <span className="text-[11px] font-medium">{step.dq_flags.join(", ")}: Inferred attributes retained.</span>
            </div>
          </div>
        )}

        {/* Actions */}
        <div className="pt-2 flex items-center gap-2">
          <Button
            variant="cyan"
            size="sm"
            className="w-full"
            icon={<FileSearch className="w-3.5 h-3.5" />}
            onClick={() => onInspectEvidence(step)}
          >
            Inspect Evidence ({step.evidence_event_uids.length} Records)
          </Button>
        </div>
      </div>
    </div>
  );
}
