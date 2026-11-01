"use client";

import React from "react";
import { AttackStep } from "@/lib/api/types";
import { formatTimeOnly } from "@/lib/utils/formatters";
import { Badge } from "@/components/ui/Badge";
import { Clock, Terminal, User, Server, FileSearch, Maximize2, Minimize2 } from "lucide-react";
import { cn } from "@/lib/utils/cn";

interface ChronologicalTimelineProps {
  steps: AttackStep[];
  selectedStepUid: string | null;
  onSelectStep: (step: AttackStep) => void;
  onInspectEvidence: (step: AttackStep) => void;
  isEnlarged?: boolean;
  onToggleEnlarge?: () => void;
}

export function ChronologicalTimeline({
  steps,
  selectedStepUid,
  onSelectStep,
  onInspectEvidence,
  isEnlarged = false,
  onToggleEnlarge,
}: ChronologicalTimelineProps) {
  return (
    <div className="flex flex-col border-2 border-[var(--border-color)] bg-[var(--bg-surface)] shadow-[4px_4px_0px_var(--border-color)] hover:shadow-[6px_6px_0px_var(--border-color)] transition-all h-full overflow-hidden select-none">
      {/* Timeline Header */}
      <div className="px-4 py-3 border-b-2 border-[var(--border-color)] bg-[var(--bg-surface-elevated)] flex items-center justify-between shrink-0">
        <div className="flex items-center gap-2">
          <Clock className="w-4 h-4 text-[#00C8FF]" />
          <h3 className="font-mono text-xs font-black uppercase tracking-wider text-[var(--text-primary)]">
            Chronological Attack Timeline
          </h3>
        </div>
        <div className="flex items-center gap-2">
          <span className="font-mono text-[10px] font-bold text-[var(--text-dim)] uppercase bg-[var(--bg-surface)] px-2 py-0.5 border border-[var(--border-color)]">
            {steps.length} Steps
          </span>
          {onToggleEnlarge && (
            <button
              onClick={onToggleEnlarge}
              className={cn(
                "px-2 py-0.5 border text-xs font-mono font-bold flex items-center gap-1 transition-all cursor-pointer shadow-[2px_2px_0px_var(--border-color)]",
                isEnlarged
                  ? "bg-[#B7FF3C] text-black border-black shadow-[2px_2px_0px_#000]"
                  : "bg-[var(--bg-surface)] text-[var(--text-muted)] hover:text-[#00C8FF] border-[var(--border-color)]"
              )}
              title={isEnlarged ? "Restore Standard View (Esc)" : "Enlarge Cytoscape & Timeline Full Window (Side-by-Side)"}
            >
              {isEnlarged ? <Minimize2 className="w-3.5 h-3.5" /> : <Maximize2 className="w-3.5 h-3.5" />}
              <span className="text-[10px] uppercase font-bold">{isEnlarged ? "RESTORE" : "ENLARGE"}</span>
            </button>
          )}
        </div>
      </div>

      {/* Steps List */}
      <div className="flex-1 overflow-y-auto divide-y-2 divide-[var(--border-subtle)]">
        {steps.map((step) => {
          const isSelected = selectedStepUid === step.step_uid;

          return (
            <div
              key={step.step_uid}
              onClick={() => onSelectStep(step)}
              className={cn(
                "p-3.5 transition-all cursor-pointer font-mono group relative",
                isSelected
                  ? "bg-[#2563FF]/15 border-l-4 border-l-[#00C8FF] shadow-[inset_0_0_12px_rgba(0,200,255,0.1)]"
                  : "hover:bg-[var(--bg-surface-elevated)] border-l-4 border-l-transparent"
              )}
            >
              {/* Top row: Order, Timestamp, Severity & Kill Chain Badge */}
              <div className="flex items-center justify-between mb-1.5 text-xs">
                <div className="flex items-center gap-2">
                  <span className="font-black text-[#00C8FF] text-sm">#{step.order_index}</span>
                  <span className="text-[var(--text-primary)] font-bold text-[11px]">
                    {formatTimeOnly(step.timestamp)}
                  </span>
                </div>
                <div className="flex items-center gap-1.5">
                  <Badge variant={step.severity === "CRITICAL" ? "critical" : step.severity === "HIGH" ? "warning" : "default"}>
                    {step.severity}
                  </Badge>
                  <span className="text-[9px] bg-[var(--bg-surface-elevated)] border border-[var(--border-color)] px-1.5 py-0.2 text-[var(--text-muted)] font-bold uppercase">
                    {step.kill_chain_stage}
                  </span>
                </div>
              </div>

              {/* Technique & Description */}
              <div className="mb-2">
                <div className="flex items-center gap-2 text-xs font-bold text-[var(--text-primary)] group-hover:text-[#00C8FF] transition-colors">
                  <span className="text-[#2563FF] font-black">{step.mitre.technique_id}</span>
                  <span>{step.mitre.technique_name}</span>
                </div>
                <p className="text-[11px] text-[var(--text-muted)] line-clamp-2 mt-1 leading-relaxed font-medium">
                  {step.explanation}
                </p>
              </div>

              {/* Host, User & Process Entities */}
              <div className="flex flex-wrap items-center gap-3 text-[10px] text-[var(--text-dim)] pt-1.5 border-t border-[var(--border-subtle)]">
                <span className="flex items-center gap-1 text-[var(--text-muted)] font-bold">
                  <Server className="w-3 h-3 text-[#00C8FF]" />
                  {step.host_name}
                </span>
                <span className="flex items-center gap-1 text-[var(--text-muted)] font-bold">
                  <User className="w-3 h-3 text-[#86D400] dark:text-[#B7FF3C]" />
                  {step.user_name}
                </span>
                {step.process_name && (
                  <span className="flex items-center gap-1 text-[var(--text-muted)] font-bold">
                    <Terminal className="w-3 h-3 text-[#FFB800]" />
                    {step.process_name}
                  </span>
                )}

                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    onInspectEvidence(step);
                  }}
                  className="ml-auto flex items-center gap-1 text-[#00C8FF] hover:text-[#B7FF3C] font-bold cursor-pointer uppercase transition-colors"
                >
                  <FileSearch className="w-3 h-3" />
                  <span>{step.evidence_event_uids.length} Evidence</span>
                </button>
              </div>
            </div>
          );
        })}
      </div>

      {/* Timeline Footer / End of Sequence Marker */}
      <div className="p-2.5 border-t-2 border-[var(--border-color)] bg-[var(--bg-surface-elevated)] shrink-0 flex items-center justify-between text-[10px] text-[var(--text-dim)] font-bold">
        <span>{"// END OF ATTACK PATH"}</span>
        <span className="text-[#86D400] dark:text-[#B7FF3C]">ALL STEPS CORRELATED</span>
      </div>
    </div>
  );
}
