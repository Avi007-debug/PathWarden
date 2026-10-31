"use client";

import React from "react";
import { CheckCircle2, AlertCircle } from "lucide-react";

export function ObservedVsPotentialExplainer() {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs select-none">
      {/* Category A: Observed Access */}
      <div className="p-4 border-2 border-[#B7FF3C] bg-[var(--bg-surface)] shadow-[4px_4px_0px_#B7FF3C] hover:shadow-[6px_6px_0px_#B7FF3C] hover:-translate-x-[2px] hover:-translate-y-[2px] transition-all flex flex-col gap-2">
        <div className="flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-[#86D400] dark:text-[#B7FF3C]" />
          <h3 className="font-black text-sm uppercase tracking-wider text-[var(--text-primary)]">
            Category A: Observed Access
          </h3>
        </div>
        <p className="text-[11px] text-[var(--text-muted)] leading-relaxed font-medium">
          Confirmed, evidence-backed access. An authenticated session (e.g. Logon Type 3, SSH, Kerberos TGS)
          or bidirectional transport flow has been directly recorded in the ingested security logs.
        </p>
        <div className="mt-1 flex items-center gap-2 text-[10px] text-[#86D400] dark:text-[#B7FF3C] font-bold">
          <span className="px-2 py-0.5 bg-[#B7FF3C] text-black border border-black shadow-[1px_1px_0px_#000] uppercase">
            OBSERVED_SESSION
          </span>
          <span>Zero inference • Grounded in raw telemetry</span>
        </div>
      </div>

      {/* Category B: Potential Reachability */}
      <div className="p-4 border-2 border-[#00C8FF] bg-[var(--bg-surface)] shadow-[4px_4px_0px_#00C8FF] hover:shadow-[6px_6px_0px_#00C8FF] hover:-translate-x-[2px] hover:-translate-y-[2px] transition-all flex flex-col gap-2">
        <div className="flex items-center gap-2">
          <AlertCircle className="w-4 h-4 text-[#00C8FF]" />
          <h3 className="font-black text-sm uppercase tracking-wider text-[var(--text-primary)]">
            Category B: Potential Reachability
          </h3>
        </div>
        <p className="text-[11px] text-[var(--text-muted)] leading-relaxed font-medium">
          Hypothetical blast radius derived from open firewall routing or harvested Active Directory privileges.
          No active session is confirmed on the target. Unverified network reachability is explicitly noted.
        </p>
        <div className="mt-1 flex flex-wrap items-center gap-2 text-[10px] font-bold">
          <span className="px-2 py-0.5 bg-[#00C8FF] text-black border border-black shadow-[1px_1px_0px_#000] uppercase">
            NETWORK_REACHABLE
          </span>
          <span className="px-2 py-0.5 bg-amber-400 text-black border border-black shadow-[1px_1px_0px_#000] uppercase">
            PRIVILEGE_RELATIONSHIP
          </span>
        </div>
      </div>
    </div>
  );
}
