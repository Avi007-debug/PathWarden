"use client";

import React from "react";
import { ShieldCheck, Wifi, WifiOff } from "lucide-react";
import { useApp } from "@/lib/context/AppContext";
import { cn } from "@/lib/utils/cn";

export function DemoModeToggle({ className }: { className?: string }) {
  const { isDemoMode, setDemoMode, backendOnline } = useApp();

  return (
    <div className={cn("flex items-center gap-2", className)}>
      <button
        onClick={() => setDemoMode(!isDemoMode)}
        className={cn(
          "flex items-center gap-2 px-3 py-1 text-xs font-mono border-2 transition-all cursor-pointer shadow-[2px_2px_0px_var(--border-color)] hover:shadow-[3px_3px_0px_#00C8FF] hover:-translate-x-[1px] hover:-translate-y-[1px] active:translate-x-[1px] active:translate-y-[1px] active:shadow-none select-none",
          isDemoMode
            ? "bg-[#00C8FF]/15 text-[#00C8FF] border-[#00C8FF]"
            : backendOnline
            ? "bg-[#B7FF3C]/15 text-[#86D400] dark:text-[#B7FF3C] border-[#B7FF3C]"
            : "bg-amber-500/15 text-amber-500 border-amber-500"
        )}
        title="Toggle between Live FastAPI Backend and Synthetic Demonstration Fixtures"
      >
        <span
          className={cn(
            "w-2 h-2 rounded-full shrink-0 animate-pulse",
            isDemoMode ? "bg-[#00C8FF]" : backendOnline ? "bg-[#B7FF3C]" : "bg-amber-500"
          )}
        />
        <span className="font-bold tracking-wider uppercase text-[10px]">
          {isDemoMode ? "DEMO DATA - SYNTHETIC SCENARIO" : "LIVE BACKEND API"}
        </span>

        {isDemoMode ? (
          <ShieldCheck className="w-3.5 h-3.5 ml-1 text-[#00C8FF]" />
        ) : backendOnline ? (
          <Wifi className="w-3.5 h-3.5 ml-1 text-[#B7FF3C]" />
        ) : (
          <WifiOff className="w-3.5 h-3.5 ml-1 text-amber-500" />
        )}
      </button>
    </div>
  );
}
