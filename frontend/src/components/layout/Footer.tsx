"use client";

import React from "react";
import Link from "next/link";
import { useApp } from "@/lib/context/AppContext";
import {
  ShieldCheck,
  Activity,
  ArrowUp,
  GitFork,
  Radio,
  FileCheck2,
  Gauge,
  Layers,
  LayoutDashboard,
} from "lucide-react";

export function Footer() {
  const { selectedIncidentId } = useApp();
  const scrollToTop = () => {
    if (typeof window !== "undefined") {
      const mainElement = document.querySelector("main");
      if (mainElement) {
        mainElement.scrollTo({ top: 0, behavior: "smooth" });
      } else {
        window.scrollTo({ top: 0, behavior: "smooth" });
      }
    }
  };

  return (
    <footer className="mt-auto border-t-2 border-[var(--border-color)] bg-[var(--bg-surface)] font-mono text-xs select-none shadow-[0_-2px_0px_rgba(0,0,0,0.1)] shrink-0">
      {/* Top Banner Row */}
      <div className="max-w-7xl mx-auto px-6 py-6 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {/* Col 1: System Brand & Enclave Status */}
        <div className="flex flex-col gap-2.5">
          <div className="flex items-center gap-2">
            <div className="w-6 h-6 border border-[var(--border-color)] bg-transparent flex items-center justify-center shadow-[1px_1px_0px_var(--border-color)] p-0.5">
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img src="/logo.png" alt="PathWarden" className="w-full h-full object-contain filter drop-shadow-[0_0_2px_#00C8FF]" />
            </div>
            <span className="font-heading font-black text-sm uppercase tracking-tight text-[var(--text-primary)]">
              PathWarden
            </span>
            <span className="text-[9px] font-bold bg-[#B7FF3C] text-black border border-black px-1.5 py-0.2 shadow-[1px_1px_0px_#000]">
              v5.1
            </span>
          </div>
          <p className="text-[11px] text-[var(--text-muted)] leading-relaxed">
            Evidence-driven cyberattack reconstruction, deterministic DAG graph correlation, and explainable blast-radius analysis.
          </p>
          <div className="flex items-center gap-2 mt-1">
            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 bg-[#B7FF3C]/15 border border-[#86D400] text-[#86D400] dark:text-[#B7FF3C] text-[10px] font-extrabold uppercase">
              <span className="w-1.5 h-1.5 rounded-full bg-[#86D400] dark:bg-[#B7FF3C] animate-pulse" />
              SOC Enclave Online
            </span>
            <span className="text-[10px] text-[var(--text-dim)] font-bold">
              30 GB Tier
            </span>
          </div>
        </div>

        {/* Col 2: Navigation HUD */}
        <div className="flex flex-col gap-2">
          <span className="text-[10px] uppercase font-black tracking-wider text-[var(--text-dim)] pb-1 border-b border-[var(--border-subtle)]">
            {"// QUICK NAVIGATION"}
          </span>
          <nav className="flex flex-col gap-1.5 text-[11px]">
            <Link
              href="/"
              className="flex items-center gap-1.5 text-[var(--text-muted)] hover:text-[#00C8FF] hover:translate-x-1 transition-all"
            >
              <LayoutDashboard className="w-3 h-3 text-[#2563FF]" />
              <span>Investigation Overview</span>
            </Link>
            <Link
              href="/incidents"
              className="flex items-center gap-1.5 text-[var(--text-muted)] hover:text-[#00C8FF] hover:translate-x-1 transition-all"
            >
              <ShieldCheck className="w-3 h-3 text-[#FF334B]" />
              <span>Incidents Explorer</span>
            </Link>
            <Link
              href={`/incidents/${selectedIncidentId}`}
              className="flex items-center gap-1.5 text-[var(--text-muted)] hover:text-[#00C8FF] hover:translate-x-1 transition-all"
            >
              <GitFork className="w-3 h-3 text-[#00C8FF]" />
              <span>Attack Path DAG ({selectedIncidentId})</span>
            </Link>
            <Link
              href="/reachability"
              className="flex items-center gap-1.5 text-[var(--text-muted)] hover:text-[#00C8FF] hover:translate-x-1 transition-all"
            >
              <Radio className="w-3 h-3 text-[#86D400] dark:text-[#B7FF3C]" />
              <span>Reachability & Blast Radius</span>
            </Link>
          </nav>
        </div>

        {/* Col 3: Quality & Benchmark Metrics */}
        <div className="flex flex-col gap-2">
          <span className="text-[10px] uppercase font-black tracking-wider text-[var(--text-dim)] pb-1 border-b border-[var(--border-subtle)]">
            {"// VERIFICATION & COMPLIANCE"}
          </span>
          <nav className="flex flex-col gap-1.5 text-[11px]">
            <Link
              href="/data-quality"
              className="flex items-center gap-1.5 text-[var(--text-muted)] hover:text-[#00C8FF] hover:translate-x-1 transition-all"
            >
              <FileCheck2 className="w-3 h-3 text-[#FFB800]" />
              <span>Data Quality Reconciliation</span>
            </Link>
            <Link
              href="/benchmarks"
              className="flex items-center gap-1.5 text-[var(--text-muted)] hover:text-[#00C8FF] hover:translate-x-1 transition-all"
            >
              <Gauge className="w-3 h-3 text-[#2563FF]" />
              <span>30 GB Performance Benchmarks</span>
            </Link>
            <div className="flex items-center gap-1.5 text-[var(--text-dim)] pt-1 text-[10px]">
              <Layers className="w-3 h-3 text-[#00BFA6]" />
              <span>MITRE ATT&CK v14.1 Enterprise</span>
            </div>
            <div className="flex items-center gap-1.5 text-[var(--text-dim)] text-[10px]">
              <Activity className="w-3 h-3 text-[#B7FF3C]" />
              <span>Elastic Common Schema (ECS 1.12)</span>
            </div>
          </nav>
        </div>

        {/* Col 4: Platform Engine Specs & Back to Top */}
        <div className="flex flex-col justify-between gap-4 p-3 border-2 border-[var(--border-color)] bg-[var(--bg-surface-elevated)] shadow-[2px_2px_0px_var(--border-color)]">
          <div>
            <span className="text-[10px] uppercase font-extrabold text-[var(--text-dim)] block mb-1">
              {"// EXECUTION PROFILE"}
            </span>
            <div className="flex flex-col gap-1 text-[10px] text-[var(--text-muted)] font-bold">
              <span>Memory Budget: 8.0 GB Enclave Cap</span>
              <span>Host Constraints: 8 Cores • 16 GB RAM</span>
              <span className="text-[#00C8FF]">Engine Throughput: 8.7 MB/s</span>
            </div>
          </div>

          <button
            onClick={scrollToTop}
            className="flex items-center justify-center gap-1.5 px-3 py-1.5 bg-[var(--bg-surface)] hover:bg-[#00C8FF] text-[var(--text-primary)] hover:text-black border-2 border-[var(--border-color)] shadow-[2px_2px_0px_var(--border-color)] hover:shadow-none hover:translate-x-[1px] hover:translate-y-[1px] font-bold text-[10px] uppercase transition-all cursor-pointer"
          >
            <ArrowUp className="w-3.5 h-3.5" />
            <span>Return to Top</span>
          </button>
        </div>
      </div>

      {/* Bottom Sub-bar */}
      <div className="border-t-2 border-[var(--border-color)] bg-[var(--bg-surface-elevated)] px-6 py-2.5">
        <div className="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-3 text-[10px] text-[var(--text-dim)]">
          <div className="flex items-center gap-2">
            <span>© 2026 PathWarden Security Operations</span>
            <span>•</span>
            <span className="text-[var(--text-muted)]">Evidence-grounded intrusion reconstruction</span>
          </div>

          <div className="flex items-center gap-3 font-mono font-bold">
            <span className="text-[#86D400] dark:text-[#B7FF3C]">● UTC TIME SYNCHRONIZED</span>
            <span>•</span>
            <span>CONFIDENTIAL SOC TELEMETRY</span>
          </div>
        </div>
      </div>
    </footer>
  );
}

