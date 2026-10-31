"use client";

import React, { Suspense, useState } from "react";
import Link from "next/link";
import { Activity, Layers, Terminal } from "lucide-react";
import { ThemeToggle } from "@/components/ui/ThemeToggle";
import { DemoModeToggle } from "@/components/ui/DemoModeToggle";
import { CyberSplashScreen } from "@/components/ui/CyberSplashScreen";
import { Breadcrumbs } from "./Breadcrumbs";

export function TopBar() {
  const [replaySplash, setReplaySplash] = useState(false);

  return (
    <>
      {replaySplash && (
        <CyberSplashScreen
          onComplete={() => setReplaySplash(false)}
        />
      )}

      <header className="h-14 border-b-2 border-[var(--border-color)] bg-[var(--bg-surface)] px-4 flex items-center justify-between shrink-0 select-none z-30 shadow-[0_2px_0px_rgba(0,0,0,0.15)]">
        {/* Left: Branding & Context */}
        <div className="flex items-center gap-4">
          <Link href="/" className="flex items-center gap-2.5 group">
            {/* Neo-Brutalist Frame with Neon Shield Logo */}
            <div
              style={{ width: "36px", height: "36px", minWidth: "36px", minHeight: "36px" }}
              className="w-9 h-9 relative border-2 border-[var(--border-color)] bg-[#050B14] flex items-center justify-center overflow-hidden shadow-[2px_2px_0px_var(--border-color)] group-hover:shadow-[3px_3px_0px_#00C8FF] group-hover:border-[#00C8FF] group-hover:-translate-x-[1px] group-hover:-translate-y-[1px] transition-all shrink-0 p-1"
            >
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img
                src="/logo.png"
                alt="PathWarden Neon Shield Logo"
                style={{ width: "100%", height: "100%", objectFit: "contain" }}
                className="w-full h-full object-contain filter drop-shadow-[0_0_4px_#00C8FF]"
              />
            </div>
            <div className="flex flex-col">
              <div className="flex items-center gap-2">
                <span className="font-heading font-black tracking-tight text-base text-[var(--text-primary)] uppercase group-hover:text-[#00C8FF] transition-colors">
                  PathWarden
                </span>
                <span className="text-[9px] font-mono font-bold bg-[#B7FF3C] text-black border border-black px-1 py-0.2 tracking-widest uppercase shadow-[1px_1px_0px_#000]">
                  v5.1
                </span>
              </div>
              <span className="text-[10px] font-mono text-[var(--text-muted)] tracking-wider uppercase -mt-0.5 hidden sm:inline">
                Attack Path Reconstruction
              </span>
            </div>
          </Link>

          {/* Separator */}
          <div className="h-6 w-[2px] bg-[var(--border-color)] hidden md:block" />

          {/* Workspace & Dataset Context Chips with hard borders */}
          <div className="hidden lg:flex items-center gap-2.5 text-xs font-mono">
            <div className="flex items-center gap-1.5 px-2 py-0.5 bg-[var(--bg-surface-elevated)] border-2 border-[var(--border-color)] text-[var(--text-muted)] shadow-[2px_2px_0px_var(--border-color)]">
              <Layers className="w-3.5 h-3.5 text-[#00C8FF]" />
              <span className="text-[var(--text-primary)] font-bold">SimEDR Enclave</span>
              <span className="text-[var(--text-dim)]">|</span>
              <span className="text-[11px] font-semibold text-[#00C8FF]">10,000 ECS Events</span>
            </div>
            <div className="flex items-center gap-1.5 px-2 py-0.5 bg-[var(--bg-surface-elevated)] border-2 border-[var(--border-color)] text-[var(--text-muted)] shadow-[2px_2px_0px_var(--border-color)]">
              <Activity className="w-3.5 h-3.5 text-[#B7FF3C]" />
              <span className="text-[11px] uppercase font-bold text-[#86D400] dark:text-[#B7FF3C]">
                Engine: 8.7 MB/s
              </span>
            </div>
          </div>
        </div>

        {/* Right Controls: Replay Boot Reticle, Breadcrumbs, Mode Toggle, Theme */}
        <div className="flex items-center gap-3">
          <Suspense fallback={null}>
            <Breadcrumbs />
          </Suspense>

          {/* Cyber Boot Sequence Replay Button */}
          <button
            onClick={() => setReplaySplash(true)}
            title="Replay Cyber Boot Sequence"
            className="hidden sm:flex items-center gap-1.5 px-2 py-1 bg-[var(--bg-surface)] border-2 border-[var(--border-color)] hover:border-[#00C8FF] text-[10px] font-mono font-bold uppercase tracking-wider text-[var(--text-muted)] hover:text-[#00C8FF] shadow-[2px_2px_0px_var(--border-color)] hover:shadow-[3px_3px_0px_#00C8FF] hover:-translate-x-[1px] hover:-translate-y-[1px] active:translate-x-[1px] active:translate-y-[1px] active:shadow-none transition-all cursor-pointer"
          >
            <Terminal className="w-3 h-3 text-[#00C8FF]" />
            <span>BOOT RETICLE</span>
          </button>

          <div className="h-6 w-[2px] bg-[var(--border-color)] hidden sm:block" />

          <DemoModeToggle />

          <div className="h-6 w-[2px] bg-[var(--border-color)]" />

          <ThemeToggle />
        </div>
      </header>
    </>
  );
}
