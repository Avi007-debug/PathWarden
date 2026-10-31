"use client";

import React, { useState, useEffect, useRef, useCallback } from "react";
import { Terminal, CheckCircle2, ChevronRight, Play, ShieldAlert, Activity, Cpu } from "lucide-react";

interface CyberSplashScreenProps {
  onComplete?: () => void;
}

const BOOT_LOGS = [
  { time: "0.012s", scope: "SYS-INIT", msg: "Allocating 8.0 GB in-memory graph budget", status: "OK" },
  { time: "0.045s", scope: "INGEST", msg: "Mounting SimEDR stream (10,000 ECS telemetry records)", status: "OK" },
  { time: "0.089s", scope: "NORMALIZER", msg: "Validating temporal timestamps, host GUIDs, & process lineage", status: "OK" },
  { time: "0.142s", scope: "CORRELATOR", msg: "Applying sliding temporal window (Tau = 300s, Max Gap = 600s)", status: "OK" },
  { time: "0.198s", scope: "GRAPH-CORE", msg: "Generating directed acyclic graph (Cytoscape Dagre engine)", status: "OK" },
  { time: "0.245s", scope: "MITRE-MAP", msg: "Correlating 9 ATT&CK tactics across 4 isolated incident chains", status: "OK" },
  { time: "0.288s", scope: "REACHABILITY", msg: "Reconciling observed lateral traversal vs potential paths", status: "OK" },
  { time: "0.320s", scope: "HUD-ONLINE", msg: "PathWarden Threat Investigation HUD stabilized", status: "READY" },
];

export function CyberSplashScreen({ onComplete }: CyberSplashScreenProps) {
  const [mounted, setMounted] = useState(false);
  const [visible, setVisible] = useState(true);
  const [fading, setFading] = useState(false);
  const [logIndex, setLogIndex] = useState(0);
  const [progress, setProgress] = useState(15);
  const logsEndRef = useRef<HTMLDivElement>(null);

  const handleDismiss = useCallback(() => {
    setFading(true);
    setTimeout(() => {
      setVisible(false);
      onComplete?.();
    }, 350);
  }, [onComplete]);

  // Display on every page mount / refresh
  useEffect(() => {
    setMounted(true);

    const interval = setInterval(() => {
      setLogIndex((prev) => {
        if (prev < BOOT_LOGS.length) {
          const next = prev + 1;
          setProgress(Math.min(100, Math.round((next / BOOT_LOGS.length) * 100)));
          return next;
        }
        clearInterval(interval);
        return prev;
      });
    }, 160);

    return () => clearInterval(interval);
  }, []);

  // Auto-dismiss after stream completes
  useEffect(() => {
    if (logIndex >= BOOT_LOGS.length) {
      const timer = setTimeout(() => {
        handleDismiss();
      }, 750);
      return () => clearTimeout(timer);
    }
  }, [logIndex, handleDismiss]);

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logIndex]);

  // Keyboard shortcut ESC to skip instantly
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && visible) {
        handleDismiss();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [visible, handleDismiss]);

  if (!mounted || !visible) return null;

  return (
    <div
      className={`fixed inset-0 z-50 flex flex-col items-center justify-center bg-[#050B14] text-[#F1F7FA] font-mono select-none transition-opacity duration-300 ${
        fading ? "opacity-0 pointer-events-none" : "opacity-100"
      }`}
    >
      {/* Background Cyber Grid & Vignette */}
      <div className="absolute inset-0 bg-grid-tech pointer-events-none opacity-40" />
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,rgba(0,200,255,0.08)_0,transparent_75%)] pointer-events-none" />

      {/* Atmospheric Scanline */}
      <div className="absolute inset-0 pointer-events-none bg-[linear-gradient(rgba(18,16,16,0)_50%,rgba(0,0,0,0.25)_50%)] bg-[length:100%_4px] opacity-25" />

      {/* Decorative Technical Crosshairs in 4 corners */}
      <div className="absolute top-6 left-6 text-[#00C8FF]/60 text-[11px] tracking-widest flex items-center gap-2">
        <Activity className="w-3.5 h-3.5 text-[#00C8FF] animate-pulse" />
        <span>+ SEC_ENCLAVE // LATENCY: 0.12ms</span>
      </div>
      <div className="absolute top-6 right-6 text-[#B7FF3C]/80 text-[11px] tracking-widest flex items-center gap-2">
        <Cpu className="w-3.5 h-3.5 text-[#B7FF3C]" />
        <span>LOCKED MEMORY: 6.4 GB / 8.0 GB +</span>
      </div>
      <div className="absolute bottom-6 left-6 text-[#546579] text-[11px] tracking-wider">
        {"CORE-ENGINE: v5.1-RELEASE // MITIGATA_ECS"}
      </div>
      <div className="absolute bottom-6 right-6 flex items-center gap-2">
        <button
          onClick={handleDismiss}
          className="px-3 py-1.5 bg-[#0B1624] border-2 border-[#1E3754] hover:border-[#00C8FF] text-xs uppercase tracking-wider text-[#00C8FF] hover:bg-[#102136] transition-all cursor-pointer shadow-[3px_3px_0px_#03080F]"
        >
          SKIP BOOT [ESC]
        </button>
      </div>

      {/* Center Boot Enclave Window */}
      <div className="relative w-full max-w-2xl mx-4 bg-[#0B1624] border-2 border-[#1E3754] shadow-[8px_8px_0px_#03080F] overflow-hidden flex flex-col">
        {/* Enclave Header Bar */}
        <div className="h-10 bg-[#0E1E31] border-b-2 border-[#1E3754] px-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="w-2.5 h-2.5 bg-[#FF334B] border border-black/40" />
            <div className="w-2.5 h-2.5 bg-[#FFB800] border border-black/40" />
            <div className="w-2.5 h-2.5 bg-[#B7FF3C] border border-black/40" />
            <span className="text-xs font-bold text-[#8E9CAE] tracking-wider ml-2">
              {"PATHWARDEN // BOOTSTRAP_SUBSYSTEM"}
            </span>
          </div>

          <div className="flex items-center gap-2 text-[10px] text-[#00C8FF] uppercase tracking-widest bg-[#00C8FF]/10 px-2 py-0.5 border border-[#00C8FF]/30">
            <span className="w-1.5 h-1.5 rounded-full bg-[#00C8FF] animate-pulse" />
            INITIALIZING
          </div>
        </div>

        {/* Brand Reticle & Logo Section */}
        <div className="p-6 flex flex-col items-center justify-center text-center border-b border-[#1E3754] relative overflow-hidden bg-gradient-to-b from-[#0E1E31]/50 to-[#0B1624]">
          {/* Holographic Radar Scanner Reticle */}
          <div className="relative mb-4 flex items-center justify-center">
            {/* Outer radar circle with sweep line */}
            <div className="w-32 h-32 rounded-full border border-[#00C8FF]/30 border-dashed animate-radar-sweep absolute" />
            {/* Middle pulsing ring */}
            <div className="w-28 h-28 rounded-full border border-[#2563FF]/40 absolute animate-ping [animation-duration:3s]" />
            {/* Targeting brackets */}
            <div className="w-24 h-24 absolute border-t-2 border-b-2 border-[#00C8FF]/50 pointer-events-none" />
            <div className="w-24 h-24 absolute border-l-2 border-r-2 border-[#00C8FF]/50 pointer-events-none" />

            {/* Neon Shield Emblem Frame */}
            <div
              style={{ width: "80px", height: "80px" }}
              className="w-20 h-20 border-2 border-[#00C8FF] bg-[#060D17] p-1.5 shadow-[0_0_24px_rgba(0,200,255,0.4)] relative z-10 flex items-center justify-center shrink-0"
            >
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img
                src="/logo.png"
                alt="PathWarden Neon Shield"
                style={{ width: "100%", height: "100%", objectFit: "contain", maxWidth: "100%", maxHeight: "100%" }}
                className="w-full h-full object-contain filter drop-shadow-[0_0_8px_#00C8FF]"
              />
            </div>
          </div>

          <h1 className="font-heading text-2xl font-black tracking-tight text-white uppercase flex items-center gap-2">
            PATHWARDEN
            <span className="text-[10px] font-mono font-bold bg-[#B7FF3C] text-black px-1.5 py-0.5 border border-black shadow-[2px_2px_0px_#000]">
              v5.1
            </span>
          </h1>
          <p className="text-xs text-[#8E9CAE] uppercase tracking-widest mt-1">
            Evidence-Driven Cyber Attack Path Reconstruction
          </p>

          {/* Equalizer Frequency Signal Meter */}
          <div className="flex items-center gap-1 mt-3">
            {[40, 65, 85, 55, 95, 75, 45, 90, 60, 80, 50, 70].map((h, i) => (
              <div
                key={i}
                className="w-1 bg-[#00C8FF] opacity-70 animate-pulse"
                style={{
                  height: `${h * 0.16}px`,
                  animationDuration: `${0.4 + (i % 5) * 0.15}s`,
                }}
              />
            ))}
          </div>
        </div>

        {/* Live Terminal Stream */}
        <div className="p-4 bg-[#07111F] text-xs h-44 overflow-y-auto border-b border-[#1E3754] font-mono flex flex-col gap-1.5">
          <div className="text-[#546579] flex items-center gap-2 pb-1 border-b border-[#14273E] text-[11px]">
            <Terminal className="w-3.5 h-3.5 text-[#00C8FF]" />
            <span>REALTIME SUBSYSTEM VERIFICATION STREAM</span>
          </div>

          {BOOT_LOGS.slice(0, logIndex).map((log, idx) => (
            <div key={idx} className="flex items-start gap-2 text-[11px] leading-tight">
              <span className="text-[#546579] shrink-0">{log.time}</span>
              <span className="text-[#00C8FF] font-semibold shrink-0">[{log.scope}]</span>
              <span className="text-[#F1F7FA] flex-1">{log.msg}</span>
              <span
                className={`text-[10px] font-bold px-1 shrink-0 ${
                  log.status === "READY"
                    ? "bg-[#B7FF3C] text-black"
                    : "bg-[#00C8FF]/20 text-[#00C8FF] border border-[#00C8FF]/40"
                }`}
              >
                {log.status}
              </span>
            </div>
          ))}

          {logIndex < BOOT_LOGS.length && (
            <div className="flex items-center gap-2 text-[11px] text-[#00C8FF] animate-pulse">
              <ChevronRight className="w-3.5 h-3.5" />
              <span>Synthesizing attack trajectory graph nodes...</span>
            </div>
          )}

          <div ref={logsEndRef} />
        </div>

        {/* Progress Bar & Status Footer */}
        <div className="p-4 bg-[#0B1624] flex flex-col gap-3">
          <div className="flex items-center justify-between text-xs">
            <div className="flex items-center gap-2">
              {progress === 100 ? (
                <CheckCircle2 className="w-4 h-4 text-[#B7FF3C]" />
              ) : (
                <div className="w-4 h-4 border-2 border-[#00C8FF] border-t-transparent animate-spin" />
              )}
              <span className="font-bold text-white uppercase tracking-wider">
                {progress === 100 ? "Reconstruction Complete" : "Ingesting Telemetry..."}
              </span>
            </div>
            <span className="text-sm font-black text-[#00C8FF]">{progress}%</span>
          </div>

          {/* Neo-brutalist hard progress meter */}
          <div className="w-full h-3 bg-[#060D17] border-2 border-[#1E3754] p-0.5">
            <div
              className="h-full bg-gradient-to-r from-[#2563FF] via-[#00C8FF] to-[#B7FF3C] transition-all duration-150"
              style={{ width: `${progress}%` }}
            />
          </div>

          <div className="flex items-center justify-between pt-1">
            <div className="text-[10px] text-[#546579] flex items-center gap-2">
              <ShieldAlert className="w-3 h-3 text-[#B7FF3C]" />
              <span>4 INCIDENTS LOADED (10K ECS TELEMETRY)</span>
            </div>

            <button
              onClick={handleDismiss}
              className="px-4 py-1.5 bg-[#B7FF3C] hover:bg-[#a5ec2c] text-black font-extrabold text-xs uppercase tracking-wider flex items-center gap-2 border-2 border-black shadow-[3px_3px_0px_#000] active:translate-x-[2px] active:translate-y-[2px] active:shadow-none transition-all cursor-pointer"
            >
              <Play className="w-3 h-3 fill-current" />
              ENTER CONSOLE
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
