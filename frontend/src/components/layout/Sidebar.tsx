"use client";

import React, { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  ShieldAlert,
  GitFork,
  Radio,
  FileCheck2,
  Gauge,
  ChevronLeft,
  ChevronRight,
  Cpu,
} from "lucide-react";
import { cn } from "@/lib/utils/cn";
import { useApp } from "@/lib/context/AppContext";

interface NavItem {
  label: string;
  href: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: string;
  matchPrefix?: boolean;
}

export function Sidebar() {
  const pathname = usePathname();
  const [collapsed, setCollapsed] = useState(false);
  const { selectedIncidentId, incidentCount, systemStatus, isDemoMode } = useApp();

  const usedRamGb = systemStatus?.memory_used_gb ?? (isDemoMode ? 6.4 : 1.2);
  const budgetCapGb = systemStatus?.memory_budget_gb ?? (systemStatus?.machine_specifications?.budget_limit_gb ?? 8.0);
  const ramUsagePct = systemStatus?.memory_usage_pct ?? Math.min(100, Math.round((usedRamGb / budgetCapGb) * 100));
  const totalHostRamGb = systemStatus?.machine_specifications?.total_ram_gb;
  const processRssMb = systemStatus?.machine_specifications?.process_memory_mb;
  const cpuPct = systemStatus?.cpu_usage_pct;

  const navItems: NavItem[] = [
    {
      label: "Overview",
      href: "/",
      icon: LayoutDashboard,
    },
    {
      label: "Incidents",
      href: "/incidents",
      icon: ShieldAlert,
      badge: incidentCount > 0 ? String(incidentCount) : "2",
      matchPrefix: true,
    },
    {
      label: "Attack Path",
      href: `/incidents/${selectedIncidentId}`,
      icon: GitFork,
    },
    {
      label: "Reachability",
      href: "/reachability",
      icon: Radio,
    },
    {
      label: "Data Quality",
      href: "/data-quality",
      icon: FileCheck2,
    },
    {
      label: "Benchmarks",
      href: "/benchmarks",
      icon: Gauge,
      badge: "30GB",
    },
  ];

  return (
    <aside
      className={cn(
        "border-r-2 border-[var(--border-color)] bg-[var(--bg-surface)] flex flex-col justify-between shrink-0 select-none transition-all duration-200 z-20 shadow-[2px_0px_0px_rgba(0,0,0,0.1)]",
        collapsed ? "w-16" : "w-60"
      )}
    >
      {/* Navigation List */}
      <div className="flex flex-col py-3">
        <div className="px-3 pb-2 flex items-center justify-between">
          {!collapsed && (
            <span className="text-[10px] font-mono font-bold tracking-widest uppercase text-[var(--text-dim)]">
              {"// HUD_NAVIGATION"}
            </span>
          )}
          <button
            onClick={() => setCollapsed(!collapsed)}
            className="p-1 text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-surface-elevated)] border-2 border-[var(--border-color)] shadow-[2px_2px_0px_var(--border-color)] hover:shadow-[3px_3px_0px_#00C8FF] hover:border-[#00C8FF] transition-all cursor-pointer ml-auto"
            title={collapsed ? "Expand Sidebar" : "Collapse Sidebar"}
          >
            {collapsed ? (
              <ChevronRight className="w-3.5 h-3.5" />
            ) : (
              <ChevronLeft className="w-3.5 h-3.5" />
            )}
          </button>
        </div>

        <nav className="flex flex-col gap-1.5 px-2">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive =
              item.href === "/"
                ? pathname === "/"
                : item.matchPrefix
                ? pathname.startsWith(item.href) && !pathname.includes(selectedIncidentId)
                : pathname === item.href;

            return (
              <Link
                key={item.label}
                href={item.href}
                className={cn(
                  "flex items-center gap-3 px-3 py-2 text-xs font-mono uppercase tracking-wider font-bold border-2 transition-all group relative",
                  isActive
                    ? "bg-[#2563FF]/20 text-[#00C8FF] border-[#00C8FF] shadow-[3px_3px_0px_#00C8FF] -translate-x-[1px] -translate-y-[1px]"
                    : "text-[var(--text-muted)] border-transparent hover:text-[var(--text-primary)] hover:bg-[var(--bg-surface-elevated)] hover:border-[var(--border-color)] hover:shadow-[3px_3px_0px_var(--border-color)] hover:-translate-x-[1px] hover:-translate-y-[1px]"
                )}
                title={collapsed ? item.label : undefined}
              >
                {/* Active indicator bar */}
                {isActive && (
                  <div className="absolute left-0 top-0 bottom-0 w-1 bg-[#00C8FF]" />
                )}

                <Icon
                  className={cn(
                    "w-4 h-4 shrink-0 transition-colors",
                    isActive
                      ? "text-[#00C8FF]"
                      : "text-[var(--text-dim)] group-hover:text-[var(--text-primary)]"
                  )}
                />

                {!collapsed && (
                  <div className="flex items-center justify-between w-full">
                    <span>{item.label}</span>
                    {item.badge && (
                      <span
                        className={cn(
                          "text-[9px] px-1.5 py-0.2 font-mono font-bold tracking-widest border border-black/30",
                          isActive
                            ? "bg-[#00C8FF] text-black shadow-[1px_1px_0px_#000]"
                            : "bg-[var(--bg-surface-elevated)] text-[var(--text-dim)] border-[var(--border-color)]"
                        )}
                      >
                        {item.badge}
                      </span>
                    )}
                  </div>
                )}
              </Link>
            );
          })}
        </nav>
      </div>

      {/* Bottom Telemetry & Resource Budget Footprint */}
      <div
        className="p-3 border-t-2 border-[var(--border-color)] bg-[var(--bg-surface-elevated)]"
        title={
          totalHostRamGb
            ? `Host Physical RAM: ${usedRamGb.toFixed(1)} / ${totalHostRamGb.toFixed(1)} GB | Process Peak: ${processRssMb ? processRssMb.toFixed(0) : 175} MB | Enclave Budget Cap: ${budgetCapGb.toFixed(1)} GB${cpuPct !== undefined ? ` | CPU: ${cpuPct}%` : ""}`
            : `RAM Budget: ${usedRamGb.toFixed(1)} / ${budgetCapGb.toFixed(1)} GB`
        }
      >
        {!collapsed ? (
          <div className="flex flex-col gap-2 font-mono text-[11px]">
            <div className="flex items-center justify-between text-[var(--text-muted)]">
              <span className="flex items-center gap-1.5 font-bold">
                <Cpu className="w-3.5 h-3.5 text-[#B7FF3C]" />
                RAM Budget
              </span>
              <span className="text-[var(--text-primary)] font-bold">
                {usedRamGb.toFixed(1)} / {budgetCapGb.toFixed(1)} GB
              </span>
            </div>
            {/* Neo-brutalist memory progress meter */}
            <div className="w-full h-2.5 bg-[#050B14] border-2 border-[var(--border-color)] p-0.5">
              <div
                className="h-full bg-gradient-to-r from-[#00C8FF] to-[#B7FF3C] transition-all duration-500"
                style={{ width: `${Math.max(4, Math.min(100, ramUsagePct))}%` }}
              />
            </div>
            <div className="flex items-center justify-between text-[10px] text-[var(--text-dim)] font-bold">
              <span>ENCLAVE LOCK</span>
              <span>{budgetCapGb.toFixed(1)} GB MAX</span>
            </div>
          </div>
        ) : (
          <div className="flex justify-center" title={`RAM Budget: ${usedRamGb.toFixed(1)} / ${budgetCapGb.toFixed(1)} GB`}>
            <Cpu className="w-4 h-4 text-[#B7FF3C]" />
          </div>
        )}
      </div>
    </aside>
  );
}
