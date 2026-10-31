"use client";

import React from "react";
import { Sun, Moon } from "lucide-react";
import { useApp } from "@/lib/context/AppContext";
import { cn } from "@/lib/utils/cn";

export function ThemeToggle({ className }: { className?: string }) {
  const { theme, toggleTheme } = useApp();
  const isDark = theme === "dark";

  return (
    <button
      onClick={(e) => toggleTheme(e)}
      title={`Switch to ${isDark ? "Light" : "Dark"} Mode (Current: ${isDark ? "Dark" : "Light"})`}
      aria-label="Toggle Theme"
      className={cn(
        "relative flex items-center justify-between w-16 h-8 p-1 bg-[var(--bg-surface)] border-2 border-[var(--border-color)] shadow-[3px_3px_0px_var(--border-color)] hover:shadow-[4px_4px_0px_var(--accent-cyan)] hover:-translate-x-[1px] hover:-translate-y-[1px] active:translate-x-[1px] active:translate-y-[1px] active:shadow-none transition-all cursor-pointer select-none group",
        className
      )}
    >
      {/* Background Icons */}
      <span className="flex items-center justify-center w-6 h-6 text-amber-500 opacity-80 group-hover:opacity-100 transition-opacity">
        <Sun className={cn("w-3.5 h-3.5 transition-transform duration-300", !isDark && "rotate-45 scale-110")} />
      </span>
      <span className="flex items-center justify-center w-6 h-6 text-[#00C8FF] opacity-80 group-hover:opacity-100 transition-opacity">
        <Moon className={cn("w-3.5 h-3.5 transition-transform duration-300", isDark && "-rotate-12 scale-110")} />
      </span>

      {/* Mechanical Sliding Neo-Brutalist Knob */}
      <div
        className={cn(
          "absolute top-0.5 bottom-0.5 w-7 bg-[var(--bg-surface-elevated)] border-2 border-[var(--border-color)] flex items-center justify-center transition-all duration-300 ease-[cubic-bezier(0.34,1.56,0.64,1)] shadow-[1px_1px_0px_var(--border-color)]",
          isDark
            ? "left-[calc(100%-1.85rem)] bg-[#112236] text-[#00C8FF] border-[#00C8FF]"
            : "left-0.5 bg-[#FFF275] text-[#101820] border-[#101820]"
        )}
      >
        {isDark ? (
          <Moon className="w-3.5 h-3.5 text-[#00C8FF] animate-pulse" />
        ) : (
          <Sun className="w-3.5 h-3.5 text-[#101820] animate-[spin_10s_linear_infinite]" />
        )}
      </div>
    </button>
  );
}
