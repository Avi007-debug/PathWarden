"use client";

import React, { useEffect } from "react";
import { X } from "lucide-react";
import { cn } from "@/lib/utils/cn";

interface DrawerProps {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  subtitle?: string;
  children: React.ReactNode;
  width?: "md" | "lg" | "xl";
}

export function Drawer({
  isOpen,
  onClose,
  title,
  subtitle,
  children,
  width = "lg",
}: DrawerProps) {
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    if (isOpen) {
      window.addEventListener("keydown", handleKeyDown);
    }
    return () => {
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const widthStyles = {
    md: "max-w-md",
    lg: "max-w-xl",
    xl: "max-w-3xl",
  };

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-black/75 backdrop-blur-[2px] animate-in fade-in duration-200 select-none">
      <div className="absolute inset-y-0 right-0 max-w-full flex pl-10">
        <div
          className={cn(
            "w-screen bg-[var(--bg-surface)] border-l-2 border-[var(--border-color)] shadow-[-8px_0px_0px_rgba(0,0,0,0.4)] flex flex-col animate-in slide-in-from-right duration-200",
            widthStyles[width]
          )}
        >
          {/* Drawer Header */}
          <div className="p-4 border-b-2 border-[var(--border-color)] bg-[var(--bg-surface-elevated)] flex items-start justify-between">
            <div>
              <h2 className="font-mono text-sm font-black tracking-wider uppercase text-[var(--text-primary)] flex items-center gap-2">
                <span className="w-2.5 h-2.5 bg-[#00C8FF]" />
                {title}
              </h2>
              {subtitle && (
                <p className="font-mono text-xs text-[var(--text-muted)] font-medium mt-1">
                  {subtitle}
                </p>
              )}
            </div>
            <button
              onClick={onClose}
              className="p-1.5 text-[var(--text-muted)] hover:text-[#FF334B] border border-transparent hover:border-[#FF334B] transition-all cursor-pointer"
              aria-label="Close Drawer"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Drawer Body */}
          <div className="flex-1 p-6 overflow-y-auto">{children}</div>
        </div>
      </div>
    </div>
  );
}
