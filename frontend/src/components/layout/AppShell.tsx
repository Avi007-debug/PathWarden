"use client";

import React, { Suspense } from "react";
import { TopBar } from "./TopBar";
import { Sidebar } from "./Sidebar";
import { CyberSplashScreen } from "@/components/ui/CyberSplashScreen";

export function AppShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex flex-col h-screen w-screen overflow-hidden bg-[var(--bg-main)]">
      <CyberSplashScreen />
      <TopBar />
      <div className="flex flex-1 overflow-hidden">
        <Suspense fallback={<div className="w-60 border-r-2 border-[var(--border-color)] bg-[var(--bg-surface)]" />}>
          <Sidebar />
        </Suspense>
        <main className="flex-1 overflow-y-auto overflow-x-hidden relative flex flex-col">
          {children}
        </main>
      </div>
    </div>
  );
}
