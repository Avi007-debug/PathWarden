"use client";

import React, { createContext, useContext, useEffect, useState, useCallback } from "react";
import { pathWardenApi } from "../api/client";

interface AppContextValue {
  theme: "dark" | "light";
  toggleTheme: (e?: React.MouseEvent) => void;
  isDemoMode: boolean;
  setDemoMode: (val: boolean) => void;
  backendOnline: boolean | null;
  checkBackendHealth: () => Promise<void>;
  selectedIncidentId: string;
  setSelectedIncidentId: (id: string) => void;
}

const AppContext = createContext<AppContextValue | undefined>(undefined);

export function AppProvider({ children }: { children: React.ReactNode }) {
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const [isDemoMode, setIsDemoMode] = useState<boolean>(true); // Default to synthetic scenario demo
  const [backendOnline, setBackendOnline] = useState<boolean | null>(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>("INC-2026-0841");

  const applyTheme = useCallback((t: "dark" | "light") => {
    if (t === "dark") {
      document.documentElement.classList.add("dark");
      document.documentElement.setAttribute("data-theme", "dark");
    } else {
      document.documentElement.classList.remove("dark");
      document.documentElement.setAttribute("data-theme", "light");
    }
  }, []);

  const checkBackendHealth = useCallback(async () => {
    try {
      await pathWardenApi.getStatus(false);
      setBackendOnline(true);
    } catch {
      setBackendOnline(false);
    }
  }, []);

  // Load saved theme or system preference
  useEffect(() => {
    const saved = localStorage.getItem("pathwarden_theme") as "dark" | "light" | null;
    if (saved === "dark" || saved === "light") {
      setTheme(saved);
      applyTheme(saved);
    } else {
      const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
      const initialTheme = prefersDark ? "dark" : "light";
      setTheme(initialTheme);
      applyTheme(initialTheme);
    }

    const savedMode = localStorage.getItem("pathwarden_demo_mode");
    if (savedMode !== null) {
      setIsDemoMode(savedMode === "true");
    }

    checkBackendHealth();
  }, [applyTheme, checkBackendHealth]);

  const toggleTheme = useCallback(
    (e?: React.MouseEvent) => {
      const nextTheme = theme === "dark" ? "light" : "dark";

      // If document.startViewTransition is supported and prefers-reduced-motion is false
      if (
        typeof document !== "undefined" &&
        "startViewTransition" in document &&
        !window.matchMedia("(prefers-reduced-motion: reduce)").matches
      ) {
        // Calculate circle origin coordinates from click or viewport center
        const x = e ? e.clientX : window.innerWidth / 2;
        const y = e ? e.clientY : window.innerHeight / 2;

        // Radius to furthest corner of screen
        const endRadius = Math.hypot(
          Math.max(x, window.innerWidth - x),
          Math.max(y, window.innerHeight - y)
        );

        const doc = document as unknown as {
          startViewTransition: (cb: () => void) => { ready: Promise<void> };
        };

        const transition = doc.startViewTransition(() => {
          setTheme(nextTheme);
          localStorage.setItem("pathwarden_theme", nextTheme);
          applyTheme(nextTheme);
        });

        transition.ready.then(() => {
          document.documentElement.animate(
            {
              clipPath: [
                `circle(0px at ${x}px ${y}px)`,
                `circle(${endRadius}px at ${x}px ${y}px)`,
              ],
            },
            {
              duration: 500,
              easing: "cubic-bezier(0.2, 0.9, 0.3, 1)",
              pseudoElement: "::view-transition-new(root)",
            }
          );
        });
      } else {
        setTheme(nextTheme);
        localStorage.setItem("pathwarden_theme", nextTheme);
        applyTheme(nextTheme);
      }
    },
    [theme, applyTheme]
  );

  const setDemoMode = (val: boolean) => {
    setIsDemoMode(val);
    localStorage.setItem("pathwarden_demo_mode", String(val));
  };

  return (
    <AppContext.Provider
      value={{
        theme,
        toggleTheme,
        isDemoMode,
        setDemoMode,
        backendOnline,
        checkBackendHealth,
        selectedIncidentId,
        setSelectedIncidentId,
      }}
    >
      {children}
    </AppContext.Provider>
  );
}

export function useApp() {
  const context = useContext(AppContext);
  if (!context) {
    throw new Error("useApp must be used within an AppProvider");
  }
  return context;
}
