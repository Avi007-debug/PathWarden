"use client";

import React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { ChevronRight, Home } from "lucide-react";

export function Breadcrumbs() {
  const pathname = usePathname();
  if (pathname === "/") return null;

  const segments = pathname.split("/").filter(Boolean);

  return (
    <nav className="flex items-center gap-1.5 text-xs font-mono text-[var(--text-muted)] py-1">
      <Link
        href="/"
        className="flex items-center gap-1 hover:text-[#00C8FF] transition-colors"
      >
        <Home className="w-3.5 h-3.5" />
        <span className="uppercase tracking-wider">ROOT</span>
      </Link>
      {segments.map((segment, idx) => {
        const href = `/${segments.slice(0, idx + 1).join("/")}`;
        const isLast = idx === segments.length - 1;
        return (
          <React.Fragment key={href}>
            <ChevronRight className="w-3 h-3 text-[var(--text-dim)] shrink-0" />
            {isLast ? (
              <span className="text-[var(--text-primary)] font-semibold uppercase tracking-wider">
                {segment}
              </span>
            ) : (
              <Link
                href={href}
                className="hover:text-[#00C8FF] transition-colors uppercase tracking-wider"
              >
                {segment}
              </Link>
            )}
          </React.Fragment>
        );
      })}
    </nav>
  );
}

