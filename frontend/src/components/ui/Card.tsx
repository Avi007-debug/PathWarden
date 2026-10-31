import React from "react";
import { cn } from "@/lib/utils/cn";

interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: "default" | "elevated" | "accent" | "critical" | "cyan" | "green";
  interactive?: boolean;
  withCorners?: boolean;
}

export function Card({
  className,
  variant = "default",
  interactive = false,
  withCorners = false,
  children,
  ...props
}: CardProps) {
  const variantStyles = {
    default:
      "bg-[var(--bg-surface)] border-2 border-[var(--border-color)] shadow-[4px_4px_0px_var(--border-color)]",
    elevated:
      "bg-[var(--bg-surface-elevated)] border-2 border-[var(--border-color)] shadow-[4px_4px_0px_var(--border-color)]",
    accent:
      "bg-[var(--bg-surface)] border-2 border-[var(--border-color)] border-l-4 border-l-[#2563FF] shadow-[4px_4px_0px_var(--border-color)]",
    critical:
      "bg-[var(--bg-surface)] border-2 border-red-500/80 border-l-4 border-l-red-500 shadow-[4px_4px_0px_rgba(239,68,68,0.5)]",
    cyan:
      "bg-[var(--bg-surface)] border-2 border-[#00C8FF] shadow-[4px_4px_0px_#00C8FF]",
    green:
      "bg-[var(--bg-surface)] border-2 border-[#B7FF3C] shadow-[4px_4px_0px_#B7FF3C]",
  };

  const interactiveStyles =
    interactive &&
    "cursor-pointer transition-all duration-150 hover:-translate-x-[3px] hover:-translate-y-[3px] hover:shadow-[7px_7px_0px_#00C8FF] hover:border-[#00C8FF] active:translate-x-[1px] active:translate-y-[1px] active:shadow-[2px_2px_0px_#00C8FF]";

  return (
    <div
      className={cn(
        "relative p-4 select-none",
        variantStyles[variant],
        interactiveStyles,
        className
      )}
      {...props}
    >
      {/* Corner Crosshair Reticles for Neo-Brutalist Technical Aesthetic */}
      {withCorners && (
        <>
          <span className="absolute -top-[5px] -left-[5px] font-mono text-[10px] text-[#00C8FF] pointer-events-none select-none font-bold leading-none">
            +
          </span>
          <span className="absolute -top-[5px] -right-[5px] font-mono text-[10px] text-[#00C8FF] pointer-events-none select-none font-bold leading-none">
            +
          </span>
          <span className="absolute -bottom-[5px] -left-[5px] font-mono text-[10px] text-[#00C8FF] pointer-events-none select-none font-bold leading-none">
            +
          </span>
          <span className="absolute -bottom-[5px] -right-[5px] font-mono text-[10px] text-[#00C8FF] pointer-events-none select-none font-bold leading-none">
            +
          </span>
        </>
      )}
      {children}
    </div>
  );
}

export function CardHeader({
  className,
  children,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        "flex items-center justify-between pb-3 border-b-2 border-[var(--border-subtle)] mb-3",
        className
      )}
      {...props}
    >
      {children}
    </div>
  );
}

export function CardTitle({
  className,
  children,
  ...props
}: React.HTMLAttributes<HTMLHeadingElement>) {
  return (
    <h3
      className={cn(
        "font-mono text-xs font-bold uppercase tracking-wider text-[var(--text-primary)] flex items-center gap-2",
        className
      )}
      {...props}
    >
      {children}
    </h3>
  );
}
