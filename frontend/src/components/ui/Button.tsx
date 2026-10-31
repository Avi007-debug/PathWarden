import React from "react";
import { cn } from "@/lib/utils/cn";

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary" | "danger" | "ghost" | "cyan" | "green";
  size?: "sm" | "md" | "lg";
  icon?: React.ReactNode;
}

export function Button({
  className,
  variant = "secondary",
  size = "md",
  icon,
  children,
  disabled,
  ...props
}: ButtonProps) {
  const base =
    "inline-flex items-center justify-center font-mono text-xs uppercase tracking-wider font-bold select-none cursor-pointer border-2 transition-all duration-100 disabled:opacity-50 disabled:pointer-events-none active:translate-x-[2px] active:translate-y-[2px] active:shadow-none";

  const variants = {
    primary:
      "bg-[#2563FF] text-white border-[var(--border-color)] shadow-[3px_3px_0px_var(--border-color)] hover:shadow-[5px_5px_0px_#00C8FF] hover:-translate-x-[1px] hover:-translate-y-[1px] hover:border-[#00C8FF]",
    secondary:
      "bg-[var(--bg-surface)] text-[var(--text-primary)] border-[var(--border-color)] shadow-[3px_3px_0px_var(--border-color)] hover:shadow-[5px_5px_0px_#00C8FF] hover:-translate-x-[1px] hover:-translate-y-[1px] hover:border-[#00C8FF] hover:bg-[var(--bg-surface-elevated)]",
    cyan:
      "bg-[#00C8FF] text-black border-black shadow-[3px_3px_0px_#000] hover:shadow-[5px_5px_0px_#2563FF] hover:-translate-x-[1px] hover:-translate-y-[1px]",
    green:
      "bg-[#B7FF3C] text-black border-black shadow-[3px_3px_0px_#000] hover:shadow-[5px_5px_0px_#00C8FF] hover:-translate-x-[1px] hover:-translate-y-[1px]",
    danger:
      "bg-red-500/15 text-red-500 border-red-500 shadow-[3px_3px_0px_rgba(239,68,68,0.4)] hover:shadow-[5px_5px_0px_#FF334B] hover:-translate-x-[1px] hover:-translate-y-[1px] hover:bg-red-500/25",
    ghost:
      "bg-transparent text-[var(--text-muted)] border-transparent hover:text-[var(--text-primary)] hover:bg-[var(--bg-surface-elevated)] hover:border-[var(--border-color)] shadow-none hover:shadow-[2px_2px_0px_var(--border-color)]",
  };

  const sizes = {
    sm: "px-2.5 py-1 text-[11px] gap-1.5",
    md: "px-3.5 py-1.5 text-xs gap-2",
    lg: "px-5 py-2.5 text-sm gap-2.5",
  };

  return (
    <button
      className={cn(base, variants[variant], sizes[size], className)}
      disabled={disabled}
      {...props}
    >
      {icon && <span className="shrink-0">{icon}</span>}
      {children}
    </button>
  );
}
