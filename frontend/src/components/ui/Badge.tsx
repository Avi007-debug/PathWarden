import React from "react";
import { cn } from "@/lib/utils/cn";

interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  variant?: "default" | "cyan" | "green" | "critical" | "warning" | "neutral" | "outline";
  size?: "sm" | "md";
}

export function Badge({
  className,
  variant = "default",
  size = "sm",
  children,
  ...props
}: BadgeProps) {
  const variantStyles = {
    default:
      "bg-[#2563FF]/20 text-[#2563FF] dark:text-[#709BFF] border-2 border-[#2563FF] shadow-[2px_2px_0px_#2563FF]",
    cyan:
      "bg-[#00C8FF]/15 text-[#0088CC] dark:text-[#00C8FF] border-2 border-[#00C8FF] shadow-[2px_2px_0px_#00C8FF]",
    green:
      "bg-[#B7FF3C]/15 text-[#4D8500] dark:text-[#B7FF3C] border-2 border-[#B7FF3C] shadow-[2px_2px_0px_#B7FF3C]",
    critical:
      "bg-red-500/15 text-red-600 dark:text-red-400 border-2 border-red-500 shadow-[2px_2px_0px_#FF334B]",
    warning:
      "bg-amber-500/15 text-amber-600 dark:text-amber-400 border-2 border-amber-500 shadow-[2px_2px_0px_#FFB800]",
    neutral:
      "bg-slate-500/15 text-slate-700 dark:text-slate-300 border-2 border-slate-500/50 shadow-[2px_2px_0px_var(--border-color)]",
    outline:
      "border-2 border-[var(--border-color)] text-[var(--text-muted)] bg-[var(--bg-surface)] shadow-[2px_2px_0px_var(--border-color)]",
  };

  const sizeStyles = {
    sm: "text-[10px] px-1.5 py-0.5 tracking-wider uppercase font-bold",
    md: "text-xs px-2.5 py-1 tracking-wider uppercase font-bold",
  };

  return (
    <span
      className={cn(
        "inline-flex items-center font-mono select-none transition-all",
        variantStyles[variant],
        sizeStyles[size],
        className
      )}
      {...props}
    >
      {children}
    </span>
  );
}
