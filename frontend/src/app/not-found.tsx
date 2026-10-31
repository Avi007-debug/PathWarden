import Link from "next/link";
import { ShieldAlert, ArrowLeft } from "lucide-react";

export default function NotFound() {
  return (
    <div className="flex-1 flex items-center justify-center p-6 font-mono">
      <div className="max-w-md w-full p-6 border border-[var(--border-color)] bg-[var(--bg-surface)] text-center flex flex-col items-center gap-4">
        <ShieldAlert className="w-10 h-10 text-amber-500" />
        <div>
          <h1 className="font-heading text-lg font-bold text-[var(--text-primary)] uppercase tracking-wider">
            404 // Target Entity Not Found
          </h1>
          <p className="text-xs text-[var(--text-muted)] mt-1.5 leading-relaxed">
            The requested investigation route, incident identifier, or telemetry artifact does not exist in the active enclave.
          </p>
        </div>
        <Link
          href="/"
          className="inline-flex items-center gap-2 px-4 py-2 bg-[#2563FF] text-white text-xs font-bold uppercase tracking-wider hover:bg-[#1a4fdb] transition-colors"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Return to Console</span>
        </Link>
      </div>
    </div>
  );
}

