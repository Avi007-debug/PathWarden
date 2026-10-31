"use client";

import React, { useState, useEffect } from "react";
import { pathWardenApi } from "@/lib/api/client";
import { DetectionRule } from "@/lib/api/types";
import { useApp } from "@/lib/context/AppContext";
import { FileCode2, Plus, Check, AlertCircle, RefreshCw, Trash2, Edit3 } from "lucide-react";
import { Button } from "@/components/ui/Button";

export function DetectionRuleConfigEditor() {
  const { isDemoMode } = useApp();
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [configPath, setConfigPath] = useState("detection_rules.yaml");
  const [showAddForm, setShowAddForm] = useState(false);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // New rule form state
  const [ruleId, setRuleId] = useState("");
  const [ruleName, setRuleName] = useState("");
  const [techniqueId, setTechniqueId] = useState("T1059.001");
  const [techniqueName, setTechniqueName] = useState("PowerShell");
  const [severity, setSeverity] = useState<"CRITICAL" | "HIGH" | "MEDIUM" | "LOW">("HIGH");
  const [tactic, setTactic] = useState("Execution");
  const [description, setDescription] = useState("");
  const [query, setQuery] = useState("");

  const loadRules = React.useCallback(async () => {
    setLoading(true);
    try {
      const res = await pathWardenApi.getRules(isDemoMode);
      setRules(res.rules || []);
      setConfigPath(res.config_path || "detection_rules.yaml");
    } catch {
      // Fallback if not available
    } finally {
      setLoading(false);
    }
  }, [isDemoMode]);

  useEffect(() => {
    loadRules();
  }, [loadRules]);

  const handleCreateRule = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);
    setSuccessMessage(null);

    if (!ruleId || !ruleName || !query || !description) {
      setErrorMessage("Please complete all required fields for the detection rule.");
      return;
    }

    const payload: DetectionRule = {
      rule_id: ruleId.trim(),
      rule_name: ruleName.trim(),
      rule_version: "1.0.0",
      technique_id: techniqueId.trim(),
      technique_name: techniqueName.trim(),
      severity,
      tactic: tactic.trim(),
      description: description.trim(),
      query: query.trim(),
    };

    try {
      const res = await pathWardenApi.createRule(payload, isDemoMode);
      setSuccessMessage(res.message || `Rule ${payload.rule_id} saved to ${configPath}!`);
      setShowAddForm(false);
      // Reset form
      setRuleId("");
      setRuleName("");
      setDescription("");
      setQuery("");
      // Refresh list
      loadRules();
    } catch (err: unknown) {
      const error = err as Error;
      setErrorMessage(error.message || "Failed to persist detection rule to YAML config.");
    }
  };

  const handleDeleteRule = async (targetId: string) => {
    if (!confirm(`Delete rule ${targetId} from ${configPath}?`)) return;
    try {
      await pathWardenApi.deleteRule(targetId, isDemoMode);
      setSuccessMessage(`Rule ${targetId} deleted from ${configPath}.`);
      loadRules();
    } catch (err: unknown) {
      const error = err as Error;
      setErrorMessage(error.message || `Failed to remove rule ${targetId}`);
    }
  };

  return (
    <div className="border-2 border-[var(--border-color)] bg-[var(--bg-surface)] shadow-[4px_4px_0px_var(--border-color)] overflow-hidden font-mono select-none">
      {/* Header */}
      <div className="px-5 py-3.5 border-b-2 border-[var(--border-color)] bg-[var(--bg-surface-elevated)] flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <FileCode2 className="w-5 h-5 text-[#00C8FF]" />
          <div>
            <h3 className="font-heading font-black text-xs uppercase tracking-wider text-[var(--text-primary)]">
              Bonus B-4: Config-Driven Detection Rules Manager
            </h3>
            <span className="text-[10px] text-[var(--text-dim)]">
              File: <code className="text-[#00C8FF]">{configPath}</code> (Hot-reloaded without Python code edits)
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="secondary"
            size="sm"
            onClick={loadRules}
            icon={<RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />}
          >
            Refresh
          </Button>
          <Button
            variant="primary"
            size="sm"
            onClick={() => setShowAddForm(!showAddForm)}
            icon={<Plus className="w-3.5 h-3.5" />}
          >
            {showAddForm ? "Cancel" : "Add Detection Rule (YAML)"}
          </Button>
        </div>
      </div>

      {/* Notifications */}
      {successMessage && (
        <div className="p-3 bg-emerald-500/10 border-b-2 border-emerald-500/30 text-emerald-400 text-xs flex items-center gap-2 font-bold">
          <Check className="w-4 h-4 shrink-0" />
          <span>{successMessage}</span>
        </div>
      )}

      {errorMessage && (
        <div className="p-3 bg-red-500/10 border-b-2 border-red-500/30 text-red-400 text-xs flex items-center gap-2 font-bold">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{errorMessage}</span>
        </div>
      )}

      {/* Add Rule Form */}
      {showAddForm && (
        <form onSubmit={handleCreateRule} className="p-5 border-b-2 border-[var(--border-color)] bg-[var(--bg-surface-elevated)] flex flex-col gap-4 text-xs">
          <div className="font-black text-sm text-[var(--text-primary)] uppercase flex items-center gap-2 pb-2 border-b border-[var(--border-color)]">
            <Edit3 className="w-4 h-4 text-[#B7FF3C]" />
            Define New Detection Rule (Persisted to {configPath})
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div>
              <label className="block text-[10px] uppercase font-bold text-[var(--text-dim)] mb-1">
                Rule ID (Unique) *
              </label>
              <input
                type="text"
                placeholder="e.g. RULE-T1059-CUSTOM"
                value={ruleId}
                onChange={(e) => setRuleId(e.target.value)}
                className="w-full px-3 py-1.5 border border-[var(--border-color)] bg-[var(--bg-surface)] text-[var(--text-primary)] font-mono text-xs focus:outline-none focus:border-[#00C8FF]"
                required
              />
            </div>

            <div>
              <label className="block text-[10px] uppercase font-bold text-[var(--text-dim)] mb-1">
                Rule Name *
              </label>
              <input
                type="text"
                placeholder="e.g. PowerShell Download Cradle"
                value={ruleName}
                onChange={(e) => setRuleName(e.target.value)}
                className="w-full px-3 py-1.5 border border-[var(--border-color)] bg-[var(--bg-surface)] text-[var(--text-primary)] font-mono text-xs focus:outline-none focus:border-[#00C8FF]"
                required
              />
            </div>

            <div>
              <label className="block text-[10px] uppercase font-bold text-[var(--text-dim)] mb-1">
                Severity *
              </label>
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value as any)}
                className="w-full px-3 py-1.5 border border-[var(--border-color)] bg-[var(--bg-surface)] text-[var(--text-primary)] font-mono text-xs focus:outline-none focus:border-[#00C8FF]"
              >
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="LOW">LOW</option>
              </select>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div>
              <label className="block text-[10px] uppercase font-bold text-[var(--text-dim)] mb-1">
                MITRE Technique ID *
              </label>
              <input
                type="text"
                placeholder="e.g. T1059.001"
                value={techniqueId}
                onChange={(e) => setTechniqueId(e.target.value)}
                className="w-full px-3 py-1.5 border border-[var(--border-color)] bg-[var(--bg-surface)] text-[var(--text-primary)] font-mono text-xs focus:outline-none focus:border-[#00C8FF]"
                required
              />
            </div>

            <div>
              <label className="block text-[10px] uppercase font-bold text-[var(--text-dim)] mb-1">
                Technique Name *
              </label>
              <input
                type="text"
                placeholder="e.g. PowerShell"
                value={techniqueName}
                onChange={(e) => setTechniqueName(e.target.value)}
                className="w-full px-3 py-1.5 border border-[var(--border-color)] bg-[var(--bg-surface)] text-[var(--text-primary)] font-mono text-xs focus:outline-none focus:border-[#00C8FF]"
                required
              />
            </div>

            <div>
              <label className="block text-[10px] uppercase font-bold text-[var(--text-dim)] mb-1">
                Tactic (Kill Chain Stage) *
              </label>
              <input
                type="text"
                placeholder="e.g. Execution"
                value={tactic}
                onChange={(e) => setTactic(e.target.value)}
                className="w-full px-3 py-1.5 border border-[var(--border-color)] bg-[var(--bg-surface)] text-[var(--text-primary)] font-mono text-xs focus:outline-none focus:border-[#00C8FF]"
                required
              />
            </div>
          </div>

          <div>
            <label className="block text-[10px] uppercase font-bold text-[var(--text-dim)] mb-1">
              Description *
            </label>
            <input
              type="text"
              placeholder="e.g. Detects suspicious PowerShell hidden web client invocation from CLI"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="w-full px-3 py-1.5 border border-[var(--border-color)] bg-[var(--bg-surface)] text-[var(--text-primary)] font-mono text-xs focus:outline-none focus:border-[#00C8FF]"
              required
            />
          </div>

          <div>
            <label className="block text-[10px] uppercase font-bold text-[var(--text-dim)] mb-1">
              DuckDB SQL Detection Query *
            </label>
            <textarea
              rows={2}
              placeholder="SELECT event_uid, src_ip, dst_ip FROM events WHERE command_line LIKE '%Net.WebClient%'"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className="w-full px-3 py-1.5 border border-[var(--border-color)] bg-[var(--bg-surface)] text-[var(--text-primary)] font-mono text-xs focus:outline-none focus:border-[#00C8FF]"
              required
            />
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <Button type="button" variant="ghost" size="sm" onClick={() => setShowAddForm(false)}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" size="sm">
              Save & Validate Rule (Bonus B-4)
            </Button>
          </div>
        </form>
      )}

      {/* Rules List Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse text-xs">
          <thead>
            <tr className="border-b-2 border-[var(--border-color)] bg-[var(--bg-surface-elevated)] text-[10px] uppercase text-[var(--text-dim)] tracking-wider font-extrabold">
              <th className="py-3 px-4">Rule ID / Name</th>
              <th className="py-3 px-4">MITRE ATT&CK</th>
              <th className="py-3 px-4">Severity</th>
              <th className="py-3 px-4">Tactic</th>
              <th className="py-3 px-4">Query / Logic</th>
              <th className="py-3 px-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y-2 divide-[var(--border-subtle)]">
            {rules.map((r) => (
              <tr key={r.rule_id} className="hover:bg-[var(--bg-surface-elevated)] transition-colors">
                <td className="py-3 px-4 align-top">
                  <div className="font-bold text-[var(--text-primary)]">{r.rule_id}</div>
                  <div className="text-[11px] text-[var(--text-muted)]">{r.rule_name}</div>
                </td>
                <td className="py-3 px-4 align-top">
                  <span className="font-bold text-[#00C8FF]">{r.technique_id}</span>
                  <div className="text-[10px] text-[var(--text-dim)]">{r.technique_name}</div>
                </td>
                <td className="py-3 px-4 align-top">
                  <span
                    className={`text-[10px] font-extrabold px-1.5 py-0.5 border ${
                      r.severity === "CRITICAL"
                        ? "bg-red-500/20 text-red-400 border-red-500"
                        : r.severity === "HIGH"
                        ? "bg-amber-500/20 text-amber-400 border-amber-500"
                        : "bg-blue-500/20 text-blue-400 border-blue-500"
                    }`}
                  >
                    {r.severity}
                  </span>
                </td>
                <td className="py-3 px-4 align-top font-bold text-[var(--text-muted)]">
                  {r.tactic}
                </td>
                <td className="py-3 px-4 align-top max-w-xs font-mono text-[10px] text-[var(--text-dim)] truncate" title={r.query}>
                  {r.query}
                </td>
                <td className="py-3 px-4 align-top text-right">
                  <button
                    onClick={() => handleDeleteRule(r.rule_id)}
                    className="p-1 hover:text-red-400 transition-colors"
                    title="Delete rule"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

