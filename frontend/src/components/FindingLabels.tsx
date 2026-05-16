"use client";

import { apiFetch } from "@/lib/http";
import { useEffect, useMemo, useState } from "react";
import { useToast } from "@/components/ToastProvider";

type LabelKey =
  | "awaiting_feedback"
  | "carried_over"
  | "invalid"
  | "previously_accepted_risk"
  | "retest_blocked"
  | "triaging"
  | "valid";

const LABELS: Array<{ key: LabelKey; name: string; color: string }> = [
  { key: "awaiting_feedback", name: "Awaiting Feedback", color: "bg-violet-500" },
  { key: "carried_over", name: "Carried Over", color: "bg-slate-400" },
  { key: "invalid", name: "Invalid", color: "bg-slate-600" },
  { key: "previously_accepted_risk", name: "Previously Accepted Risk", color: "bg-slate-400" },
  { key: "retest_blocked", name: "Retest Blocked", color: "bg-red-500" },
  { key: "triaging", name: "Triaging", color: "bg-sky-500" },
  { key: "valid", name: "Valid", color: "bg-emerald-500" },
];

function pillColor(k: string) {
  const m = LABELS.find((x) => x.key === k);
  if (!m) return { dot: "bg-slate-500", pill: "bg-slate-500/10 border-slate-500/30 text-slate-300" };
  const dot = m.color;
  const pill =
    m.key === "retest_blocked"
      ? "bg-red-500/10 border-red-500/30 text-red-300"
      : m.key === "awaiting_feedback"
        ? "bg-violet-500/10 border-violet-500/30 text-violet-300"
        : m.key === "triaging"
          ? "bg-sky-500/10 border-sky-500/30 text-sky-300"
          : m.key === "valid"
            ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-300"
            : "bg-slate-500/10 border-slate-500/30 text-slate-300";
  return { dot, pill };
}

export function FindingLabels({
  findingId,
  role,
  initialLabels,
}: {
  findingId: string;
  role: "admin" | "client" | "pentester";
  initialLabels?: string[] | string;
}) {
  const toast = useToast();
  const [open, setOpen] = useState(false);
  const [labels, setLabels] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);

  const canEdit = role === "admin" || role === "pentester";

  useEffect(() => {
    // seed from initial labels if provided
    if (Array.isArray(initialLabels)) {
      setLabels(initialLabels.map((x) => String(x)).filter(Boolean));
      return;
    }
    if (typeof initialLabels === "string" && initialLabels.trim().startsWith("[")) {
      try {
        const arr = JSON.parse(initialLabels);
        if (Array.isArray(arr)) setLabels(arr.map((x) => String(x)).filter(Boolean));
      } catch {}
    }
  }, [initialLabels]);

  const selected = useMemo(() => {
    const uniq: string[] = [];
    for (const x of labels || []) if (x && !uniq.includes(x)) uniq.push(x);
    return uniq;
  }, [labels]);

  const toggle = (k: LabelKey) => {
    setLabels((prev) => (prev.includes(k) ? prev.filter((x) => x !== k) : [...prev, k]));
  };

  const save = async () => {
    if (!canEdit) return;
    setSaving(true);
    const r = await apiFetch<any>(`/api/findings/${encodeURIComponent(findingId)}/labels`, {
      method: "PUT",
      body: JSON.stringify({ labels }),
    });
    setSaving(false);
    if (!r.ok) {
      toast.push({ type: "error", title: "Failed to save labels", message: r.error }, 5200);
      return;
    }
    setLabels(r.data.labels || labels);
    setOpen(false);
  };

  return (
    <div className="flex items-center gap-2 flex-wrap">
      {selected.length === 0 ? (
        <span className="text-xs text-text-muted">No labels</span>
      ) : (
        selected.map((k) => {
          const meta = LABELS.find((x) => x.key === k);
          const c = pillColor(k);
          return (
            <span key={k} className={`inline-flex items-center gap-2 rounded-full border px-2.5 py-1 text-xs ${c.pill}`}>
              <span className={`h-2.5 w-2.5 rounded-full ${c.dot}`} />
              {meta?.name || k}
            </span>
          );
        })
      )}

      {canEdit ? (
        <div className="relative">
          <button
            onClick={() => setOpen((v) => !v)}
            className="rounded-lg bg-bg-elevated border border-border px-2.5 py-2 text-xs text-text-secondary hover:bg-bg-hover hover:text-text-primary transition"
            title="Edit labels"
          >
            ⚙️
          </button>
          {open ? (
            <div className="absolute z-40 right-0 mt-2 w-[280px] rounded-2xl border border-border bg-bg-card shadow-[0_20px_60px_rgba(0,0,0,0.55)] overflow-hidden">
              <div className="px-4 py-3 border-b border-border">
                <div className="text-sm font-medium">Labels</div>
                <div className="text-xs text-text-muted">Select labels for this finding</div>
              </div>
              <div className="p-2">
                {LABELS.map((l) => (
                  <button
                    key={l.key}
                    onClick={() => toggle(l.key)}
                    className="w-full flex items-center gap-3 px-3 py-2 rounded-xl hover:bg-bg-hover transition text-left"
                  >
                    <span className={`h-6 w-6 rounded-lg ${l.color} flex items-center justify-center text-white`}>🏷️</span>
                    <div className="flex-1 text-sm text-text-secondary">{l.name}</div>
                    <input type="checkbox" checked={labels.includes(l.key)} readOnly />
                  </button>
                ))}
              </div>
              <div className="px-3 py-2 border-t border-border flex items-center justify-end gap-2">
                <button
                  onClick={() => setOpen(false)}
                  className="rounded-xl bg-bg-elevated border border-border px-3 py-2 text-sm text-text-secondary hover:bg-bg-hover hover:text-text-primary transition"
                >
                  Cancel
                </button>
                <button
                  disabled={saving}
                  onClick={save}
                  className="rounded-xl bg-blue-primary/15 border border-blue-primary/30 px-3 py-2 text-sm text-blue-primary hover:bg-blue-primary/20 transition disabled:opacity-60"
                >
                  {saving ? "Saving…" : "Save"}
                </button>
              </div>
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

