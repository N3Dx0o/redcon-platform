"use client";

import { AppShell } from "@/components/AppShell";
import { IconBug, IconClock, IconTarget } from "@/components/Icons";
import { Modal } from "@/components/Modal";
import { useToast } from "@/components/ToastProvider";
import { formatSubmittedAt } from "@/lib/date";
import { apiFetch } from "@/lib/http";
import { titleCaseLabel } from "@/lib/text";
import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { FindingLabels } from "@/components/FindingLabels";

function sevColor(sev: string) {
  const s = String(sev || "").toLowerCase();
  if (s === "critical") return { bg: "bg-rose-500", text: "text-rose-400", pill: "bg-rose-500/15 border-rose-500/40" };
  if (s === "high") return { bg: "bg-orange-500", text: "text-orange-400", pill: "bg-orange-500/15 border-orange-500/40" };
  if (s === "medium") return { bg: "bg-amber-400", text: "text-amber-300", pill: "bg-amber-500/10 border-amber-500/30" };
  if (s === "low") return { bg: "bg-sky-400", text: "text-sky-300", pill: "bg-sky-500/10 border-sky-500/30" };
  return { bg: "bg-slate-500", text: "text-slate-300", pill: "bg-slate-500/10 border-slate-500/30" };
}

function statusColor(status: string) {
  const s = String(status || "").toLowerCase();
  // Lifecycle
  if (s === "draft") return { text: "text-slate-300", pill: "bg-slate-500/10 border-slate-500/30" };
  if (s === "new") return { text: "text-sky-300", pill: "bg-sky-500/10 border-sky-500/30" };
  if (s === "need_more_info") return { text: "text-amber-300", pill: "bg-amber-500/10 border-amber-500/30" };
  if (s === "triaged") return { text: "text-violet-300", pill: "bg-violet-500/10 border-violet-500/30" };
  if (s === "accepted") return { text: "text-emerald-300", pill: "bg-emerald-500/10 border-emerald-500/30" };
  // Resolution
  if (s === "fixed") return { text: "text-teal-300", pill: "bg-teal-500/10 border-teal-500/30" };
  if (s === "retest") return { text: "text-sky-300", pill: "bg-sky-500/10 border-sky-500/30" };
  if (s === "verified") return { text: "text-emerald-300", pill: "bg-emerald-500/10 border-emerald-500/30" };
  if (s === "duplicate" || s === "wont_fix") return { text: "text-slate-300", pill: "bg-slate-500/10 border-slate-500/30" };
  return { text: "text-slate-300", pill: "bg-slate-500/10 border-slate-500/30" };
}

export default function PentesterFindingsPage() {
  const toast = useToast();
  const [loading, setLoading] = useState(true);
  const [findings, setFindings] = useState<any[]>([]);
  const [severity, setSeverity] = useState("all");
  const [status, setStatus] = useState("all");

  const [editOpen, setEditOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const [editId, setEditId] = useState<string | null>(null);
  const [form, setForm] = useState({
    title: "",
    severity: "medium",
    category: "other",
    affected_url: "",
    description: "",
    poc: "",
    impact: "",
    remediation: "",
  });

  const load = async () => {
    setLoading(true);
    const qs = new URLSearchParams();
    if (severity !== "all") qs.set("severity", severity);
    if (status !== "all") qs.set("status", status);
    qs.set("_", String(Date.now()));
    const r = await apiFetch<any>(`/api/ptaas/findings?${qs.toString()}`);
    if (r.ok) setFindings(r.data.findings || []);
    setLoading(false);
  };

  const openEdit = async (findingId: string) => {
    const res = await apiFetch<{ finding: any }>(`/api/pentester/finding/${encodeURIComponent(findingId)}?_=${Date.now()}`);
    if (!res.ok) {
      toast.push({ type: "error", title: "Couldn’t load finding", message: res.error }, 5200);
      return;
    }
    const f = res.data.finding || {};
    setEditId(findingId);
    setForm({
      title: f.title || "",
      severity: f.severity || "medium",
      category: f.category || "other",
      affected_url: f.affected_url || "",
      description: f.description || "",
      poc: f.steps_to_reproduce || f.poc || "",
      impact: f.impact || "",
      remediation: f.remediation || "",
    });
    setEditOpen(true);
  };

  const saveEdit = async () => {
    if (!editId) return;
    if (!form.title || !form.description || !form.poc) {
      toast.push({ type: "warning", title: "Missing required fields", message: "Title, Description, and PoC are required." });
      return;
    }
    setSaving(true);
    try {
      const res = await apiFetch<any>(`/api/pentester/finding/${encodeURIComponent(editId)}`, {
        method: "PUT",
        body: JSON.stringify({ ...form, steps_to_reproduce: form.poc }),
      });
      if (!res.ok) throw new Error(res.error);
      toast.push({ type: "success", title: "Finding updated" });
      setEditOpen(false);
      await load();
    } catch (e: any) {
      toast.push({ type: "error", title: "Update failed", message: e?.message || "Failed" }, 5200);
    } finally {
      setSaving(false);
    }
  };

  const deleteFinding = async (findingId: string, title: string) => {
    if (!confirm(`Delete "${title}"? This cannot be undone.`)) return;
    const res = await apiFetch<any>(`/api/pentester/finding/${encodeURIComponent(findingId)}`, { method: "DELETE" });
    if (!res.ok) {
      toast.push({ type: "error", title: "Cannot delete finding", message: res.error }, 5200);
      return;
    }
    toast.push({ type: "success", title: "Finding deleted" });
    await load();
  };

  const readyForRetest = async (findingId: string) => {
    const r = await apiFetch<any>(`/api/findings/${encodeURIComponent(findingId)}/ready-retest`, { method: "POST", body: "{}" });
    if (!r.ok) {
      toast.push({ type: "error", title: "Action failed", message: r.error }, 5200);
      return;
    }
    toast.push({ type: "success", title: "Marked ready for re-test" });
    await load();
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [severity, status]);

  const counts = useMemo(() => {
    const out: Record<string, number> = { total: findings.length, critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of findings) {
      const s = String(f.severity || "").toLowerCase();
      if (s in out) out[s] += 1;
    }
    return out;
  }, [findings]);

  return (
    <AppShell role="pentester">
      <div className="max-w-6xl mx-auto space-y-5">
        {/* Hero Header */}
        <div className="rounded-3xl border border-border bg-gradient-to-r from-bg-card via-bg-elevated to-bg-card overflow-hidden shadow-xl shadow-black/10">
          <div className="relative p-6">
            <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_top_right,_var(--tw-gradient-stops))] from-rose-500/20 via-amber-500/10 to-transparent" />
            <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_bottom_left,_var(--tw-gradient-stops))] from-sky-500/15 via-violet-500/10 to-transparent" />
            <div className="relative flex flex-col md:flex-row md:items-end justify-between gap-4">
          <div>
                <div className="text-2xl font-bold">Findings</div>
                <div className="text-sm text-text-secondary mt-1">All findings across your assigned pentests.</div>
          </div>
              <div className="flex flex-col sm:flex-row gap-2">
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
                  className="rounded-xl bg-[#1a1a24] border border-border px-3 py-2.5 text-sm text-white outline-none hover:border-border-light focus:border-sky-500/50 focus:ring-2 focus:ring-sky-500/10"
            >
              <option value="all">All severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
            <select
              value={status}
              onChange={(e) => setStatus(e.target.value)}
                  className="rounded-xl bg-[#1a1a24] border border-border px-3 py-2.5 text-sm text-white outline-none hover:border-border-light focus:border-sky-500/50 focus:ring-2 focus:ring-sky-500/10"
            >
              <option value="all">All statuses</option>
              <option value="draft">Draft</option>
              <option value="new">New</option>
              <option value="triaged">Triaged</option>
              <option value="need_more_info">Need more info</option>
              <option value="accepted">Accepted</option>
              <option value="fixed">Fixed</option>
              <option value="verified">Verified</option>
            </select>
              </div>
            </div>
          </div>
        </div>

        {/* Stat Cards */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <div className="rounded-2xl bg-gradient-to-br from-bg-card to-bg-elevated border border-border p-4 shadow-lg shadow-black/10">
            <div className="text-xs uppercase text-text-muted">Total</div>
            <div className="text-2xl font-bold mt-1">{counts.total}</div>
          </div>
          <div className="rounded-2xl bg-gradient-to-br from-bg-card to-bg-elevated border border-border p-4 shadow-lg shadow-black/10">
            <div className="text-xs uppercase text-rose-400">Critical</div>
            <div className="text-2xl font-bold mt-1">{counts.critical}</div>
          </div>
          <div className="rounded-2xl bg-gradient-to-br from-bg-card to-bg-elevated border border-border p-4 shadow-lg shadow-black/10">
            <div className="text-xs uppercase text-orange-400">High</div>
            <div className="text-2xl font-bold mt-1">{counts.high}</div>
          </div>
          <div className="rounded-2xl bg-gradient-to-br from-bg-card to-bg-elevated border border-border p-4 shadow-lg shadow-black/10">
            <div className="text-xs uppercase text-amber-300">Medium</div>
            <div className="text-2xl font-bold mt-1">{counts.medium}</div>
          </div>
          <div className="rounded-2xl bg-gradient-to-br from-bg-card to-bg-elevated border border-border p-4 shadow-lg shadow-black/10">
            <div className="text-xs uppercase text-sky-300">Low</div>
            <div className="text-2xl font-bold mt-1">{counts.low}</div>
          </div>
        </div>

        {loading ? (
          <div className="rounded-2xl bg-gradient-to-br from-bg-card to-bg-elevated border border-border p-10 text-center shadow-lg shadow-black/10">
            <div className="mx-auto w-12 h-12 rounded-xl bg-sky-500/10 flex items-center justify-center mb-3 animate-pulse">
              <IconClock className="h-6 w-6 text-sky-400" />
            </div>
            <div className="text-text-secondary">Loading findings…</div>
          </div>
        ) : findings.length === 0 ? (
          <div className="rounded-2xl bg-gradient-to-br from-bg-card to-bg-elevated border border-border p-10 text-center shadow-lg shadow-black/10">
            <div className="mx-auto w-12 h-12 rounded-xl bg-rose-500/10 flex items-center justify-center mb-3">
              <IconBug className="h-6 w-6 text-rose-400" />
            </div>
            <div className="text-lg font-medium">No findings yet</div>
            <div className="text-text-secondary text-sm mt-1">Once you submit findings on assigned pentests, they’ll appear here.</div>
          </div>
        ) : (
          <div className="space-y-3">
            {findings.map((f) => {
              const canDelete = ["new", "draft"].includes(String(f.status || "").toLowerCase());
              const canReady = String(f.status || "").toLowerCase() === "fixed";
              return (
                <div key={f.id} className="rounded-2xl bg-gradient-to-br from-bg-card to-bg-elevated border border-border p-5 shadow-lg shadow-black/10">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                    <div className="font-semibold text-lg">{f.title}</div>
                    <div className="flex flex-wrap items-center gap-2 mt-2 text-sm">
                      {f.public_id ? <span className="text-text-muted">{f.public_id}</span> : null}
                      <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${sevColor(f.severity).pill} ${sevColor(f.severity).text}`}>
                        {titleCaseLabel(f.severity)}
                      </span>
                      <span className="text-text-muted">•</span>
                      <span
                        className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${statusColor(f.status).pill} ${statusColor(f.status).text}`}
                      >
                        {titleCaseLabel(f.status)}
                      </span>
                      {f.pentestTitle ? <span className="text-text-muted">• {f.pentestTitle}</span> : null}
                    </div>
                    <div className="mt-2">
                      <FindingLabels findingId={f.id} role="pentester" initialLabels={f.labels || "[]"} />
                    </div>
                    {f.description ? (
                      <div className="text-sm text-text-secondary mt-2 whitespace-pre-wrap">
                        {String(f.description).slice(0, 220)}
                        {String(f.description).length > 220 ? "…" : ""}
                      </div>
                    ) : null}
                    <div className="text-xs text-text-muted mt-2">🕒 {formatSubmittedAt(f.date || f.created_at)}</div>
                  </div>
                    <div className="flex items-center gap-2">
                      {canReady ? (
                        <button
                          onClick={() => readyForRetest(f.id)}
                          className="rounded-xl bg-emerald-500/15 border border-emerald-500/30 px-4 py-2 text-sm text-emerald-300 hover:bg-emerald-500/20 transition whitespace-nowrap"
                        >
                          Ready for re-test
                        </button>
                      ) : null}
                      <Link
                        href={`/ptaas/finding/${encodeURIComponent(f.id)}`}
                        className="rounded-xl bg-bg-elevated border border-border px-4 py-2 text-sm text-text-secondary hover:bg-bg-hover hover:text-text-primary transition whitespace-nowrap"
                      >
                        View
                      </Link>
                      <button
                        onClick={() => openEdit(f.id)}
                        className="rounded-xl bg-bg-elevated border border-border px-4 py-2 text-sm text-text-secondary hover:bg-bg-hover hover:text-text-primary transition whitespace-nowrap"
                      >
                        Edit
                      </button>
                      {canDelete ? (
                        <button
                          onClick={() => deleteFinding(f.id, f.title)}
                          className="rounded-xl bg-redcon-primary/10 border border-redcon-primary/30 px-4 py-2 text-sm text-redcon-bright hover:bg-redcon-primary/15 transition whitespace-nowrap"
                        >
                          Delete
                        </button>
                      ) : null}
                      {f.pentestId ? (
                        <Link
                          href={`/ptaas/pentest/${f.pentestId}#findings`}
                          className="rounded-xl bg-sky-500/15 border border-sky-500/30 px-4 py-2 text-sm text-sky-300 hover:bg-sky-500/20 transition whitespace-nowrap inline-flex items-center gap-2"
                        >
                          <IconTarget className="h-4 w-4" />
                          Open pentest
                        </Link>
                      ) : null}
                    </div>
                </div>
              </div>
              );
            })}
          </div>
        )}
      </div>

      <Modal
        open={editOpen}
        title="Edit Finding"
        onClose={() => setEditOpen(false)}
        footer={
          <>
            <button
              onClick={() => setEditOpen(false)}
              className="rounded-xl bg-bg-elevated border border-border px-4 py-2 text-sm text-text-secondary hover:bg-bg-hover hover:text-text-primary transition"
            >
              Cancel
            </button>
            <button
              disabled={saving}
              onClick={saveEdit}
              className="rounded-xl bg-redcon-primary hover:bg-redcon-bright transition text-white px-4 py-2 text-sm font-medium disabled:opacity-60"
            >
              {saving ? "Saving…" : "Save"}
            </button>
          </>
        }
        maxWidthClass="max-w-3xl"
      >
        <div className="grid grid-cols-1 gap-3">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs uppercase text-text-muted mb-1">Title *</label>
              <input
                value={form.title}
                onChange={(e) => setForm((p) => ({ ...p, title: e.target.value }))}
                className="w-full rounded-xl bg-bg-elevated border border-border px-3 py-2 text-sm outline-none focus:border-border-light"
              />
            </div>
            <div>
              <label className="block text-xs uppercase text-text-muted mb-1">Severity *</label>
              <select
                value={form.severity}
                onChange={(e) => setForm((p) => ({ ...p, severity: e.target.value }))}
                className="w-full rounded-xl bg-bg-elevated border border-border px-3 py-2 text-sm outline-none focus:border-border-light"
              >
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
            </div>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs uppercase text-text-muted mb-1">Category</label>
              <select
                value={form.category}
                onChange={(e) => setForm((p) => ({ ...p, category: e.target.value }))}
                className="w-full rounded-xl bg-bg-elevated border border-border px-3 py-2 text-sm outline-none focus:border-border-light"
              >
                <option value="injection">Injection</option>
                <option value="xss">XSS</option>
                <option value="auth">Authentication</option>
                <option value="access_control">Access Control</option>
                <option value="crypto">Cryptography</option>
                <option value="ssrf">SSRF</option>
                <option value="config">Misconfiguration</option>
                <option value="other">Other</option>
              </select>
            </div>
            <div>
              <label className="block text-xs uppercase text-text-muted mb-1">Affected URL</label>
              <input
                value={form.affected_url}
                onChange={(e) => setForm((p) => ({ ...p, affected_url: e.target.value }))}
                className="w-full rounded-xl bg-bg-elevated border border-border px-3 py-2 text-sm outline-none focus:border-border-light"
              />
            </div>
          </div>
          <div>
            <label className="block text-xs uppercase text-text-muted mb-1">Description *</label>
            <textarea
              value={form.description}
              onChange={(e) => setForm((p) => ({ ...p, description: e.target.value }))}
              rows={4}
              className="w-full rounded-xl bg-bg-elevated border border-border px-3 py-2 text-sm outline-none focus:border-border-light"
            />
          </div>
          <div>
            <label className="block text-xs uppercase text-text-muted mb-1">Proof of Concept / Steps *</label>
            <textarea
              value={form.poc}
              onChange={(e) => setForm((p) => ({ ...p, poc: e.target.value }))}
              rows={4}
              className="w-full rounded-xl bg-bg-elevated border border-border px-3 py-2 text-sm outline-none focus:border-border-light font-mono"
            />
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs uppercase text-text-muted mb-1">Impact</label>
              <textarea
                value={form.impact}
                onChange={(e) => setForm((p) => ({ ...p, impact: e.target.value }))}
                rows={3}
                className="w-full rounded-xl bg-bg-elevated border border-border px-3 py-2 text-sm outline-none focus:border-border-light"
              />
            </div>
            <div>
              <label className="block text-xs uppercase text-text-muted mb-1">Remediation</label>
              <textarea
                value={form.remediation}
                onChange={(e) => setForm((p) => ({ ...p, remediation: e.target.value }))}
                rows={3}
                className="w-full rounded-xl bg-bg-elevated border border-border px-3 py-2 text-sm outline-none focus:border-border-light"
              />
            </div>
          </div>
        </div>
      </Modal>
    </AppShell>
  );
}




