"use client";

import { AppShell } from "@/components/AppShell";
import { Modal } from "@/components/Modal";
import { useToast } from "@/components/ToastProvider";
import { apiFetch } from "@/lib/http";
import Link from "next/link";
import { useEffect, useMemo, useState } from "react";

type Target = {
  id: string;
  name: string;
  url?: string;
  type?: string;
  created_at?: string;
  last_scan?: {
    id: string;
    status: string;
    created_at?: string;
    finished_at?: string;
    summary?: any;
  } | null;
};

type ScanRow = {
  id: string;
  asset_id: string;
  status: string;
  created_at?: string;
  started_at?: string;
  finished_at?: string;
  findings_summary?: any;
  error?: string;
};

type ScheduledRow = {
  id: string;
  asset_id: string;
  cadence: string;
  enabled: number | boolean;
  asset_name?: string;
  asset_url?: string;
  created_at?: string;
};

type CreditsResp = { credits?: number; scan_cost?: number };

function pillColor(status: string) {
  const s = String(status || "").toLowerCase();
  if (["completed", "done"].includes(s)) return { bg: "bg-emerald-500/15", border: "border-emerald-500/40", text: "text-emerald-300" };
  if (["running", "active"].includes(s)) return { bg: "bg-sky-500/15", border: "border-sky-500/40", text: "text-sky-300" };
  if (["queued", "pending"].includes(s)) return { bg: "bg-amber-500/15", border: "border-amber-500/40", text: "text-amber-300" };
  if (["failed", "error"].includes(s)) return { bg: "bg-rose-500/15", border: "border-rose-500/40", text: "text-rose-300" };
  return { bg: "bg-slate-500/15", border: "border-slate-500/40", text: "text-slate-300" };
}

export default function ClientScansPage() {
  const toast = useToast();
  const [tab, setTab] = useState<"targets" | "scans" | "scheduled">("targets");
  const [targets, setTargets] = useState<Target[]>([]);
  const [scans, setScans] = useState<ScanRow[]>([]);
  const [scheduled, setScheduled] = useState<ScheduledRow[]>([]);
  const [credits, setCredits] = useState<CreditsResp | null>(null);
  const [loading, setLoading] = useState(true);

  // schedule modal
  const [open, setOpen] = useState(false);
  const [schedAssetId, setSchedAssetId] = useState("");
  const [schedCadence, setSchedCadence] = useState("weekly");
  const [schedEnabled, setSchedEnabled] = useState(true);

  const loadAll = async () => {
    setLoading(true);
    const c = await apiFetch<CreditsResp>("/api/client/credits");
    if (c.ok) setCredits(c.data);

    const t = await apiFetch<{ targets?: Target[] }>(`/api/client/scans/targets?_=${Date.now()}`);
    if (t.ok) setTargets(t.data.targets || []);

    const s = await apiFetch<{ scans?: ScanRow[] }>(`/api/client/scans?_=${Date.now()}`);
    if (s.ok) setScans(s.data.scans || []);

    const sch = await apiFetch<{ scheduled?: ScheduledRow[] }>(`/api/client/scheduled-scans?_=${Date.now()}`);
    if (sch.ok) setScheduled(sch.data.scheduled || []);

    setLoading(false);
  };

  useEffect(() => {
    loadAll();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const availableTargets = useMemo(() => targets || [], [targets]);

  const runScan = async (assetId: string) => {
    const r = await apiFetch<any>(`/api/client/scans/run`, { method: "POST", body: JSON.stringify({ asset_id: assetId }) });
    if (!r.ok) {
      toast.push({ type: "error", title: "Scan failed", message: r.error }, 5200);
      return;
    }
    toast.push({ type: "success", title: "Scan started", message: "We’ll update the scan status shortly." });
    await loadAll();
  };

  const download = async (scanId: string) => {
    // Let browser handle download.
    window.open(`/api/client/scans/${encodeURIComponent(scanId)}/download`, "_blank");
  };

  const createSchedule = async () => {
    if (!schedAssetId) {
      toast.push({ type: "warning", title: "Select a target", message: "Choose an asset to schedule scans for." });
      return;
    }
    const r = await apiFetch<any>(`/api/client/scheduled-scans`, {
      method: "POST",
      body: JSON.stringify({ asset_id: schedAssetId, cadence: schedCadence, enabled: schedEnabled }),
    });
    if (!r.ok) {
      toast.push({ type: "error", title: "Schedule failed", message: r.error }, 5200);
      return;
    }
    toast.push({ type: "success", title: "Scheduled scan created" });
    setOpen(false);
    setSchedAssetId("");
    await loadAll();
  };

  const delSchedule = async (id: string) => {
    if (!confirm("Delete this scheduled scan?")) return;
    const r = await apiFetch<any>(`/api/client/scheduled-scans/${encodeURIComponent(id)}`, { method: "DELETE" });
    if (!r.ok) {
      toast.push({ type: "error", title: "Delete failed", message: r.error }, 5200);
      return;
    }
    toast.push({ type: "success", title: "Deleted" });
    await loadAll();
  };

  return (
    <AppShell role="client">
      <div className="max-w-6xl mx-auto space-y-5">
        {/* Header */}
        <div className="rounded-3xl border border-border bg-gradient-to-r from-bg-card via-bg-elevated to-bg-card overflow-hidden shadow-xl shadow-black/10">
          <div className="relative p-6">
            <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_top_right,_var(--tw-gradient-stops))] from-sky-500/15 via-violet-500/10 to-transparent" />
            <div className="relative flex flex-col md:flex-row md:items-end justify-between gap-4">
              <div>
                <div className="text-2xl font-bold">Scans</div>
                <div className="text-sm text-text-secondary mt-1">
                  Available balance: <span className="font-semibold text-text-primary">{credits?.credits ?? 0}</span>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Link
                  href="/client/credits"
                  className="rounded-xl bg-white/5 backdrop-blur border border-white/10 px-4 py-2.5 text-sm text-text-secondary hover:bg-white/10 hover:text-text-primary transition-all"
                >
                  Add Scan Units
                </Link>
                <button
                  onClick={loadAll}
                  className="rounded-xl bg-bg-elevated border border-border px-4 py-2.5 text-sm text-text-secondary hover:bg-bg-hover hover:text-text-primary transition"
                >
                  Refresh
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="rounded-2xl bg-bg-card border border-border p-2 flex gap-2">
          {[
            { id: "targets", label: "Targets" },
            { id: "scans", label: "Scans" },
            { id: "scheduled", label: "Scheduled Scans" },
          ].map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id as any)}
              className={`flex-1 rounded-xl px-3 py-2 text-sm transition ${
                tab === t.id ? "bg-bg-elevated border border-border text-text-primary" : "text-text-secondary hover:bg-bg-hover"
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>

        {/* Content */}
        {tab === "targets" ? (
          <div className="rounded-2xl bg-bg-card border border-border overflow-hidden">
            <div className="p-4 flex items-center justify-between">
              <div className="text-sm text-text-secondary">Manage scan targets (assets)</div>
              <Link
                href="/client/assets"
                className="rounded-xl bg-gradient-to-r from-sky-600 to-sky-500 hover:from-sky-500 hover:to-sky-400 transition-all text-white px-4 py-2 text-sm font-semibold"
              >
                Add Target
              </Link>
            </div>
            <div className="overflow-x-auto">
              <table className="min-w-[900px] w-full text-sm">
                <thead className="bg-bg-elevated/40 text-text-muted">
                  <tr>
                    <th className="text-left px-4 py-3 font-medium">Name</th>
                    <th className="text-left px-4 py-3 font-medium">URL</th>
                    <th className="text-left px-4 py-3 font-medium">Last scanned</th>
                    <th className="text-left px-4 py-3 font-medium">Findings</th>
                    <th className="text-right px-4 py-3 font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {loading ? (
                    <tr>
                      <td className="px-4 py-6 text-text-secondary" colSpan={5}>
                        Loading…
                      </td>
                    </tr>
                  ) : targets.length === 0 ? (
                    <tr>
                      <td className="px-4 py-8 text-text-secondary" colSpan={5}>
                        No targets yet. Add an asset first.
                      </td>
                    </tr>
                  ) : (
                    targets.map((a) => {
                      const last = a.last_scan;
                      const sum = last?.summary || {};
                      const total = (sum.total ?? ((sum.critical || 0) + (sum.high || 0) + (sum.medium || 0) + (sum.low || 0) + (sum.info || 0))) || 0;
                      return (
                        <tr key={a.id} className="hover:bg-bg-hover/30">
                          <td className="px-4 py-3 font-medium text-text-primary">{a.name}</td>
                          <td className="px-4 py-3 text-text-secondary">{a.url || "—"}</td>
                          <td className="px-4 py-3 text-text-secondary">
                            {last?.finished_at ? String(last.finished_at).replace("T", " ").slice(0, 16) : "—"}
                          </td>
                          <td className="px-4 py-3">
                            <div className="flex items-center gap-2">
                              <span className="inline-flex items-center rounded-full bg-rose-500/15 border border-rose-500/40 px-2 py-0.5 text-xs text-rose-300">
                                C {sum.critical || 0}
                              </span>
                              <span className="inline-flex items-center rounded-full bg-orange-500/15 border border-orange-500/40 px-2 py-0.5 text-xs text-orange-300">
                                H {sum.high || 0}
                              </span>
                              <span className="inline-flex items-center rounded-full bg-amber-500/15 border border-amber-500/40 px-2 py-0.5 text-xs text-amber-300">
                                M {sum.medium || 0}
                              </span>
                              <span className="inline-flex items-center rounded-full bg-sky-500/15 border border-sky-500/40 px-2 py-0.5 text-xs text-sky-300">
                                L {sum.low || 0}
                              </span>
                              <span className="text-xs text-text-muted">({total})</span>
                            </div>
                          </td>
                          <td className="px-4 py-3">
                            <div className="flex items-center justify-end gap-2">
                              <button
                                onClick={() => runScan(a.id)}
                                className="rounded-lg bg-bg-elevated border border-border px-3 py-1.5 text-xs text-text-secondary hover:bg-bg-hover hover:text-text-primary transition"
                              >
                                Scan
                              </button>
                              <button
                                disabled={!last?.id}
                                onClick={() => (last?.id ? download(last.id) : null)}
                                className="rounded-lg bg-bg-elevated border border-border px-3 py-1.5 text-xs text-text-secondary hover:bg-bg-hover hover:text-text-primary transition disabled:opacity-50"
                              >
                                Download
                              </button>
                            </div>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        ) : null}

        {tab === "scans" ? (
          <div className="rounded-2xl bg-bg-card border border-border overflow-hidden">
            <div className="p-4 text-sm text-text-secondary">Recent scans (history)</div>
            <div className="divide-y divide-border">
              {loading ? (
                <div className="p-6 text-text-secondary">Loading…</div>
              ) : scans.length === 0 ? (
                <div className="p-8 text-text-secondary">No scans yet. Run your first scan from the Targets tab.</div>
              ) : (
                scans.map((s) => {
                  const pill = pillColor(s.status);
                  const sum = s.findings_summary || {};
                  return (
                    <div key={s.id} className="p-4 flex items-center justify-between gap-3">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <div className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs ${pill.bg} ${pill.border} ${pill.text}`}>
                            {s.status}
                          </div>
                          <div className="text-sm text-text-muted truncate">Scan #{s.id.slice(0, 8)}</div>
                        </div>
                        <div className="text-xs text-text-secondary mt-1">
                          {s.created_at ? String(s.created_at).replace("T", " ").slice(0, 19) : ""}{" "}
                          {s.error ? <span className="text-rose-300">• {s.error}</span> : null}
                        </div>
                        <div className="mt-2 flex items-center gap-2 text-xs text-text-secondary">
                          <span className="rounded-full bg-rose-500/15 border border-rose-500/40 px-2 py-0.5">C {sum.critical || 0}</span>
                          <span className="rounded-full bg-orange-500/15 border border-orange-500/40 px-2 py-0.5">H {sum.high || 0}</span>
                          <span className="rounded-full bg-amber-500/15 border border-amber-500/40 px-2 py-0.5">M {sum.medium || 0}</span>
                          <span className="rounded-full bg-sky-500/15 border border-sky-500/40 px-2 py-0.5">L {sum.low || 0}</span>
                          <span className="rounded-full bg-slate-500/15 border border-slate-500/40 px-2 py-0.5">I {sum.info || 0}</span>
                        </div>
                      </div>
                      <button
                        onClick={() => download(s.id)}
                        className="rounded-xl bg-bg-elevated border border-border px-4 py-2 text-sm text-text-secondary hover:bg-bg-hover hover:text-text-primary transition"
                      >
                        Download
                      </button>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        ) : null}

        {tab === "scheduled" ? (
          <div className="rounded-2xl bg-bg-card border border-border overflow-hidden">
            <div className="p-4 flex items-center justify-between">
              <div className="text-sm text-text-secondary">Set recurring scans (cadence)</div>
              <button
                onClick={() => setOpen(true)}
                className="rounded-xl bg-gradient-to-r from-violet-600 to-violet-500 hover:from-violet-500 hover:to-violet-400 transition-all text-white px-4 py-2 text-sm font-semibold"
              >
                + Schedule Scan
              </button>
            </div>
            <div className="divide-y divide-border">
              {loading ? (
                <div className="p-6 text-text-secondary">Loading…</div>
              ) : scheduled.length === 0 ? (
                <div className="p-8 text-text-secondary">No schedules yet.</div>
              ) : (
                scheduled.map((s) => {
                  const pill = pillColor(Boolean(s.enabled) ? "active" : "disabled");
                  return (
                    <div key={s.id} className="p-4 flex items-center justify-between gap-3">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <div className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs ${pill.bg} ${pill.border} ${pill.text}`}>
                            {Boolean(s.enabled) ? "Enabled" : "Disabled"}
                          </div>
                          <div className="font-medium truncate">{s.asset_name || s.asset_id}</div>
                        </div>
                        <div className="text-xs text-text-secondary mt-1">
                          {s.asset_url ? <span className="mr-2">{s.asset_url}</span> : null}
                          <span className="text-text-muted">•</span> <span className="ml-2">Cadence: {s.cadence}</span>
                        </div>
                      </div>
                      <button
                        onClick={() => delSchedule(s.id)}
                        className="rounded-xl bg-bg-elevated border border-border px-4 py-2 text-sm text-text-secondary hover:bg-bg-hover hover:text-text-primary transition"
                      >
                        Delete
                      </button>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        ) : null}

        <Modal open={open} title="Schedule Scan" onClose={() => setOpen(false)}>
          <div className="space-y-3">
            <div>
              <div className="text-xs uppercase tracking-wide text-text-muted mb-1">Target</div>
              <select
                className="w-full rounded-xl bg-bg-elevated border border-border px-3 py-2 text-sm outline-none focus:border-border-light"
                value={schedAssetId}
                onChange={(e) => setSchedAssetId(e.target.value)}
              >
                <option value="">Select an asset…</option>
                {availableTargets.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <div className="text-xs uppercase tracking-wide text-text-muted mb-1">Cadence</div>
              <select
                className="w-full rounded-xl bg-bg-elevated border border-border px-3 py-2 text-sm outline-none focus:border-border-light"
                value={schedCadence}
                onChange={(e) => setSchedCadence(e.target.value)}
              >
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
                <option value="monthly">Monthly</option>
              </select>
            </div>
            <label className="flex items-center gap-2 text-sm text-text-secondary">
              <input type="checkbox" checked={schedEnabled} onChange={(e) => setSchedEnabled(e.target.checked)} />
              Enable immediately
            </label>

            <div className="flex justify-end gap-2 pt-2">
              <button
                onClick={() => setOpen(false)}
                className="rounded-xl bg-bg-elevated border border-border px-4 py-2 text-sm text-text-secondary hover:bg-bg-hover hover:text-text-primary transition"
              >
                Cancel
              </button>
              <button
                onClick={createSchedule}
                className="rounded-xl bg-gradient-to-r from-violet-600 to-violet-500 hover:from-violet-500 hover:to-violet-400 transition-all text-white px-4 py-2 text-sm font-semibold"
              >
                Save
              </button>
            </div>
          </div>
        </Modal>
      </div>
    </AppShell>
  );
}

