"use client";

import { AppShell } from "@/components/AppShell";
import { IconCube } from "@/components/Icons";
import { Modal } from "@/components/Modal";
import { useToast } from "@/components/ToastProvider";
import { apiFetch } from "@/lib/http";
import { useEffect, useMemo, useState } from "react";

type Asset = {
  id: string;
  name: string;
  type: string;
  url?: string;
  environment?: string;
  technology_stack?: string;
  risk_level?: string;
  authentication_info?: string;
  description?: string;
  status?: string;
  created_at?: string;
};

function riskColor(risk: string) {
  const r = String(risk || "").toLowerCase();
  if (r === "critical") return { bg: "bg-rose-500", text: "text-rose-400", border: "border-rose-500/40", pill: "bg-rose-500/15" };
  if (r === "high") return { bg: "bg-orange-500", text: "text-orange-400", border: "border-orange-500/40", pill: "bg-orange-500/15" };
  if (r === "medium") return { bg: "bg-amber-400", text: "text-amber-400", border: "border-amber-400/40", pill: "bg-amber-400/15" };
  if (r === "low") return { bg: "bg-sky-400", text: "text-sky-400", border: "border-sky-400/40", pill: "bg-sky-400/15" };
  return { bg: "bg-slate-500", text: "text-slate-400", border: "border-slate-500/40", pill: "bg-slate-500/15" };
}

function envColor(env: string) {
  const e = String(env || "").toLowerCase();
  if (e === "production") return { bg: "bg-rose-500", text: "text-rose-400", border: "border-rose-500/40", pill: "bg-rose-500/15" };
  if (e === "staging") return { bg: "bg-amber-500", text: "text-amber-400", border: "border-amber-500/40", pill: "bg-amber-500/15" };
  if (["development", "dev"].includes(e)) return { bg: "bg-sky-500", text: "text-sky-400", border: "border-sky-500/40", pill: "bg-sky-500/15" };
  return { bg: "bg-slate-600", text: "text-slate-400", border: "border-slate-600/40", pill: "bg-slate-600/15" };
}

function typeColor(type: string) {
  const t = String(type || "").toLowerCase();
  if (["web"].includes(t)) return { bg: "bg-sky-500", text: "text-sky-400", border: "border-sky-500/40", pill: "bg-sky-500/15" };
  if (["api"].includes(t)) return { bg: "bg-emerald-500", text: "text-emerald-400", border: "border-emerald-500/40", pill: "bg-emerald-500/15" };
  if (["mobile", "mobile_ios", "mobile_android"].includes(t)) return { bg: "bg-violet-500", text: "text-violet-400", border: "border-violet-500/40", pill: "bg-violet-500/15" };
  if (["network", "internal_network", "external_network"].includes(t)) return { bg: "bg-rose-500", text: "text-rose-400", border: "border-rose-500/40", pill: "bg-rose-500/15" };
  if (["cloud"].includes(t)) return { bg: "bg-cyan-500", text: "text-cyan-400", border: "border-cyan-500/40", pill: "bg-cyan-500/15" };
  return { bg: "bg-slate-600", text: "text-slate-400", border: "border-slate-600/40", pill: "bg-slate-600/15" };
}

function statusColor(status: string) {
  const s = String(status || "").toLowerCase();
  if (s === "active") return { bg: "bg-emerald-500", text: "text-emerald-400", border: "border-emerald-500/40", pill: "bg-emerald-500/15" };
  if (["inactive", "paused"].includes(s)) return { bg: "bg-amber-500", text: "text-amber-400", border: "border-amber-500/40", pill: "bg-amber-500/15" };
  if (s === "archived") return { bg: "bg-slate-600", text: "text-slate-400", border: "border-slate-600/40", pill: "bg-slate-600/15" };
  return { bg: "bg-slate-600", text: "text-slate-400", border: "border-slate-600/40", pill: "bg-slate-600/15" };
}

export default function ClientAssetsPage() {
  const toast = useToast();
  const [loading, setLoading] = useState(true);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [types, setTypes] = useState<Array<{ value: string; label: string }>>([]);

  const [open, setOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const [editId, setEditId] = useState<string | null>(null);
  const [form, setForm] = useState<any>({
    name: "",
    type: "web",
    url: "",
    environment: "production",
    technology_stack: "",
    risk_level: "medium",
    authentication_info: "",
    description: "",
    status: "active",
  });

  const load = async () => {
    setLoading(true);
    const r1 = await apiFetch<any>(`/api/client/assets?_=${Date.now()}`);
    const r2 = await apiFetch<any>(`/api/asset-types?_=${Date.now()}`);
    if (r1.ok) setAssets(r1.data.assets || []);
    if (r2.ok) setTypes((r2.data.types || []).map((t: any) => ({ value: t.value, label: t.label })));
    setLoading(false);
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const resetForm = () => {
    setForm({
      name: "",
      type: "web",
      url: "",
      environment: "production",
      technology_stack: "",
      risk_level: "medium",
      authentication_info: "",
      description: "",
      status: "active",
    });
    setEditId(null);
  };

  const openCreate = () => {
    resetForm();
    setOpen(true);
  };

  const openEdit = (a: Asset) => {
    setEditId(a.id);
    setForm({
      name: a.name || "",
      type: a.type || "web",
      url: a.url || "",
      environment: a.environment || "production",
      technology_stack: a.technology_stack || "",
      risk_level: a.risk_level || "medium",
      authentication_info: a.authentication_info || "",
      description: a.description || "",
      status: a.status || "active",
    });
    setOpen(true);
  };

  const save = async () => {
    if (!form.name || !form.type) {
      toast.push({ type: "warning", title: "Missing fields", message: "Name and type are required." });
      return;
    }
    setSaving(true);
    try {
      if (editId) {
        const r = await apiFetch<any>(`/api/client/assets/${encodeURIComponent(editId)}`, {
          method: "PUT",
          body: JSON.stringify(form),
        });
        if (!r.ok) throw new Error(r.error);
        toast.push({ type: "success", title: "Asset updated" });
      } else {
        const r = await apiFetch<any>(`/api/client/assets`, { method: "POST", body: JSON.stringify(form) });
        if (!r.ok) throw new Error(r.error);
        toast.push({ type: "success", title: "Asset created" });
      }
      setOpen(false);
      resetForm();
      await load();
    } catch (e: any) {
      toast.push({ type: "error", title: "Save failed", message: e?.message || "Unknown error" }, 5200);
    } finally {
      setSaving(false);
    }
  };

  const del = async (id: string) => {
    if (!confirm("Delete this asset?")) return;
    const r = await apiFetch<any>(`/api/client/assets/${encodeURIComponent(id)}`, { method: "DELETE" });
    if (!r.ok) {
      toast.push({ type: "error", title: "Delete failed", message: r.error }, 5200);
      return;
    }
    toast.push({ type: "success", title: "Asset deleted" });
    await load();
  };

  const typeLabel = useMemo(() => {
    const map = new Map(types.map((t) => [t.value, t.label]));
    return (v: string) => map.get(v) || v;
  }, [types]);

  return (
    <AppShell role="client">
      <div className="max-w-6xl mx-auto space-y-5">
        {/* Hero Header */}
        <div className="rounded-3xl border border-border bg-gradient-to-r from-bg-card via-bg-elevated to-bg-card overflow-hidden shadow-xl shadow-black/10">
          <div className="relative p-6">
            <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_top_right,_var(--tw-gradient-stops))] from-amber-500/20 via-emerald-500/10 to-transparent" />
            <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_bottom_left,_var(--tw-gradient-stops))] from-sky-500/15 via-violet-500/10 to-transparent" />
            <div className="relative flex flex-col md:flex-row md:items-end justify-between gap-4">
              <div>
                <div className="text-2xl font-bold">Assets</div>
                <div className="text-sm text-text-secondary mt-1">
                  Define your attack surface — what should we test?
                </div>
              </div>
              <button
                onClick={openCreate}
                className="rounded-xl bg-gradient-to-r from-emerald-600 to-emerald-500 hover:from-emerald-500 hover:to-emerald-400 transition-all text-white px-5 py-2.5 text-sm font-semibold shadow-lg shadow-emerald-500/25"
              >
                + Add Asset
              </button>
            </div>
          </div>
        </div>

        {/* Assets List */}
        {loading ? (
          <div className="rounded-2xl bg-gradient-to-br from-bg-card to-bg-elevated border border-border p-10 text-center shadow-lg shadow-black/10">
            <div className="mx-auto w-12 h-12 rounded-xl bg-amber-500/10 flex items-center justify-center mb-3 animate-pulse">
              <IconCube className="h-6 w-6 text-amber-400" />
            </div>
            <div className="text-text-secondary">Loading assets…</div>
          </div>
        ) : assets.length === 0 ? (
          <div className="rounded-2xl bg-gradient-to-br from-bg-card to-bg-elevated border border-dashed border-border p-10 text-center shadow-lg shadow-black/10">
            <div className="mx-auto w-14 h-14 rounded-xl bg-amber-500/10 flex items-center justify-center mb-3">
              <IconCube className="h-7 w-7 text-amber-400" />
            </div>
            <div className="text-lg font-medium">No assets yet</div>
            <div className="text-text-secondary text-sm mt-1">Add your first asset to start planning pentests</div>
            <button
              onClick={openCreate}
              className="inline-block mt-4 rounded-xl bg-gradient-to-r from-emerald-600 to-emerald-500 hover:from-emerald-500 hover:to-emerald-400 transition-all text-white px-5 py-2.5 text-sm font-semibold shadow-lg shadow-emerald-500/25"
            >
              Add Asset
            </button>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {assets.map((a) => {
              const tc = typeColor(a.type);
              const ec = envColor(a.environment || "production");
              const rc = riskColor(a.risk_level || "medium");
              const sc = statusColor(a.status || "active");
              return (
                <div key={a.id} className="rounded-2xl bg-gradient-to-br from-bg-card to-bg-elevated border border-border p-5 relative overflow-hidden group transition-all duration-200 hover:border-border-light shadow-lg shadow-black/10">
                  <div className={`pointer-events-none absolute inset-y-0 left-0 w-1 ${tc.bg}`} />
                  <div className="flex items-start justify-between gap-3 mb-3">
                    <div className="min-w-0 flex-1">
                      <div className="font-semibold text-lg group-hover:text-white transition truncate">{a.name}</div>
                      {a.url ? (
                        <div className="text-sm text-text-muted truncate mt-0.5">{a.url}</div>
                      ) : null}
                    </div>
                    <div className="flex gap-2 flex-shrink-0">
                      <button
                        onClick={() => openEdit(a)}
                        className="rounded-lg bg-white/5 border border-white/10 px-3 py-1.5 text-xs text-text-secondary hover:bg-white/10 hover:text-white transition-all"
                      >
                        Edit
                      </button>
                      <button
                        onClick={() => del(a.id)}
                        className="rounded-lg bg-rose-500/10 border border-rose-500/30 px-3 py-1.5 text-xs text-rose-400 hover:bg-rose-500/20 transition-all"
                      >
                        Delete
                      </button>
                    </div>
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className={`inline-flex items-center rounded-lg ${tc.pill} ${tc.border} border px-2.5 py-1 text-xs font-medium ${tc.text}`}>
                      {typeLabel(a.type)}
                    </span>
                    <span className={`inline-flex items-center rounded-lg ${ec.pill} ${ec.border} border px-2.5 py-1 text-xs font-medium ${ec.text}`}>
                      {a.environment || "production"}
                    </span>
                    <span className={`inline-flex items-center rounded-lg ${rc.pill} ${rc.border} border px-2.5 py-1 text-xs font-medium ${rc.text}`}>
                      {a.risk_level || "medium"} risk
                    </span>
                    <span className={`inline-flex items-center rounded-lg ${sc.pill} ${sc.border} border px-2.5 py-1 text-xs font-medium ${sc.text}`}>
                      {a.status || "active"}
                    </span>
                  </div>
                  {a.technology_stack ? (
                    <div className="mt-3 text-xs text-text-muted">
                      <span className="font-medium text-text-secondary">Tech:</span> {a.technology_stack}
                    </div>
                  ) : null}
                </div>
              );
            })}
          </div>
        )}

        <Modal
          open={open}
          title={editId ? "Edit Asset" : "Add Asset"}
          onClose={() => {
            setOpen(false);
            resetForm();
          }}
          maxWidthClass="max-w-4xl"
          footer={
            <>
              <button
                onClick={() => {
                  setOpen(false);
                  resetForm();
                }}
                className="rounded-xl bg-bg-elevated border border-border px-4 py-2 text-sm text-text-secondary hover:bg-bg-hover hover:text-text-primary transition"
              >
                Cancel
              </button>
              <button
                disabled={saving}
                onClick={save}
                className="rounded-xl bg-gradient-to-r from-emerald-600 to-emerald-500 hover:from-emerald-500 hover:to-emerald-400 transition-all text-white px-5 py-2 text-sm font-semibold disabled:opacity-60 shadow-lg shadow-emerald-500/25"
              >
                {saving ? "Saving…" : "Save"}
              </button>
            </>
          }
        >
          <div className="grid grid-cols-1 gap-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label className="block text-xs uppercase text-text-muted mb-1">Name *</label>
                <input
                  value={form.name}
                  onChange={(e) => setForm((p: any) => ({ ...p, name: e.target.value }))}
                  className="w-full rounded-xl bg-bg-elevated border border-border px-3 py-2.5 text-sm outline-none focus:border-border-light"
                  placeholder="e.g., Main Website"
                />
              </div>
              <div>
                <label className="block text-xs uppercase text-text-muted mb-1">Type *</label>
                <select
                  value={form.type}
                  onChange={(e) => setForm((p: any) => ({ ...p, type: e.target.value }))}
                  className="w-full rounded-xl bg-[#1a1a24] border border-border px-3 py-2.5 text-sm text-white outline-none hover:border-border-light focus:border-sky-500/50 focus:ring-2 focus:ring-sky-500/10"
                >
                  {types.map((t) => (
                    <option key={t.value} value={t.value}>
                      {t.label}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label className="block text-xs uppercase text-text-muted mb-1">URL</label>
                <input
                  value={form.url}
                  onChange={(e) => setForm((p: any) => ({ ...p, url: e.target.value }))}
                  className="w-full rounded-xl bg-bg-elevated border border-border px-3 py-2.5 text-sm outline-none focus:border-border-light"
                  placeholder="https://app.example.com"
                />
              </div>
              <div>
                <label className="block text-xs uppercase text-text-muted mb-1">Environment</label>
                <select
                  value={form.environment}
                  onChange={(e) => setForm((p: any) => ({ ...p, environment: e.target.value }))}
                  className="w-full rounded-xl bg-[#1a1a24] border border-border px-3 py-2.5 text-sm text-white outline-none hover:border-border-light focus:border-sky-500/50 focus:ring-2 focus:ring-sky-500/10"
                >
                  <option value="production">Production</option>
                  <option value="staging">Staging</option>
                  <option value="development">Development</option>
                </select>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label className="block text-xs uppercase text-text-muted mb-1">Risk Level</label>
                <select
                  value={form.risk_level}
                  onChange={(e) => setForm((p: any) => ({ ...p, risk_level: e.target.value }))}
                  className="w-full rounded-xl bg-[#1a1a24] border border-border px-3 py-2.5 text-sm text-white outline-none hover:border-border-light focus:border-sky-500/50 focus:ring-2 focus:ring-sky-500/10"
                >
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
                </select>
              </div>
              <div>
                <label className="block text-xs uppercase text-text-muted mb-1">Status</label>
                <select
                  value={form.status}
                  onChange={(e) => setForm((p: any) => ({ ...p, status: e.target.value }))}
                  className="w-full rounded-xl bg-[#1a1a24] border border-border px-3 py-2.5 text-sm text-white outline-none hover:border-border-light focus:border-sky-500/50 focus:ring-2 focus:ring-sky-500/10"
                >
                  <option value="active">Active</option>
                  <option value="inactive">Inactive</option>
                  <option value="archived">Archived</option>
                </select>
              </div>
            </div>

            <div>
              <label className="block text-xs uppercase text-text-muted mb-1">Technology Stack</label>
              <input
                value={form.technology_stack}
                onChange={(e) => setForm((p: any) => ({ ...p, technology_stack: e.target.value }))}
                className="w-full rounded-xl bg-bg-elevated border border-border px-3 py-2.5 text-sm outline-none focus:border-border-light"
                placeholder="e.g., React, Node.js, PostgreSQL"
              />
            </div>

            <div>
              <label className="block text-xs uppercase text-text-muted mb-1">Authentication Info</label>
              <textarea
                value={form.authentication_info}
                onChange={(e) => setForm((p: any) => ({ ...p, authentication_info: e.target.value }))}
                rows={2}
                className="w-full rounded-xl bg-bg-elevated border border-border px-3 py-2.5 text-sm outline-none focus:border-border-light"
                placeholder="Auth methods, roles to test, etc."
              />
            </div>

            <div>
              <label className="block text-xs uppercase text-text-muted mb-1">Description</label>
              <textarea
                value={form.description}
                onChange={(e) => setForm((p: any) => ({ ...p, description: e.target.value }))}
                rows={3}
                className="w-full rounded-xl bg-bg-elevated border border-border px-3 py-2.5 text-sm outline-none focus:border-border-light"
                placeholder="Additional notes about this asset…"
              />
            </div>
          </div>
        </Modal>
      </div>
    </AppShell>
  );
}
