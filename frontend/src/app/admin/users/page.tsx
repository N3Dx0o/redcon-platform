"use client";

import { AppShell } from "@/components/AppShell";
import { IconUsers, IconUser } from "@/components/Icons";
import { Modal } from "@/components/Modal";
import { useToast } from "@/components/ToastProvider";
import { apiFetch } from "@/lib/http";
import { useEffect, useState } from "react";

type UserRow = {
  id: string;
  name: string;
  email: string;
  role: "admin" | "client" | "pentester";
  company?: string;
  is_active?: number;
  verified?: number;
};

function roleColor(role: string) {
  const r = String(role || "").toLowerCase();
  if (r === "admin") return { bg: "bg-violet-500", text: "text-violet-400", pill: "bg-violet-500/15 border-violet-500/40" };
  if (r === "client") return { bg: "bg-sky-500", text: "text-sky-400", pill: "bg-sky-500/15 border-sky-500/40" };
  if (r === "pentester") return { bg: "bg-emerald-500", text: "text-emerald-400", pill: "bg-emerald-500/15 border-emerald-500/40" };
  return { bg: "bg-slate-600", text: "text-slate-400", pill: "bg-slate-600/15 border-slate-600/40" };
}

function statusColor(active: boolean) {
  if (active) return { bg: "bg-emerald-500", text: "text-emerald-400", pill: "bg-emerald-500/15 border-emerald-500/40" };
  return { bg: "bg-rose-500", text: "text-rose-400", pill: "bg-rose-500/15 border-rose-500/40" };
}

export default function AdminUsersPage() {
  const toast = useToast();
  const [users, setUsers] = useState<UserRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<string>("all");

  const [open, setOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const [form, setForm] = useState({
    name: "",
    email: "",
    role: "client",
    company: "",
  });

  const load = async () => {
    setLoading(true);
    const r = await apiFetch<{ success?: boolean; users?: UserRow[] }>(`/api/admin/users?_=${Date.now()}`);
    if (r.ok) setUsers(r.data.users || []);
    setLoading(false);
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const create = async () => {
    if (!form.name || !form.email) {
      toast.push({ type: "warning", title: "Missing fields", message: "Name and email are required." });
      return;
    }
    setSaving(true);
    const r = await apiFetch<any>(`/api/admin/users`, { method: "POST", body: JSON.stringify(form) });
    setSaving(false);
    if (!r.ok) {
      toast.push({ type: "error", title: "Create failed", message: r.error }, 5200);
      return;
    }
    toast.push({ type: "success", title: "User created", message: "Setup link sent to user's email" }, 5000);
    setOpen(false);
    setForm({ name: "", email: "", role: "client", company: "" });
    await load();
  };

  const toggleActive = async (id: string) => {
    const r = await apiFetch<any>(`/api/admin/users/${encodeURIComponent(id)}/toggle-active`, { method: "POST", body: "{}" });
    if (!r.ok) {
      toast.push({ type: "error", title: "Update failed", message: r.error }, 5200);
      return;
    }
    await load();
  };

  const del = async (id: string, email: string) => {
    if (!confirm(`Delete user ${email}?`)) return;
    const r = await apiFetch<any>(`/api/admin/users/${encodeURIComponent(id)}`, { method: "DELETE" });
    if (!r.ok) {
      toast.push({ type: "error", title: "Delete failed", message: r.error }, 5200);
      return;
    }
    toast.push({ type: "success", title: "User deleted" });
    await load();
  };

  const filteredUsers = filter === "all" ? users : users.filter((u) => u.role === filter);

  const counts = {
    all: users.length,
    admin: users.filter((u) => u.role === "admin").length,
    client: users.filter((u) => u.role === "client").length,
    pentester: users.filter((u) => u.role === "pentester").length,
  };

  return (
    <AppShell role="admin">
      <div className="max-w-6xl mx-auto space-y-5">
        {/* Hero Header */}
        <div className="rounded-3xl border border-border bg-gradient-to-r from-bg-card via-bg-elevated to-bg-card overflow-hidden shadow-xl shadow-black/10">
          <div className="relative p-6">
            <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_top_right,_var(--tw-gradient-stops))] from-violet-500/20 via-sky-500/10 to-transparent" />
            <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_bottom_left,_var(--tw-gradient-stops))] from-emerald-500/15 via-violet-500/10 to-transparent" />
            <div className="relative flex flex-col md:flex-row md:items-end justify-between gap-4">
              <div>
                <div className="text-2xl font-bold">User Management</div>
                <div className="text-sm text-text-secondary mt-1">
                  Create, enable/disable, and delete platform users
                </div>
              </div>
              <button
                onClick={() => setOpen(true)}
                className="rounded-xl bg-gradient-to-r from-violet-600 to-violet-500 hover:from-violet-500 hover:to-violet-400 transition-all text-white px-5 py-2.5 text-sm font-semibold shadow-lg shadow-violet-500/25"
              >
                + Create User
              </button>
            </div>
          </div>
        </div>

        {/* Filter Tabs */}
        <div className="flex flex-wrap gap-2">
          {[
            { key: "all", label: "All Users", count: counts.all, color: "bg-slate-600" },
            { key: "admin", label: "Admins", count: counts.admin, color: "bg-violet-500" },
            { key: "client", label: "Clients", count: counts.client, color: "bg-sky-500" },
            { key: "pentester", label: "Pentesters", count: counts.pentester, color: "bg-emerald-500" },
          ].map((t) => (
            <button
              key={t.key}
              onClick={() => setFilter(t.key)}
              className={[
                "inline-flex items-center gap-2 rounded-xl px-4 py-2 text-sm font-medium transition-all duration-200",
                filter === t.key
                  ? "bg-white/10 border border-white/20 text-white shadow-lg"
                  : "bg-bg-elevated border border-border text-text-secondary hover:bg-bg-hover hover:text-text-primary",
              ].join(" ")}
            >
              <span className={`h-2 w-2 rounded-full ${t.color}`} />
              {t.label}
              <span className="text-xs text-text-muted">({t.count})</span>
            </button>
          ))}
        </div>

        {/* Users List */}
        {loading ? (
          <div className="rounded-2xl bg-gradient-to-br from-bg-card to-bg-elevated border border-border p-10 text-center shadow-lg shadow-black/10">
            <div className="mx-auto w-12 h-12 rounded-xl bg-violet-500/10 flex items-center justify-center mb-3 animate-pulse">
              <IconUsers className="h-6 w-6 text-violet-400" />
            </div>
            <div className="text-text-secondary">Loading users…</div>
          </div>
        ) : filteredUsers.length === 0 ? (
          <div className="rounded-2xl bg-gradient-to-br from-bg-card to-bg-elevated border border-dashed border-border p-10 text-center shadow-lg shadow-black/10">
            <div className="mx-auto w-14 h-14 rounded-xl bg-violet-500/10 flex items-center justify-center mb-3">
              <IconUser className="h-7 w-7 text-violet-400" />
            </div>
            <div className="text-lg font-medium">No users found</div>
            <div className="text-text-secondary text-sm mt-1">
              {filter === "all" ? "Create your first user to get started" : `No ${filter}s in the system`}
            </div>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filteredUsers.map((u) => {
              const rc = roleColor(u.role);
              const sc = statusColor(!!u.is_active);
              return (
                <div key={u.id} className="rounded-2xl bg-gradient-to-br from-bg-card to-bg-elevated border border-border p-5 relative overflow-hidden group transition-all duration-200 hover:border-border-light shadow-lg shadow-black/10">
                  <div className={`pointer-events-none absolute inset-y-0 left-0 w-1 ${rc.bg}`} />
                  <div className="flex items-start justify-between gap-3 mb-3">
                    <div className="min-w-0 flex-1">
                      <div className="font-semibold text-lg truncate group-hover:text-white transition">{u.name}</div>
                      <div className="text-sm text-text-muted truncate">{u.email}</div>
                    </div>
                  </div>
                  <div className="flex flex-wrap items-center gap-2 mb-4">
                    <span className={`inline-flex items-center rounded-lg border px-2.5 py-1 text-xs font-medium ${rc.pill} ${rc.text}`}>
                      {u.role}
                    </span>
                    <span className={`inline-flex items-center rounded-lg border px-2.5 py-1 text-xs font-medium ${sc.pill} ${sc.text}`}>
                      {u.is_active ? "Active" : "Disabled"}
                    </span>
                    {u.company ? (
                      <span className="text-xs text-text-muted">{u.company}</span>
                    ) : null}
                  </div>
                  <div className="flex gap-2">
                    <button
                      onClick={() => toggleActive(u.id)}
                      className={[
                        "flex-1 rounded-lg border px-3 py-2 text-xs font-medium transition",
                        u.is_active
                          ? "bg-amber-500/10 border-amber-500/30 text-amber-400 hover:bg-amber-500/15"
                          : "bg-emerald-500/10 border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/15",
                      ].join(" ")}
                    >
                      {u.is_active ? "Disable" : "Enable"}
                    </button>
                    <button
                      onClick={() => del(u.id, u.email)}
                      className="rounded-lg bg-rose-500/10 border border-rose-500/30 px-3 py-2 text-xs font-medium text-rose-400 hover:bg-rose-500/15 transition"
                    >
                      Delete
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}

        <Modal
          open={open}
          title="Create User"
          onClose={() => setOpen(false)}
          maxWidthClass="max-w-xl"
          footer={
            <>
              <button
                onClick={() => setOpen(false)}
                className="rounded-xl bg-bg-elevated border border-border px-4 py-2 text-sm text-text-secondary hover:bg-bg-hover hover:text-text-primary transition"
              >
                Cancel
              </button>
              <button
                disabled={saving}
                onClick={create}
                className="rounded-xl bg-gradient-to-r from-violet-600 to-violet-500 hover:from-violet-500 hover:to-violet-400 text-white px-5 py-2 text-sm font-semibold transition disabled:opacity-60 shadow-lg shadow-violet-500/25"
              >
                {saving ? "Creating…" : "Create"}
              </button>
            </>
          }
        >
          <div className="grid grid-cols-1 gap-4">
            <div>
              <label className="block text-xs uppercase text-text-muted mb-1">Name *</label>
              <input
                value={form.name}
                onChange={(e) => setForm((p) => ({ ...p, name: e.target.value }))}
                className="w-full rounded-xl bg-bg-elevated border border-border px-3 py-2.5 text-sm outline-none focus:border-border-light"
                placeholder="John Doe"
              />
            </div>
            <div>
              <label className="block text-xs uppercase text-text-muted mb-1">Email *</label>
              <input
                type="email"
                value={form.email}
                onChange={(e) => setForm((p) => ({ ...p, email: e.target.value }))}
                className="w-full rounded-xl bg-bg-elevated border border-border px-3 py-2.5 text-sm outline-none focus:border-border-light"
                placeholder="john@example.com"
              />
              <p className="mt-1 text-xs text-gray-500">
                User will receive a secure setup link to create their own password
              </p>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label className="block text-xs uppercase text-text-muted mb-1">Role</label>
                <select
                  value={form.role}
                  onChange={(e) => setForm((p) => ({ ...p, role: e.target.value }))}
                  className="w-full rounded-xl bg-[#1a1a24] border border-border px-3 py-2.5 text-sm text-white outline-none hover:border-border-light focus:border-sky-500/50 focus:ring-2 focus:ring-sky-500/10"
                >
                  <option value="client">Client</option>
                  <option value="pentester">Pentester</option>
                  <option value="admin">Admin</option>
                </select>
              </div>
              <div>
                <label className="block text-xs uppercase text-text-muted mb-1">Company</label>
                <input
                  value={form.company}
                  onChange={(e) => setForm((p) => ({ ...p, company: e.target.value }))}
                  className="w-full rounded-xl bg-bg-elevated border border-border px-3 py-2.5 text-sm outline-none focus:border-border-light"
                  placeholder="Acme Inc."
                />
              </div>
            </div>
          </div>
        </Modal>
      </div>
    </AppShell>
  );
}
