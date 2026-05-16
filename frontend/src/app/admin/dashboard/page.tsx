"use client";

import { AppShell } from "@/components/AppShell";
import { IconUsers, IconClock, IconShield, IconBug, IconClipboard, IconUser, IconRocket, IconCode } from "@/components/Icons";
import { apiFetch } from "@/lib/http";
import { formatPentestStatusLabel, pentestStatusAccentBg, pentestStatusPill } from "@/lib/pentestStatus";
import Link from "next/link";
import { useEffect, useState } from "react";

type AdminStats = {
  success?: boolean;
  total_users?: number;
  pending_requests?: number;
  active_pentests?: number;
  total_pentests?: number;
  total_findings?: number;
  clients_count?: number;
  pentesters_count?: number;
};

type PentestRow = {
  id: string;
  public_id?: string;
  title: string;
  status: string;
  type?: string;
  company_name?: string;
  created_at?: string;
};

function StatCard({
  label,
  value,
  icon,
  gradient,
  iconBg,
}: {
  label: string;
  value: any;
  icon: React.ReactNode;
  gradient: string;
  iconBg: string;
}) {
  return (
    <div className="group rounded-2xl bg-gradient-to-br from-bg-card to-bg-elevated border border-border p-4 relative overflow-hidden transition-all duration-300 hover:border-border-light hover:shadow-lg hover:shadow-black/20">
      <div className={`pointer-events-none absolute inset-0 opacity-30 bg-gradient-to-br ${gradient}`} />
      <div className="pointer-events-none absolute -top-8 -right-8 h-24 w-24 rounded-full bg-white/5 blur-2xl group-hover:bg-white/10 transition-all duration-500" />
      <div className="relative flex items-center gap-3">
        <div className={`flex-shrink-0 h-10 w-10 rounded-xl ${iconBg} flex items-center justify-center text-lg shadow-lg`}>
          {icon}
        </div>
        <div>
          <div className="text-text-muted text-xs uppercase tracking-wide">{label}</div>
          <div className="text-2xl font-bold mt-0.5">{value}</div>
        </div>
      </div>
    </div>
  );
}

export default function AdminDashboardPage() {
  const [stats, setStats] = useState<AdminStats | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [pending, setPending] = useState<PentestRow[]>([]);
  const [active, setActive] = useState<PentestRow[]>([]);

  useEffect(() => {
    (async () => {
      const res = await apiFetch<AdminStats>("/api/admin/stats");
      if (!res.ok) {
        setErr(res.error);
        return;
      }
      setStats(res.data);

      const r1 = await apiFetch<{ requests?: PentestRow[] }>(`/api/admin/pending-requests?_=${Date.now()}`);
      if (r1.ok) setPending((r1.data.requests || []).slice(0, 5));

      const r2 = await apiFetch<{ pentests?: PentestRow[] }>(`/api/admin/pentests?_=${Date.now()}`);
      if (r2.ok) setActive((r2.data.pentests || []).slice(0, 5));
    })();
  }, []);

  return (
    <AppShell role="admin">
      <div className="max-w-6xl mx-auto space-y-5">
        {/* Hero Header */}
        <div className="rounded-3xl border border-border bg-gradient-to-r from-bg-card via-bg-elevated to-bg-card overflow-hidden shadow-xl shadow-black/10">
          <div className="relative p-6">
            <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_top_right,_var(--tw-gradient-stops))] from-violet-500/20 via-rose-500/10 to-transparent" />
            <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_bottom_left,_var(--tw-gradient-stops))] from-sky-500/15 via-emerald-500/10 to-transparent" />
            <div className="relative flex flex-col md:flex-row md:items-end justify-between gap-4">
              <div>
                <div className="text-2xl font-bold bg-gradient-to-r from-white via-white to-text-secondary bg-clip-text">
                  Admin Dashboard
                </div>
                <div className="text-sm text-text-secondary mt-1">
                  Manage pentests, users, and platform operations
                </div>
              </div>
              <div className="flex gap-2">
                <Link
                  href="/admin/users"
                  className="rounded-xl bg-white/5 backdrop-blur border border-white/10 px-4 py-2.5 text-sm text-text-secondary hover:bg-white/10 hover:text-text-primary transition-all"
                >
                  Manage Users
                </Link>
                <Link
                  href="/admin/pentests"
                  className="rounded-xl bg-gradient-to-r from-violet-600 to-violet-500 hover:from-violet-500 hover:to-violet-400 transition-all text-white px-5 py-2.5 text-sm font-semibold shadow-lg shadow-violet-500/25"
                >
                  View Pentests
                </Link>
              </div>
            </div>
          </div>
        </div>

        {err ? (
          <div className="rounded-xl border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-300">
            {err}
          </div>
        ) : null}

        {/* Stat Cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <StatCard
            label="Total Users"
            value={stats?.total_users ?? "—"}
            icon={<IconUsers className="h-5 w-5 text-white" />}
            gradient="from-violet-500/30 to-violet-600/10"
            iconBg="bg-gradient-to-br from-violet-500 to-violet-600"
          />
          <StatCard
            label="Pending Requests"
            value={stats?.pending_requests ?? "—"}
            icon={<IconClock className="h-5 w-5 text-white" />}
            gradient="from-amber-500/30 to-amber-600/10"
            iconBg="bg-gradient-to-br from-amber-500 to-amber-600"
          />
          <StatCard
            label="Active Pentests"
            value={stats?.active_pentests ?? "—"}
            icon={<IconShield className="h-5 w-5 text-white" />}
            gradient="from-emerald-500/30 to-emerald-600/10"
            iconBg="bg-gradient-to-br from-emerald-500 to-emerald-600"
          />
          <StatCard
            label="Total Findings"
            value={stats?.total_findings ?? "—"}
            icon={<IconBug className="h-5 w-5 text-white" />}
            gradient="from-rose-500/30 to-rose-600/10"
            iconBg="bg-gradient-to-br from-rose-500 to-rose-600"
          />
        </div>

        {/* Main Content */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Pending Requests */}
          <div className="rounded-2xl bg-gradient-to-br from-bg-card to-bg-elevated border border-border p-5 shadow-lg shadow-black/10">
            <div className="flex items-center justify-between mb-4">
              <div className="font-semibold text-lg flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-amber-500 animate-pulse" />
                Pending Requests
              </div>
              <Link href="/admin/pentests" className="text-sm text-sky-400 hover:text-sky-300 transition">
                View all →
              </Link>
            </div>
            {pending.length === 0 ? (
              <div className="rounded-xl bg-bg-elevated/50 border border-dashed border-border p-6 text-center">
                <div className="mx-auto w-10 h-10 rounded-lg bg-emerald-500/10 flex items-center justify-center mb-2">
                  <IconShield className="h-5 w-5 text-emerald-400" />
                </div>
                <div className="text-text-secondary text-sm">No pending requests</div>
              </div>
            ) : (
              <div className="space-y-2">
                {pending.map((p) => {
                  const sc = pentestStatusPill(p.status);
                  return (
                    <Link
                      key={p.id}
                      href="/admin/pentests"
                      className="block rounded-xl bg-bg-elevated/50 border border-border hover:border-border-light transition-all px-4 py-3 relative overflow-hidden group"
                    >
                      <div className={`pointer-events-none absolute inset-y-0 left-0 w-1 ${pentestStatusAccentBg(p.status)}`} />
                      <div className="flex items-center justify-between gap-3">
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            <div className="font-medium truncate group-hover:text-white transition">{p.title}</div>
                            {p.public_id && (
                              <span className="text-xs font-mono text-sky-400 bg-sky-400/10 px-2 py-0.5 rounded border border-sky-400/20">
                                {p.public_id}
                              </span>
                            )}
                          </div>
                          <div className="text-sm text-text-secondary">
                            {p.company_name || "—"} •{" "}
                            <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${sc.pill} ${sc.text}`}>
                              {formatPentestStatusLabel(p.status)}
                            </span>
                          </div>
                        </div>
                        <div className="text-xs text-text-muted">{p.created_at ? String(p.created_at).slice(0, 10) : ""}</div>
                      </div>
                    </Link>
                  );
                })}
              </div>
            )}
          </div>

          {/* Active Pentests */}
          <div className="rounded-2xl bg-gradient-to-br from-bg-card to-bg-elevated border border-border p-5 shadow-lg shadow-black/10">
            <div className="flex items-center justify-between mb-4">
              <div className="font-semibold text-lg flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-emerald-500" />
                Active Pentests
              </div>
              <Link href="/admin/pentests" className="text-sm text-sky-400 hover:text-sky-300 transition">
                View all →
              </Link>
            </div>
            {active.length === 0 ? (
              <div className="rounded-xl bg-bg-elevated/50 border border-dashed border-border p-6 text-center">
                <div className="mx-auto w-10 h-10 rounded-lg bg-emerald-500/10 flex items-center justify-center mb-2">
                  <IconShield className="h-5 w-5 text-emerald-400" />
                </div>
                <div className="text-text-secondary text-sm">No active pentests</div>
              </div>
            ) : (
              <div className="space-y-2">
                {active.map((p) => {
                  const sc = pentestStatusPill(p.status);
                  return (
                    <Link
                      key={p.id}
                      href="/admin/pentests"
                      className="block rounded-xl bg-bg-elevated/50 border border-border hover:border-border-light transition-all px-4 py-3 relative overflow-hidden group"
                    >
                      <div className={`pointer-events-none absolute inset-y-0 left-0 w-1 ${pentestStatusAccentBg(p.status)}`} />
                      <div className="flex items-center justify-between gap-3">
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            <div className="font-medium truncate group-hover:text-white transition">{p.title}</div>
                            {p.public_id && (
                              <span className="text-xs font-mono text-sky-400 bg-sky-400/10 px-2 py-0.5 rounded border border-sky-400/20">
                                {p.public_id}
                              </span>
                            )}
                          </div>
                          <div className="text-sm text-text-secondary">
                            {p.type || "—"} •{" "}
                            <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${sc.pill} ${sc.text}`}>
                              {formatPentestStatusLabel(p.status)}
                            </span>
                          </div>
                        </div>
                      </div>
                    </Link>
                  );
                })}
              </div>
            )}
          </div>
        </div>

        {/* Quick Actions */}
        <div className="rounded-2xl bg-gradient-to-br from-bg-card to-bg-elevated border border-border p-5 shadow-lg shadow-black/10">
          <div className="font-semibold text-lg mb-4">Quick Actions</div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <Link
              href="/admin/pentests"
              className="rounded-xl bg-amber-500/10 border border-amber-500/30 p-4 text-center hover:bg-amber-500/15 transition group"
            >
              <div className="mx-auto w-10 h-10 rounded-lg bg-amber-500/20 flex items-center justify-center mb-2">
                <IconClipboard className="h-5 w-5 text-amber-400" />
              </div>
              <div className="text-sm font-medium text-amber-400 group-hover:text-amber-300">Review Requests</div>
            </Link>
            <Link
              href="/admin/users"
              className="rounded-xl bg-violet-500/10 border border-violet-500/30 p-4 text-center hover:bg-violet-500/15 transition group"
            >
              <div className="mx-auto w-10 h-10 rounded-lg bg-violet-500/20 flex items-center justify-center mb-2">
                <IconUser className="h-5 w-5 text-violet-400" />
              </div>
              <div className="text-sm font-medium text-violet-400 group-hover:text-violet-300">Add User</div>
            </Link>
            <Link
              href="/admin/pentests"
              className="rounded-xl bg-emerald-500/10 border border-emerald-500/30 p-4 text-center hover:bg-emerald-500/15 transition group"
            >
              <div className="mx-auto w-10 h-10 rounded-lg bg-emerald-500/20 flex items-center justify-center mb-2">
                <IconRocket className="h-5 w-5 text-emerald-400" />
              </div>
              <div className="text-sm font-medium text-emerald-400 group-hover:text-emerald-300">Start Pentest</div>
            </Link>
            <Link
              href="/admin/pentests"
              className="rounded-xl bg-sky-500/10 border border-sky-500/30 p-4 text-center hover:bg-sky-500/15 transition group"
            >
              <div className="mx-auto w-10 h-10 rounded-lg bg-sky-500/20 flex items-center justify-center mb-2">
                <IconCode className="h-5 w-5 text-sky-400" />
              </div>
              <div className="text-sm font-medium text-sky-400 group-hover:text-sky-300">Assign Pentester</div>
            </Link>
          </div>
        </div>
      </div>
    </AppShell>
  );
}
