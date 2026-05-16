"use client";

import { AppShell } from "@/components/AppShell";
import { IconLock, IconClock, IconBug, IconCube, IconGem, IconShield, IconTarget } from "@/components/Icons";
import { apiFetch } from "@/lib/http";
import { formatPentestStatusLabel, pentestStatusAccentBg, pentestStatusBorder, pentestStatusPill } from "@/lib/pentestStatus";
import { titleCaseLabel } from "@/lib/text";
import Link from "next/link";
import { useEffect, useMemo, useState } from "react";

type ClientStats = {
  success?: boolean;
  user?: { name?: string; email?: string; company?: string; role?: string };
  active_pentests?: number;
  pending_requests?: number;
  total_findings?: number;
  credits?: number;
  assets_count?: number;
  critical_findings?: number;
  high_findings?: number;
  medium_findings?: number;
  low_findings?: number;
};

function severityColor(sev: string) {
  const s = String(sev || "").toLowerCase();
  if (s === "critical") return { bg: "bg-rose-500", text: "text-rose-400", border: "border-rose-500/40", glow: "shadow-rose-500/20" };
  if (s === "high") return { bg: "bg-orange-500", text: "text-orange-400", border: "border-orange-500/40", glow: "shadow-orange-500/20" };
  if (s === "medium") return { bg: "bg-amber-400", text: "text-amber-400", border: "border-amber-400/40", glow: "shadow-amber-400/20" };
  if (s === "low") return { bg: "bg-sky-400", text: "text-sky-400", border: "border-sky-400/40", glow: "shadow-sky-400/20" };
  return { bg: "bg-slate-500", text: "text-slate-400", border: "border-slate-500/40", glow: "" };
}

function findingStatusColor(status: string) {
  const s = String(status || "").toLowerCase();
  if (s === "draft") return { bg: "bg-slate-500", text: "text-slate-300", border: "border-slate-500/30" };
  if (s === "new") return { bg: "bg-sky-500", text: "text-sky-300", border: "border-sky-500/30" };
  if (s === "need_more_info") return { bg: "bg-amber-500", text: "text-amber-300", border: "border-amber-500/30" };
  if (s === "triaged") return { bg: "bg-violet-500", text: "text-violet-300", border: "border-violet-500/30" };
  if (s === "accepted") return { bg: "bg-emerald-500", text: "text-emerald-300", border: "border-emerald-500/30" };
  if (s === "fixed") return { bg: "bg-teal-500", text: "text-teal-300", border: "border-teal-500/30" };
  if (s === "verified") return { bg: "bg-emerald-500", text: "text-emerald-300", border: "border-emerald-500/30" };
  if (s === "duplicate" || s === "wont_fix") return { bg: "bg-slate-500", text: "text-slate-300", border: "border-slate-500/30" };
  return { bg: "bg-slate-500", text: "text-slate-300", border: "border-slate-500/30" };
}

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

function SeverityBar({ label, count, total, color }: { label: string; count: number; total: number; color: string }) {
  const pct = total > 0 ? Math.round((count / total) * 100) : 0;
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between text-sm">
        <span className="flex items-center gap-2">
          <span className={`h-2.5 w-2.5 rounded-full ${color}`} />
          {label}
        </span>
        <span className="font-semibold text-text-primary">{count}</span>
      </div>
      <div className="h-1.5 rounded-full bg-bg-elevated overflow-hidden">
        <div className={`h-full rounded-full ${color} transition-all duration-700`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

export default function ClientDashboardPage() {
  const [stats, setStats] = useState<ClientStats | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [pentests, setPentests] = useState<any[]>([]);
  const [findings, setFindings] = useState<any[]>([]);

  useEffect(() => {
    (async () => {
      const res = await apiFetch<ClientStats>("/api/client/stats");
      if (!res.ok) {
        setErr(res.error);
        return;
      }
      setStats(res.data);

      const p = await apiFetch<any>(`/api/client/pentests?status=all&_=${Date.now()}`);
      if (p.ok) setPentests(p.data.pentests || []);
      const f = await apiFetch<any>(`/api/client/findings?limit=8&_=${Date.now()}`);
      if (f.ok) setFindings(f.data.findings || []);
    })();
  }, []);

  const openPentests = useMemo(() => {
    return (pentests || []).filter((p) => !["archived", "completed"].includes(String(p.status || "").toLowerCase())).slice(0, 5);
  }, [pentests]);

  const totalFindings = (stats?.critical_findings ?? 0) + (stats?.high_findings ?? 0) + (stats?.medium_findings ?? 0) + (stats?.low_findings ?? 0);

  return (
    <AppShell role="client">
      <div className="max-w-6xl mx-auto space-y-5">
        {/* Hero Header */}
        <div className="rounded-3xl border border-border bg-gradient-to-r from-bg-card via-bg-elevated to-bg-card overflow-hidden shadow-xl shadow-black/10">
          <div className="relative p-6">
            <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_top_right,_var(--tw-gradient-stops))] from-rose-500/20 via-purple-500/10 to-transparent" />
            <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_bottom_left,_var(--tw-gradient-stops))] from-sky-500/15 via-emerald-500/10 to-transparent" />
            <div className="relative flex flex-col md:flex-row md:items-end justify-between gap-4">
              <div>
                <div className="text-2xl font-bold bg-gradient-to-r from-white via-white to-text-secondary bg-clip-text">
                  Welcome back{stats?.user?.name ? `, ${stats.user.name}` : ""}
                </div>
                <div className="text-sm text-text-secondary mt-1">
                  Your PTaaS command center — assets → pentests → findings → reports
                </div>
              </div>
              <div className="flex gap-2">
                <Link
                  href="/client/assets"
                  className="rounded-xl bg-white/5 backdrop-blur border border-white/10 px-4 py-2.5 text-sm text-text-secondary hover:bg-white/10 hover:text-text-primary transition-all"
                >
                  Manage assets
                </Link>
                <Link
                  href="/client/pentests?new=1"
                  className="rounded-xl bg-gradient-to-r from-rose-600 to-rose-500 hover:from-rose-500 hover:to-rose-400 transition-all text-white px-5 py-2.5 text-sm font-semibold shadow-lg shadow-rose-500/25"
                >
                  + Request pentest
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
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <StatCard
            label="Active Pentests"
            value={stats?.active_pentests ?? "—"}
            icon={<IconShield className="h-5 w-5 text-white" />}
            gradient="from-emerald-500/30 to-emerald-600/10"
            iconBg="bg-gradient-to-br from-emerald-500 to-emerald-600"
          />
          <StatCard
            label="Pending"
            value={stats?.pending_requests ?? "—"}
            icon={<IconClock className="h-5 w-5 text-white" />}
            gradient="from-sky-500/30 to-sky-600/10"
            iconBg="bg-gradient-to-br from-sky-500 to-sky-600"
          />
          <StatCard
            label="Findings"
            value={stats?.total_findings ?? "—"}
            icon={<IconBug className="h-5 w-5 text-white" />}
            gradient="from-rose-500/30 to-rose-600/10"
            iconBg="bg-gradient-to-br from-rose-500 to-rose-600"
          />
          <StatCard
            label="Assets"
            value={stats?.assets_count ?? "—"}
            icon={<IconCube className="h-5 w-5 text-white" />}
            gradient="from-amber-500/30 to-amber-600/10"
            iconBg="bg-gradient-to-br from-amber-500 to-amber-600"
          />
          <StatCard
            label="Credits"
            value={stats?.credits ?? "—"}
            icon={<IconGem className="h-5 w-5 text-white" />}
            gradient="from-violet-500/30 to-violet-600/10"
            iconBg="bg-gradient-to-br from-violet-500 to-violet-600"
          />
        </div>

        {/* Main Content Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Open Pentests */}
          <div className="lg:col-span-2 rounded-2xl bg-gradient-to-br from-bg-card to-bg-elevated border border-border p-5 shadow-lg shadow-black/10">
            <div className="flex items-center justify-between mb-4">
              <div className="font-semibold text-lg">Open Pentests</div>
              <Link href="/client/pentests" className="text-sm text-sky-400 hover:text-sky-300 transition">
                View all →
              </Link>
            </div>
            {openPentests.length === 0 ? (
              <div className="rounded-xl bg-bg-elevated/50 border border-dashed border-border p-8 text-center">
                <div className="mx-auto w-12 h-12 rounded-xl bg-emerald-500/10 flex items-center justify-center mb-3">
                  <IconLock className="h-6 w-6 text-emerald-400" />
                </div>
                <div className="text-text-secondary text-sm">No active pentests</div>
                <Link href="/client/pentests" className="inline-block mt-3 text-sm text-sky-400 hover:text-sky-300">
                  Request your first pentest →
                </Link>
              </div>
            ) : (
              <div className="space-y-2">
                {openPentests.map((p) => {
                  const sc = pentestStatusPill(p.status);
                  return (
                    <Link
                      key={p.id}
                      href={`/client/pentest/${p.id}`}
                      className="block rounded-xl bg-bg-elevated/50 border border-border hover:border-border-light transition-all duration-200 px-4 py-3 group relative overflow-hidden"
                    >
                      <div className={`pointer-events-none absolute inset-y-0 left-0 w-1 ${pentestStatusAccentBg(p.status)}`} />
                      <div className="flex items-center justify-between gap-3">
                        <div className="min-w-0">
                          <div className="font-medium truncate group-hover:text-white transition">{p.title}</div>
                          <div className="flex items-center gap-2 mt-1 text-sm text-text-secondary">
                            <span>{p.type}</span>
                            <span className="text-text-muted">•</span>
                            <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${sc.pill} ${pentestStatusBorder(p.status)} ${sc.text}`}>
                              {formatPentestStatusLabel(p.status)}
                            </span>
                          </div>
                        </div>
                        <div className="text-xs text-text-muted whitespace-nowrap">{p.start_date ? String(p.start_date).slice(0, 10) : ""}</div>
                      </div>
                    </Link>
                  );
                })}
              </div>
            )}
          </div>

          {/* Severity Breakdown */}
          <div className="rounded-2xl bg-gradient-to-br from-bg-card to-bg-elevated border border-border p-5 shadow-lg shadow-black/10">
            <div className="font-semibold text-lg mb-4">Finding Severity</div>
            <div className="space-y-4">
              <SeverityBar label="Critical" count={stats?.critical_findings ?? 0} total={totalFindings} color="bg-rose-500" />
              <SeverityBar label="High" count={stats?.high_findings ?? 0} total={totalFindings} color="bg-orange-500" />
              <SeverityBar label="Medium" count={stats?.medium_findings ?? 0} total={totalFindings} color="bg-amber-400" />
              <SeverityBar label="Low" count={stats?.low_findings ?? 0} total={totalFindings} color="bg-sky-400" />
            </div>
            <div className="mt-5 pt-4 border-t border-border">
              <Link href="/client/findings" className="text-sm text-sky-400 hover:text-sky-300 transition">
                Review all findings →
              </Link>
            </div>
          </div>
        </div>

        {/* Recent Findings */}
        <div className="rounded-2xl bg-gradient-to-br from-bg-card to-bg-elevated border border-border p-5 shadow-lg shadow-black/10">
          <div className="flex items-center justify-between mb-4">
            <div className="font-semibold text-lg">Recent Findings</div>
            <Link href="/client/findings" className="text-sm text-sky-400 hover:text-sky-300 transition">
              View all →
            </Link>
          </div>
          {findings.length === 0 ? (
            <div className="rounded-xl bg-bg-elevated/50 border border-dashed border-border p-8 text-center">
              <div className="mx-auto w-12 h-12 rounded-xl bg-rose-500/10 flex items-center justify-center mb-3">
                <IconTarget className="h-6 w-6 text-rose-400" />
              </div>
              <div className="text-text-secondary text-sm">No findings yet</div>
              <div className="text-text-muted text-xs mt-1">Findings will appear here once pentesters report issues</div>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {findings.map((f) => {
                const sev = severityColor(f.severity);
                const stat = findingStatusColor(f.status);
                return (
                  <Link
                    key={f.id}
                    href={`/client/finding/${f.id}`}
                    className="block rounded-xl bg-bg-elevated/50 border border-border hover:border-border-light transition-all duration-200 p-4 relative overflow-hidden group"
                  >
                    <div className={`pointer-events-none absolute inset-y-0 left-0 w-1 ${sev.bg}`} />
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0 flex-1">
                        <div className="font-medium truncate group-hover:text-white transition">{f.title}</div>
                        <div className="flex flex-wrap items-center gap-1.5 mt-2">
                          <span className={`inline-flex items-center rounded-full ${sev.bg}/15 ${sev.border} border px-2 py-0.5 text-xs font-medium ${sev.text}`}>
                            {titleCaseLabel(f.severity)}
                          </span>
                          <span className={`inline-flex items-center rounded-full ${stat.bg}/15 ${stat.border} border px-2 py-0.5 text-xs font-medium ${stat.text}`}>
                            {titleCaseLabel(f.status)}
                          </span>
                        </div>
                      </div>
                      <div className="text-xs text-text-muted whitespace-nowrap">{f.created_at ? String(f.created_at).slice(0, 10) : ""}</div>
                    </div>
                  </Link>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </AppShell>
  );
}
