"use client";

import { AppShell } from "@/components/AppShell";
import { IconTarget } from "@/components/Icons";
import { apiFetch } from "@/lib/http";
import { titleCaseLabel } from "@/lib/text";
import Link from "next/link";
import { useEffect, useState } from "react";

type ClientFindings = {
  success?: boolean;
  findings?: Array<{
    id: string;
    title: string;
    severity: string;
    status: string;
    pentest_id?: string;
    pentest_title?: string;
    created_at?: string;
  }>;
};

function severityColor(sev: string) {
  const s = String(sev || "").toLowerCase();
  if (s === "critical") return { bg: "bg-rose-500", text: "text-rose-400", border: "border-rose-500/40", pill: "bg-rose-500/15" };
  if (s === "high") return { bg: "bg-orange-500", text: "text-orange-400", border: "border-orange-500/40", pill: "bg-orange-500/15" };
  if (s === "medium") return { bg: "bg-amber-400", text: "text-amber-400", border: "border-amber-400/40", pill: "bg-amber-400/15" };
  if (s === "low") return { bg: "bg-sky-400", text: "text-sky-400", border: "border-sky-400/40", pill: "bg-sky-400/15" };
  return { bg: "bg-slate-500", text: "text-slate-400", border: "border-slate-500/40", pill: "bg-slate-500/15" };
}

function statusColor(status: string) {
  const s = String(status || "").toLowerCase();
  if (["new", "triaged"].includes(s)) return { bg: "bg-sky-500", text: "text-sky-400", border: "border-sky-500/40", pill: "bg-sky-500/15" };
  if (["accepted", "fixed"].includes(s)) return { bg: "bg-emerald-500", text: "text-emerald-400", border: "border-emerald-500/40", pill: "bg-emerald-500/15" };
  if (["wont_fix", "duplicate"].includes(s)) return { bg: "bg-slate-600", text: "text-slate-400", border: "border-slate-600/40", pill: "bg-slate-600/15" };
  if (["need_more_info"].includes(s)) return { bg: "bg-amber-500", text: "text-amber-400", border: "border-amber-500/40", pill: "bg-amber-500/15" };
  return { bg: "bg-slate-600", text: "text-slate-400", border: "border-slate-600/40", pill: "bg-slate-600/15" };
}

export default function ClientFindingsPage() {
  const [data, setData] = useState<ClientFindings | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [filter, setFilter] = useState<string>("all");

  useEffect(() => {
    (async () => {
      const res = await apiFetch<ClientFindings>("/api/client/findings");
      if (!res.ok) {
        setErr(res.error);
        return;
      }
      setData(res.data);
    })();
  }, []);

  const allFindings = data?.findings || [];
  const findings = filter === "all" ? allFindings : allFindings.filter((f) => String(f.severity || "").toLowerCase() === filter);

  const counts = {
    all: allFindings.length,
    critical: allFindings.filter((f) => String(f.severity).toLowerCase() === "critical").length,
    high: allFindings.filter((f) => String(f.severity).toLowerCase() === "high").length,
    medium: allFindings.filter((f) => String(f.severity).toLowerCase() === "medium").length,
    low: allFindings.filter((f) => String(f.severity).toLowerCase() === "low").length,
  };

  return (
    <AppShell role="client">
      <div className="max-w-5xl mx-auto space-y-5">
        {/* Hero Header */}
        <div className="rounded-3xl border border-border bg-gradient-to-r from-bg-card via-bg-elevated to-bg-card overflow-hidden shadow-xl shadow-black/10">
          <div className="relative p-6">
            <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_top_right,_var(--tw-gradient-stops))] from-rose-500/20 via-orange-500/10 to-transparent" />
            <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_bottom_left,_var(--tw-gradient-stops))] from-amber-500/15 via-rose-500/10 to-transparent" />
            <div className="relative">
              <div className="text-2xl font-bold">Findings</div>
              <div className="text-sm text-text-secondary mt-1">
                Security vulnerabilities discovered during pentests
              </div>
            </div>
          </div>
        </div>

        {err ? (
          <div className="rounded-xl border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-300">
            {err}
          </div>
        ) : null}

        {/* Filter Tabs */}
        <div className="flex flex-wrap gap-2">
          {[
            { key: "all", label: "All", count: counts.all, color: "bg-slate-600" },
            { key: "critical", label: "Critical", count: counts.critical, color: "bg-rose-500" },
            { key: "high", label: "High", count: counts.high, color: "bg-orange-500" },
            { key: "medium", label: "Medium", count: counts.medium, color: "bg-amber-400" },
            { key: "low", label: "Low", count: counts.low, color: "bg-sky-400" },
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

        {/* Findings List */}
        <div className="space-y-3">
          {findings.length === 0 ? (
            <div className="rounded-2xl bg-gradient-to-br from-bg-card to-bg-elevated border border-dashed border-border p-10 text-center shadow-lg shadow-black/10">
              <div className="mx-auto w-14 h-14 rounded-xl bg-rose-500/10 flex items-center justify-center mb-3">
                <IconTarget className="h-7 w-7 text-rose-400" />
              </div>
              <div className="text-lg font-medium">No findings</div>
              <div className="text-text-secondary text-sm mt-1">
                {filter === "all"
                  ? "Findings will appear here once pentesters report security issues"
                  : `No ${filter} severity findings found`}
              </div>
            </div>
          ) : (
            findings.map((f) => {
              const sev = severityColor(f.severity);
              const stat = statusColor(f.status);
              return (
                <div key={f.id} className="rounded-2xl bg-gradient-to-br from-bg-card to-bg-elevated border border-border p-5 relative overflow-hidden group transition-all duration-200 hover:border-border-light shadow-lg shadow-black/10">
                  <div className={`pointer-events-none absolute inset-y-0 left-0 w-1 ${sev.bg}`} />
                  <div className="flex items-center justify-between gap-4">
                    <div className="min-w-0 flex-1">
                      <div className="font-semibold text-lg group-hover:text-white transition">{f.title}</div>
                      <div className="flex flex-wrap items-center gap-2 mt-2 text-sm">
                        <span className={`inline-flex items-center rounded-lg ${sev.pill} ${sev.border} border px-2.5 py-1 text-xs font-medium ${sev.text}`}>
                          {titleCaseLabel(f.severity)}
                        </span>
                        <span className={`inline-flex items-center rounded-lg ${stat.pill} ${stat.border} border px-2.5 py-1 text-xs font-medium ${stat.text}`}>
                          {titleCaseLabel(f.status)}
                        </span>
                        {f.pentest_title ? (
                          <span className="text-text-muted text-xs">• {f.pentest_title}</span>
                        ) : null}
                        {f.created_at ? (
                          <span className="text-text-muted text-xs">• {String(f.created_at).slice(0, 10)}</span>
                        ) : null}
                      </div>
                    </div>
                    <Link
                      href={`/client/finding/${f.id}`}
                      className="rounded-xl bg-white/5 backdrop-blur border border-white/10 px-4 py-2 text-sm text-text-secondary hover:bg-white/10 hover:text-white transition-all"
                    >
                      View →
                    </Link>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>
    </AppShell>
  );
}
