"use client";

import { AppShell } from "@/components/AppShell";
import { IconBug, IconClock, IconShield, IconTarget } from "@/components/Icons";
import { useToast } from "@/components/ToastProvider";
import { apiFetch } from "@/lib/http";
import { useEffect, useMemo, useState } from "react";

type InsightsResp = {
  success?: boolean;
  kpis?: {
    pentests_performed?: number;
    findings_reported?: number;
    findings_open?: number;
    findings_resolved?: number;
  };
  pentest_findings_by_severity?: { critical?: number; high?: number; medium?: number; low?: number; info?: number };
  findings_by_day?: { date: string; count: number }[];
  scan_findings_by_severity?: { critical?: number; high?: number; medium?: number; low?: number; info?: number };
  scans_by_day?: { date: string; count: number }[];
};

function Stat({
  label,
  value,
  icon,
  tone,
}: {
  label: string;
  value: any;
  icon: React.ReactNode;
  tone: string;
}) {
  return (
    <div className="rounded-2xl bg-bg-card border border-border p-4">
      <div className="flex items-center gap-3">
        <div className={`h-10 w-10 rounded-xl ${tone} flex items-center justify-center shadow-lg`}>{icon}</div>
        <div>
          <div className="text-xs uppercase tracking-wide text-text-muted">{label}</div>
          <div className="text-2xl font-bold">{value}</div>
        </div>
      </div>
    </div>
  );
}

function DonutChart({
  title,
  data,
}: {
  title: string;
  data: { label: string; value: number; color: string }[];
}) {
  const total = data.reduce((a, b) => a + (b.value || 0), 0);
  const r = 44;
  const c = 2 * Math.PI * r;
  let offset = 0;

  return (
    <div className="rounded-2xl bg-bg-card border border-border p-5">
      <div className="flex items-center justify-between">
        <div className="font-semibold text-lg">{title}</div>
        <div className="text-sm text-text-muted">Total {total}</div>
      </div>
      <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4 items-center">
        <div className="flex items-center justify-center">
          <svg width="160" height="160" viewBox="0 0 120 120">
            <circle cx="60" cy="60" r={r} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="12" />
            {total > 0
              ? data.map((d, idx) => {
                  const pct = (d.value || 0) / total;
                  const dash = c * pct;
                  const seg = (
                    <circle
                      key={idx}
                      cx="60"
                      cy="60"
                      r={r}
                      fill="none"
                      stroke={d.color}
                      strokeWidth="12"
                      strokeLinecap="butt"
                      strokeDasharray={`${dash} ${c - dash}`}
                      strokeDashoffset={-offset}
                      transform="rotate(-90 60 60)"
                    />
                  );
                  offset += dash;
                  return seg;
                })
              : null}
            <circle cx="60" cy="60" r="34" fill="rgba(0,0,0,0.35)" />
            <text x="60" y="56" textAnchor="middle" fill="rgba(255,255,255,0.9)" fontSize="16" fontWeight="700">
              {total}
            </text>
            <text x="60" y="74" textAnchor="middle" fill="rgba(255,255,255,0.55)" fontSize="10">
              total
            </text>
          </svg>
        </div>
        <div className="space-y-2">
          {data.map((d) => (
            <div key={d.label} className="flex items-center justify-between text-sm">
              <div className="flex items-center gap-2">
                <span className="h-2.5 w-2.5 rounded-full" style={{ background: d.color }} />
                <span className="text-text-secondary">{d.label}</span>
              </div>
              <div className="font-semibold">{d.value}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function LineChart({
  title,
  series,
  color,
}: {
  title: string;
  series: { date: string; count: number }[];
  color: string;
}) {
  const points = series || [];
  const max = Math.max(1, ...points.map((p) => p.count || 0));
  const w = 520;
  const h = 160;
  const padX = 18;
  const padY = 18;

  const toXY = (i: number, v: number) => {
    const x = padX + (i * (w - padX * 2)) / Math.max(1, points.length - 1);
    const y = h - padY - ((v || 0) * (h - padY * 2)) / max;
    return { x, y };
  };

  const d = points
    .map((p, i) => {
      const { x, y } = toXY(i, p.count);
      return `${i === 0 ? "M" : "L"} ${x} ${y}`;
    })
    .join(" ");

  const area = `${d} L ${padX + ((points.length - 1) * (w - padX * 2)) / Math.max(1, points.length - 1)} ${h - padY} L ${padX} ${
    h - padY
  } Z`;

  return (
    <div className="rounded-2xl bg-bg-card border border-border p-5">
      <div className="flex items-center justify-between">
        <div className="font-semibold text-lg">{title}</div>
        <div className="text-sm text-text-muted">Last 30 days</div>
      </div>
      <div className="mt-4">
        {points.length === 0 ? (
          <div className="text-sm text-text-secondary">No data yet.</div>
        ) : (
          <svg viewBox={`0 0 ${w} ${h}`} className="w-full h-[170px]">
            <defs>
              <linearGradient id="areaGrad" x1="0" x2="0" y1="0" y2="1">
                <stop offset="0%" stopColor={color} stopOpacity="0.35" />
                <stop offset="100%" stopColor={color} stopOpacity="0.05" />
              </linearGradient>
            </defs>
            {/* grid */}
            {[0.25, 0.5, 0.75].map((t) => (
              <line
                key={t}
                x1={padX}
                x2={w - padX}
                y1={padY + (h - padY * 2) * t}
                y2={padY + (h - padY * 2) * t}
                stroke="rgba(255,255,255,0.06)"
              />
            ))}
            <path d={area} fill="url(#areaGrad)" />
            <path d={d} fill="none" stroke={color} strokeWidth="2.5" />
            {points.map((p, i) => {
              const { x, y } = toXY(i, p.count);
              return <circle key={p.date + i} cx={x} cy={y} r="3" fill={color} opacity="0.95" />;
            })}
          </svg>
        )}
      </div>
    </div>
  );
}

function Bar({ label, value, total, color }: { label: string; value: number; total: number; color: string }) {
  const pct = total > 0 ? Math.round((value / total) * 100) : 0;
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between text-sm">
        <div className="flex items-center gap-2">
          <span className={`h-2.5 w-2.5 rounded-full ${color}`} />
          <span>{label}</span>
        </div>
        <div className="font-semibold">{value}</div>
      </div>
      <div className="h-2 rounded-full bg-bg-elevated overflow-hidden">
        <div className={`h-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

export default function ClientInsightsPage() {
  const toast = useToast();
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState<InsightsResp | null>(null);

  const load = async () => {
    setLoading(true);
    const r = await apiFetch<InsightsResp>("/api/client/insights");
    setLoading(false);
    if (!r.ok) {
      toast.push({ type: "error", title: "Failed to load insights", message: r.error }, 5200);
      return;
    }
    setData(r.data);
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const sev = data?.scan_findings_by_severity || {};
  const pSev = data?.pentest_findings_by_severity || {};
  const total = useMemo(() => {
    return (sev.critical || 0) + (sev.high || 0) + (sev.medium || 0) + (sev.low || 0) + (sev.info || 0);
  }, [sev.critical, sev.high, sev.medium, sev.low, sev.info]);

  return (
    <AppShell role="client">
      <div className="max-w-6xl mx-auto space-y-5">
        <div className="rounded-3xl border border-border bg-gradient-to-r from-bg-card via-bg-elevated to-bg-card overflow-hidden shadow-xl shadow-black/10">
          <div className="relative p-6">
            <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_top_right,_var(--tw-gradient-stops))] from-sky-500/18 via-violet-500/10 to-transparent" />
            <div className="relative flex items-end justify-between gap-4">
              <div>
                <div className="text-2xl font-bold">Insights</div>
                <div className="text-sm text-text-secondary mt-1">Operational metrics across pentests, findings, and scans</div>
              </div>
              <button
                onClick={load}
                className="rounded-xl bg-bg-elevated border border-border px-4 py-2 text-sm text-text-secondary hover:bg-bg-hover hover:text-text-primary transition"
              >
                Refresh
              </button>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          <Stat
            label="Pentests performed"
            value={loading ? "—" : data?.kpis?.pentests_performed ?? 0}
            icon={<IconShield className="h-5 w-5 text-white" />}
            tone="bg-gradient-to-br from-emerald-500 to-emerald-600"
          />
          <Stat
            label="Findings reported"
            value={loading ? "—" : data?.kpis?.findings_reported ?? 0}
            icon={<IconBug className="h-5 w-5 text-white" />}
            tone="bg-gradient-to-br from-rose-500 to-rose-600"
          />
          <Stat
            label="Findings open"
            value={loading ? "—" : data?.kpis?.findings_open ?? 0}
            icon={<IconClock className="h-5 w-5 text-white" />}
            tone="bg-gradient-to-br from-amber-500 to-amber-600"
          />
          <Stat
            label="Findings resolved"
            value={loading ? "—" : data?.kpis?.findings_resolved ?? 0}
            icon={<IconTarget className="h-5 w-5 text-white" />}
            tone="bg-gradient-to-br from-sky-500 to-sky-600"
          />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <DonutChart
            title="Pentest Findings (Severity)"
            data={[
              { label: "Critical", value: pSev.critical || 0, color: "#ef4444" },
              { label: "High", value: pSev.high || 0, color: "#f97316" },
              { label: "Medium", value: pSev.medium || 0, color: "#f59e0b" },
              { label: "Low", value: pSev.low || 0, color: "#38bdf8" },
              { label: "Info", value: pSev.info || 0, color: "#64748b" },
            ]}
          />
          <DonutChart
            title="Scan Findings (Severity)"
            data={[
              { label: "Critical", value: sev.critical || 0, color: "#ef4444" },
              { label: "High", value: sev.high || 0, color: "#f97316" },
              { label: "Medium", value: sev.medium || 0, color: "#f59e0b" },
              { label: "Low", value: sev.low || 0, color: "#38bdf8" },
              { label: "Info", value: sev.info || 0, color: "#64748b" },
            ]}
          />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <LineChart title="Findings Created" series={data?.findings_by_day || []} color="#f43f5e" />
          <LineChart title="Scan Runs" series={data?.scans_by_day || []} color="#38bdf8" />
        </div>
      </div>
    </AppShell>
  );
}

