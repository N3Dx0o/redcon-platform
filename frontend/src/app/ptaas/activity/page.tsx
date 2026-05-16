"use client";

import { AppShell } from "@/components/AppShell";
import { IconClock, IconShield } from "@/components/Icons";
import { apiFetch } from "@/lib/http";
import Link from "next/link";
import { useEffect, useState } from "react";

function fmtDay(ts: string) {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return String(ts).slice(0, 10);
  return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

function fmtTime(ts: string) {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return String(ts).slice(11, 16);
  return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}

function statusPillFromTypeOrFinding(item: any) {
  const t = String(item?.type || "").toLowerCase();
  const fs = String(item?.finding_status || "").toLowerCase();
  const s = fs || t;
  if (s.includes("fixed")) return { text: "text-teal-300", pill: "bg-teal-500/10 border-teal-500/30", label: "Fixed" };
  if (s.includes("verified")) return { text: "text-emerald-300", pill: "bg-emerald-500/10 border-emerald-500/30", label: "Verified" };
  if (s.includes("accepted")) return { text: "text-emerald-300", pill: "bg-emerald-500/10 border-emerald-500/30", label: "Accepted" };
  if (s.includes("triaged")) return { text: "text-violet-300", pill: "bg-violet-500/10 border-violet-500/30", label: "Triaged" };
  if (s.includes("need_more_info")) return { text: "text-amber-300", pill: "bg-amber-500/10 border-amber-500/30", label: "Need info" };
  if (s.includes("paused")) return { text: "text-orange-300", pill: "bg-orange-500/10 border-orange-500/30", label: "Paused" };
  if (s.includes("started") || s.includes("active")) return { text: "text-emerald-300", pill: "bg-emerald-500/10 border-emerald-500/30", label: "Active" };
  if (s.includes("planned") || s.includes("approved")) return { text: "text-sky-300", pill: "bg-sky-500/10 border-sky-500/30", label: "Planned" };
  if (s.includes("pending") || s.includes("requested")) return { text: "text-amber-300", pill: "bg-amber-500/10 border-amber-500/30", label: "Pending" };
  if (s.includes("deleted") || s.includes("rejected")) return { text: "text-rose-300", pill: "bg-rose-500/10 border-rose-500/30", label: "Removed" };
  return null;
}

function initials(name: string) {
  const t = String(name || "").trim();
  if (!t) return "R";
  const parts = t.split(/\s+/).filter(Boolean);
  const a = (parts[0] || "").slice(0, 1).toUpperCase();
  const b = (parts[1] || "").slice(0, 1).toUpperCase();
  return (a + b) || a || "R";
}

export default function PentesterActivityPage() {
  const [loading, setLoading] = useState(true);
  const [items, setItems] = useState<any[]>([]);

  useEffect(() => {
    (async () => {
      setLoading(true);
      const r = await apiFetch<any>(`/api/ptaas/activity?_=${Date.now()}`);
      if (r.ok) setItems(r.data.activity || []);
      setLoading(false);
    })();
  }, []);

  return (
    <AppShell role="pentester">
      <div className="max-w-6xl mx-auto space-y-5">
        {/* Hero Header */}
        <div className="rounded-3xl border border-border bg-gradient-to-r from-bg-card via-bg-elevated to-bg-card overflow-hidden shadow-xl shadow-black/10">
          <div className="relative p-6">
            <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_top_right,_var(--tw-gradient-stops))] from-sky-500/20 via-emerald-500/10 to-transparent" />
            <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_bottom_left,_var(--tw-gradient-stops))] from-amber-500/15 via-violet-500/10 to-transparent" />
            <div className="relative">
              <div className="text-2xl font-bold">Activity</div>
              <div className="text-sm text-text-secondary mt-1">Recent updates across your pentests.</div>
            </div>
          </div>
        </div>

        {loading ? (
          <div className="rounded-2xl bg-gradient-to-br from-bg-card to-bg-elevated border border-border p-10 text-center shadow-lg shadow-black/10">
            <div className="mx-auto w-12 h-12 rounded-xl bg-sky-500/10 flex items-center justify-center mb-3 animate-pulse">
              <IconClock className="h-6 w-6 text-sky-400" />
            </div>
            <div className="text-text-secondary">Loading activity…</div>
          </div>
        ) : items.length === 0 ? (
          <div className="rounded-2xl bg-gradient-to-br from-bg-card to-bg-elevated border border-border p-10 text-center shadow-lg shadow-black/10">
            <div className="mx-auto w-12 h-12 rounded-xl bg-emerald-500/10 flex items-center justify-center mb-3">
              <IconShield className="h-6 w-6 text-emerald-400" />
            </div>
            <div className="text-lg font-medium">No activity yet</div>
            <div className="text-text-secondary text-sm mt-1">Once testing starts, updates will show up here in real time.</div>
          </div>
        ) : (
          <div className="space-y-4">
            {(() => {
              const groups: Record<string, any[]> = {};
              for (const it of items) {
                const day = fmtDay(it.created_at || "");
                groups[day] = groups[day] || [];
                groups[day].push(it);
              }
              const days = Object.keys(groups);
              return days.map((day) => (
                <div key={day} className="rounded-2xl bg-gradient-to-br from-bg-card to-bg-elevated border border-border shadow-lg shadow-black/10 overflow-hidden">
                  <div className="px-5 py-3 border-b border-border flex items-center justify-between">
                    <div className="font-semibold">{day}</div>
                    <div className="text-xs text-text-muted">{groups[day].length} events</div>
                  </div>
                  <div className="divide-y divide-border">
                    {groups[day].map((a) => {
                      const pill = statusPillFromTypeOrFinding(a);
                      const link = String(a.link || "").trim();
                      const isLink = link.startsWith("/");
                      const who = String(a.actor || "System");
                      const title = String(a.title || "Activity");
                      const msg = String(a.message || "");
                      const right = fmtTime(a.created_at || "");
                      const subject =
                        a.pentest_number
                          ? `#${a.pentest_number}`
                          : a.finding_public_id
                            ? `#${a.finding_public_id}`
                            : a.finding_id
                              ? `#${a.finding_id}`
                            : "";

                      return (
                        <div key={`${a.source || "x"}-${a.id}`} className="px-5 py-4 flex items-start justify-between gap-4">
                          <div className="flex items-start gap-3 min-w-0">
                            <div className="h-9 w-9 rounded-full bg-bg-elevated border border-border flex items-center justify-center text-xs font-semibold text-text-secondary flex-shrink-0">
                              {String(a.icon || "").trim() ? String(a.icon).slice(0, 2) : initials(who)}
                            </div>

                            <div className="min-w-0">
                              <div className="text-sm text-text-secondary">
                                <span className="font-semibold text-text-primary">{who}</span>{" "}
                                <span className="text-text-secondary">{title}</span>{" "}
                                {subject ? (
                                  isLink ? (
                                    <Link href={link} className="text-sky-400 hover:text-sky-300 transition">
                                      {subject}
                                    </Link>
                                  ) : (
                                    <span className="text-text-muted">{subject}</span>
                                  )
                                ) : null}
                                {pill ? (
                                  <span className={`ml-2 inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${pill.pill} ${pill.text}`}>
                                    {pill.label}
                                  </span>
                                ) : null}
                              </div>
                              {msg ? <div className="text-sm text-text-muted mt-1 whitespace-pre-wrap">{msg}</div> : null}
                              {a.pentest_title ? (
                                <div className="text-xs text-text-muted mt-2">
                                  Pentest:{" "}
                                  {isLink ? (
                                    <Link href={link} className="text-text-secondary hover:text-text-primary transition">
                                      {a.pentest_title}
                                    </Link>
                                  ) : (
                                    <span className="text-text-secondary">{a.pentest_title}</span>
                                  )}
                                </div>
                              ) : null}
                              {a.finding_title ? (
                                <div className="text-xs text-text-muted mt-1">
                                  Finding: <span className="text-text-secondary">{a.finding_title}</span>
                                  {a.finding_severity ? <span className="text-text-muted"> • {String(a.finding_severity).toLowerCase()}</span> : null}
                                </div>
                              ) : null}
                            </div>
                          </div>

                          <div className="text-xs text-text-muted whitespace-nowrap">{right}</div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              ));
            })()}
          </div>
        )}
      </div>
    </AppShell>
  );
}




