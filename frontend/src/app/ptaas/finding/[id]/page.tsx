"use client";

import { AppShell } from "@/components/AppShell";
import { FindingComments } from "@/components/FindingComments";
import { FindingLabels } from "@/components/FindingLabels";
import { IconImage, IconPaperclip } from "@/components/Icons";
import { useToast } from "@/components/ToastProvider";
import { formatSubmittedAt } from "@/lib/date";
import { apiFetch } from "@/lib/http";
import { titleCaseLabel } from "@/lib/text";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useMemo, useState } from "react";

type ActivityRow = {
  id: string;
  type?: string;
  title?: string;
  description?: string;
  icon?: string;
  created_at?: string;
  user_name?: string;
  user_email?: string;
};

function pillForSeverity(sev: string) {
  const s = String(sev || "").toLowerCase();
  if (s === "critical") return "bg-rose-500/15 border-rose-500/40 text-rose-300";
  if (s === "high") return "bg-orange-500/15 border-orange-500/40 text-orange-300";
  if (s === "medium") return "bg-amber-500/10 border-amber-500/30 text-amber-300";
  if (s === "low") return "bg-sky-500/10 border-sky-500/30 text-sky-300";
  return "bg-slate-500/10 border-slate-500/30 text-slate-300";
}

function pillForStatus(status: string) {
  const s = String(status || "").toLowerCase();
  if (s === "draft") return "bg-slate-500/10 border-slate-500/30 text-slate-300";
  if (s === "new") return "bg-sky-500/10 border-sky-500/30 text-sky-300";
  if (s === "triaged") return "bg-violet-500/10 border-violet-500/30 text-violet-300";
  if (s === "accepted") return "bg-emerald-500/10 border-emerald-500/30 text-emerald-300";
  if (s === "need_more_info") return "bg-amber-500/10 border-amber-500/30 text-amber-300";
  if (s === "fixed") return "bg-teal-500/10 border-teal-500/30 text-teal-300";
  if (s === "verified") return "bg-emerald-500/10 border-emerald-500/30 text-emerald-300";
  if (s === "wont_fix" || s === "duplicate" || s === "rejected") return "bg-slate-500/10 border-slate-500/30 text-slate-300";
  return "bg-slate-500/10 border-slate-500/30 text-slate-300";
}

export default function PentesterFindingPage() {
  const params = useParams<{ id: string }>();
  const id = String(params?.id || "");
  const toast = useToast();

  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [finding, setFinding] = useState<any>(null);
  const [activity, setActivity] = useState<ActivityRow[]>([]);
  const [watching, setWatching] = useState<boolean>(false);
  const [me, setMe] = useState<any>(null);

  const normalizedEvidence = useMemo(() => {
    const out: Array<{ name: string; url: string; kind: "image" | "file" }> = [];
    if (!finding) return out;
    let shots: any[] = [];
    let atts: any[] = [];
    try {
      shots = JSON.parse(finding.screenshots || "[]");
    } catch {}
    try {
      atts = JSON.parse(finding.attachments || "[]");
    } catch {}
    const norm = (x: any, kindHint: "image" | "file") => {
      if (!x) return null;
      if (typeof x === "string") {
        const name = x.split("/").pop() || x;
        return { name, url: x, kind: kindHint };
      }
      if (typeof x === "object") {
        const path = String(x.path || "").split("/").pop() || String(x.path || "");
        const url = x.url || (path ? `/uploads/finding_attachments/${path}` : "");
        const name = x.original_name || x.name || path || "attachment";
        const isImg = String(x.kind || "").toLowerCase() === "screenshot" || kindHint === "image";
        return { name: String(name), url: String(url), kind: isImg ? "image" : "file" };
      }
      return null;
    };
    [...shots.map((x) => norm(x, "image")), ...atts.map((x) => norm(x, "file"))].filter(Boolean).forEach((x: any) => out.push(x));
    return out;
  }, [finding]);

  const load = async () => {
    if (!id) return;
    setLoading(true);
    const meRes = await apiFetch<any>("/api/auth/me");
    if (meRes.ok) setMe(meRes.data);

    const r = await apiFetch<any>(`/api/pentester/finding/${encodeURIComponent(id)}?_=${Date.now()}`);
    if (!r.ok) {
      toast.push({ type: "error", title: "Failed to load finding", message: r.error }, 5200);
      setLoading(false);
      return;
    }
    setFinding(r.data.finding || null);

    const a = await apiFetch<any>(`/api/findings/${encodeURIComponent(id)}/activity?_=${Date.now()}`);
    if (a.ok) setActivity((a.data.activity || []) as ActivityRow[]);

    const w = await apiFetch<any>(`/api/findings/${encodeURIComponent(id)}/watch?_=${Date.now()}`);
    if (w.ok) setWatching(Boolean(w.data.watching));

    setLoading(false);
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  const updateFinding = async (patch: any) => {
    if (!id) return;
    setSaving(true);
    const r = await apiFetch<any>(`/api/pentester/finding/${encodeURIComponent(id)}`, {
      method: "PUT",
      body: JSON.stringify(patch),
    });
    setSaving(false);
    if (!r.ok) {
      toast.push({ type: "error", title: "Update failed", message: r.error }, 5200);
      return;
    }
    await load();
  };

  const toggleWatch = async () => {
    const next = !watching;
    setWatching(next);
    const r = await apiFetch<any>(`/api/findings/${encodeURIComponent(id)}/watch`, { method: "POST", body: JSON.stringify({ watching: next }) });
    if (!r.ok) {
      setWatching(!next);
      toast.push({ type: "error", title: "Failed", message: r.error }, 5200);
      return;
    }
    setWatching(Boolean(r.data.watching));
  };

  const whoAmI = (finding?.pentester_id && me?.id && String(finding.pentester_id) === String(me.id)) ? "You" : (finding?.pentester_id || "—");

  return (
    <AppShell role="pentester">
      <div className="max-w-7xl mx-auto space-y-4">
        <div className="flex items-center justify-between gap-3">
          <div className="min-w-0">
            <div className="text-xs text-text-muted">
              <Link href="/ptaas/findings" className="hover:underline">
                Findings
              </Link>
              {finding?.pentest_id ? (
                <>
                  <span className="mx-2">/</span>
                  <Link href={`/ptaas/pentest/${finding.pentest_id}`} className="hover:underline">
                    Pentest
                  </Link>
                </>
              ) : null}
            </div>
            <div className="text-2xl font-bold truncate">{finding?.title || "Finding"}</div>
            <div className="flex flex-wrap items-center gap-2 mt-2 text-sm">
              {finding?.public_id ? <span className="text-text-muted">{String(finding.public_id)}</span> : null}
              <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${pillForSeverity(finding?.severity)}`}>
                {titleCaseLabel(finding?.severity || "info")}
              </span>
              <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${pillForStatus(finding?.status)}`}>
                {titleCaseLabel(finding?.status)}
              </span>
              {finding?.created_at ? <span className="text-text-muted">• {formatSubmittedAt(finding.created_at)}</span> : null}
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={toggleWatch}
              className="rounded-xl bg-bg-elevated border border-border px-4 py-2 text-sm text-text-secondary hover:bg-bg-hover hover:text-text-primary transition"
              disabled={!id}
            >
              {watching ? "Unfollow" : "Follow"}
            </button>
          </div>
        </div>

        {loading ? (
          <div className="rounded-2xl bg-bg-card border border-border p-6 text-text-secondary">Loading…</div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Main */}
            <div className="lg:col-span-2 space-y-4">
              <div className="rounded-2xl bg-bg-card border border-border p-4">
                <div className="font-semibold mb-2">Details</div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm text-text-secondary">
                  <div>
                    <div className="text-xs uppercase text-text-muted">Affected URL</div>
                    <div className="break-words">{finding?.affected_url || "—"}</div>
                  </div>
                  <div>
                    <div className="text-xs uppercase text-text-muted">Category</div>
                    <div className="break-words">{finding?.category || "—"}</div>
                  </div>
                </div>

                <div className="mt-4">
                  <div className="font-semibold mb-2">Description</div>
                  <div className="text-sm text-text-secondary whitespace-pre-wrap">{finding?.description || "—"}</div>
                </div>

                <div className="mt-4">
                  <div className="font-semibold mb-2">Proof of Concept / Steps</div>
                  <pre className="rounded-xl bg-bg-elevated border border-border p-3 text-xs text-text-secondary overflow-x-auto whitespace-pre-wrap">
{finding?.steps_to_reproduce || finding?.poc || "—"}
                  </pre>
                </div>

                {finding?.impact ? (
                  <div className="mt-4">
                    <div className="font-semibold mb-2">Impact</div>
                    <div className="text-sm text-text-secondary whitespace-pre-wrap">{finding.impact}</div>
                  </div>
                ) : null}

                {finding?.remediation ? (
                  <div className="mt-4">
                    <div className="font-semibold mb-2">Remediation</div>
                    <div className="text-sm text-text-secondary whitespace-pre-wrap">{finding.remediation}</div>
                  </div>
                ) : null}

                {normalizedEvidence.length ? (
                  <div className="mt-4">
                    <div className="font-semibold mb-2">Evidence</div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                      {normalizedEvidence.map((e, idx) => (
                        <a
                          key={`${e.url}-${idx}`}
                          href={e.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="rounded-xl bg-bg-elevated border border-border px-3 py-2 text-sm text-sky-400 hover:text-sky-300 truncate"
                        >
                          <span className="mr-2 inline-flex items-center">
                            {e.kind === "image" ? <IconImage className="h-4 w-4 text-text-muted" /> : <IconPaperclip className="h-4 w-4 text-text-muted" />}
                          </span>
                          {e.name}
                        </a>
                      ))}
                    </div>
                  </div>
                ) : null}
              </div>

              <div className="rounded-2xl bg-bg-card border border-border p-4">
                <div className="font-semibold mb-3">Activity</div>
                {activity.length === 0 ? (
                  <div className="text-sm text-text-secondary">No activity yet.</div>
                ) : (
                  <div className="space-y-3">
                    {activity.map((a) => {
                      const who = a.user_name || a.user_email || "User";
                      return (
                        <div key={a.id} className="rounded-xl bg-bg-elevated border border-border p-3">
                          <div className="flex items-start justify-between gap-3">
                            <div className="min-w-0">
                              <div className="text-sm">
                                <span className="text-text-primary font-medium">{who}</span>{" "}
                                <span className="text-text-secondary">{a.title || a.type || "Activity"}</span>
                              </div>
                              {a.description ? <div className="text-xs text-text-muted mt-1">{a.description}</div> : null}
                            </div>
                            <div className="text-xs text-text-muted whitespace-nowrap">{a.created_at ? formatSubmittedAt(a.created_at) : ""}</div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              <FindingComments findingId={id} role="pentester" />
            </div>

            {/* Sidebar */}
            <div className="space-y-4">
              <div className="rounded-2xl bg-bg-card border border-border p-4">
                <div className="font-semibold mb-3">State</div>
                <select
                  value={String(finding?.status || "new")}
                  onChange={(e) => updateFinding({ status: e.target.value })}
                  disabled={saving}
                  className="w-full rounded-xl bg-bg-elevated border border-border px-3 py-2 text-sm outline-none hover:border-border-light"
                >
                  <option value="draft">Draft</option>
                  <option value="new">New</option>
                  <option value="triaged">Triaged</option>
                  <option value="accepted">Accepted</option>
                  <option value="need_more_info">Need more info</option>
                  <option value="fixed">Fixed</option>
                  <option value="retest">Retest</option>
                  <option value="verified">Verified</option>
                  <option value="duplicate">Duplicate</option>
                  <option value="wont_fix">Won't fix</option>
                </select>
              </div>

              <div className="rounded-2xl bg-bg-card border border-border p-4">
                <div className="font-semibold mb-3">Exploitation Status</div>
                <select
                  value={String(finding?.exploitation_status || "did_not_attempt")}
                  onChange={(e) => updateFinding({ exploitation_status: e.target.value })}
                  disabled={saving}
                  className="w-full rounded-xl bg-bg-elevated border border-border px-3 py-2 text-sm outline-none hover:border-border-light"
                >
                  <option value="did_not_attempt">Did not attempt</option>
                  <option value="not_attempted">Not attempted</option>
                  <option value="attempted">Attempted</option>
                  <option value="exploited">Exploited</option>
                </select>
              </div>

              <div className="rounded-2xl bg-bg-card border border-border p-4">
                <div className="font-semibold mb-3">Assignee</div>
                <div className="text-sm text-text-secondary">{whoAmI}</div>
              </div>

              <div className="rounded-2xl bg-bg-card border border-border p-4">
                <div className="font-semibold mb-2">Labels</div>
                <FindingLabels findingId={id} role="pentester" initialLabels={finding?.labels || "[]"} />
              </div>

              <div className="rounded-2xl bg-bg-card border border-border p-4">
                <div className="font-semibold mb-2">Custom Reference</div>
                <input
                  defaultValue={String(finding?.custom_reference || "")}
                  onBlur={(e) => {
                    const v = String(e.target.value || "");
                    if (v !== String(finding?.custom_reference || "")) updateFinding({ custom_reference: v });
                  }}
                  className="w-full rounded-xl bg-bg-elevated border border-border px-3 py-2 text-sm outline-none hover:border-border-light"
                  placeholder="Not set"
                />
                <div className="text-xs text-text-muted mt-2">Saved on blur.</div>
              </div>

              <div className="rounded-2xl bg-bg-card border border-border p-4">
                <div className="font-semibold mb-2">Notifications</div>
                <button
                  onClick={toggleWatch}
                  className="w-full rounded-xl bg-bg-elevated border border-border px-4 py-2 text-sm text-text-secondary hover:bg-bg-hover hover:text-text-primary transition"
                >
                  {watching ? "Unfollow" : "Follow"}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </AppShell>
  );
}

