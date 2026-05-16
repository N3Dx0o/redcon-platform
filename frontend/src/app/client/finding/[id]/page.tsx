"use client";

import { AppShell } from "@/components/AppShell";
import { Modal } from "@/components/Modal";
import { useToast } from "@/components/ToastProvider";
import { formatSubmittedAt } from "@/lib/date";
import { apiFetch } from "@/lib/http";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import { FindingComments } from "@/components/FindingComments";
import { FindingLabels } from "@/components/FindingLabels";
import { titleCaseLabel } from "@/lib/text";

function severityColor(sev: string) {
  const s = String(sev || "").toLowerCase();
  if (s === "critical") return { text: "text-rose-300", border: "border-rose-500/40", pill: "bg-rose-500/15" };
  if (s === "high") return { text: "text-orange-300", border: "border-orange-500/40", pill: "bg-orange-500/15" };
  if (s === "medium") return { text: "text-amber-300", border: "border-amber-500/30", pill: "bg-amber-500/10" };
  if (s === "low") return { text: "text-sky-300", border: "border-sky-500/30", pill: "bg-sky-500/10" };
  return { text: "text-slate-300", border: "border-slate-500/30", pill: "bg-slate-500/10" };
}

function statusColor(status: string) {
  const s = String(status || "").toLowerCase();
  if (["new", "triaged"].includes(s)) return { text: "text-sky-300", border: "border-sky-500/30", pill: "bg-sky-500/10" };
  if (["accepted", "fixed", "verified"].includes(s)) return { text: "text-emerald-300", border: "border-emerald-500/30", pill: "bg-emerald-500/10" };
  if (["need_more_info"].includes(s)) return { text: "text-amber-300", border: "border-amber-500/30", pill: "bg-amber-500/10" };
  return { text: "text-slate-300", border: "border-slate-500/30", pill: "bg-slate-500/10" };
}

export default function ClientFindingDetailPage() {
  const params = useParams<{ id: string }>();
  const findingId = String(params?.id || "");
  const toast = useToast();
  const [loading, setLoading] = useState(true);
  const [finding, setFinding] = useState<any>(null);

  const [respondOpen, setRespondOpen] = useState(false);
  const [respStatus, setRespStatus] = useState("accepted");
  const [respText, setRespText] = useState("");
  const [saving, setSaving] = useState(false);

  const load = async () => {
    setLoading(true);
    const r = await apiFetch<any>(`/api/client/finding/${encodeURIComponent(findingId)}?_=${Date.now()}`);
    if (r.ok) setFinding(r.data.finding || r.data);
    setLoading(false);
  };

  useEffect(() => {
    if (!findingId) return;
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [findingId]);

  const submitResponse = async () => {
    setSaving(true);
    const r = await apiFetch<any>(`/api/client/finding/${encodeURIComponent(findingId)}/respond`, {
      method: "POST",
      body: JSON.stringify({ status: respStatus, response: respText }),
    });
    setSaving(false);
    if (!r.ok) {
      toast.push({ type: "error", title: "Update failed", message: r.error }, 5200);
      return;
    }
    toast.push({ type: "success", title: "Response saved" });
    setRespondOpen(false);
    setRespText("");
    await load();
  };

  return (
    <AppShell role="client">
      <div className="max-w-6xl mx-auto space-y-4">
        {loading ? (
          <div className="rounded-2xl bg-bg-card border border-border p-6 text-text-secondary">Loading…</div>
        ) : (
          <>
            <div className="rounded-2xl bg-bg-card border border-border p-4">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="text-xl font-semibold">{finding?.title || "Finding"}</div>
                  <div className="flex flex-wrap items-center gap-2 mt-2 text-sm">
                    <span
                      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${
                        severityColor(finding?.severity).pill
                      } ${severityColor(finding?.severity).border} ${severityColor(finding?.severity).text}`}
                    >
                      {titleCaseLabel(finding?.severity)}
                    </span>
                    <span
                      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${
                        statusColor(finding?.status).pill
                      } ${statusColor(finding?.status).border} ${statusColor(finding?.status).text}`}
                    >
                      {titleCaseLabel(finding?.status)}
                    </span>
                    <span className="text-text-muted text-xs">• 🕒 {formatSubmittedAt(finding?.created_at)}</span>
                  </div>
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={() => setRespondOpen(true)}
                    className="rounded-xl bg-blue-primary/15 border border-blue-primary/30 px-4 py-2 text-sm text-blue-primary hover:bg-blue-primary/20 transition"
                  >
                    Respond
                  </button>
                  <Link
                    href="/client/findings"
                    className="rounded-xl bg-bg-elevated border border-border px-4 py-2 text-sm text-text-secondary hover:bg-bg-hover hover:text-text-primary transition"
                  >
                    Back
                  </Link>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
              <div className="lg:col-span-2 rounded-2xl bg-bg-card border border-border p-4">
                <div className="font-semibold mb-2">Description</div>
                <div className="text-sm text-text-secondary whitespace-pre-wrap">{finding?.description || "—"}</div>
                <div className="mt-4 font-semibold mb-2">Proof of concept / steps</div>
                <pre className="rounded-xl bg-bg-elevated border border-border p-3 text-xs text-text-secondary overflow-x-auto whitespace-pre-wrap">
{finding?.steps_to_reproduce || finding?.poc || "—"}
                </pre>
              </div>
              <div className="rounded-2xl bg-bg-card border border-border p-4">
                <div className="font-semibold mb-2">Details</div>
                <div className="text-sm text-text-secondary space-y-2">
                  <div>
                    <div className="text-xs uppercase text-text-muted mb-1">Labels</div>
                    <FindingLabels findingId={findingId} role="client" initialLabels={finding?.labels || "[]"} />
                  </div>
                  {finding?.affected_url ? (
                    <div>
                      <div className="text-xs uppercase text-text-muted">Affected URL</div>
                      <div className="break-words">{finding.affected_url}</div>
                    </div>
                  ) : null}
                  {finding?.impact ? (
                    <div>
                      <div className="text-xs uppercase text-text-muted">Impact</div>
                      <div className="whitespace-pre-wrap">{finding.impact}</div>
                    </div>
                  ) : null}
                  {finding?.remediation ? (
                    <div>
                      <div className="text-xs uppercase text-text-muted">Remediation</div>
                      <div className="whitespace-pre-wrap">{finding.remediation}</div>
                    </div>
                  ) : null}
                  {finding?.pentester_name ? (
                    <div>
                      <div className="text-xs uppercase text-text-muted">Pentester</div>
                      <div>{finding.pentester_name}</div>
                    </div>
                  ) : null}
                </div>
              </div>
            </div>

            <FindingComments findingId={findingId} role="client" />
          </>
        )}

        <Modal
          open={respondOpen}
          title="Respond to finding"
          onClose={() => setRespondOpen(false)}
          maxWidthClass="max-w-xl"
          footer={
            <>
              <button
                onClick={() => setRespondOpen(false)}
                className="rounded-xl bg-bg-elevated border border-border px-4 py-2 text-sm text-text-secondary hover:bg-bg-hover hover:text-text-primary transition"
              >
                Cancel
              </button>
              <button
                disabled={saving}
                onClick={submitResponse}
                className="rounded-xl bg-blue-primary/15 border border-blue-primary/30 px-4 py-2 text-sm text-blue-primary hover:bg-blue-primary/20 transition disabled:opacity-50"
              >
                {saving ? "Saving…" : "Save"}
              </button>
            </>
          }
        >
          <div className="grid grid-cols-1 gap-3">
            <div>
              <label className="block text-xs uppercase text-text-muted mb-1">Status</label>
              <select
                value={respStatus}
                onChange={(e) => setRespStatus(e.target.value)}
                className="w-full rounded-xl bg-bg-elevated border border-border px-3 py-2 text-sm outline-none"
              >
                <option value="accepted">Accept</option>
                <option value="need_more_info">Need more info</option>
                <option value="wont_fix">Won't fix</option>
                <option value="fixed">Fixed</option>
                <option value="verified">Verified</option>
              </select>
            </div>
            <div>
              <label className="block text-xs uppercase text-text-muted mb-1">Response</label>
              <textarea
                value={respText}
                onChange={(e) => setRespText(e.target.value)}
                rows={4}
                className="w-full rounded-xl bg-bg-elevated border border-border px-3 py-2 text-sm outline-none"
                placeholder="Add context for your decision…"
              />
            </div>
          </div>
        </Modal>
      </div>
    </AppShell>
  );
}


