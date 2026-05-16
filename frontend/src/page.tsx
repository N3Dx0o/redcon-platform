"use client";

import { AppShell } from "@/components/AppShell";
import { IconClipboard, IconClock, IconShield } from "@/components/Icons";
import { useToast } from "@/components/ToastProvider";
import { apiFetch } from "@/lib/http";
import { useEffect, useState } from "react";

export default function PentesterPostingsPage() {
  const toast = useToast();
  const [loading, setLoading] = useState(true);
  const [postings, setPostings] = useState<any[]>([]);

  const load = async () => {
    setLoading(true);
    const r = await apiFetch<any>(`/api/ptaas/postings?_=${Date.now()}`);
    if (r.ok) setPostings(r.data.postings || []);
    setLoading(false);
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const apply = async (id: string) => {
    const r = await apiFetch<any>(`/api/ptaas/apply/${encodeURIComponent(id)}`, { method: "POST", body: "{}" });
    if (!r.ok) {
      toast.push({ type: "error", title: "Apply failed", message: r.error }, 5200);
      return;
    }
    toast.push({ type: "success", title: "Applied" });
    await load();
  };

  return (
    <AppShell role="pentester">
      <div className="max-w-6xl mx-auto space-y-5">
        {/* Hero Header */}
        <div className="rounded-3xl border border-border bg-gradient-to-r from-bg-card via-bg-elevated to-bg-card overflow-hidden shadow-xl shadow-black/10">
          <div className="relative p-6">
            <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_top_right,_var(--tw-gradient-stops))] from-violet-500/20 via-sky-500/10 to-transparent" />
            <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_bottom_left,_var(--tw-gradient-stops))] from-amber-500/15 via-rose-500/10 to-transparent" />
            <div className="relative">
              <div className="text-2xl font-bold">Available engagements</div>
              <div className="text-sm text-text-secondary mt-1">Browse open engagements and apply in one click.</div>
            </div>
          </div>
        </div>

        {loading ? (
          <div className="rounded-2xl bg-gradient-to-br from-bg-card to-bg-elevated border border-border p-10 text-center shadow-lg shadow-black/10">
            <div className="mx-auto w-12 h-12 rounded-xl bg-sky-500/10 flex items-center justify-center mb-3 animate-pulse">
              <IconClock className="h-6 w-6 text-sky-400" />
            </div>
            <div className="text-text-secondary">Loading engagements…</div>
          </div>
        ) : postings.length === 0 ? (
          <div className="rounded-2xl bg-gradient-to-br from-bg-card to-bg-elevated border border-border p-10 text-center shadow-lg shadow-black/10">
            <div className="mx-auto w-12 h-12 rounded-xl bg-emerald-500/10 flex items-center justify-center mb-3">
              <IconShield className="h-6 w-6 text-emerald-400" />
            </div>
            <div className="text-lg font-medium">No engagements right now</div>
            <div className="text-text-secondary text-sm mt-1">When new pentests are opened for applications, they’ll appear here.</div>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {postings.map((p) => (
              <div key={p.id} className="rounded-2xl bg-gradient-to-br from-bg-card to-bg-elevated border border-border p-5 shadow-lg shadow-black/10">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="font-semibold text-lg truncate">{p.title}</div>
                    <div className="flex flex-wrap items-center gap-2 mt-2 text-sm text-text-secondary">
                      <span className="inline-flex items-center gap-1.5 rounded-lg bg-bg-elevated px-2.5 py-1 text-xs">
                        <IconClipboard className="h-4 w-4 text-text-muted" /> {p.type}
                      </span>
                      {p.company_name ? <span className="text-text-muted text-xs">• {p.company_name}</span> : null}
                      {p.payout_total ? <span className="text-emerald-400 text-xs font-medium">• ${p.payout_total}</span> : null}
                    </div>
                    {p.description ? (
                      <div className="text-sm text-text-secondary mt-3 whitespace-pre-wrap">
                        {String(p.description).slice(0, 220)}
                        {String(p.description).length > 220 ? "…" : ""}
                      </div>
                    ) : null}
                  </div>
                  <button
                    onClick={() => apply(p.id)}
                    className="rounded-xl bg-violet-500/15 border border-violet-500/30 px-4 py-2 text-sm text-violet-300 hover:bg-violet-500/20 transition whitespace-nowrap"
                  >
                    Apply
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </AppShell>
  );
}




