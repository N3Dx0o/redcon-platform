"use client";

import { AppShell } from "@/components/AppShell";
import { apiFetch } from "@/lib/http";
import { useEffect, useState } from "react";

export default function PentesterFeedbackPage() {
  const [loading, setLoading] = useState(true);
  const [items, setItems] = useState<any[]>([]);

  useEffect(() => {
    (async () => {
      setLoading(true);
      const r = await apiFetch<any>(`/api/ptaas/feedback?_=${Date.now()}`);
      if (r.ok) setItems(r.data.feedback || []);
      setLoading(false);
    })();
  }, []);

  return (
    <AppShell role="pentester">
      <div className="max-w-6xl mx-auto space-y-4">
        <div>
          <div className="text-xl font-semibold">Feedback</div>
          <div className="text-sm text-text-secondary">Feedback & ratings on your engagements (admin/client).</div>
        </div>
        {loading ? (
          <div className="rounded-2xl bg-bg-card border border-border p-6 text-text-secondary">Loading…</div>
        ) : items.length === 0 ? (
          <div className="rounded-2xl bg-bg-card border border-border p-6 text-text-secondary">No feedback.</div>
        ) : (
          <div className="rounded-2xl bg-bg-card border border-border p-4 space-y-2">
            {items.map((f) => (
              <div key={f.id} className="rounded-xl bg-bg-elevated border border-border p-3">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="font-medium truncate">{f.pentest_title || "Engagement feedback"}</div>
                    <div className="text-xs text-text-muted mt-1">
                      From:{" "}
                      <span className="text-text-secondary">
                        {f.client_role === "admin" ? "Our team" : f.client_role || "Client"}
                      </span>
                      {f.client_name ? <span className="text-text-muted"> • {f.client_name}</span> : null}
                      {f.client_company ? <span className="text-text-muted"> • {f.client_company}</span> : null}
                    </div>
                  </div>
                  {typeof f.overall_rating !== "undefined" && f.overall_rating !== null ? (
                    <span className="inline-flex items-center rounded-full border border-amber-500/30 bg-amber-500/10 px-3 py-1 text-xs font-medium text-amber-300">
                      ⭐ {f.overall_rating}/5
                    </span>
                  ) : null}
                </div>
                {f.comment ? <div className="text-sm text-text-secondary mt-2 whitespace-pre-wrap">{f.comment}</div> : null}
                <div className="text-xs text-text-muted mt-2">{f.created_at ? String(f.created_at).slice(0, 19) : ""}</div>
              </div>
            ))}
          </div>
        )}
      </div>
    </AppShell>
  );
}




