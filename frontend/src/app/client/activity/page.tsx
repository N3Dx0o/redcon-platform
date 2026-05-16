"use client";

import { AppShell } from "@/components/AppShell";
import { useToast } from "@/components/ToastProvider";
import { apiFetch } from "@/lib/http";
import { useEffect, useState } from "react";

type ActivityItem = {
  id: string;
  type?: string;
  title?: string;
  description?: string;
  icon?: string;
  created_at?: string;
};

export default function ClientActivityPage() {
  const toast = useToast();
  const [loading, setLoading] = useState(true);
  const [items, setItems] = useState<ActivityItem[]>([]);

  const load = async () => {
    setLoading(true);
    const r = await apiFetch<{ success?: boolean; activity?: ActivityItem[] }>(`/api/client/activity?_=${Date.now()}`);
    setLoading(false);
    if (!r.ok) {
      toast.push({ type: "error", title: "Failed to load activity", message: r.error }, 5200);
      return;
    }
    setItems(r.data.activity || []);
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <AppShell role="client">
      <div className="max-w-5xl mx-auto space-y-5">
        <div className="rounded-3xl border border-border bg-gradient-to-r from-bg-card via-bg-elevated to-bg-card overflow-hidden shadow-xl shadow-black/10">
          <div className="relative p-6">
            <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_top_right,_var(--tw-gradient-stops))] from-emerald-500/15 via-sky-500/10 to-transparent" />
            <div className="relative flex items-end justify-between gap-4">
              <div>
                <div className="text-2xl font-bold">Activity</div>
                <div className="text-sm text-text-secondary mt-1">Recent actions across your account</div>
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

        <div className="rounded-2xl bg-bg-card border border-border overflow-hidden">
          {loading ? (
            <div className="p-6 text-sm text-text-secondary">Loading…</div>
          ) : items.length === 0 ? (
            <div className="p-8 text-sm text-text-secondary">No activity yet.</div>
          ) : (
            <div className="divide-y divide-border">
              {items.map((a) => (
                <div key={a.id} className="p-4 flex items-start gap-3">
                  <div className="h-9 w-9 rounded-xl bg-bg-elevated border border-border flex items-center justify-center">
                    <span className="text-lg">{a.icon || "•"}</span>
                  </div>
                  <div className="min-w-0">
                    <div className="font-medium">{a.title || a.type || "Activity"}</div>
                    {a.description ? <div className="text-sm text-text-secondary mt-0.5">{a.description}</div> : null}
                    {a.created_at ? <div className="text-xs text-text-muted mt-1">{String(a.created_at).replace("T", " ").slice(0, 19)}</div> : null}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </AppShell>
  );
}

