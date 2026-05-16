"use client";

import { AppShell } from "@/components/AppShell";
import { IconGem } from "@/components/Icons";
import { useToast } from "@/components/ToastProvider";
import { apiFetch } from "@/lib/http";
import { useEffect, useState } from "react";

type CreditsResp = { success?: boolean; credits?: number; tier?: string; scan_cost?: number };

export default function ClientCreditsPage() {
  const toast = useToast();
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState<CreditsResp | null>(null);

  const load = async () => {
    setLoading(true);
    const r = await apiFetch<CreditsResp>("/api/client/credits");
    setLoading(false);
    if (!r.ok) {
      toast.push({ type: "error", title: "Failed to load credits", message: r.error }, 5200);
      return;
    }
    setData(r.data);
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
            <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_top_right,_var(--tw-gradient-stops))] from-violet-500/20 via-sky-500/10 to-transparent" />
            <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_bottom_left,_var(--tw-gradient-stops))] from-emerald-500/15 via-violet-500/10 to-transparent" />
            <div className="relative flex items-end justify-between gap-4">
              <div>
                <div className="text-2xl font-bold">Credits</div>
                <div className="text-sm text-text-secondary mt-1">Scan units and platform usage balance</div>
              </div>
              <button
                onClick={() => toast.push({ type: "info", title: "Purchasing coming soon", message: "Stripe billing will be enabled next." }, 4200)}
                className="rounded-xl bg-gradient-to-r from-violet-600 to-violet-500 hover:from-violet-500 hover:to-violet-400 transition-all text-white px-5 py-2.5 text-sm font-semibold shadow-lg shadow-violet-500/25"
              >
                Add Scan Units
              </button>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="rounded-2xl bg-bg-card border border-border p-5">
            <div className="flex items-center gap-3">
              <div className="h-10 w-10 rounded-xl bg-gradient-to-br from-violet-500 to-violet-600 flex items-center justify-center shadow-lg">
                <IconGem className="h-5 w-5 text-white" />
              </div>
              <div>
                <div className="text-xs uppercase tracking-wide text-text-muted">Available balance</div>
                <div className="text-2xl font-bold">{loading ? "—" : data?.credits ?? 0}</div>
              </div>
            </div>
            <div className="mt-3 text-sm text-text-secondary">
              Each scan currently costs <span className="font-semibold text-text-primary">{data?.scan_cost ?? 1}</span> credit.
            </div>
          </div>

          <div className="rounded-2xl bg-bg-card border border-border p-5">
            <div className="text-xs uppercase tracking-wide text-text-muted">Tier</div>
            <div className="text-lg font-semibold mt-1">{loading ? "—" : (data?.tier || "free")}</div>
            <div className="mt-3 text-sm text-text-secondary">Upgrade options coming soon.</div>
          </div>

          <div className="rounded-2xl bg-bg-card border border-border p-5">
            <div className="text-xs uppercase tracking-wide text-text-muted">Notes</div>
            <div className="mt-2 text-sm text-text-secondary">
              Credits are decremented when you run a scan. Scheduled scans will also consume credits when enabled.
            </div>
            <button
              onClick={load}
              className="mt-4 rounded-xl bg-bg-elevated border border-border px-4 py-2 text-sm text-text-secondary hover:bg-bg-hover hover:text-text-primary transition"
            >
              Refresh
            </button>
          </div>
        </div>
      </div>
    </AppShell>
  );
}

