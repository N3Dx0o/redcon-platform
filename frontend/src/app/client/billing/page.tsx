"use client";

import { AppShell } from "@/components/AppShell";
import { useToast } from "@/components/ToastProvider";
import { apiFetch } from "@/lib/http";
import { useEffect, useState } from "react";

export default function ClientBillingPage() {
  const toast = useToast();
  const [loading, setLoading] = useState(true);
  const [billing, setBilling] = useState<any>(null);
  const [credits, setCredits] = useState(10);
  const [buying, setBuying] = useState(false);

  const load = async () => {
    setLoading(true);
    const r = await apiFetch<any>(`/api/client/billing?_=${Date.now()}`);
    if (r.ok) setBilling(r.data);
    setLoading(false);
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const purchase = async () => {
    setBuying(true);
    const r = await apiFetch<any>(`/api/client/purchase-credits`, { method: "POST", body: JSON.stringify({ credits }) });
    setBuying(false);
    if (!r.ok) {
      toast.push({ type: "error", title: "Purchase failed", message: r.error }, 5200);
      return;
    }
    toast.push({ type: "success", title: "Credits added" });
    await load();
  };

  return (
    <AppShell role="client">
      <div className="max-w-4xl mx-auto space-y-4">
        <div>
          <div className="text-xl font-semibold">Billing</div>
          <div className="text-sm text-text-secondary">Credits and billing details.</div>
        </div>

        {loading ? (
          <div className="rounded-2xl bg-bg-card border border-border p-6 text-text-secondary">Loading…</div>
        ) : (
          <>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div className="rounded-2xl bg-bg-card border border-border p-4">
                <div className="text-xs uppercase text-text-muted">Credits</div>
                <div className="text-3xl font-bold mt-1">{billing?.credits ?? 0}</div>
              </div>
              <div className="rounded-2xl bg-bg-card border border-border p-4">
                <div className="text-xs uppercase text-text-muted">Company</div>
                <div className="text-lg font-semibold mt-1">{billing?.company || "—"}</div>
                <div className="text-sm text-text-secondary">{billing?.address || ""}</div>
              </div>
            </div>

            <div className="rounded-2xl bg-bg-card border border-border p-4">
              <div className="font-semibold mb-2">Purchase credits</div>
              <div className="flex flex-col md:flex-row gap-2 items-start md:items-center">
                <input
                  type="number"
                  min={10}
                  value={credits}
                  onChange={(e) => setCredits(Number(e.target.value))}
                  className="w-full md:w-40 rounded-xl bg-bg-elevated border border-border px-3 py-2 text-sm text-text-secondary outline-none"
                />
                <button
                  disabled={buying}
                  onClick={purchase}
                  className="rounded-xl bg-blue-primary/15 border border-blue-primary/30 px-4 py-2 text-sm text-blue-primary hover:bg-blue-primary/20 transition disabled:opacity-50"
                >
                  {buying ? "Processing…" : "Purchase"}
                </button>
                <div className="text-xs text-text-muted">Min 10 credits (simulated).</div>
              </div>
            </div>
          </>
        )}
      </div>
    </AppShell>
  );
}




