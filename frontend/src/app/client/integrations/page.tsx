"use client";

import { AppShell } from "@/components/AppShell";
import { useToast } from "@/components/ToastProvider";
import { apiFetch } from "@/lib/http";
import { useEffect, useMemo, useState } from "react";

type IntegrationRow = {
  id: string;
  type: string;
  enabled: number | boolean;
  config?: any;
};

const INTEGRATIONS = [
  { type: "jira", name: "Jira", desc: "Push findings as issues to Jira Cloud/Server", icon: "🔷" },
  { type: "github", name: "GitHub", desc: "Push findings as issues in GitHub", icon: "🐙" },
  { type: "webhooks", name: "Webhooks", desc: "Subscribe to events for your pentests", icon: "🪝" },
  { type: "azure_devops", name: "Azure DevOps", desc: "Push findings as work items", icon: "🧩" },
  { type: "servicenow", name: "ServiceNow", desc: "Push findings as incidents", icon: "🧾" },
  { type: "bitbucket", name: "Bitbucket", desc: "Push findings as issues", icon: "🟦" },
  { type: "zendesk", name: "Zendesk", desc: "Push findings as tickets", icon: "🎫" },
  { type: "trello", name: "Trello", desc: "Push findings as cards", icon: "🗂️" },
];

export default function ClientIntegrationsPage() {
  const toast = useToast();
  const [loading, setLoading] = useState(true);
  const [rows, setRows] = useState<IntegrationRow[]>([]);
  const [draft, setDraft] = useState<Record<string, any>>({});
  const [enabled, setEnabled] = useState<Record<string, boolean>>({});

  const byType = useMemo(() => {
    const m: Record<string, IntegrationRow> = {};
    for (const r of rows) m[String(r.type || "").toLowerCase()] = r;
    return m;
  }, [rows]);

  const load = async () => {
    setLoading(true);
    const r = await apiFetch<{ success?: boolean; integrations?: IntegrationRow[] }>(`/api/client/integrations?_=${Date.now()}`);
    setLoading(false);
    if (!r.ok) {
      toast.push({ type: "error", title: "Failed to load integrations", message: r.error }, 5200);
      return;
    }
    const list = r.data.integrations || [];
    setRows(list);
    const nextEnabled: Record<string, boolean> = {};
    const nextDraft: Record<string, any> = {};
    for (const i of INTEGRATIONS) {
      const row = list.find((x) => String(x.type || "").toLowerCase() === i.type);
      nextEnabled[i.type] = row ? Boolean(row.enabled) : false;
      nextDraft[i.type] = row?.config || {};
    }
    setEnabled(nextEnabled);
    setDraft(nextDraft);
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const save = async (type: string) => {
    const body = {
      type,
      enabled: !!enabled[type],
      config: draft[type] || {},
    };
    const r = await apiFetch<any>(`/api/client/integrations`, { method: "POST", body: JSON.stringify(body) });
    if (!r.ok) {
      toast.push({ type: "error", title: "Save failed", message: r.error }, 5200);
      return;
    }
    toast.push({ type: "success", title: "Saved", message: `${type} integration updated` }, 3200);
    await load();
  };

  return (
    <AppShell role="client">
      <div className="max-w-6xl mx-auto space-y-5">
        <div className="rounded-3xl border border-border bg-gradient-to-r from-bg-card via-bg-elevated to-bg-card overflow-hidden shadow-xl shadow-black/10">
          <div className="relative p-6">
            <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_top_right,_var(--tw-gradient-stops))] from-sky-500/15 via-violet-500/10 to-transparent" />
            <div className="relative flex items-end justify-between gap-4">
              <div>
                <div className="text-2xl font-bold">Integrations</div>
                <div className="text-sm text-text-secondary mt-1">Connect your workflow tools to REDCON</div>
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

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {INTEGRATIONS.map((i) => {
            const row = byType[i.type];
            const on = !!enabled[i.type];
            const cfg = draft[i.type] || {};
            return (
              <div key={i.type} className="rounded-2xl bg-bg-card border border-border p-5">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <div className="h-9 w-9 rounded-xl bg-bg-elevated border border-border flex items-center justify-center">
                        <span className="text-lg">{i.icon}</span>
                      </div>
                      <div className="font-semibold">{i.name}</div>
                    </div>
                    <div className="text-sm text-text-secondary mt-2">{i.desc}</div>
                    {row?.id ? <div className="text-xs text-text-muted mt-1">Configured</div> : <div className="text-xs text-text-muted mt-1">Not configured</div>}
                  </div>
                  <label className="inline-flex items-center gap-2 text-sm">
                    <input
                      type="checkbox"
                      checked={on}
                      onChange={(e) => setEnabled((p) => ({ ...p, [i.type]: e.target.checked }))}
                    />
                    <span className="text-text-secondary">{on ? "On" : "Off"}</span>
                  </label>
                </div>

                <div className="mt-4 space-y-2">
                  {i.type === "webhooks" ? (
                    <input
                      className="w-full rounded-xl bg-bg-elevated border border-border px-3 py-2 text-sm outline-none focus:border-border-light"
                      placeholder="Webhook URL (https://...)"
                      value={cfg.url || ""}
                      onChange={(e) => setDraft((p) => ({ ...p, [i.type]: { ...cfg, url: e.target.value } }))}
                    />
                  ) : (
                    <textarea
                      className="w-full min-h-[80px] rounded-xl bg-bg-elevated border border-border px-3 py-2 text-xs font-mono outline-none focus:border-border-light"
                      placeholder='Config JSON, e.g. {"projectKey":"SEC","repo":"org/repo"}'
                      value={JSON.stringify(cfg || {}, null, 2)}
                      onChange={(e) => {
                        try {
                          const parsed = JSON.parse(e.target.value || "{}");
                          setDraft((p) => ({ ...p, [i.type]: parsed }));
                        } catch (_) {
                          // keep last valid, but allow typing without breaking UX
                        }
                      }}
                    />
                  )}

                  <button
                    disabled={loading}
                    onClick={() => save(i.type)}
                    className="w-full rounded-xl bg-gradient-to-r from-sky-600 to-sky-500 hover:from-sky-500 hover:to-sky-400 transition-all text-white px-4 py-2 text-sm font-semibold disabled:opacity-60"
                  >
                    Save
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </AppShell>
  );
}

