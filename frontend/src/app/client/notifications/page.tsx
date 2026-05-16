"use client";

import { AppShell } from "@/components/AppShell";
import { useToast } from "@/components/ToastProvider";
import { apiFetch } from "@/lib/http";
import { useEffect, useState } from "react";

export default function ClientNotificationsPage() {
  const toast = useToast();
  const [loading, setLoading] = useState(true);
  const [notifications, setNotifications] = useState<any[]>([]);
  const [settings, setSettings] = useState<any>({});
  const [tab, setTab] = useState<"inbox" | "settings">("inbox");

  const load = async () => {
    setLoading(true);
    const r1 = await apiFetch<any>(`/api/notifications?unread_only=0&_=${Date.now()}`);
    if (r1.ok) setNotifications(r1.data.notifications || []);
    const r2 = await apiFetch<any>(`/api/client/notification-settings?_=${Date.now()}`);
    if (r2.ok) setSettings(r2.data.settings || r2.data);
    setLoading(false);
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const save = async () => {
    const r = await apiFetch<any>(`/api/client/notification-settings`, { method: "POST", body: JSON.stringify(settings) });
    if (!r.ok) {
      toast.push({ type: "error", title: "Save failed", message: r.error }, 5200);
      return;
    }
    toast.push({ type: "success", title: "Saved" });
    await load();
  };

  return (
    <AppShell role="client">
      <div className="max-w-5xl mx-auto space-y-4">
        <div className="flex items-end justify-between">
          <div>
            <div className="text-xl font-semibold">Notifications</div>
            <div className="text-sm text-text-secondary">Inbox + preferences.</div>
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => setTab("inbox")}
              className={[
                "rounded-xl px-4 py-2 text-sm border transition",
                tab === "inbox" ? "bg-blue-primary/15 border-blue-primary/30 text-blue-primary" : "bg-bg-elevated border-border text-text-secondary hover:bg-bg-hover",
              ].join(" ")}
            >
              Inbox
            </button>
            <button
              onClick={() => setTab("settings")}
              className={[
                "rounded-xl px-4 py-2 text-sm border transition",
                tab === "settings" ? "bg-blue-primary/15 border-blue-primary/30 text-blue-primary" : "bg-bg-elevated border-border text-text-secondary hover:bg-bg-hover",
              ].join(" ")}
            >
              Settings
            </button>
          </div>
        </div>

        {loading ? (
          <div className="rounded-2xl bg-bg-card border border-border p-6 text-text-secondary">Loading…</div>
        ) : tab === "inbox" ? (
          <div className="rounded-2xl bg-bg-card border border-border p-4 space-y-2">
            {notifications.length === 0 ? (
              <div className="text-sm text-text-secondary">No notifications.</div>
            ) : (
              notifications.map((n) => (
                <div key={n.id} className="rounded-xl bg-bg-elevated border border-border p-3">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="font-medium">{n.title || n.type || "Notification"}</div>
                      {n.message ? <div className="text-sm text-text-secondary mt-1">{n.message}</div> : null}
                    </div>
                    <div className="text-xs text-text-muted">{n.created_at ? String(n.created_at).slice(0, 19) : ""}</div>
                  </div>
                </div>
              ))
            )}
          </div>
        ) : (
          <div className="rounded-2xl bg-bg-card border border-border p-4 space-y-3">
            <div className="text-sm text-text-secondary">Choose which notifications you want to receive.</div>
            {[
              ["email_enabled", "Email notifications"],
              ["pentest_updates", "Pentest updates"],
              ["finding_updates", "Finding updates"],
              ["billing_updates", "Billing updates"],
            ].map(([k, label]) => (
              <label key={k} className="flex items-center gap-2 text-sm text-text-secondary">
                <input
                  type="checkbox"
                  checked={Boolean(settings?.[k])}
                  onChange={(e) => setSettings((p: any) => ({ ...(p || {}), [k]: e.target.checked }))}
                  className="accent-redcon-primary"
                />
                <span>{label}</span>
              </label>
            ))}
            <div className="flex justify-end">
              <button
                onClick={save}
                className="rounded-xl bg-blue-primary/15 border border-blue-primary/30 px-4 py-2 text-sm text-blue-primary hover:bg-blue-primary/20 transition"
              >
                Save
              </button>
            </div>
          </div>
        )}
      </div>
    </AppShell>
  );
}




