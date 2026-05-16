"use client";

import { AppShell } from "@/components/AppShell";
import { useToast } from "@/components/ToastProvider";
import { apiFetch } from "@/lib/http";
import { useEffect, useState } from "react";

export default function PentesterSettingsPage() {
  const toast = useToast();
  const [saving, setSaving] = useState(false);
  const [revoking, setRevoking] = useState(false);
  const [sessionsLoading, setSessionsLoading] = useState(true);
  const [sessions, setSessions] = useState<any[]>([]);
  const [form, setForm] = useState({ current: "", next: "", confirm: "" });

  const loadSessions = async () => {
    setSessionsLoading(true);
    const r = await apiFetch<any>(`/api/ptaas/sessions?_=${Date.now()}`);
    if (r.ok) setSessions(r.data.sessions || []);
    setSessionsLoading(false);
  };

  useEffect(() => {
    loadSessions();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const changePassword = async () => {
    if (!form.current || !form.next || !form.confirm) {
      toast.push({ type: "warning", title: "Missing fields", message: "Please fill all password fields." });
      return;
    }
    if (form.next !== form.confirm) {
      toast.push({ type: "warning", title: "Passwords do not match", message: "Confirm password must match the new password." });
      return;
    }
    if (form.next.length < 12) {
      toast.push({ type: "warning", title: "Weak password", message: "Use at least 12 characters." });
      return;
    }

    setSaving(true);
    try {
      const r = await apiFetch<any>(`/api/ptaas/change-password`, {
        method: "POST",
        body: JSON.stringify({ current_password: form.current, new_password: form.next }),
      });
      if (!r.ok) throw new Error(r.error);
      toast.push({ type: "success", title: "Password changed", message: "We also signed out other sessions for security." });
      setForm({ current: "", next: "", confirm: "" });
      await loadSessions();
    } catch (e: any) {
      toast.push({ type: "error", title: "Password change failed", message: e?.message || "Failed" }, 5200);
    } finally {
      setSaving(false);
    }
  };

  const revokeOthers = async () => {
    setRevoking(true);
    try {
      const r = await apiFetch<any>(`/api/ptaas/sessions/revoke-others`, { method: "POST", body: "{}" });
      if (!r.ok) throw new Error(r.error);
      toast.push({ type: "success", title: "Signed out other sessions" });
      await loadSessions();
    } catch (e: any) {
      toast.push({ type: "error", title: "Failed to revoke sessions", message: e?.message || "Failed" }, 5200);
    } finally {
      setRevoking(false);
    }
  };

  return (
    <AppShell role="pentester">
      <div className="max-w-3xl mx-auto space-y-4">
        <div>
          <div className="text-xl font-semibold">Settings</div>
          <div className="text-sm text-text-secondary">Account and preferences.</div>
        </div>

        <div className="rounded-2xl bg-bg-card border border-border p-6">
          <div className="font-semibold">Change password</div>
          <div className="text-sm text-text-secondary mt-1">
            For security, you must enter your current password. After changing, we rotate your session and sign out other devices.
          </div>

          <div className="mt-4 space-y-3">
            <div>
              <label className="block text-xs uppercase text-text-muted mb-1">Current password</label>
              <input
                type="password"
                value={form.current}
                onChange={(e) => setForm((p) => ({ ...p, current: e.target.value }))}
                className="w-full rounded-xl bg-bg-elevated border border-border px-3 py-2.5 text-sm outline-none focus:border-border-light"
                autoComplete="current-password"
              />
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label className="block text-xs uppercase text-text-muted mb-1">New password</label>
                <input
                  type="password"
                  value={form.next}
                  onChange={(e) => setForm((p) => ({ ...p, next: e.target.value }))}
                  className="w-full rounded-xl bg-bg-elevated border border-border px-3 py-2.5 text-sm outline-none focus:border-border-light"
                  autoComplete="new-password"
                />
              </div>
              <div>
                <label className="block text-xs uppercase text-text-muted mb-1">Confirm new password</label>
                <input
                  type="password"
                  value={form.confirm}
                  onChange={(e) => setForm((p) => ({ ...p, confirm: e.target.value }))}
                  className="w-full rounded-xl bg-bg-elevated border border-border px-3 py-2.5 text-sm outline-none focus:border-border-light"
                  autoComplete="new-password"
                />
              </div>
            </div>
            <div className="text-xs text-text-muted">
              Password rules: <span className="text-text-secondary">12+ chars</span>, no spaces, and include at least 3 of: lowercase, uppercase, number, symbol.
            </div>

            <div className="flex flex-wrap gap-2 pt-2">
              <button
                disabled={saving}
                onClick={changePassword}
                className="rounded-xl bg-gradient-to-r from-emerald-600 to-emerald-500 hover:from-emerald-500 hover:to-emerald-400 transition text-white px-4 py-2 text-sm font-medium disabled:opacity-60"
              >
                {saving ? "Saving…" : "Change password"}
              </button>
              <button
                disabled={revoking}
                onClick={revokeOthers}
                className="rounded-xl bg-amber-500/15 border border-amber-500/30 px-4 py-2 text-sm text-amber-300 hover:bg-amber-500/20 transition disabled:opacity-60"
              >
                {revoking ? "Working…" : "Sign out other sessions"}
              </button>
            </div>
          </div>
        </div>

        <div className="rounded-2xl bg-bg-card border border-border p-6">
          <div className="font-semibold">Sessions</div>
          <div className="text-sm text-text-secondary mt-1">Recent devices signed in to your account.</div>
          {sessionsLoading ? (
            <div className="mt-4 text-sm text-text-secondary">Loading…</div>
          ) : sessions.length === 0 ? (
            <div className="mt-4 text-sm text-text-secondary">No sessions found.</div>
          ) : (
            <div className="mt-4 space-y-2">
              {sessions.map((s) => (
                <div key={s.id} className="rounded-xl bg-bg-elevated border border-border p-3 flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="text-sm font-medium truncate">
                      {s.is_current ? <span className="text-emerald-300 mr-2">● Current</span> : null}
                      {s.ip_address || "—"}
                    </div>
                    <div className="text-xs text-text-muted truncate">{s.user_agent || "—"}</div>
                  </div>
                  <div className="text-xs text-text-muted whitespace-nowrap">
                    {s.last_active ? String(s.last_active).slice(0, 19) : ""}
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




