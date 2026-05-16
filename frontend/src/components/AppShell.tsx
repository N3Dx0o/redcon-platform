"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { getMe, logout, type Me } from "@/lib/auth";
import { apiFetch } from "@/lib/http";

function NavItem({ href, label }: { href: string; label: string }) {
  const pathname = usePathname();
  // App is served under /app/* in production, but hrefs are /client/*, /admin/*, /ptaas/*.
  // Normalize so active highlighting works reliably on all dashboards.
  const p = pathname?.startsWith("/app/") ? pathname.slice(4) : pathname;
  const active = p === href || (p ? p.startsWith(href + "/") : false);
  return (
    <Link
      href={href}
      className={[
        "flex items-center gap-2 rounded-lg px-3 py-2 text-sm transition",
        active
          ? "bg-redcon-primary/20 text-redcon-bright border border-redcon-primary/40 shadow-[0_0_0_1px_rgba(201,53,63,0.25)]"
          : "text-text-secondary hover:bg-bg-hover hover:text-text-primary border border-transparent",
      ].join(" ")}
    >
      <span className="font-medium">{label}</span>
    </Link>
  );
}

// Logo is served by Nginx from /static/logo.png (shared across apps).

export function AppShell({
  children,
  role,
}: {
  children: React.ReactNode;
  role: "client" | "admin" | "pentester";
}) {
  const router = useRouter();
  const [me, setMe] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);
  const [authError, setAuthError] = useState<string | null>(null);
  const [notifOpen, setNotifOpen] = useState(false);
  const [notifs, setNotifs] = useState<any[]>([]);
  const [notifCount, setNotifCount] = useState<number>(0);
  const [profileOpen, setProfileOpen] = useState(false);

  useEffect(() => {
    (async () => {
      const res = await getMe();
      if (!res.ok) {
        // Don't get stuck on an infinite loader if navigation fails or the network hangs.
        setAuthError(res.error || "Not authenticated");
        setLoading(false);
        // Hard redirect is more reliable than client router when deep-linking.
        try {
          window.location.href = "/app/portal";
        } catch {
          router.replace("/portal");
        }
        return;
      }
      if (res.data?.role !== role) {
        setAuthError("Access denied");
        setLoading(false);
        try {
          window.location.href = "/app/portal";
        } catch {
          router.replace("/portal");
        }
        return;
      }
      setMe(res.data);
      setLoading(false);
    })();
  }, [role, router]);

  const loadNotifications = async () => {
    const r = await apiFetch<{ success?: boolean; notifications?: any[]; count?: number }>(
      `/api/notifications?unread_only=0&_=${Date.now()}`
    );
    if (r.ok) {
      setNotifs(r.data.notifications || []);
      setNotifCount(r.data.count || 0);
    }
  };

  useEffect(() => {
    if (!loading) {
      loadNotifications();
      const t = window.setInterval(loadNotifications, 30000);
      return () => window.clearInterval(t);
    }
    return;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [loading]);

  const markAllRead = async () => {
    await apiFetch(`/api/notifications/read-all`, { method: "POST", body: "{}" });
    await loadNotifications();
  };

  const markRead = async (id: string) => {
    await apiFetch(`/api/notifications/${encodeURIComponent(id)}/read`, { method: "POST", body: "{}" });
    await loadNotifications();
  };

  const onLogout = async () => {
    await logout();
    router.replace("/portal");
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-bg-dark text-text-primary flex items-center justify-center">
        <div className="text-text-secondary">Loading…</div>
      </div>
    );
  }
  if (!me) {
    return (
      <div className="min-h-screen bg-bg-dark text-text-primary flex items-center justify-center px-4">
        <div className="w-full max-w-md rounded-2xl bg-bg-card border border-border p-6 text-center">
          <div className="text-lg font-semibold">Session required</div>
          <div className="text-sm text-text-secondary mt-2">{authError || "Please sign in again."}</div>
          <a
            href="/app/portal"
            className="inline-flex mt-4 rounded-xl bg-redcon-primary/15 border border-redcon-primary/30 px-4 py-2 text-sm text-redcon-primary hover:bg-redcon-primary/20 transition"
          >
            Go to login
          </a>
        </div>
      </div>
    );
  }

  const sidebarLinks =
    role === "client"
      ? [
          { href: "/client/dashboard", label: "Dashboard" },
          { href: "/client/assets", label: "Assets" },
          { href: "/client/scans", label: "Scans" },
          { href: "/client/pentests", label: "Pentests" },
          { href: "/client/findings", label: "Findings" },
          { href: "/client/insights", label: "Insights" },
          { href: "/client/activity", label: "Activity" },
          { href: "/client/integrations", label: "Integrations" },
          { href: "/client/reports", label: "Reports" },
          { href: "/client/credits", label: "Credits" },
          { href: "/client/notifications", label: "Notifications" },
          { href: "/client/billing", label: "Billing" },
          { href: "/client/settings", label: "Settings" },
        ]
      : role === "admin"
      ? [
          { href: "/admin/dashboard", label: "Dashboard" },
          { href: "/admin/pentests", label: "Pentests" },
          { href: "/admin/users", label: "Users" },
        ]
      : [
          { href: "/ptaas/pentests", label: "Pentests" },
          { href: "/ptaas/findings", label: "Findings" },
          { href: "/ptaas/activity", label: "Activity" },
          { href: "/ptaas/feedback", label: "Feedback" },
          { href: "/ptaas/profile", label: "Profile" },
          { href: "/ptaas/settings", label: "Settings" },
        ];

  const settingsHref = role === "client" ? "/client/settings" : role === "pentester" ? "/ptaas/settings" : null;
  const homeHref = role === "client" ? "/client/dashboard" : role === "admin" ? "/admin/dashboard" : "/ptaas/pentests";

  return (
    <div className="min-h-screen bg-bg-dark text-text-primary flex">
      <aside className="w-[240px] bg-bg-sidebar border-r border-border p-4 hidden md:flex flex-col gap-3">
        <div className="mb-2">
          <Link href={homeHref} className="inline-flex items-center">
            <img
              src="/static/logo.png"
              alt="REDCON"
              className="h-10 w-auto object-contain"
            />
          </Link>
        </div>
        <nav className="flex flex-col gap-2">
          {sidebarLinks.map((l) => (
            <NavItem key={l.href} href={l.href} label={l.label} />
          ))}
        </nav>
      </aside>

      <main className="flex-1">
        <header className="sticky top-0 z-20 bg-bg-sidebar/80 backdrop-blur border-b border-border px-4 py-3 flex items-center justify-between">
          <div className="text-sm text-text-secondary">
            {me?.name || "User"} <span className="text-text-muted">({role})</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="relative">
              <button
                onClick={() => {
                  setNotifOpen((v) => !v);
                  if (!notifOpen) loadNotifications();
                }}
                className="relative rounded-lg bg-bg-elevated border border-border h-10 w-10 flex items-center justify-center text-text-secondary hover:bg-bg-hover hover:text-text-primary transition"
                aria-label="Notifications"
              >
                🔔
                {notifCount ? (
                  <span className="absolute -top-1 -right-1 text-[10px] bg-redcon-primary text-white rounded-full px-1.5 py-0.5 border border-bg-sidebar">
                    {notifCount}
                  </span>
                ) : null}
              </button>
              {notifOpen ? (
                <div className="absolute right-0 mt-2 w-[360px] max-w-[calc(100vw-2rem)] rounded-2xl border border-border bg-bg-card shadow-[0_20px_60px_rgba(0,0,0,0.55)] overflow-hidden">
                  <div className="px-4 py-3 border-b border-border flex items-center justify-between">
                    <div className="font-semibold text-sm">Notifications</div>
                    <button
                      onClick={markAllRead}
                      className="text-xs text-blue-primary hover:underline"
                    >
                      Mark all read
                    </button>
                  </div>
                  <div className="max-h-[360px] overflow-y-auto">
                    {notifs.length === 0 ? (
                      <div className="px-4 py-4 text-sm text-text-secondary">No notifications.</div>
                    ) : (
                      notifs.map((n) => (
                        <button
                          key={n.id}
                          onClick={() => markRead(n.id)}
                          className="w-full text-left px-4 py-3 border-b border-border/50 hover:bg-bg-hover transition"
                        >
                          <div className="flex items-center justify-between gap-2">
                            <div className="text-sm font-medium">{n.title || n.type || "Notification"}</div>
                            <div className="text-xs text-text-muted">{n.created_at ? String(n.created_at).slice(0, 16) : ""}</div>
                          </div>
                          {n.message ? <div className="text-xs text-text-secondary mt-1">{n.message}</div> : null}
                        </button>
                      ))
                    )}
                  </div>
                </div>
              ) : null}
            </div>
            <div className="relative">
              <button
                onClick={() => setProfileOpen((v) => !v)}
                className="rounded-lg bg-bg-elevated border border-border px-3 py-2 text-sm text-text-secondary hover:bg-bg-hover hover:text-text-primary transition flex items-center gap-2"
                aria-label="Profile"
              >
                <span className="inline-flex h-6 w-6 items-center justify-center rounded-full bg-white/5 border border-border text-xs">
                  {(me?.name || me?.email || "U").slice(0, 1).toUpperCase()}
                </span>
                <span className="hidden sm:block">{me?.name || "Profile"}</span>
              </button>
              {profileOpen ? (
                <div className="absolute right-0 mt-2 w-[280px] rounded-2xl border border-border bg-bg-card shadow-[0_20px_60px_rgba(0,0,0,0.55)] overflow-hidden">
                  <div className="px-4 py-3 border-b border-border">
                    <div className="text-xs uppercase text-text-muted">Signed in as</div>
                    <div className="text-sm font-medium mt-1">{me?.name || "—"}</div>
                    <div className="text-xs text-text-secondary mt-0.5">{me?.email || "—"}</div>
                  </div>
                  <div className="p-2">
                    {settingsHref ? (
                      <Link
                        href={settingsHref}
                        onClick={() => setProfileOpen(false)}
                        className="block rounded-xl px-3 py-2 text-sm text-text-secondary hover:bg-bg-hover hover:text-text-primary transition"
                      >
                        Settings
                      </Link>
                    ) : null}
            <button
              onClick={onLogout}
                      className="w-full text-left rounded-xl px-3 py-2 text-sm text-rose-300 hover:bg-rose-500/10 transition"
            >
              Logout
            </button>
                  </div>
                </div>
              ) : null}
            </div>
          </div>
        </header>
        <div className="p-5">{children}</div>
      </main>
    </div>
  );
}


