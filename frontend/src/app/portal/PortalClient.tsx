"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import Link from "next/link";

function mapBackendRedirect(path: string) {
  // Backend returns Flask template routes; we map them to Next routes for the new UI.
  // In production we run Next with basePath=/app, so backend may return /app/...
  const p = (path || "").startsWith("/app/") ? (path || "").replace(/^\/app/, "") : (path || "");
  const m: Record<string, string> = {
    "/client/dashboard": "/client/dashboard",
    "/admin/dashboard": "/admin/dashboard",
    "/ptaas/pentests": "/ptaas/pentests",
  };
  return m[p] || "/portal";
}

export default function PortalClient() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ email, password }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(data?.error || "Login failed");
        setLoading(false);
        return;
      }
      const next = mapBackendRedirect(data?.redirect || "");
      router.replace(next);
    } catch (err: any) {
      setError(err?.message || "Network error");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-bg-dark text-text-primary flex items-center justify-center px-4">
      <div className="w-full max-w-md bg-bg-card border border-border rounded-2xl p-6 shadow-[0_20px_80px_rgba(0,0,0,0.55)]">
        <div className="mb-5">
          <div className="flex items-center gap-3">
            <img src="/static/logo.png" alt="REDCON OFFENCE" className="h-8 w-auto" />
          </div>
          <div className="text-text-secondary text-sm mt-2">Sign in to your dashboard</div>
        </div>

        <form onSubmit={onSubmit} className="space-y-4">
          <div>
            <label className="block text-xs uppercase tracking-wide text-text-secondary mb-1">
              Email
            </label>
            <input
              className="w-full rounded-xl bg-bg-elevated border border-border px-3 py-2 text-sm outline-none focus:border-border-light"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@company.com"
              autoComplete="email"
              required
            />
          </div>
          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="block text-xs uppercase tracking-wide text-text-secondary">
                Password
              </label>
              <Link 
                href="/app/forgot-password"
                className="text-xs text-sky-400 hover:text-sky-300 transition"
              >
                Forgot password?
              </Link>
            </div>
            <input
              type="password"
              className="w-full rounded-xl bg-bg-elevated border border-border px-3 py-2 text-sm outline-none focus:border-border-light"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              autoComplete="current-password"
              required
            />
          </div>

          {error ? (
            <div className="rounded-xl border border-redcon-primary/40 bg-redcon-primary/10 px-3 py-2 text-sm text-text-secondary">
              {error}
            </div>
          ) : null}

          <button
            type="submit"
            disabled={loading}
            className="w-full rounded-xl bg-redcon-primary hover:bg-redcon-bright transition text-white font-medium py-2 disabled:opacity-60"
          >
            {loading ? "Signing in…" : "Sign in"}
          </button>
        </form>
      </div>
    </div>
  );
}


