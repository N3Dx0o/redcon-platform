"use client";

import React, { createContext, useCallback, useContext, useMemo, useState } from "react";

type ToastType = "success" | "error" | "warning" | "info";

type Toast = {
  id: string;
  type: ToastType;
  title: string;
  message?: string;
};

type ToastCtx = {
  push: (t: Omit<Toast, "id">, durationMs?: number) => void;
};

const Ctx = createContext<ToastCtx | null>(null);

export function useToast() {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useToast must be used within ToastProvider");
  return ctx;
}

function iconFor(type: ToastType) {
  if (type === "success") return "✓";
  if (type === "warning") return "!";
  if (type === "error") return "×";
  return "i";
}

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const push = useCallback((t: Omit<Toast, "id">, durationMs = 3200) => {
    const id = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const toast: Toast = { id, ...t };
    setToasts((prev) => [...prev, toast]);
    window.setTimeout(() => {
      setToasts((prev) => prev.filter((x) => x.id !== id));
    }, Math.max(1200, durationMs));
  }, []);

  const value = useMemo(() => ({ push }), [push]);

  return (
    <Ctx.Provider value={value}>
      {children}
      <div className="fixed top-4 right-4 z-[5000] flex flex-col gap-2 pointer-events-none">
        {toasts.map((t) => (
          <div
            key={t.id}
            className={[
              "pointer-events-auto w-[min(420px,calc(100vw-2rem))] rounded-2xl border px-4 py-3 shadow-[0_20px_60px_rgba(0,0,0,0.55)] backdrop-blur bg-bg-card/95 flex gap-3 items-start",
              t.type === "success"
                ? "border-green-primary/30"
                : t.type === "warning"
                ? "border-yellow-primary/30"
                : t.type === "error"
                ? "border-redcon-primary/30"
                : "border-border",
            ].join(" ")}
          >
            <div
              className={[
                "h-9 w-9 rounded-xl flex items-center justify-center border text-sm font-bold",
                t.type === "success"
                  ? "bg-green-primary/15 text-green-primary border-green-primary/25"
                  : t.type === "warning"
                  ? "bg-yellow-primary/15 text-yellow-primary border-yellow-primary/25"
                  : t.type === "error"
                  ? "bg-redcon-primary/15 text-redcon-bright border-redcon-primary/25"
                  : "bg-bg-elevated text-text-secondary border-border",
              ].join(" ")}
            >
              {iconFor(t.type)}
            </div>
            <div className="flex-1">
              <div className="text-sm font-semibold">{t.title}</div>
              {t.message ? <div className="text-xs text-text-secondary mt-0.5">{t.message}</div> : null}
            </div>
          </div>
        ))}
      </div>
    </Ctx.Provider>
  );
}




