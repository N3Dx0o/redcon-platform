"use client";

import React, { useEffect } from "react";

export function Modal({
  open,
  title,
  children,
  onClose,
  footer,
  maxWidthClass = "max-w-2xl",
}: {
  open: boolean;
  title: string;
  children: React.ReactNode;
  onClose: () => void;
  footer?: React.ReactNode;
  maxWidthClass?: string;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    if (open) window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-[4000] flex items-center justify-center bg-black/60 px-4">
      <div className={["w-full rounded-2xl border border-border bg-bg-card shadow-[0_20px_80px_rgba(0,0,0,0.65)]", maxWidthClass].join(" ")}>
        <div className="flex items-center justify-between px-5 py-4 border-b border-border">
          <div className="font-semibold">{title}</div>
          <button
            onClick={onClose}
            className="h-9 w-9 rounded-xl bg-bg-elevated border border-border text-text-secondary hover:bg-bg-hover hover:text-text-primary transition"
            aria-label="Close"
          >
            ×
          </button>
        </div>
        <div className="px-5 py-4 max-h-[70vh] overflow-y-auto">{children}</div>
        {footer ? <div className="px-5 py-4 border-t border-border flex justify-end gap-3">{footer}</div> : null}
      </div>
    </div>
  );
}




