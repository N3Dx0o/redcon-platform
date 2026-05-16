"use client";

import { AppShell } from "@/components/AppShell";

export default function ClientSettingsPage() {
  return (
    <AppShell role="client">
      <div className="max-w-4xl mx-auto space-y-4">
        <div>
          <div className="text-xl font-semibold">Settings</div>
          <div className="text-sm text-text-secondary">Account and preferences.</div>
        </div>
        <div className="rounded-2xl bg-bg-card border border-border p-6 text-text-secondary">
          Settings are managed under the Notifications page for now. More settings will be added here next.
        </div>
      </div>
    </AppShell>
  );
}




