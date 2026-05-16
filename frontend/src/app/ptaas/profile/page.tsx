"use client";

import { AppShell } from "@/components/AppShell";
import { useToast } from "@/components/ToastProvider";
import { apiFetch } from "@/lib/http";
import { useEffect, useState } from "react";

function countChars(val: any) {
  if (!val) return 0;
  if (Array.isArray(val)) return val.map((x) => String(x || "")).join(", ").length;
  return String(val || "").length;
}

function TagSection({
  label,
  value,
  setValue,
  input,
  setInput,
  placeholder,
  chipClassName,
  maxItems = 24,
  maxChars = 500,
}: {
  label: string;
  value: string[];
  setValue: (next: string[]) => void;
  input: string;
  setInput: (v: string) => void;
  placeholder: string;
  chipClassName: string;
  maxItems?: number;
  maxChars?: number;
}) {
  const chars = countChars(value);
  const add = (raw: string) => {
    const v = String(raw || "").trim().replace(/,$/, "");
    if (!v) return;
    const cleaned = v.slice(0, 48);
    const lower = cleaned.toLowerCase();
    const existing = new Set(value.map((x) => String(x || "").toLowerCase()));
    if (existing.has(lower)) return;
    if (value.length >= maxItems) return;
    // keep within maxChars (soft limit)
    const projected = countChars([...value, cleaned]);
    if (projected > maxChars) return;
    setValue([...value, cleaned]);
  };
  const remove = (idx: number) => setValue(value.filter((_, i) => i !== idx));

  return (
    <div>
      <div className="flex items-center justify-between">
        <div className="text-sm font-semibold">{label}</div>
        <div className="text-xs text-text-muted">
          {chars}/{maxChars} • {value.length}/{maxItems}
        </div>
      </div>
      <div className="mt-2 rounded-xl bg-bg-elevated border border-border p-3">
        <div className="flex flex-wrap gap-2">
          {value.map((s, i) => (
            <span key={`${s}-${i}`} className={`inline-flex items-center gap-2 rounded-lg border px-3 py-1.5 text-sm ${chipClassName}`}>
              {s}
              <button onClick={() => remove(i)} className="opacity-70 hover:opacity-100">
                ×
              </button>
            </span>
          ))}
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === ",") {
                e.preventDefault();
                add(input);
                setInput("");
              }
            }}
            placeholder={placeholder}
            className="min-w-[240px] flex-1 bg-transparent outline-none text-sm text-text-secondary placeholder:text-text-muted px-2 py-1.5"
          />
        </div>
      </div>
      <div className="mt-1 text-xs text-text-muted">Tip: press Enter to add, click × to remove.</div>
    </div>
  );
}

export default function PentesterProfilePage() {
  const toast = useToast();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [profile, setProfile] = useState<any>(null);
  const [skillInput, setSkillInput] = useState("");
  const [certInput, setCertInput] = useState("");
  const [hofInput, setHofInput] = useState("");

  const load = async () => {
    setLoading(true);
    const r = await apiFetch<any>(`/api/ptaas/profile?_=${Date.now()}`);
    if (r.ok) setProfile(r.data.profile || r.data);
    setLoading(false);
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const save = async () => {
    setSaving(true);
    const r = await apiFetch<any>(`/api/ptaas/profile`, { method: "PUT", body: JSON.stringify(profile || {}) });
    setSaving(false);
    if (!r.ok) {
      toast.push({ type: "error", title: "Save failed", message: r.error }, 5200);
      return;
    }
    toast.push({ type: "success", title: "Saved" });
    await load();
  };

  const tags = {
    skills: Array.isArray(profile?.skills) ? profile.skills : [],
    certifications: Array.isArray(profile?.certifications) ? profile.certifications : [],
    halls_of_fame: Array.isArray(profile?.halls_of_fame) ? profile.halls_of_fame : [],
  };

  return (
    <AppShell role="pentester">
      <div className="max-w-4xl mx-auto space-y-5">
        <div>
          <div className="text-2xl font-semibold">Profile</div>
          <div className="text-sm text-text-secondary">Your public pentester profile details.</div>
        </div>

        {loading ? (
          <div className="rounded-2xl bg-bg-card border border-border p-6 text-text-secondary">Loading…</div>
        ) : (
          <div className="rounded-2xl bg-bg-card border border-border p-5 space-y-5">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs uppercase text-text-muted mb-1">Name</label>
                <div className="w-full rounded-xl bg-bg-elevated/60 border border-border px-3 py-2.5 text-sm text-text-secondary">
                  {profile?.name || "—"}
                </div>
                <div className="mt-1 text-xs text-text-muted">Name can only be changed by an admin.</div>
              </div>
              <div>
                <label className="block text-xs uppercase text-text-muted mb-1">Email</label>
                <div className="w-full rounded-xl bg-bg-elevated/60 border border-border px-3 py-2.5 text-sm text-text-secondary">
                  {profile?.email || "—"}
                </div>
                <div className="mt-1 text-xs text-text-muted">Email can only be changed by an admin.</div>
              </div>
            </div>

            {/* Bio */}
            <div>
              <div className="flex items-center justify-between">
                <label className="block text-xs uppercase text-text-muted mb-1">Bio</label>
                <div className="text-xs text-text-muted">{String(profile?.bio || "").length}/500</div>
              </div>
              <textarea
                value={profile?.bio || ""}
                onChange={(e) => setProfile((p: any) => ({ ...(p || {}), bio: e.target.value.slice(0, 500) }))}
                rows={4}
                className="w-full rounded-xl bg-bg-elevated border border-border px-3 py-2.5 text-sm outline-none focus:border-border-light"
                placeholder="Tell clients about your background, focus areas, and experience…"
              />
            </div>

            {/* Skills */}
            <TagSection
              label="Skills"
              value={tags.skills}
              setValue={(next) => setProfile((p: any) => ({ ...(p || {}), skills: next }))}
              input={skillInput}
              setInput={setSkillInput}
              placeholder="Type a skill and press Enter…"
              chipClassName="bg-sky-500/15 border-sky-500/30 text-sky-300"
            />

            {/* Certifications */}
            <TagSection
              label="Certifications"
              value={tags.certifications}
              setValue={(next) => setProfile((p: any) => ({ ...(p || {}), certifications: next }))}
              input={certInput}
              setInput={setCertInput}
              placeholder="Type a certification and press Enter…"
              chipClassName="bg-emerald-500/15 border-emerald-500/30 text-emerald-300"
            />

            {/* Halls of Fame */}
            <TagSection
              label="Halls of Fame"
              value={tags.halls_of_fame}
              setValue={(next) => setProfile((p: any) => ({ ...(p || {}), halls_of_fame: next }))}
              input={hofInput}
              setInput={setHofInput}
              placeholder="Type to add Halls of Fame…"
              chipClassName="bg-violet-500/15 border-violet-500/30 text-violet-300"
            />

            <div className="pt-2 flex justify-end">
              <button
                disabled={saving}
                onClick={async () => {
                  // flush pending inputs (without requiring enter)
                  if (skillInput.trim()) setProfile((p: any) => ({ ...(p || {}), skills: [...(tags.skills || []), skillInput.trim()].slice(0, 24) }));
                  if (certInput.trim())
                    setProfile((p: any) => ({ ...(p || {}), certifications: [...(tags.certifications || []), certInput.trim()].slice(0, 24) }));
                  if (hofInput.trim())
                    setProfile((p: any) => ({ ...(p || {}), halls_of_fame: [...(tags.halls_of_fame || []), hofInput.trim()].slice(0, 24) }));
                  setSkillInput("");
                  setCertInput("");
                  setHofInput("");
                  await save();
                }}
                className="rounded-xl bg-blue-600 hover:bg-blue-500 transition text-white px-5 py-2.5 text-sm font-semibold disabled:opacity-60"
              >
                {saving ? "Updating…" : "Update Profile"}
              </button>
            </div>
          </div>
        )}
      </div>
    </AppShell>
  );
}




