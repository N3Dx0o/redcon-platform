"use client";

import { AppShell } from "@/components/AppShell";
import { Modal } from "@/components/Modal";
import { useToast } from "@/components/ToastProvider";
import { formatSubmittedAt } from "@/lib/date";
import { apiFetch } from "@/lib/http";
import { useParams } from "next/navigation";
import { useEffect, useMemo, useState } from "react";

type Collaborator = { id?: string; name?: string; email?: string; role?: string; is_poc?: boolean };

type PentestDetail = {
  success?: boolean;
  pentest: {
    id: string;
    title: string;
    pentestNumber?: string;
    type?: string;
    status?: string;
    start_date?: string;
    end_date?: string;
    scope?: string;
    targets?: string[] | string;
    description?: string;
    objectives?: string;
    technology_stack?: string;
    environment_type?: string;
    collaboration_preference?: string;
    sensitive_data?: string[] | string;
    credential_type?: string;
    credentials?: string;
    notes?: string;
    priority?: string;
    compliance?: string[] | string;
    attachments?: { name?: string; url?: string; size?: number }[] | string;
    company_name?: string;
    client_name?: string;
    payout_total?: number;
    required_skills?: string[] | string;
    created_at?: string;
    collaborators?: Collaborator[];
  };
};

type Finding = {
  id: string;
  title: string;
  severity: string;
  status: string;
  category?: string;
  description?: string;
  affected_url?: string;
  created_at?: string;
  cvss_score?: string;
  cwe_id?: string;
};

export default function PentestDetailPage() {
  const params = useParams<{ id: string }>();
  const pentestId = String(params?.id || "");
  const toast = useToast();

  const [tab, setTab] = useState<"brief" | "collaborators" | "coverage" | "findings">("brief");
  const [loading, setLoading] = useState(true);
  const [pentest, setPentest] = useState<PentestDetail["pentest"] | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [coverageLoading, setCoverageLoading] = useState(false);
  const [coverage, setCoverage] = useState<any[]>([]);
  const [coverageStats, setCoverageStats] = useState<{ percent?: number; total?: number; completed?: number } | null>(null);

  const [findingModalOpen, setFindingModalOpen] = useState(false);
  const [savingFinding, setSavingFinding] = useState(false);
  const [editFindingId, setEditFindingId] = useState<string | null>(null);
  const [form, setForm] = useState({
    title: "",
    severity: "medium",
    category: "other",
    affected_url: "",
    description: "",
    poc: "",
    impact: "",
    remediation: "",
  });

  const canSubmitFinding = (() => {
    const s = String(pentest?.status || "").toLowerCase();
    // Allow findings during active execution and remediation.
    // Back-compat: some older pentests used "live".
    return ["active", "live", "remediation"].includes(s);
  })();

  const load = async () => {
    setLoading(true);
    const res = await apiFetch<PentestDetail>(`/api/ptaas/pentest/${encodeURIComponent(pentestId)}?_=${Date.now()}`);
    if (!res.ok) {
      toast.push({ type: "error", title: "Failed to load pentest", message: res.error }, 5200);
      setLoading(false);
      return;
    }
    setPentest(res.data.pentest);

    const resF = await apiFetch<{ success?: boolean; findings?: Finding[] }>(
      `/api/ptaas/findings?pentest_id=${encodeURIComponent(pentestId)}&_=${Date.now()}`
    );
    if (resF.ok) setFindings(resF.data.findings || []);
    setLoading(false);
  };

  const loadCoverage = async () => {
    setCoverageLoading(true);
    try {
      const res = await apiFetch<{ success?: boolean; items?: any[] }>(
        `/api/ptaas/pentest/${encodeURIComponent(pentestId)}/coverage?_=${Date.now()}`
      );
      if (res.ok) setCoverage(res.data.items || []);

      const resS = await apiFetch<{ success?: boolean; percent?: number; total?: number; completed?: number }>(
        `/api/ptaas/pentest/${encodeURIComponent(pentestId)}/coverage-stats?_=${Date.now()}`
      );
      if (resS.ok) setCoverageStats({ percent: resS.data.percent, total: resS.data.total, completed: resS.data.completed });
    } finally {
      setCoverageLoading(false);
    }
  };

  const initCoverage = async () => {
    const res = await apiFetch<any>(`/api/ptaas/pentest/${encodeURIComponent(pentestId)}/coverage`, { method: "POST" });
    if (!res.ok) {
      toast.push({ type: "error", title: "Coverage checklist error", message: res.error }, 5200);
      return;
    }
    toast.push({ type: "success", title: "Coverage initialized" });
    await loadCoverage();
  };

  const updateCoverageItem = async (itemId: string, status: string) => {
    const res = await apiFetch<any>(`/api/ptaas/coverage/${encodeURIComponent(itemId)}`, {
      method: "PUT",
      body: JSON.stringify({ status }),
    });
    if (!res.ok) {
      toast.push({ type: "error", title: "Failed to update coverage", message: res.error }, 5200);
      return;
    }
    await loadCoverage();
  };

  useEffect(() => {
    if (!pentestId) return;
    load();
    loadCoverage();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pentestId]);

  const openNewFinding = () => {
    setEditFindingId(null);
    setForm({
      title: "",
      severity: "medium",
      category: "other",
      affected_url: "",
      description: "",
      poc: "",
      impact: "",
      remediation: "",
    });
    setFindingModalOpen(true);
  };

  const openEditFinding = async (id: string) => {
    const res = await apiFetch<{ finding: any }>(`/api/pentester/finding/${encodeURIComponent(id)}?_=${Date.now()}`);
    if (!res.ok) {
      toast.push({ type: "error", title: "Couldn’t load finding", message: res.error }, 5200);
      return;
    }
    const f = res.data.finding || {};
    setEditFindingId(id);
    setForm({
      title: f.title || "",
      severity: f.severity || "medium",
      category: f.category || "other",
      affected_url: f.affected_url || "",
      description: f.description || "",
      poc: f.steps_to_reproduce || f.poc || "",
      impact: f.impact || "",
      remediation: f.remediation || "",
    });
    setFindingModalOpen(true);
  };

  const submitFinding = async () => {
    if (!form.title || !form.description || !form.poc) {
      toast.push({ type: "warning", title: "Missing required fields", message: "Title, Description, and PoC are required." });
      return;
    }
    setSavingFinding(true);
    try {
      if (editFindingId) {
        const res = await apiFetch<any>(`/api/pentester/finding/${encodeURIComponent(editFindingId)}`, {
          method: "PUT",
          body: JSON.stringify({ ...form, steps_to_reproduce: form.poc }),
        });
        if (!res.ok) throw new Error(res.error);
        toast.push({ type: "success", title: "Finding updated" });
      } else {
        const res = await apiFetch<any>(`/api/ptaas/findings`, {
          method: "POST",
          body: JSON.stringify({ ...form, steps_to_reproduce: form.poc, pentest_id: pentestId }),
        });
        if (!res.ok) throw new Error(res.error);
        toast.push({ type: "success", title: "Finding submitted" });
      }
      setFindingModalOpen(false);
      await load();
    } catch (e: any) {
      toast.push({ type: "error", title: "Couldn’t save finding", message: e?.message || "Failed" }, 5200);
    } finally {
      setSavingFinding(false);
    }
  };

  const deleteFinding = async (id: string, title: string) => {
    if (!confirm(`Delete "${title}"? This cannot be undone.`)) return;
    const res = await apiFetch<any>(`/api/pentester/finding/${encodeURIComponent(id)}`, { method: "DELETE" });
    if (!res.ok) {
      toast.push({ type: "error", title: "Cannot delete finding", message: res.error }, 5200);
      return;
    }
    toast.push({ type: "success", title: "Finding deleted" });
    await load();
  };

  const parseJsonArray = (val: any): string[] => {
    if (Array.isArray(val)) return val;
    if (typeof val === "string") {
      try {
        const parsed = JSON.parse(val);
        if (Array.isArray(parsed)) return parsed;
      } catch (_) {}
      return val ? [val] : [];
    }
    return [];
  };

  const targets = useMemo(() => parseJsonArray(pentest?.targets), [pentest?.targets]);
  const sensitiveData = useMemo(() => parseJsonArray(pentest?.sensitive_data), [pentest?.sensitive_data]);
  const compliance = useMemo(() => parseJsonArray(pentest?.compliance), [pentest?.compliance]);
  const requiredSkills = useMemo(() => parseJsonArray(pentest?.required_skills), [pentest?.required_skills]);
  const attachments = useMemo(() => {
    const a = pentest?.attachments;
    if (Array.isArray(a)) return a;
    if (typeof a === "string") {
      try {
        const parsed = JSON.parse(a);
        if (Array.isArray(parsed)) return parsed;
      } catch (_) {}
    }
    return [];
  }, [pentest?.attachments]);

  return (
    <AppShell role="pentester">
      <div className="max-w-6xl mx-auto space-y-4">
        <div className="rounded-2xl bg-bg-card border border-border p-4">
          <div className="flex items-start justify-between gap-3">
            <div>
              <div className="text-xl font-semibold">{pentest?.title || "Pentest"}</div>
              <div className="text-sm text-text-secondary">
                {pentest?.pentestNumber ? <span className="mr-2">{pentest.pentestNumber}</span> : null}
                <span className="mr-2">{pentest?.type || "—"}</span>
                <span className="inline-flex items-center rounded-md border border-border px-2 py-0.5 text-xs text-text-secondary">
                  {pentest?.status || "—"}
                </span>
              </div>
            </div>
            <button
              disabled={!canSubmitFinding}
              onClick={openNewFinding}
              className="rounded-xl bg-redcon-primary hover:bg-redcon-bright transition text-white px-4 py-2 text-sm font-medium disabled:opacity-50"
            >
              + Submit Finding
            </button>
          </div>
        </div>

        <div className="flex gap-2 overflow-x-auto border-b border-border">
          {[
            { id: "brief", label: "Brief" },
            { id: "collaborators", label: "Collaborators" },
            { id: "coverage", label: "Coverage" },
            { id: "findings", label: "Findings" },
          ].map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id as any)}
              className={[
                "px-4 py-3 text-sm whitespace-nowrap border-b-2 transition",
                tab === (t.id as any) ? "text-blue-primary border-blue-primary" : "text-text-secondary border-transparent hover:text-text-primary",
              ].join(" ")}
            >
              {t.label}
            </button>
          ))}
        </div>

        {loading ? (
          <div className="rounded-2xl bg-bg-card border border-border p-6 text-text-secondary">Loading…</div>
        ) : tab === "brief" ? (
          <div className="space-y-4">
            {/* Overview Row */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <div className="rounded-xl bg-bg-card border border-border p-3">
                <div className="text-xs uppercase text-text-muted">Priority</div>
                <div className="font-semibold capitalize">{pentest?.priority || "normal"}</div>
              </div>
              <div className="rounded-xl bg-bg-card border border-border p-3">
                <div className="text-xs uppercase text-text-muted">Client</div>
                <div className="font-semibold truncate">{pentest?.client_name || pentest?.company_name || "—"}</div>
              </div>
              <div className="rounded-xl bg-bg-card border border-border p-3">
                <div className="text-xs uppercase text-text-muted">Start Date</div>
                <div className="font-semibold">{pentest?.start_date ? String(pentest.start_date).slice(0, 10) : "—"}</div>
              </div>
              <div className="rounded-xl bg-bg-card border border-border p-3">
                <div className="text-xs uppercase text-text-muted">End Date</div>
                <div className="font-semibold">{pentest?.end_date ? String(pentest.end_date).slice(0, 10) : "—"}</div>
              </div>
            </div>

            {/* Description */}
            {pentest?.description ? (
              <div className="rounded-2xl bg-bg-card border border-border p-4">
                <div className="font-semibold mb-2">Description</div>
                <div className="text-sm text-text-secondary whitespace-pre-wrap">{pentest.description}</div>
              </div>
            ) : null}

            {/* Scope & Targets */}
            <div className="rounded-2xl bg-bg-card border border-border p-4">
              <div className="font-semibold mb-2">Scope & Targets</div>
              <div className="text-sm text-text-secondary whitespace-pre-wrap">{pentest?.scope || "—"}</div>
              {targets.length > 0 ? (
                <div className="mt-3 flex flex-wrap gap-2">
                  {targets.map((x, i) => (
                    <span key={i} className="inline-flex items-center rounded-lg bg-sky-500/15 border border-sky-500/30 px-3 py-1 text-xs text-sky-400 font-mono">
                      {x}
                    </span>
                  ))}
                </div>
              ) : null}
            </div>

            {/* Two Column Layout */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
              {/* Left Column - Technical Details */}
              <div className="space-y-3">
            <div className="rounded-2xl bg-bg-card border border-border p-4">
                  <div className="font-semibold mb-3">Technical Details</div>
                  <div className="space-y-3 text-sm">
                <div>
                  <div className="text-xs uppercase text-text-muted">Objectives</div>
                      <div className="text-text-secondary whitespace-pre-wrap">{pentest?.objectives || "—"}</div>
                </div>
                <div>
                      <div className="text-xs uppercase text-text-muted">Technology Stack</div>
                      <div className="text-text-secondary whitespace-pre-wrap">{pentest?.technology_stack || "—"}</div>
                </div>
                    <div className="grid grid-cols-2 gap-3">
                  <div>
                    <div className="text-xs uppercase text-text-muted">Environment</div>
                        <div className="text-text-secondary capitalize">{pentest?.environment_type || "—"}</div>
                  </div>
                  <div>
                    <div className="text-xs uppercase text-text-muted">Collaboration</div>
                        <div className="text-text-secondary capitalize">{pentest?.collaboration_preference || "—"}</div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Compliance */}
                {compliance.length > 0 ? (
                  <div className="rounded-2xl bg-bg-card border border-border p-4">
                    <div className="font-semibold mb-2">Compliance Requirements</div>
                    <div className="flex flex-wrap gap-2">
                      {compliance.map((c, i) => (
                        <span key={i} className="inline-flex items-center rounded-lg bg-violet-500/15 border border-violet-500/30 px-3 py-1 text-xs text-violet-400">
                          {c}
                        </span>
                      ))}
                    </div>
                  </div>
                ) : null}

                {/* Required Skills */}
                {requiredSkills.length > 0 ? (
                  <div className="rounded-2xl bg-bg-card border border-border p-4">
                    <div className="font-semibold mb-2">Required Skills</div>
                    <div className="flex flex-wrap gap-2">
                      {requiredSkills.map((s, i) => (
                        <span key={i} className="inline-flex items-center rounded-lg bg-emerald-500/15 border border-emerald-500/30 px-3 py-1 text-xs text-emerald-400">
                          {s}
                        </span>
                      ))}
                    </div>
                  </div>
                ) : null}
              </div>

              {/* Right Column - Sensitive Info */}
              <div className="space-y-3">
                {/* Sensitive Data */}
                {sensitiveData.length > 0 ? (
                  <div className="rounded-2xl bg-bg-card border border-border p-4">
                    <div className="font-semibold mb-2">Sensitive Data Types</div>
                    <div className="flex flex-wrap gap-2">
                      {sensitiveData.map((d, i) => (
                        <span key={i} className="inline-flex items-center rounded-lg bg-rose-500/15 border border-rose-500/30 px-3 py-1 text-xs text-rose-400">
                          ⚠️ {d}
                        </span>
                      ))}
                    </div>
                  </div>
                ) : null}

                {/* Credentials */}
                {pentest?.credential_type && pentest.credential_type !== "none" ? (
                  <div className="rounded-2xl bg-bg-card border border-amber-500/30 p-4">
                    <div className="font-semibold mb-2 flex items-center gap-2">
                      <span className="text-amber-400">🔑</span> Credentials Provided
                    </div>
                    <div className="space-y-2 text-sm">
                      <div>
                        <div className="text-xs uppercase text-text-muted">Type</div>
                        <div className="text-text-secondary capitalize">{pentest.credential_type}</div>
                      </div>
                      {pentest.credentials ? (
                        <div>
                          <div className="text-xs uppercase text-text-muted">Details</div>
                          <div className="text-text-secondary whitespace-pre-wrap font-mono text-xs bg-bg-elevated rounded-lg p-2 mt-1">{pentest.credentials}</div>
                        </div>
                      ) : null}
                    </div>
                  </div>
                ) : null}

                {/* Notes */}
                {pentest?.notes ? (
                  <div className="rounded-2xl bg-bg-card border border-border p-4">
                    <div className="font-semibold mb-2">Additional Notes</div>
                    <div className="text-sm text-text-secondary whitespace-pre-wrap">{pentest.notes}</div>
                  </div>
                ) : null}

                {/* Attachments */}
                {attachments.length > 0 ? (
                  <div className="rounded-2xl bg-bg-card border border-border p-4">
                    <div className="font-semibold mb-2">Attachments ({attachments.length})</div>
                    <div className="space-y-2">
                      {attachments.map((file, i) => (
                        <a
                          key={i}
                          href={file.url || "#"}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="flex items-center gap-2 rounded-lg bg-bg-elevated border border-border p-2 text-sm hover:bg-bg-hover transition group"
                        >
                          <span className="text-text-muted">📎</span>
                          <span className="flex-1 truncate text-text-secondary group-hover:text-text-primary">{file.name || "Attachment"}</span>
                          {file.size ? <span className="text-xs text-text-muted">{Math.round((file.size || 0) / 1024)} KB</span> : null}
                        </a>
                      ))}
                    </div>
                  </div>
                ) : null}

                {/* Payout Info */}
                {(pentest?.payout_total ?? 0) > 0 ? (
                  <div className="rounded-2xl bg-bg-card border border-emerald-500/30 p-4">
                    <div className="font-semibold mb-2 flex items-center gap-2">
                      <span className="text-emerald-400">💰</span> Payout Budget
                    </div>
                    <div className="text-2xl font-bold text-emerald-400">${pentest?.payout_total?.toLocaleString() || 0}</div>
                  </div>
                ) : null}
              </div>
            </div>
          </div>
        ) : tab === "collaborators" ? (
          <div className="rounded-2xl bg-bg-card border border-border p-4">
            <div className="font-semibold mb-3">People</div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="text-xs uppercase text-text-muted">
                  <tr className="border-b border-border">
                    <th className="text-left py-2">Name</th>
                    <th className="text-left py-2">Email</th>
                    <th className="text-left py-2">Role</th>
                    <th className="text-left py-2">POC</th>
                  </tr>
                </thead>
                <tbody>
                  {(pentest?.collaborators || []).map((c) => (
                    <tr key={`${c.role}-${c.email}`} className="border-b border-border/50">
                      <td className="py-2">{c.name || "—"}</td>
                      <td className="py-2 text-text-secondary">{c.email || "—"}</td>
                      <td className="py-2">{c.role || "—"}</td>
                      <td className="py-2">{c.is_poc ? "Yes" : ""}</td>
                    </tr>
                  ))}
                  {!(pentest?.collaborators || []).length ? (
                    <tr>
                      <td className="py-3 text-text-secondary" colSpan={4}>
                        No collaborators found.
                      </td>
                    </tr>
                  ) : null}
                </tbody>
              </table>
            </div>
          </div>
        ) : tab === "coverage" ? (
          <div className="rounded-2xl bg-bg-card border border-border p-4">
            <div className="flex items-center justify-between gap-3 mb-3">
              <div>
                <div className="font-semibold">Coverage Checklist</div>
                <div className="text-sm text-text-secondary">Track testing progress across security areas.</div>
              </div>
              <button
                onClick={initCoverage}
                className="rounded-xl bg-bg-elevated border border-border px-4 py-2 text-sm text-text-secondary hover:bg-bg-hover hover:text-text-primary transition"
              >
                Initialize Checklist
              </button>
            </div>

            <div className="mb-4 flex items-center gap-3">
              <div className="h-2 w-[220px] bg-bg-elevated rounded-full overflow-hidden border border-border">
                <div
                  className="h-full bg-green-primary"
                  style={{ width: `${Math.max(0, Math.min(100, coverageStats?.percent ?? 0))}%` }}
                />
              </div>
              <div className="text-sm text-text-secondary">
                <span className="font-semibold text-green-primary">{Math.round(coverageStats?.percent ?? 0)}%</span>{" "}
                <span className="text-text-muted">
                  ({coverageStats?.completed ?? 0}/{coverageStats?.total ?? 0})
                </span>
              </div>
            </div>

            {coverageLoading ? (
              <div className="text-text-secondary text-sm">Loading…</div>
            ) : coverage.length === 0 ? (
              <div className="text-text-secondary text-sm">No checklist items yet. Click “Initialize Checklist”.</div>
            ) : (
              <div className="space-y-2">
                {coverage.map((i) => (
                  <div key={i.id} className="rounded-xl bg-bg-elevated border border-border p-3 flex items-start gap-3">
                    <select
                      value={i.status || "pending"}
                      onChange={(e) => updateCoverageItem(i.id, e.target.value)}
                      className="rounded-lg bg-bg-hover border border-border px-3 py-2 text-sm text-text-secondary outline-none"
                    >
                      <option value="pending">Pending</option>
                      <option value="in_progress">In Progress</option>
                      <option value="completed">Completed</option>
                      <option value="not_applicable">N/A</option>
                    </select>
                    <div className="flex-1">
                      <div className="font-medium">{i.item || "Checklist item"}</div>
                      {i.description ? <div className="text-sm text-text-secondary">{i.description}</div> : null}
                      {i.category ? <div className="text-xs text-text-muted mt-1">{i.category}</div> : null}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        ) : (
          <div className="rounded-2xl bg-bg-card border border-border p-4">
            <div className="font-semibold mb-3">Findings</div>
            {!findings.length ? (
              <div className="text-text-secondary text-sm">No findings yet.</div>
            ) : (
              <div className="space-y-3">
                {findings.map((f) => {
                  const canEdit = true; // pentesters can edit their own findings; backend enforces ownership
                  const canDelete = ["new", "draft"].includes((f.status || "").toLowerCase());
                  return (
                    <div key={f.id} className="rounded-2xl bg-bg-elevated border border-border p-4">
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <div className="font-semibold">{f.title}</div>
                          <div className="text-xs text-text-muted mt-1">
                            {f.severity} • {f.status} • 🕒 {formatSubmittedAt(f.created_at)}
                          </div>
                        </div>
                        <div className="flex gap-2">
                          {canEdit ? (
                            <button
                              onClick={() => openEditFinding(f.id)}
                              className="rounded-lg bg-bg-hover border border-border px-3 py-2 text-xs text-text-secondary hover:text-text-primary transition"
                            >
                              Edit
                            </button>
                          ) : null}
                          {canDelete ? (
                            <button
                              onClick={() => deleteFinding(f.id, f.title)}
                              className="rounded-lg bg-redcon-primary/10 border border-redcon-primary/30 px-3 py-2 text-xs text-redcon-bright hover:bg-redcon-primary/15 transition"
                            >
                              Delete
                            </button>
                          ) : null}
                        </div>
                      </div>
                      {f.description ? <div className="text-sm text-text-secondary mt-3 whitespace-pre-wrap">{f.description}</div> : null}
                      <div className="mt-3 text-xs text-text-muted flex flex-wrap gap-3">
                        {f.category ? <span>📁 {f.category}</span> : null}
                        {f.affected_url ? <span>🔗 {f.affected_url}</span> : null}
                        {f.cwe_id ? <span>🏷️ {f.cwe_id}</span> : null}
                        {f.cvss_score ? <span>📊 {f.cvss_score}</span> : null}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        <Modal
          open={findingModalOpen}
          title={editFindingId ? "Edit Finding" : "Submit New Finding"}
          onClose={() => setFindingModalOpen(false)}
          footer={
            <>
              <button
                onClick={() => setFindingModalOpen(false)}
                className="rounded-xl bg-bg-elevated border border-border px-4 py-2 text-sm text-text-secondary hover:bg-bg-hover hover:text-text-primary transition"
              >
                Cancel
              </button>
              <button
                disabled={savingFinding}
                onClick={submitFinding}
                className="rounded-xl bg-redcon-primary hover:bg-redcon-bright transition text-white px-4 py-2 text-sm font-medium disabled:opacity-60"
              >
                {savingFinding ? "Saving…" : editFindingId ? "Save" : "Submit"}
              </button>
            </>
          }
          maxWidthClass="max-w-3xl"
        >
          <div className="grid grid-cols-1 gap-3">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label className="block text-xs uppercase text-text-muted mb-1">Title *</label>
                <input
                  value={form.title}
                  onChange={(e) => setForm((p) => ({ ...p, title: e.target.value }))}
                  className="w-full rounded-xl bg-bg-elevated border border-border px-3 py-2 text-sm outline-none focus:border-border-light"
                />
              </div>
              <div>
                <label className="block text-xs uppercase text-text-muted mb-1">Severity *</label>
                <select
                  value={form.severity}
                  onChange={(e) => setForm((p) => ({ ...p, severity: e.target.value }))}
                  className="w-full rounded-xl bg-bg-elevated border border-border px-3 py-2 text-sm outline-none focus:border-border-light"
                >
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                  <option value="info">Info</option>
                </select>
              </div>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label className="block text-xs uppercase text-text-muted mb-1">Category</label>
                <select
                  value={form.category}
                  onChange={(e) => setForm((p) => ({ ...p, category: e.target.value }))}
                  className="w-full rounded-xl bg-bg-elevated border border-border px-3 py-2 text-sm outline-none focus:border-border-light"
                >
                  <option value="injection">Injection</option>
                  <option value="xss">XSS</option>
                  <option value="auth">Authentication</option>
                  <option value="access_control">Access Control</option>
                  <option value="crypto">Cryptography</option>
                  <option value="ssrf">SSRF</option>
                  <option value="config">Misconfiguration</option>
                  <option value="other">Other</option>
                </select>
              </div>
              <div>
                <label className="block text-xs uppercase text-text-muted mb-1">Affected URL</label>
                <input
                  value={form.affected_url}
                  onChange={(e) => setForm((p) => ({ ...p, affected_url: e.target.value }))}
                  className="w-full rounded-xl bg-bg-elevated border border-border px-3 py-2 text-sm outline-none focus:border-border-light"
                />
              </div>
            </div>
            <div>
              <label className="block text-xs uppercase text-text-muted mb-1">Description *</label>
              <textarea
                value={form.description}
                onChange={(e) => setForm((p) => ({ ...p, description: e.target.value }))}
                rows={4}
                className="w-full rounded-xl bg-bg-elevated border border-border px-3 py-2 text-sm outline-none focus:border-border-light"
              />
            </div>
            <div>
              <label className="block text-xs uppercase text-text-muted mb-1">Proof of Concept / Steps *</label>
              <textarea
                value={form.poc}
                onChange={(e) => setForm((p) => ({ ...p, poc: e.target.value }))}
                rows={4}
                className="w-full rounded-xl bg-bg-elevated border border-border px-3 py-2 text-sm outline-none focus:border-border-light font-mono"
              />
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label className="block text-xs uppercase text-text-muted mb-1">Impact</label>
                <textarea
                  value={form.impact}
                  onChange={(e) => setForm((p) => ({ ...p, impact: e.target.value }))}
                  rows={3}
                  className="w-full rounded-xl bg-bg-elevated border border-border px-3 py-2 text-sm outline-none focus:border-border-light"
                />
              </div>
              <div>
                <label className="block text-xs uppercase text-text-muted mb-1">Remediation</label>
                <textarea
                  value={form.remediation}
                  onChange={(e) => setForm((p) => ({ ...p, remediation: e.target.value }))}
                  rows={3}
                  className="w-full rounded-xl bg-bg-elevated border border-border px-3 py-2 text-sm outline-none focus:border-border-light"
                />
              </div>
            </div>
          </div>
        </Modal>
      </div>
    </AppShell>
  );
}


