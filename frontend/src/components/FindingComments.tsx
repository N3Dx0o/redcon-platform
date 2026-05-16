"use client";

import { apiFetch } from "@/lib/http";
import { formatSubmittedAt } from "@/lib/date";
import { markdownToSafeHtml } from "@/components/markdown";
import { useEffect, useMemo, useRef, useState } from "react";
import { useToast } from "@/components/ToastProvider";
import { IconImage } from "@/components/Icons";

type CommentRow = {
  id: string;
  finding_id: string;
  user_id: string;
  user_name?: string;
  user_email?: string;
  user_role?: string;
  content: string;
  is_internal?: number;
  created_at: string;
};

export function FindingComments({
  findingId,
  role,
}: {
  findingId: string;
  role: "admin" | "client" | "pentester";
}) {
  const toast = useToast();
  const [loading, setLoading] = useState(true);
  const [items, setItems] = useState<CommentRow[]>([]);
  const [meId, setMeId] = useState<string>("");
  const [tab, setTab] = useState<"write" | "preview">("write");
  const [text, setText] = useState("");
  const [internal, setInternal] = useState(false);
  const [posting, setPosting] = useState(false);
  const [uploading, setUploading] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement | null>(null);

  // Product decision: only admins can create internal (client-hidden) comments.
  const canInternal = role === "admin";

  const previewHtml = useMemo(() => markdownToSafeHtml(text), [text]);

  const load = async () => {
    setLoading(true);
    const r = await apiFetch<any>(`/api/findings/${encodeURIComponent(findingId)}/comments?_=${Date.now()}`);
    if (r.ok) setItems((r.data.comments || []) as CommentRow[]);
    setLoading(false);
  };

  useEffect(() => {
    if (!findingId) return;
    (async () => {
      const me = await apiFetch<any>("/api/auth/me");
      if (me.ok) setMeId(String((me.data as any)?.id || ""));
    })();
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [findingId]);

  const insertAtCursor = (snippet: string) => {
    const el = textareaRef.current;
    if (!el) {
      setText((t) => `${t}${t ? "\n" : ""}${snippet}`);
      return;
    }
    const start = el.selectionStart ?? el.value.length;
    const end = el.selectionEnd ?? el.value.length;
    const next = el.value.slice(0, start) + snippet + el.value.slice(end);
    setText(next);
    requestAnimationFrame(() => {
      el.focus();
      const pos = start + snippet.length;
      el.setSelectionRange(pos, pos);
    });
  };

  const ToolbarBtn = ({
    label,
    title,
    onClick,
  }: {
    label: React.ReactNode;
    title: string;
    onClick: () => void;
  }) => (
    <button
      type="button"
      title={title}
      onClick={onClick}
      className="h-8 w-8 rounded-lg border border-transparent text-text-muted hover:text-text-primary hover:bg-bg-hover transition flex items-center justify-center"
    >
      {label}
    </button>
  );

  const uploadFiles = async (files: FileList | File[] | null) => {
    if (!files || (Array.isArray(files) ? files.length === 0 : files.length === 0)) return;
    setUploading(true);
    try {
      const fd = new FormData();
      const arr = Array.isArray(files) ? files : Array.from(files);
      arr.forEach((f) => fd.append("files", f));
      const r = await fetch(`/api/findings/${encodeURIComponent(findingId)}/comment-attachments`, {
        method: "POST",
        credentials: "include",
        body: fd,
      });
      const data = await r.json().catch(() => ({}));
      if (!r.ok || !data?.success) {
        toast.push({ type: "error", title: "Upload failed", message: data?.detail || "Failed to upload attachment" }, 5200);
        return;
      }
      const uploaded = (data.files || []) as Array<{ markdown?: string }>;
      uploaded.forEach((u) => {
        if (u.markdown) insertAtCursor(`${u.markdown}\n`);
      });
    } finally {
      setUploading(false);
    }
  };

  const onDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    await uploadFiles(e.dataTransfer?.files);
  };

  const onPaste = async (e: React.ClipboardEvent) => {
    const files = Array.from(e.clipboardData?.files || []);
    if (files.length > 0) {
      e.preventDefault();
      await uploadFiles(files);
    }
  };

  const post = async () => {
    const content = String(text || "").trim();
    if (!content) return;
    setPosting(true);
    const r = await apiFetch<any>(`/api/findings/${encodeURIComponent(findingId)}/comments`, {
      method: "POST",
      body: JSON.stringify({ content, is_internal: canInternal ? internal : false }),
    });
    setPosting(false);
    if (!r.ok) {
      toast.push({ type: "error", title: "Failed to comment", message: r.error }, 5200);
      return;
    }
    setText("");
    setInternal(false);
    setTab("write");
    await load();
  };

  const del = async (id: string) => {
    const r = await apiFetch<any>(`/api/findings/${encodeURIComponent(findingId)}/comments/${encodeURIComponent(id)}`, {
      method: "DELETE",
    });
    if (!r.ok) {
      toast.push({ type: "error", title: "Delete failed", message: r.error }, 5200);
      return;
    }
    await load();
  };

  return (
    <div className="rounded-2xl bg-bg-card border border-border p-4">
      <div className="flex items-center justify-between gap-3">
        <div className="font-semibold">Comments</div>
        <div className="text-xs text-text-muted">Markdown supported • Max 5000 chars</div>
      </div>

      <div className="mt-3 space-y-3">
        {loading ? (
          <div className="text-sm text-text-secondary">Loading…</div>
        ) : items.length === 0 ? (
          <div className="text-sm text-text-secondary">No comments yet.</div>
        ) : (
          <div className="space-y-3">
            {items.map((c) => {
              const who = c.user_name || c.user_email || "User";
              const roleLabel = (c.user_role || "").toLowerCase();
              const isInternal = Number(c.is_internal || 0) === 1;
              return (
                <div key={c.id} className="rounded-xl bg-bg-elevated border border-border p-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <div className="text-sm font-medium truncate">{who}</div>
                        {roleLabel ? (
                          <span className="text-[11px] px-2 py-0.5 rounded-full border border-border text-text-muted">
                            {roleLabel}
                          </span>
                        ) : null}
                        {isInternal ? (
                          <span className="text-[11px] px-2 py-0.5 rounded-full border border-orange-500/40 bg-orange-500/10 text-orange-300">
                            Internal
                          </span>
                        ) : null}
                      </div>
                      <div className="text-xs text-text-muted mt-0.5">{formatSubmittedAt(c.created_at)}</div>
                    </div>
                    {role === "admin" || (meId && c.user_id === meId) ? (
                      <button
                        onClick={() => del(c.id)}
                        className="text-xs text-text-muted hover:text-redcon-bright transition"
                        title="Delete comment"
                      >
                        Delete
                      </button>
                    ) : null}
                  </div>
                  <div
                    className="mt-2 text-sm text-text-secondary prose prose-invert max-w-none"
                    dangerouslySetInnerHTML={{ __html: markdownToSafeHtml(c.content || "") }}
                  />
                </div>
              );
            })}
          </div>
        )}

        <div className="rounded-xl border border-border bg-bg-elevated overflow-hidden" onDrop={onDrop} onDragOver={(e) => e.preventDefault()}>
          <div className="flex items-center gap-2 px-3 py-2 border-b border-border">
            <button
              onClick={() => setTab("write")}
              className={`text-sm px-3 py-1.5 rounded-lg border transition ${
                tab === "write" ? "bg-bg-card border-border text-text-primary" : "bg-transparent border-transparent text-text-muted hover:text-text-secondary"
              }`}
            >
              Write
            </button>
            <button
              onClick={() => setTab("preview")}
              className={`text-sm px-3 py-1.5 rounded-lg border transition ${
                tab === "preview" ? "bg-bg-card border-border text-text-primary" : "bg-transparent border-transparent text-text-muted hover:text-text-secondary"
              }`}
            >
              Preview
            </button>
            <div className="ml-2 h-6 w-px bg-border" />
            <div className="hidden sm:flex items-center gap-1">
              <ToolbarBtn label="H" title="Heading" onClick={() => insertAtCursor("### Heading\n")} />
              <ToolbarBtn label="B" title="Bold" onClick={() => insertAtCursor("**bold**")} />
              <ToolbarBtn label="I" title="Italic" onClick={() => insertAtCursor("*italic*")} />
              <ToolbarBtn label="S" title="Strikethrough" onClick={() => insertAtCursor("~~strike~~")} />
              <ToolbarBtn label="❝" title="Quote" onClick={() => insertAtCursor("> quote\n")} />
              <ToolbarBtn label="⛓" title="Link" onClick={() => insertAtCursor("[text](https://example.com)")} />
              <ToolbarBtn label="</>" title="Code block" onClick={() => insertAtCursor("```\ncode\n```\n")} />
              <ToolbarBtn label={<IconImage className="h-4 w-4" />} title="Image" onClick={() => insertAtCursor("![alt](/uploads/...)\n")} />
              <ToolbarBtn label="•" title="List" onClick={() => insertAtCursor("- item\n")} />
            </div>
            <div className="ml-auto flex items-center gap-2">
              {canInternal ? (
                <label className="flex items-center gap-2 text-xs text-text-muted select-none">
                  <input type="checkbox" checked={internal} onChange={(e) => setInternal(e.target.checked)} />
                  Internal (hidden from client)
                </label>
              ) : null}
              <label className="text-xs text-sky-300 hover:text-sky-200 cursor-pointer">
                <input
                  type="file"
                  multiple
                  className="hidden"
                  onChange={(e) => uploadFiles(e.target.files)}
                  disabled={uploading}
                />
                {uploading ? "Uploading…" : "Attach files"}
              </label>
            </div>
          </div>

          {tab === "write" ? (
            <textarea
              ref={textareaRef}
              value={text}
              onChange={(e) => setText(e.target.value)}
              onPaste={onPaste}
              rows={7}
              maxLength={5000}
              placeholder="Write a comment… (drag & drop files, paste screenshots, or use Attach files)"
              className="w-full bg-transparent px-3 py-3 text-sm text-text-secondary outline-none resize-y"
            />
          ) : (
            <div className="px-3 py-3 text-sm text-text-secondary">
              <div className="prose prose-invert max-w-none" dangerouslySetInnerHTML={{ __html: previewHtml || "<p>Nothing to preview.</p>" }} />
            </div>
          )}

          <div className="px-3 py-2 border-t border-border flex items-center justify-between">
            <div className="text-xs text-text-muted">
              Attach files by dragging & dropping, selecting or pasting them. (Max 25MB)
            </div>
            <button
              disabled={posting || !String(text || "").trim()}
              onClick={post}
              className="rounded-xl bg-blue-primary/15 border border-blue-primary/30 px-4 py-2 text-sm text-blue-primary hover:bg-blue-primary/20 transition disabled:opacity-50"
            >
              {posting ? "Posting…" : "Comment"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

