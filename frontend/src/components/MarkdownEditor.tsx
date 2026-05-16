"use client";

import { markdownToSafeHtml } from "@/components/markdown";
import { IconImage } from "@/components/Icons";
import { useMemo, useRef, useState } from "react";

export function MarkdownEditor({
  value,
  onChange,
  placeholder,
  maxLength = 10000,
  onUploadFiles,
  helperText,
  className,
}: {
  value: string;
  onChange: (next: string) => void;
  placeholder?: string;
  maxLength?: number;
  onUploadFiles?: (files: FileList | File[] | null) => Promise<void>;
  helperText?: string;
  className?: string;
}) {
  const [tab, setTab] = useState<"write" | "preview">("write");
  const [uploading, setUploading] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement | null>(null);

  const previewHtml = useMemo(() => markdownToSafeHtml(value || ""), [value]);

  const insertAtCursor = (snippet: string) => {
    const el = textareaRef.current;
    if (!el) {
      onChange(`${value || ""}${value ? "\n" : ""}${snippet}`);
      return;
    }
    const start = el.selectionStart ?? el.value.length;
    const end = el.selectionEnd ?? el.value.length;
    const next = el.value.slice(0, start) + snippet + el.value.slice(end);
    onChange(next);
    requestAnimationFrame(() => {
      el.focus();
      const pos = start + snippet.length;
      el.setSelectionRange(pos, pos);
    });
  };

  const ToolbarBtn = ({ label, title, onClick }: { label: React.ReactNode; title: string; onClick: () => void }) => (
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
    if (!onUploadFiles) return;
    if (!files || (Array.isArray(files) ? files.length === 0 : files.length === 0)) return;
    setUploading(true);
    try {
      await onUploadFiles(files);
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

  return (
    <div className={className}>
      <div className="rounded-xl border border-border bg-bg-elevated overflow-hidden" onDrop={onDrop} onDragOver={(e) => e.preventDefault()}>
        <div className="flex items-center gap-2 px-3 py-2 border-b border-border">
          <button
            type="button"
            onClick={() => setTab("write")}
            className={`text-sm px-3 py-1.5 rounded-lg border transition ${
              tab === "write" ? "bg-bg-card border-border text-text-primary" : "bg-transparent border-transparent text-text-muted hover:text-text-secondary"
            }`}
          >
            Write
          </button>
          <button
            type="button"
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

          {onUploadFiles ? (
            <div className="ml-auto flex items-center gap-2">
              <label className="text-xs text-sky-300 hover:text-sky-200 cursor-pointer">
                <input type="file" multiple className="hidden" onChange={(e) => uploadFiles(e.target.files)} disabled={uploading} />
                {uploading ? "Uploading…" : "Attach files"}
              </label>
            </div>
          ) : (
            <div className="ml-auto" />
          )}
        </div>

        {tab === "write" ? (
          <textarea
            ref={textareaRef}
            value={value}
            onChange={(e) => onChange(e.target.value)}
            onPaste={onPaste}
            rows={7}
            maxLength={maxLength}
            placeholder={placeholder || "Write…"}
            className="w-full bg-transparent px-3 py-3 text-sm text-text-secondary outline-none resize-y"
          />
        ) : (
          <div className="px-3 py-3 text-sm text-text-secondary">
            <div className="prose prose-invert max-w-none" dangerouslySetInnerHTML={{ __html: previewHtml || "<p>Nothing to preview.</p>" }} />
          </div>
        )}

        <div className="px-3 py-2 border-t border-border flex items-center justify-between">
          <div className="text-xs text-text-muted">
            {helperText || (onUploadFiles ? "Attach files by dragging & dropping, selecting or pasting them. (Max 25MB)" : "Markdown supported")}
          </div>
          <div className="text-xs text-text-muted">{maxLength - String(value || "").length}</div>
        </div>
      </div>
    </div>
  );
}

