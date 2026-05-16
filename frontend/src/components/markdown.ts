function escapeHtml(s: string) {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function safeUrl(raw: string) {
  const s = String(raw || "").trim();
  if (!s) return "";
  // allow relative URLs and http(s) only
  if (s.startsWith("/")) return s;
  if (/^https?:\/\//i.test(s)) return s;
  return "";
}

export function markdownToSafeHtml(md: string) {
  const src = String(md || "");

  // Extract fenced code blocks first
  const codeBlocks: string[] = [];
  let tmp = src.replace(/```([\s\S]*?)```/g, (_m, code) => {
    const i = codeBlocks.length;
    codeBlocks.push(String(code || ""));
    return `@@CODEBLOCK_${i}@@`;
  });

  // Escape everything (prevents HTML/XSS)
  tmp = escapeHtml(tmp);

  // Headings
  tmp = tmp.replace(/^######\s+(.*)$/gm, "<h6>$1</h6>");
  tmp = tmp.replace(/^#####\s+(.*)$/gm, "<h5>$1</h5>");
  tmp = tmp.replace(/^####\s+(.*)$/gm, "<h4>$1</h4>");
  tmp = tmp.replace(/^###\s+(.*)$/gm, "<h3>$1</h3>");
  tmp = tmp.replace(/^##\s+(.*)$/gm, "<h2>$1</h2>");
  tmp = tmp.replace(/^#\s+(.*)$/gm, "<h1>$1</h1>");

  // Inline code
  tmp = tmp.replace(/`([^`]+)`/g, "<code>$1</code>");

  // Bold / italic (simple)
  tmp = tmp.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  tmp = tmp.replace(/\*([^*]+)\*/g, "<em>$1</em>");

  // Images: ![alt](url)
  tmp = tmp.replace(/!\[([^\]]*)\]\(([^)]+)\)/g, (_m, alt, url) => {
    const u = safeUrl(url);
    if (!u) return "";
    return `<img src="${escapeHtml(u)}" alt="${escapeHtml(alt || "")}" />`;
  });

  // Links: [text](url)
  // NOTE: Must run AFTER image replacement; otherwise the link regex will consume image markdown.
  tmp = tmp.replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_m, text, url) => {
    const u = safeUrl(url);
    if (!u) return `${text}`;
    return `<a href="${escapeHtml(u)}" target="_blank" rel="noopener noreferrer">${text}</a>`;
  });

  // Very small list support (- item)
  tmp = tmp.replace(/^(?:-|\*)\s+(.*)$/gm, "<li>$1</li>");
  tmp = tmp.replace(/(<li>[\s\S]*?<\/li>\n?)+/g, (m) => `<ul>${m}</ul>`);

  // Restore code blocks
  tmp = tmp.replace(/@@CODEBLOCK_(\d+)@@/g, (_m, idx) => {
    const code = escapeHtml(codeBlocks[Number(idx)] || "");
    return `<pre><code>${code}</code></pre>`;
  });

  // Paragraphs / line breaks
  tmp = tmp
    .split(/\n{2,}/)
    .map((p) => {
      const t = p.trim();
      if (!t) return "";
      if (/^<(h\d|ul|pre)/.test(t)) return t;
      return `<p>${t.replace(/\n/g, "<br/>")}</p>`;
    })
    .join("\n");

  return tmp;
}

