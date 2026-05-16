export function titleCaseLabel(input: any): string {
  const s = String(input ?? "").trim();
  if (!s) return "—";

  // Normalize common separators to spaces.
  const cleaned = s
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .toLowerCase();

  return cleaned
    .split(" ")
    .map((w) => (w ? w.slice(0, 1).toUpperCase() + w.slice(1) : ""))
    .join(" ");
}

