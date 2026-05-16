export function formatSubmittedAt(ts?: string | null) {
  if (!ts) return "—";
  let raw = String(ts).trim();
  // SQLite: "YYYY-MM-DD HH:MM:SS" -> ISO-ish
  if (raw.includes(" ") && !raw.includes("T")) raw = raw.replace(" ", "T");
  if (/^\d{4}-\d{2}-\d{2}$/.test(raw)) raw = `${raw}T00:00:00`;

  // IMPORTANT:
  // Many rows were written as ISO strings WITHOUT timezone (e.g. "2026-01-09T22:08:34").
  // Browsers interpret those as *local time*, which makes dates appear "wrong" for users in other timezones.
  // We treat timezone-less ISO timestamps as UTC for consistent display.
  const hasTz = /[zZ]|[+-]\d{2}:?\d{2}$/.test(raw);
  const canonical = hasTz ? raw : `${raw}Z`;
  let d = new Date(canonical);
  if (Number.isNaN(d.getTime())) return String(ts);

  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}




