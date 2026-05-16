export type ApiResult<T> = { ok: true; data: T } | { ok: false; error: string; status: number };

export async function apiFetch<T>(
  path: string,
  init: RequestInit = {}
): Promise<ApiResult<T>> {
  // Avoid infinite "Loading…" states if the network hangs.
  // If the caller provides a signal, we respect it and don't override.
  const controller = init.signal ? null : new AbortController();
  const timeoutMs = 12000;
  const timeoutId: ReturnType<typeof setTimeout> | null = controller ? setTimeout(() => controller.abort(), timeoutMs) : null;
  try {
    const res = await fetch(path, {
      ...init,
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        ...(init.headers || {}),
      },
      cache: "no-store",
      signal: init.signal ?? controller?.signal,
    });

    const text = await res.text();
    const json = text ? (JSON.parse(text) as unknown) : null;

    if (!res.ok) {
      const msg =
        (json && typeof json === "object" && "error" in (json as any) && (json as any).error) ||
        `Request failed (${res.status})`;
      return { ok: false, error: String(msg), status: res.status };
    }

    return { ok: true, data: json as T };
  } catch (e: any) {
    const msg = e?.name === "AbortError" ? "Request timed out" : (e?.message || "Network error");
    return { ok: false, error: msg, status: 0 };
  } finally {
    try {
      if (timeoutId) clearTimeout(timeoutId);
    } catch {
      // ignore
    }
  }
}




