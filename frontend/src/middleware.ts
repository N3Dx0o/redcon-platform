import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";

// Security/UX: Avoid serving a misleading server-rendered "Loading…" shell for protected routes.
// If no session cookie exists, redirect immediately to the login portal.
//
// Backend cookie name: SESSION_COOKIE = "redcon_session" (FastAPI).
const SESSION_COOKIE = "redcon_session";

export function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;

  // In some deployments, Next sees /client/*; in others it may see /app/client/*.
  const p = pathname.startsWith("/app/") ? pathname.slice(4) : pathname;

  const isProtected =
    p === "/client" ||
    p.startsWith("/client/") ||
    p === "/admin" ||
    p.startsWith("/admin/") ||
    p === "/ptaas" ||
    p.startsWith("/ptaas/");

  if (!isProtected) return NextResponse.next();

  // Allow portal and static assets without a session (defense-in-depth).
  if (
    p === "/portal" ||
    pathname.startsWith("/_next/") ||
    pathname.startsWith("/static/") ||
    pathname === "/favicon.ico"
  ) {
    return NextResponse.next();
  }

  const sid = req.cookies.get(SESSION_COOKIE)?.value;
  if (!sid) {
    return NextResponse.redirect("https://platform.redconoffence.com/app/portal");
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/app/:path*", "/client/:path*", "/admin/:path*", "/ptaas/:path*"],
};

