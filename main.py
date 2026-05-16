from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import APIRouter, BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi import File, Form, UploadFile
from fastapi.responses import JSONResponse
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.responses import Response
from starlette.templating import Jinja2Templates
import ptaas_db

SCAN_COST_CREDITS = int(os.getenv("SCAN_COST_CREDITS", "1") or "1")


# ============================================================
# Core FastAPI app (we will migrate ALL APIs here)
# ============================================================

app = FastAPI(title="REDCON API (FastAPI)", version="1.1.0")

SESSION_COOKIE = "redcon_session"
SESSION_MAX_AGE_SECONDS = int(24 * 60 * 60)  # 24h

BASE_DIR = Path(__file__).resolve().parents[1]
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Serve static files if nginx isn't doing it (safe even if nginx also serves /static)
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


def _is_pentester_assigned(pentest_id: str, pentester_id: str) -> bool:
    conn = ptaas_db.get_db()
    c = conn.cursor()
    c.execute(
        "SELECT 1 FROM pentest_pentesters WHERE pentest_id = ? AND pentester_id = ? AND status IN ('accepted','assigned') LIMIT 1",
        (pentest_id, pentester_id),
    )
    ok = c.fetchone() is not None
    conn.close()
    return ok


def _find_pentest_by_attachment_filename(filename: str) -> Optional[dict]:
    """
    Resolve an attachment filename (stored in pentests.attachments[*].path) to its owning pentest.
    Returns: {"pentest_id":..., "client_id":..., "attachment":{...}} or None
    """
    conn = ptaas_db.get_db()
    c = conn.cursor()
    # Narrow search first
    c.execute("SELECT id, client_id, attachments FROM pentests WHERE attachments LIKE ? LIMIT 50", (f"%{filename}%",))
    rows = c.fetchall()
    conn.close()

    import json

    for r in rows:
        try:
            arr = json.loads(r["attachments"] or "[]")
        except Exception:
            arr = []
        if not isinstance(arr, list):
            continue
        for a in arr:
            if isinstance(a, dict) and str(a.get("path") or "") == filename:
                return {"pentest_id": r["id"], "client_id": r["client_id"], "attachment": a}
    return None


@app.get("/uploads/pentest_attachments/{filename:path}")
def protected_pentest_attachment(filename: str, request: Request):
    """
    Protected attachment access:
    - Requires session cookie
    - Admins: always allowed
    - Clients: only if pentest.client_id == user.id
    - Pentesters: only if assigned to pentest

    Nginx should serve the actual bytes via internal X-Accel-Redirect.
    """
    def _nf():
        # Prevent caching of deny responses (important for CDN behavior)
        return JSONResponse(
            {"error": "Not found"},
            status_code=404,
            headers={
                "Cache-Control": "private, no-store",
                "Pragma": "no-cache",
                "X-Content-Type-Options": "nosniff",
            },
        )

    # Hide existence from unauthenticated users (return 404 instead of 401)
    u = _get_user_from_session(request)
    if not u:
        return _nf()

    # Prevent traversal; we only allow basename-ish filenames
    filename = (filename or "").strip().replace("\\", "/")
    if "/" in filename or ".." in filename or filename.startswith(".") or len(filename) > 200:
        return _nf()

    resolved = _find_pentest_by_attachment_filename(filename)
    if not resolved:
        return _nf()

    # RBAC
    role = (u.get("role") or "").lower()
    if role == "admin":
        pass
    elif role == "client":
        if resolved["client_id"] != u["id"]:
            return _nf()
    elif role == "pentester":
        if not _is_pentester_assigned(resolved["pentest_id"], u["id"]):
            return _nf()
    else:
        return _nf()

    # Delegate to nginx internal location for efficient file serving
    att = resolved.get("attachment") or {}
    original_name = str(att.get("original_name") or att.get("name") or filename)
    internal_path = f"/_protected_uploads/pentest_attachments/{filename}"
    resp = Response(status_code=200)
    resp.headers["X-Accel-Redirect"] = internal_path
    # Private: do not allow caching at client/proxy/CDN
    resp.headers["Cache-Control"] = "private, no-store"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    # Let browser render images; still suggest filename for downloads
    resp.headers["Content-Disposition"] = f'inline; filename="{original_name.replace("\"","")}"'
    return resp


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    resp: Response = await call_next(request)
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    return resp


@app.get("/healthz")
async def healthz():
    return {"ok": True, "service": "redcon-fastapi", "mode": "migrating"}


@app.get("/api/healthz")
async def api_healthz():
    return {"ok": True, "service": "redcon-fastapi", "mode": "migrating"}


@app.get("/api/v2/healthz")
async def api_v2_healthz():
    return {"ok": True, "service": "redcon-fastapi", "mode": "migrating"}


# ============================================================
# Marketing site (redconoffence.com) - now served by FastAPI
# ============================================================

@app.get("/", response_class=HTMLResponse)
def marketing_landing(request: Request):
    return templates.TemplateResponse("landing.html", {"request": request})


@app.get("/team", response_class=HTMLResponse)
@app.get("/team/", response_class=HTMLResponse)
def marketing_team(request: Request):
    return templates.TemplateResponse("team.html", {"request": request})


@app.get("/docs", response_class=HTMLResponse)
@app.get("/docs/", response_class=HTMLResponse)
@app.get("/docs/{subpath:path}", response_class=HTMLResponse)
def marketing_docs(request: Request, subpath: str = ""):
    # docs are handled by docs.redconoffence.com in production, but keep this for safety/back-compat
    return templates.TemplateResponse("docs.html", {"request": request, "subpath": subpath})


@app.get("/privacy", response_class=HTMLResponse)
def marketing_privacy(request: Request):
    return templates.TemplateResponse("privacy.html", {"request": request})


@app.get("/terms", response_class=HTMLResponse)
def marketing_terms(request: Request):
    return templates.TemplateResponse("terms.html", {"request": request})


@app.get("/osaas")
def marketing_osaas():
    # Landing page links to /osaas; keep it working and jump to the OSaaS section.
    return RedirectResponse(url="/#osaas", status_code=302)


# ============================================================
# Marketing forms (contact + OSaaS request)
# ============================================================

def _ensure_marketing_tables() -> None:
    conn = ptaas_db.get_db()
    c = conn.cursor()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS contact_requests (
            id TEXT PRIMARY KEY,
            name TEXT,
            email TEXT,
            company TEXT,
            interest TEXT,
            message TEXT,
            created_at TEXT
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS osaas_requests (
            id TEXT PRIMARY KEY,
            company_name TEXT,
            contact_name TEXT,
            email TEXT,
            phone TEXT,
            service_type TEXT,
            scope_description TEXT,
            target_urls TEXT,
            timeline TEXT,
            budget TEXT,
            status TEXT DEFAULT 'pending',
            created_at TEXT,
            notes TEXT
        )
        """
    )
    conn.commit()
    conn.close()


@app.post("/api/contact")
def api_contact(request: Request, body: dict):
    # Used by landing.html demo form. We store it in the main DB for now.
    _ensure_marketing_tables()
    name = str(body.get("name") or "").strip()
    email = str(body.get("email") or "").strip()
    company = str(body.get("company") or "").strip()
    interest = str(body.get("interest") or "").strip()
    message = str(body.get("message") or body.get("scope") or "").strip()
    if not name or not email:
        raise HTTPException(status_code=400, detail="Name and email are required")

    conn = ptaas_db.get_db()
    c = conn.cursor()
    rid = str(uuid.uuid4())[:12]
    c.execute(
        "INSERT INTO contact_requests (id, name, email, company, interest, message, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (rid, name, email, company, interest, message, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()
    return {"success": True, "id": rid}


@app.post("/api/osaas/request")
def api_osaas_request(body: dict):
    # Back-compat with old Flask marketing API.
    _ensure_marketing_tables()
    rid = str(uuid.uuid4())[:12]
    conn = ptaas_db.get_db()
    c = conn.cursor()
    c.execute(
        """
        INSERT INTO osaas_requests
        (id, company_name, contact_name, email, phone, service_type, scope_description,
         target_urls, timeline, budget, status, created_at, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
        """,
        (
            rid,
            str(body.get("company_name") or ""),
            str(body.get("contact_name") or ""),
            str(body.get("email") or ""),
            str(body.get("phone") or ""),
            str(body.get("service_type") or ""),
            str(body.get("scope_description") or ""),
            str(body.get("target_urls") or ""),
            str(body.get("timeline") or ""),
            str(body.get("budget") or ""),
            datetime.utcnow().isoformat(),
            str(body.get("notes") or ""),
        ),
    )
    conn.commit()
    conn.close()
    return {"success": True, "request_id": rid}


@app.get("/api/osaas/requests")
def api_osaas_requests(request: Request):
    require_role(request, "admin")
    _ensure_marketing_tables()
    conn = ptaas_db.get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM osaas_requests ORDER BY created_at DESC LIMIT 200")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return {"success": True, "requests": rows}


# ============================================================
# Session helpers (SQLite-backed, cookie-based)
# ============================================================

def _now() -> str:
    return datetime.utcnow().isoformat()


def _get_client_ip(request: Request) -> str:
    # Prefer X-Forwarded-For (nginx sets it)
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else ""


def _create_session(user_id: str, request: Request) -> str:
    """
    Create a PTaaS session row and return the session_id (stored in cookie).
    We reuse ptaas_sessions.id as the session token.
    """
    session_id = str(uuid.uuid4())
    conn = ptaas_db.get_db()
    c = conn.cursor()
    now = _now()

    # mark others not current
    try:
        c.execute("UPDATE ptaas_sessions SET is_current = 0 WHERE user_id = ?", (user_id,))
    except Exception:
        pass

    c.execute(
        """
        INSERT INTO ptaas_sessions (id, user_id, ip_address, user_agent, device, location, created_at, last_active, is_current)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
        """,
        (
            session_id,
            user_id,
            _get_client_ip(request),
            request.headers.get("user-agent", ""),
            "",
            "",
            now,
            now,
        ),
    )
    conn.commit()
    conn.close()
    return session_id


def _delete_session(session_id: str) -> None:
    try:
        conn = ptaas_db.get_db()
        c = conn.cursor()
        c.execute("DELETE FROM ptaas_sessions WHERE id = ?", (session_id,))
        conn.commit()
        conn.close()
    except Exception:
        pass


def _get_user_from_session(request: Request) -> Optional[Dict[str, Any]]:
    sid = request.cookies.get(SESSION_COOKIE, "")
    if not sid:
        return None

    conn = ptaas_db.get_db()
    c = conn.cursor()
    c.execute("SELECT user_id, last_active FROM ptaas_sessions WHERE id = ?", (sid,))
    row = c.fetchone()
    if not row:
        conn.close()
        return None

    # expire by idle time
    try:
        last_active = datetime.fromisoformat(row["last_active"])
        if datetime.utcnow() - last_active > timedelta(seconds=SESSION_MAX_AGE_SECONDS):
            conn.close()
            _delete_session(sid)
            return None
    except Exception:
        pass

    # update last_active
    try:
        c.execute("UPDATE ptaas_sessions SET last_active = ? WHERE id = ?", (_now(), sid))
        conn.commit()
    except Exception:
        pass
    conn.close()

    u = ptaas_db.get_user_by_id(row["user_id"])
    if not u:
        _delete_session(sid)
        return None
    if int(u.get("is_active", 1) or 1) != 1:
        _delete_session(sid)
        return None
    return u


def require_user(request: Request) -> Dict[str, Any]:
    u = _get_user_from_session(request)
    if not u:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return u


def require_role(request: Request, role: str) -> Dict[str, Any]:
    u = require_user(request)
    if u.get("role") != role:
        raise HTTPException(status_code=403, detail="Forbidden")
    return u


# ============================================================
# Notification helpers (security + dedupe)
# ============================================================

def _get_admin_user_ids() -> list[str]:
    conn = ptaas_db.get_db()
    c = conn.cursor()
    c.execute("SELECT id FROM ptaas_users WHERE role = 'admin' AND COALESCE(is_active,1)=1")
    ids = [r["id"] for r in c.fetchall()]
    conn.close()
    return ids


def _get_accepted_pentester_ids_for_pentest(pentest_id: str) -> list[str]:
    conn = ptaas_db.get_db()
    c = conn.cursor()
    c.execute("SELECT pentester_id FROM pentest_pentesters WHERE pentest_id = ? AND status = 'accepted'", (pentest_id,))
    ids = [r["pentester_id"] for r in c.fetchall()]
    conn.close()
    return ids


def _notify_once(user_id: str, type: str, title: str, message: str, link: str, window_seconds: int = 60) -> None:
    """
    Basic dedupe: if an identical type+link notification was created recently, skip.
    """
    try:
        conn = ptaas_db.get_db()
        c = conn.cursor()
        c.execute(
            """
            SELECT created_at FROM notifications
            WHERE user_id = ? AND type = ? AND link = ?
            ORDER BY created_at DESC LIMIT 1
            """,
            (user_id, type, link),
        )
        row = c.fetchone()
        conn.close()
        if row and row.get("created_at"):
            try:
                last = datetime.fromisoformat(str(row["created_at"]).replace("Z", "+00:00"))
                if datetime.utcnow() - last < timedelta(seconds=int(window_seconds)):
                    return
            except Exception:
                pass
    except Exception:
        # don't block the request if notif dedupe check fails
        pass
    try:
        ptaas_db.create_notification(user_id, type, title, message, link)
    except Exception:
        pass

# ============================================================
# API routers (we expose endpoints under both /api and /api/v2 during migration)
# ============================================================

api = APIRouter()


class LoginBody(BaseModel):
    email: str
    password: str
    next: Optional[str] = None


class ClientFindingRespondBody(BaseModel):
    status: str
    comment: Optional[str] = ""


class ClientAssetBody(BaseModel):
    name: str
    type: str
    description: Optional[str] = ""
    url: Optional[str] = ""
    environment: Optional[str] = "production"
    technology_stack: Optional[str] = ""
    authentication_info: Optional[str] = ""
    status: Optional[str] = "active"
    risk_level: Optional[str] = "medium"


class ClientRequestPentestBody(BaseModel):
    asset_id: Optional[str] = ""
    title: Optional[str] = ""
    type: Optional[str] = "Web Application"
    priority: Optional[str] = "normal"
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    scope: Optional[str] = ""
    targets: Optional[str] = ""
    objectives: Optional[str] = ""
    tech_stack: Optional[str] = ""
    collaboration: Optional[str] = "weekly"
    environment: Optional[str] = "production"
    sensitive_data: Optional[list[str]] = []
    credential_type: Optional[str] = "none"
    credentials_notes: Optional[str] = ""
    notes: Optional[str] = ""
    compliance: Optional[list[str]] = []
    attachments: Optional[list[dict]] = []

class AdminCreateUserBody(BaseModel):
    name: str
    email: str
    password: str
    role: str
    company: Optional[str] = ""


class AdminAssignPentesterBody(BaseModel):
    pentester_id: str
    role: Optional[str] = "tester"


class CoverageUpdateBody(BaseModel):
    status: str
    notes: Optional[str] = None


class PentesterFindingUpdateBody(BaseModel):
    title: Optional[str] = None
    severity: Optional[str] = None
    category: Optional[str] = None
    affected_url: Optional[str] = None
    description: Optional[str] = None
    steps_to_reproduce: Optional[str] = None
    poc: Optional[str] = None
    impact: Optional[str] = None
    remediation: Optional[str] = None


class ScanRunBody(BaseModel):
    asset_id: str


class ScanScheduleBody(BaseModel):
    asset_id: str
    cadence: str = "weekly"  # daily, weekly, monthly
    enabled: bool = True


class IntegrationUpsertBody(BaseModel):
    type: str
    enabled: bool = True
    config: dict = {}


@api.post("/auth/login")
def api_auth_login(request: Request, body: LoginBody):
    email = (body.email or "").lower().strip()
    password = body.password or ""
    if not email or not password:
        return JSONResponse({"error": "Email and password are required"}, status_code=400)

    user = ptaas_db.authenticate_user(email, password)
    if not user:
        return JSONResponse({"error": "Invalid email or password"}, status_code=401)

    # Create session cookie
    sid = _create_session(user["id"], request)

    # Redirects must match frontend routes
    default_redirect = (
        "/app/client/dashboard"
        if user["role"] == "client"
        else "/app/admin/dashboard"
        if user["role"] == "admin"
        else "/app/ptaas/pentests"
    )
    redirect_to = (body.next or "").strip() or default_redirect

    resp = JSONResponse(
        {
            "success": True,
            "redirect": redirect_to,
            "user": {
                "id": user["id"],
                "name": user.get("name"),
                "email": email,
                "role": user.get("role"),
                "company": user.get("company"),
            },
        }
    )
    resp.set_cookie(
        SESSION_COOKIE,
        sid,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=SESSION_MAX_AGE_SECONDS,
        path="/",
    )
    return resp


@api.post("/auth/logout")
def api_auth_logout(request: Request):
    sid = request.cookies.get(SESSION_COOKIE, "")
    if sid:
        _delete_session(sid)
    resp = JSONResponse({"success": True, "redirect": "/app/portal", "message": "Logged out successfully"})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


@api.get("/auth/me")
def api_auth_me(request: Request):
    try:
        u = require_user(request)
    except HTTPException:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    return {
        "id": u.get("id"),
        "email": u.get("email"),
        "name": u.get("name"),
        "company": u.get("company"),
        "role": u.get("role"),
        "is_active": u.get("is_active", 1),
        "ptaas": True,
    }


@api.get("/notifications")
def api_notifications(request: Request, unread_only: int = 0, unread: Optional[str] = None):
    u = require_user(request)
    # frontend uses unread_only=0; flask used unread=true|false
    want_unread = bool(unread_only) or (str(unread or "").lower() == "true")
    notifications = ptaas_db.get_notifications(u["id"], want_unread)

    formatted = []
    for n in notifications:
        created_at = n.get("created_at")
        if created_at:
            try:
                created = datetime.fromisoformat(created_at)
                diff = datetime.utcnow() - created
                if diff.days > 0:
                    time_ago = f"{diff.days}d ago"
                elif diff.seconds > 3600:
                    time_ago = f"{diff.seconds // 3600}h ago"
                else:
                    time_ago = f"{max(1, diff.seconds // 60)}m ago"
            except Exception:
                time_ago = "Now"
        else:
            time_ago = "Now"

        formatted.append(
            {
                "id": n.get("id"),
                "type": n.get("type"),
                "title": n.get("title"),
                "message": n.get("message"),
                "link": n.get("link"),
                "isRead": int(n.get("is_read") or 0) == 1,
                "time": time_ago,
                "created_at": created_at,
            }
        )

    unread_count = len([n for n in notifications if int(n.get("is_read") or 0) == 0])
    return {"success": True, "notifications": formatted, "count": unread_count}


@api.post("/notifications/read-all")
def api_notifications_read_all(request: Request):
    u = require_user(request)
    ptaas_db.mark_all_notifications_read(u["id"])
    return {"success": True}


@api.post("/notifications/{notification_id}/read")
def api_notifications_read_one(notification_id: str, request: Request):
    require_user(request)
    ptaas_db.mark_notification_read(notification_id)
    return {"success": True}


@api.get("/asset-types")
def api_asset_types():
    return {"success": True, "types": ptaas_db.get_asset_types()}


# ============================================================
# Client API
# ============================================================

def _ensure_client_ops_tables() -> None:
    """
    Client Ops "Cobalt-style" features:
    - Scans (per-asset scan runs)
    - Scheduled scans (cadence)
    - Integrations (Jira/GitHub/Webhooks/etc)
    """
    conn = ptaas_db.get_db()
    c = conn.cursor()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS asset_scans (
            id TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            asset_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'queued',
            created_at TEXT NOT NULL,
            started_at TEXT,
            finished_at TEXT,
            findings_summary TEXT,
            report_json TEXT,
            error TEXT
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS scheduled_scans (
            id TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            asset_id TEXT NOT NULL,
            cadence TEXT NOT NULL DEFAULT 'weekly',
            next_run_at TEXT,
            enabled INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS integrations (
            id TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            type TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            config TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(client_id, type)
        )
        """
    )
    conn.commit()
    conn.close()


def _basic_http_scan(url: str) -> Dict[str, Any]:
    """
    Lightweight MVP scanner:
    - Fetch response headers (HEAD -> GET fallback)
    - Produce simple findings for missing security headers and disclosures
    """
    import urllib.request

    if not url:
        return {"findings": [], "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}}
    if not (url.startswith("http://") or url.startswith("https://")):
        url = "https://" + url

    def _fetch(method: str):
        req = urllib.request.Request(url, method=method, headers={"User-Agent": "REDCON-Scanner/1.0"})
        with urllib.request.urlopen(req, timeout=12) as r:
            headers = {k.lower(): v for k, v in r.headers.items()}
            status = getattr(r, "status", 200)
            return status, headers

    status = 0
    headers: dict[str, str] = {}
    try:
        status, headers = _fetch("HEAD")
    except Exception:
        try:
            status, headers = _fetch("GET")
        except Exception as e:
            return {"error": str(e), "findings": [], "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}}

    findings: list[dict] = []

    def add(sev: str, title: str, desc: str):
        findings.append({"severity": sev, "title": title, "description": desc})

    if "strict-transport-security" not in headers:
        add("medium", "Missing HSTS", "Response missing Strict-Transport-Security header.")
    if "content-security-policy" not in headers:
        add("medium", "Missing CSP", "Response missing Content-Security-Policy header.")
    if "x-frame-options" not in headers:
        add("low", "Missing X-Frame-Options", "Response missing X-Frame-Options header.")
    if "x-content-type-options" not in headers:
        add("low", "Missing X-Content-Type-Options", "Response missing X-Content-Type-Options header.")
    if "referrer-policy" not in headers:
        add("info", "Missing Referrer-Policy", "Response missing Referrer-Policy header.")
    if "server" in headers and headers["server"]:
        add("info", "Server header present", f"Server header discloses: {headers['server']}")
    if status >= 500:
        add("low", "Server error detected", f"Target returned HTTP {status} during scan.")

    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": len(findings)}
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        if sev not in summary:
            sev = "info"
        summary[sev] += 1

    return {"url": url, "status": status, "headers": headers, "findings": findings, "summary": summary}


def _scan_worker(scan_id: str, client_id: str, asset_id: str, url: str) -> None:
    _ensure_client_ops_tables()
    conn = ptaas_db.get_db()
    c = conn.cursor()
    c.execute("UPDATE asset_scans SET status = 'running', started_at = ? WHERE id = ?", (datetime.utcnow().isoformat(), scan_id))
    conn.commit()

    result = _basic_http_scan(url)
    finished = datetime.utcnow().isoformat()
    if result.get("error"):
        c.execute(
            "UPDATE asset_scans SET status = 'failed', finished_at = ?, error = ?, report_json = ? WHERE id = ?",
            (finished, result.get("error"), json.dumps(result), scan_id),
        )
    else:
        summary = result.get("summary") or {}
        c.execute(
            "UPDATE asset_scans SET status = 'completed', finished_at = ?, findings_summary = ?, report_json = ? WHERE id = ?",
            (finished, json.dumps(summary), json.dumps(result), scan_id),
        )
    conn.commit()
    conn.close()


@api.get("/client/stats")
def api_client_stats(request: Request):
    u = require_role(request, "client")
    stats = ptaas_db.get_client_stats(u["id"])
    user_info = {
        "id": u.get("id"),
        "name": u.get("name", "Client"),
        "email": u.get("email"),
        "company": u.get("company", "Company"),
        "role": u.get("role"),
    }
    return {"success": True, "user": user_info, "stats": stats, **(stats or {})}


@api.get("/client/credits")
def api_client_credits(request: Request):
    u = require_role(request, "client")
    conn = ptaas_db.get_db()
    c = conn.cursor()
    c.execute("SELECT credits, subscription_tier FROM ptaas_users WHERE id = ? LIMIT 1", (u["id"],))
    row = c.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "success": True,
        "credits": int(row["credits"] or 0),
        "tier": row["subscription_tier"] or "free",
        "scan_cost": SCAN_COST_CREDITS,
    }


@api.get("/client/activity")
def api_client_activity(request: Request, limit: int = 50):
    u = require_role(request, "client")
    items = ptaas_db.get_activity_for_user(u["id"], limit=int(limit))
    return {"success": True, "activity": items}


@api.get("/client/insights")
def api_client_insights(request: Request):
    u = require_role(request, "client")
    conn = ptaas_db.get_db()
    c = conn.cursor()

    # Core KPIs
    c.execute("SELECT COUNT(*) as n FROM pentests WHERE client_id = ? AND status NOT IN ('draft','pending','cancelled')", (u["id"],))
    pentests_performed = int((c.fetchone() or [0])[0] or 0)

    c.execute(
        """
        SELECT COUNT(*) 
        FROM ptaas_findings f
        JOIN pentests p ON p.id = f.pentest_id
        WHERE p.client_id = ?
        """,
        (u["id"],),
    )
    findings_reported = int((c.fetchone() or [0])[0] or 0)

    c.execute(
        """
        SELECT COUNT(*)
        FROM ptaas_findings f
        JOIN pentests p ON p.id = f.pentest_id
        WHERE p.client_id = ?
          AND lower(COALESCE(f.status,'')) NOT IN ('fixed','verified','resolved')
        """,
        (u["id"],),
    )
    findings_open = int((c.fetchone() or [0])[0] or 0)

    c.execute(
        """
        SELECT COUNT(*)
        FROM ptaas_findings f
        JOIN pentests p ON p.id = f.pentest_id
        WHERE p.client_id = ?
          AND lower(COALESCE(f.status,'')) IN ('fixed','verified','resolved')
        """,
        (u["id"],),
    )
    findings_resolved = int((c.fetchone() or [0])[0] or 0)

    # Findings by severity (pentest findings)
    c.execute(
        """
        SELECT lower(COALESCE(severity,'info')) as sev, COUNT(*) as n
        FROM ptaas_findings f
        JOIN pentests p ON p.id = f.pentest_id
        WHERE p.client_id = ?
        GROUP BY lower(COALESCE(severity,'info'))
        """,
        (u["id"],),
    )
    pentest_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for r in c.fetchall():
        s = (r["sev"] or "info").lower()
        if s not in pentest_sev:
            s = "info"
        pentest_sev[s] = int(r["n"] or 0)

    # Findings per day (last 30 days)
    # SQLite: created_at is ISO string -> substr(,1,10) yields YYYY-MM-DD
    c.execute(
        """
        SELECT substr(f.created_at, 1, 10) as d, COUNT(*) as n
        FROM ptaas_findings f
        JOIN pentests p ON p.id = f.pentest_id
        WHERE p.client_id = ?
          AND f.created_at >= datetime('now', '-30 days')
        GROUP BY substr(f.created_at, 1, 10)
        ORDER BY d ASC
        """,
        (u["id"],),
    )
    findings_by_day = [{"date": row["d"], "count": int(row["n"] or 0)} for row in c.fetchall()]

    _ensure_client_ops_tables()
    c.execute("SELECT report_json FROM asset_scans WHERE client_id = ? AND status='completed' ORDER BY created_at DESC LIMIT 200", (u["id"],))
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for r in c.fetchall():
        try:
            rep = json.loads(r["report_json"] or "{}")
            for f in (rep.get("findings") or []):
                s = (f.get("severity") or "info").lower()
                if s not in sev:
                    s = "info"
                sev[s] += 1
        except Exception:
            continue

    # Scan runs per day (last 30 days)
    c.execute(
        """
        SELECT substr(created_at, 1, 10) as d, COUNT(*) as n
        FROM asset_scans
        WHERE client_id = ?
          AND created_at >= datetime('now', '-30 days')
        GROUP BY substr(created_at, 1, 10)
        ORDER BY d ASC
        """,
        (u["id"],),
    )
    scans_by_day = [{"date": row["d"], "count": int(row["n"] or 0)} for row in c.fetchall()]
    conn.close()

    return {
        "success": True,
        "kpis": {
            "pentests_performed": pentests_performed,
            "findings_reported": findings_reported,
            "findings_open": findings_open,
            "findings_resolved": findings_resolved,
        },
        "pentest_findings_by_severity": pentest_sev,
        "findings_by_day": findings_by_day,
        "scan_findings_by_severity": sev,
        "scans_by_day": scans_by_day,
    }


@api.get("/client/scans/targets")
def api_client_scan_targets(request: Request):
    u = require_role(request, "client")
    _ensure_client_ops_tables()
    conn = ptaas_db.get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM assets WHERE client_id = ? ORDER BY created_at DESC", (u["id"],))
    assets = [dict(r) for r in c.fetchall()]

    for a in assets:
        c.execute(
            "SELECT id, status, created_at, finished_at, findings_summary FROM asset_scans WHERE asset_id = ? AND client_id = ? ORDER BY created_at DESC LIMIT 1",
            (a["id"], u["id"]),
        )
        s = c.fetchone()
        if s:
            try:
                summary = json.loads(s["findings_summary"] or "{}") if s["findings_summary"] else {}
            except Exception:
                summary = {}
            a["last_scan"] = {
                "id": s["id"],
                "status": s["status"],
                "created_at": s["created_at"],
                "finished_at": s["finished_at"],
                "summary": summary,
            }
        else:
            a["last_scan"] = None

    conn.close()
    return {"success": True, "targets": assets}


@api.get("/client/scans")
def api_client_scan_history(request: Request, asset_id: Optional[str] = None):
    u = require_role(request, "client")
    _ensure_client_ops_tables()
    conn = ptaas_db.get_db()
    c = conn.cursor()
    if asset_id:
        c.execute(
            "SELECT * FROM asset_scans WHERE client_id = ? AND asset_id = ? ORDER BY created_at DESC LIMIT 200",
            (u["id"], asset_id),
        )
    else:
        c.execute("SELECT * FROM asset_scans WHERE client_id = ? ORDER BY created_at DESC LIMIT 200", (u["id"],))
    scans = [dict(r) for r in c.fetchall()]
    conn.close()
    for s in scans:
        try:
            s["findings_summary"] = json.loads(s.get("findings_summary") or "{}")
        except Exception:
            s["findings_summary"] = {}
    return {"success": True, "scans": scans}


@api.post("/client/scans/run")
def api_client_run_scan(request: Request, body: ScanRunBody, background: BackgroundTasks):
    u = require_role(request, "client")
    _ensure_client_ops_tables()
    asset_id = (body.asset_id or "").strip()
    if not asset_id:
        raise HTTPException(status_code=400, detail="asset_id is required")

    conn = ptaas_db.get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM assets WHERE id = ? AND client_id = ? LIMIT 1", (asset_id, u["id"]))
    asset = c.fetchone()
    if not asset:
        conn.close()
        raise HTTPException(status_code=404, detail="Target not found")

    c.execute("SELECT credits FROM ptaas_users WHERE id = ?", (u["id"],))
    row = c.fetchone()
    credits = int((row["credits"] if row else 0) or 0)
    if credits < SCAN_COST_CREDITS:
        conn.close()
        raise HTTPException(status_code=402, detail="Insufficient credits")

    scan_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    c.execute("INSERT INTO asset_scans (id, client_id, asset_id, status, created_at) VALUES (?, ?, ?, 'queued', ?)", (scan_id, u["id"], asset_id, now))
    c.execute("UPDATE ptaas_users SET credits = credits - ? WHERE id = ?", (SCAN_COST_CREDITS, u["id"]))
    conn.commit()
    conn.close()

    background.add_task(_scan_worker, scan_id, u["id"], asset_id, (dict(asset).get("url") or ""))
    return {"success": True, "scan_id": scan_id}


@api.get("/client/scans/{scan_id}")
def api_client_get_scan(scan_id: str, request: Request):
    u = require_role(request, "client")
    _ensure_client_ops_tables()
    conn = ptaas_db.get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM asset_scans WHERE id = ? AND client_id = ? LIMIT 1", (scan_id, u["id"]))
    row = c.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    s = dict(row)
    try:
        s["findings_summary"] = json.loads(s.get("findings_summary") or "{}")
    except Exception:
        s["findings_summary"] = {}
    try:
        s["report"] = json.loads(s.get("report_json") or "{}")
    except Exception:
        s["report"] = {}
    return {"success": True, "scan": s}


@api.get("/client/scans/{scan_id}/download")
def api_client_download_scan(scan_id: str, request: Request):
    u = require_role(request, "client")
    _ensure_client_ops_tables()
    conn = ptaas_db.get_db()
    c = conn.cursor()
    c.execute("SELECT report_json FROM asset_scans WHERE id = ? AND client_id = ? LIMIT 1", (scan_id, u["id"]))
    row = c.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    payload = row["report_json"] or "{}"
    return Response(content=payload, media_type="application/json", headers={"Content-Disposition": f'attachment; filename=\"scan-{scan_id}.json\"'})


@api.get("/client/scheduled-scans")
def api_client_scheduled_scans(request: Request):
    u = require_role(request, "client")
    _ensure_client_ops_tables()
    conn = ptaas_db.get_db()
    c = conn.cursor()
    c.execute(
        """
        SELECT ss.*, a.name as asset_name, a.url as asset_url
        FROM scheduled_scans ss
        LEFT JOIN assets a ON ss.asset_id = a.id
        WHERE ss.client_id = ?
        ORDER BY ss.created_at DESC
        """,
        (u["id"],),
    )
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return {"success": True, "scheduled": rows}


@api.post("/client/scheduled-scans")
def api_client_create_scheduled_scan(request: Request, body: ScanScheduleBody):
    u = require_role(request, "client")
    _ensure_client_ops_tables()
    cadence = (body.cadence or "weekly").lower()
    if cadence not in ("daily", "weekly", "monthly"):
        raise HTTPException(status_code=400, detail="Invalid cadence")
    sid = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    conn = ptaas_db.get_db()
    c = conn.cursor()
    c.execute(
        "INSERT INTO scheduled_scans (id, client_id, asset_id, cadence, next_run_at, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (sid, u["id"], body.asset_id, cadence, None, 1 if body.enabled else 0, now, now),
    )
    conn.commit()
    conn.close()
    return {"success": True, "id": sid}


@api.delete("/client/scheduled-scans/{schedule_id}")
def api_client_delete_scheduled_scan(schedule_id: str, request: Request):
    u = require_role(request, "client")
    _ensure_client_ops_tables()
    conn = ptaas_db.get_db()
    c = conn.cursor()
    c.execute("DELETE FROM scheduled_scans WHERE id = ? AND client_id = ?", (schedule_id, u["id"]))
    conn.commit()
    conn.close()
    return {"success": True}


@api.get("/client/integrations")
def api_client_integrations(request: Request):
    u = require_role(request, "client")
    _ensure_client_ops_tables()
    conn = ptaas_db.get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM integrations WHERE client_id = ? ORDER BY created_at DESC", (u["id"],))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    for r in rows:
        try:
            r["config"] = json.loads(r.get("config") or "{}")
        except Exception:
            r["config"] = {}
    return {"success": True, "integrations": rows}


@api.post("/client/integrations")
def api_client_upsert_integration(request: Request, body: IntegrationUpsertBody):
    u = require_role(request, "client")
    _ensure_client_ops_tables()
    typ = (body.type or "").strip().lower()
    if not typ:
        raise HTTPException(status_code=400, detail="type is required")
    now = datetime.utcnow().isoformat()
    conn = ptaas_db.get_db()
    c = conn.cursor()
    c.execute("SELECT id FROM integrations WHERE client_id = ? AND type = ? LIMIT 1", (u["id"], typ))
    row = c.fetchone()
    if row:
        c.execute(
            "UPDATE integrations SET enabled = ?, config = ?, updated_at = ? WHERE id = ?",
            (1 if body.enabled else 0, json.dumps(body.config or {}), now, row["id"]),
        )
        iid = row["id"]
    else:
        iid = str(uuid.uuid4())
        c.execute(
            "INSERT INTO integrations (id, client_id, type, enabled, config, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (iid, u["id"], typ, 1 if body.enabled else 0, json.dumps(body.config or {}), now, now),
        )
    conn.commit()
    conn.close()
    return {"success": True, "id": iid}


@api.get("/client/pentests")
def api_client_pentests(request: Request, status: str = "all"):
    u = require_role(request, "client")
    status_filter = None if status == "all" else status
    pentests = ptaas_db.get_pentests_for_client(u["id"], status_filter)
    formatted = []
    for p in pentests:
        formatted.append(
            {
                "id": p["id"],
                "title": p["title"],
                "pentest_number": p.get("pentest_number"),
                "type": p.get("type"),
                "status": str(p.get("status", "")).title(),
                "progress": p.get("progress") or 0,
                "total_findings": p.get("total_findings") or 0,
                "critical_count": p.get("critical_count") or 0,
                "high_count": p.get("high_count") or 0,
                "medium_count": p.get("medium_count") or 0,
                "low_count": p.get("low_count") or 0,
                "start_date": p.get("start_date"),
                "end_date": p.get("end_date"),
            }
        )
    return {"success": True, "pentests": formatted}


@api.get("/client/findings")
def api_client_findings(request: Request, limit: int = 50, pentest_id: Optional[str] = None):
    u = require_role(request, "client")
    all_findings: list[dict] = []

    if pentest_id:
        pentest = ptaas_db.get_pentest_by_id(pentest_id)
        if pentest and pentest.get("client_id") == u["id"]:
            findings = ptaas_db.get_findings_for_pentest(pentest_id)
            for f in findings:
                f["pentest_title"] = pentest.get("title")
                all_findings.append(f)
    else:
        for p in ptaas_db.get_pentests_for_client(u["id"]):
            for f in ptaas_db.get_findings_for_pentest(p["id"]):
                f["pentest_title"] = p.get("title")
                all_findings.append(f)

    all_findings.sort(key=lambda x: x.get("created_at") or "", reverse=True)
    all_findings = all_findings[: max(1, int(limit))]

    formatted = [
        {
            "id": f.get("id"),
            "title": f.get("title"),
            "description": f.get("description"),
            "severity": f.get("severity"),
            "status": f.get("status"),
            "category": f.get("category"),
            "affected_url": f.get("affected_url", ""),
            "pentest_title": f.get("pentest_title", ""),
            "created_at": f.get("created_at"),
        }
        for f in all_findings
    ]
    return {"success": True, "findings": formatted}


@api.get("/client/pentest/{pentest_id}")
def api_client_pentest_detail(pentest_id: str, request: Request):
    u = require_role(request, "client")
    pentest = ptaas_db.get_pentest_by_id(pentest_id)
    if not pentest:
        raise HTTPException(status_code=404, detail="Pentest not found")
    if pentest.get("client_id") != u["id"]:
        raise HTTPException(status_code=403, detail="Access denied")

    conn = ptaas_db.get_db()
    c = conn.cursor()
    c.execute(
        """
        SELECT u.name, u.email, pp.role, pp.status
        FROM pentest_pentesters pp
        JOIN ptaas_users u ON pp.pentester_id = u.id
        WHERE pp.pentest_id = ? AND pp.status = 'accepted'
        """,
        (pentest_id,),
    )
    pentesters = [dict(row) for row in c.fetchall()]
    conn.close()

    return {"success": True, "pentest": pentest, "assigned_pentesters": pentesters}


@api.get("/client/pentest/{pentest_id}/findings")
def api_client_pentest_findings(pentest_id: str, request: Request):
    u = require_role(request, "client")
    pentest = ptaas_db.get_pentest_by_id(pentest_id)
    if not pentest:
        raise HTTPException(status_code=404, detail="Pentest not found")
    if pentest.get("client_id") != u["id"]:
        raise HTTPException(status_code=403, detail="Access denied")

    findings = ptaas_db.get_findings_for_pentest(pentest_id)
    formatted = []
    for f in findings:
        formatted.append(
            {
                "id": f.get("id"),
                "title": f.get("title"),
                "severity": f.get("severity"),
                "status": f.get("status"),
                "description": f.get("description", ""),
                "category": f.get("category", ""),
                "affected_url": f.get("affected_url", ""),
                "cvss_score": f.get("cvss_score"),
                "cwe_id": f.get("cwe_id"),
                "cve_id": f.get("cve_id"),
                "created_at": f.get("created_at", ""),
                "pentester_name": f.get("pentester_name", ""),
            }
        )
    return {"success": True, "findings": formatted}


@api.get("/client/assets")
def api_client_assets(request: Request):
    u = require_role(request, "client")
    assets = ptaas_db.get_assets_for_client(u["id"])
    return {"success": True, "assets": assets}


@api.post("/client/assets")
def api_client_create_asset(request: Request, body: ClientAssetBody):
    u = require_role(request, "client")
    asset_id = ptaas_db.create_asset(
        client_id=u["id"],
        name=body.name,
        asset_type=body.type,
        description=body.description or "",
        url=body.url or "",
        environment=body.environment or "production",
        technology_stack=body.technology_stack or "",
        authentication_info=body.authentication_info or "",
        status=body.status or "active",
        risk_level=body.risk_level or "medium",
    )
    return {"success": True, "asset": ptaas_db.get_asset_by_id(asset_id)}


@api.put("/client/assets/{asset_id}")
def api_client_update_asset(asset_id: str, request: Request, body: ClientAssetBody):
    u = require_role(request, "client")
    ok = ptaas_db.update_asset(
        asset_id,
        client_id=u["id"],
        name=body.name,
        type=body.type,
        description=body.description or "",
        url=body.url or "",
        environment=body.environment or "production",
        technology_stack=body.technology_stack or "",
        authentication_info=body.authentication_info or "",
        status=body.status or "active",
        risk_level=body.risk_level or "medium",
    )
    if not ok:
        raise HTTPException(status_code=404, detail="Asset not found")
    return {"success": True}


@api.delete("/client/assets/{asset_id}")
def api_client_delete_asset(asset_id: str, request: Request):
    u = require_role(request, "client")
    ok = ptaas_db.delete_asset(asset_id, client_id=u["id"])
    if not ok:
        raise HTTPException(status_code=404, detail="Asset not found")
    return {"success": True}


@api.post("/client/upload-attachments")
async def api_client_upload_attachments(request: Request, files: list[UploadFile] = File(...)):
    require_role(request, "client")
    import os

    if not files:
        raise HTTPException(status_code=400, detail="No files provided")

    upload_dir = "/var/www/redcon/uploads/pentest_attachments"
    os.makedirs(upload_dir, exist_ok=True)
    file_ids: list[dict] = []

    for f in files:
        if not f.filename:
            continue
        file_id = str(uuid.uuid4())
        _, ext = os.path.splitext(f.filename)
        safe_filename = f"{file_id}{ext}"
        out_path = os.path.join(upload_dir, safe_filename)
        content = await f.read()
        with open(out_path, "wb") as w:
            w.write(content)
        file_ids.append({"id": file_id, "original_name": f.filename, "path": safe_filename})

    return {"success": True, "file_ids": file_ids}


@api.post("/client/request-pentest")
def api_client_request_pentest(request: Request, body: ClientRequestPentestBody):
    u = require_role(request, "client")

    # optional asset prefill
    asset = None
    if body.asset_id:
        try:
            a = ptaas_db.get_asset_by_id(body.asset_id)
            if a and a.get("client_id") == u["id"]:
                asset = a
        except Exception:
            asset = None

    title = body.title or (asset.get("name") if asset else None) or "New Pentest Request"
    ptype = body.type or (asset.get("type") if asset else None) or "Web Application"
    targets = (body.targets or "").split("\n") if body.targets else []
    if not targets and asset and asset.get("url"):
        targets = [asset.get("url")]
    targets_json = __import__("json").dumps([t.strip() for t in targets if t.strip()])

    description = ""
    pentest = ptaas_db.create_pentest(
        client_id=u["id"],
        title=title,
        type=ptype,
        description=description,
        scope=body.scope or "",
        targets=targets_json,
        start_date=body.start_date,
        end_date=body.end_date,
        compliance=__import__("json").dumps(body.compliance or []),
        company_name=u.get("company", "") or "",
        objectives=body.objectives or "",
        technology_stack=body.tech_stack or (asset.get("technology_stack") if asset else "") or "",
        environment_type=body.environment or (asset.get("environment") if asset else "") or "",
        collaboration_preference=body.collaboration or "",
        sensitive_data=__import__("json").dumps(body.sensitive_data or []),
        notes=body.notes or "",
        priority=body.priority or "normal",
        client_name=u.get("name", "") or "",
        credential_type=body.credential_type or "none",
        credentials=body.credentials_notes or "",
        attachments=__import__("json").dumps(body.attachments or []),
    )
    if not pentest:
        raise HTTPException(status_code=500, detail="Failed to create pentest request")

    ptaas_db.update_pentest(pentest["id"], status="pending")
    return {"success": True, "pentest": pentest, "message": "Pentest request submitted successfully"}


@api.get("/client/finding/{finding_id}")
def api_client_get_finding(finding_id: str, request: Request):
    u = require_role(request, "client")
    finding = ptaas_db.get_finding_by_id(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    pentest = ptaas_db.get_pentest_by_id(finding.get("pentest_id"))
    if not pentest or pentest.get("client_id") != u["id"]:
        raise HTTPException(status_code=403, detail="Access denied")
    return {"success": True, "finding": finding}


@api.post("/client/finding/{finding_id}/respond")
def api_client_respond_finding(finding_id: str, request: Request, body: ClientFindingRespondBody):
    u = require_role(request, "client")
    finding = ptaas_db.get_finding_by_id(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    pentest = ptaas_db.get_pentest_by_id(finding.get("pentest_id"))
    if not pentest or pentest.get("client_id") != u["id"]:
        raise HTTPException(status_code=403, detail="Access denied")
    # store response in finding (existing helper supports client_response)
    ok = ptaas_db.update_finding_status(finding_id, body.status, user_id=u["id"], client_response=(body.comment or ""))
    if not ok:
        raise HTTPException(status_code=400, detail="Failed to update finding")
    return {"success": True}


# ============================================================
# ADMIN APIs
# ============================================================

@api.get("/admin/stats")
def api_admin_stats(request: Request):
    require_role(request, "admin")
    conn = ptaas_db.get_db()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM ptaas_users")
    total_users = c.fetchone()[0]

    # active = planned + live/active
    c.execute("SELECT COUNT(*) FROM pentests WHERE status IN ('active','live','planned','paused')")
    active_pentests = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM pentests WHERE status = 'pending'")
    pending_requests = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM ptaas_findings")
    total_findings = c.fetchone()[0]

    try:
        c.execute("SELECT COALESCE(SUM(amount), 0) FROM payments WHERE status = 'pending'")
        pending_payouts = c.fetchone()[0]
    except Exception:
        pending_payouts = 0

    conn.close()
    return {
        "success": True,
        "total_users": total_users,
        "pending_requests": pending_requests,
        "active_pentests": active_pentests,
        "total_pentests": active_pentests + pending_requests,
        "total_findings": total_findings,
        "pending_payouts": pending_payouts,
    }


@api.get("/admin/users")
def api_admin_users(request: Request, limit: int = 200):
    require_role(request, "admin")
    conn = ptaas_db.get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM ptaas_users ORDER BY created_at DESC LIMIT ?", (int(limit),))
    rows = c.fetchall()
    conn.close()
    users = []
    for u in rows:
        uu = dict(u)
        users.append(
            {
                "id": uu.get("id"),
                "name": uu.get("name"),
                "email": uu.get("email"),
                "role": uu.get("role"),
                "company": uu.get("company"),
                "is_active": bool(int(uu.get("is_active", 1) or 1)),
                "verified": bool(int(uu.get("verified", 0) or 0)),
                "created_at": uu.get("created_at"),
            }
        )
    return {"success": True, "users": users}


@api.post("/admin/users")
def api_admin_create_user(request: Request, body: AdminCreateUserBody):
    require_role(request, "admin")
    email = (body.email or "").lower().strip()
    if not email or not body.password or not body.name or not body.role:
        raise HTTPException(status_code=400, detail="Missing required fields")
    if body.role not in ("admin", "client", "pentester"):
        raise HTTPException(status_code=400, detail="Invalid role")
    if len(body.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    if ptaas_db.get_user_by_email(email):
        raise HTTPException(status_code=400, detail="Email already registered")
    user = ptaas_db.create_user(email=email, password=body.password, name=body.name, role=body.role, company=body.company or "")
    if not user:
        raise HTTPException(status_code=500, detail="Failed to create user")
    return {"success": True, "user": {"id": user["id"], "email": user["email"], "name": user["name"], "role": user["role"], "company": user.get("company", "")}}


@api.post("/admin/users/{user_id}/toggle-active")
def api_admin_toggle_user_active(user_id: str, request: Request):
    require_role(request, "admin")
    conn = ptaas_db.get_db()
    c = conn.cursor()
    c.execute("SELECT is_active FROM ptaas_users WHERE id = ?", (user_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")
    new_status = 0 if (row["is_active"] or 0) else 1
    c.execute("UPDATE ptaas_users SET is_active = ? WHERE id = ?", (new_status, user_id))
    conn.commit()
    conn.close()
    return {"success": True, "is_active": bool(new_status)}


@api.delete("/admin/users/{user_id}")
def api_admin_delete_user(user_id: str, request: Request):
    admin = require_role(request, "admin")
    if user_id == admin.get("id"):
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    conn = ptaas_db.get_db()
    c = conn.cursor()
    c.execute("DELETE FROM pentest_pentesters WHERE pentester_id = ?", (user_id,))
    c.execute("DELETE FROM ptaas_findings WHERE pentester_id = ?", (user_id,))
    c.execute("DELETE FROM activity WHERE user_id = ?", (user_id,))
    c.execute("DELETE FROM notifications WHERE user_id = ?", (user_id,))
    c.execute("DELETE FROM payments WHERE user_id = ?", (user_id,))
    c.execute("DELETE FROM ptaas_users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return {"success": True}


@api.get("/admin/pentesters")
def api_admin_pentesters(request: Request):
    require_role(request, "admin")
    conn = ptaas_db.get_db()
    c = conn.cursor()
    c.execute("SELECT id, name, email FROM ptaas_users WHERE role = 'pentester' AND is_active = 1 ORDER BY name")
    rows = c.fetchall()
    conn.close()
    return {"success": True, "pentesters": [{"id": r["id"], "name": r["name"], "email": r["email"]} for r in rows]}


@api.get("/admin/pending-requests")
def api_admin_pending_requests(request: Request):
    require_role(request, "admin")
    conn = ptaas_db.get_db()
    c = conn.cursor()
    c.execute(
        """
        SELECT p.*, u.name as client_name, u.company as client_company
        FROM pentests p
        LEFT JOIN ptaas_users u ON p.client_id = u.id
        WHERE p.status = 'pending'
        ORDER BY p.created_at DESC
        """
    )
    rows = c.fetchall()
    conn.close()
    out = []
    for row in rows:
        r = dict(row)
        out.append(
            {
                "id": r["id"],
                "pentest_number": r.get("pentest_number", ""),
                "title": r.get("title", ""),
                "type": r.get("type", "web"),
                "scope": r.get("scope", ""),
                "targets": r.get("targets", ""),
                "description": r.get("description", ""),
                "client_name": r.get("client_name") or r.get("company_name") or "Unknown",
                "company_name": r.get("client_company") or r.get("company_name") or "Unknown",
                "created_at": r.get("created_at", ""),
            }
        )
    return {"success": True, "requests": out}


@api.get("/admin/pentests")
def api_admin_pentests(request: Request, status: Optional[str] = None, all: Optional[str] = None):  # noqa: A002
    require_role(request, "admin")
    conn = ptaas_db.get_db()
    c = conn.cursor()
    if (all or "").lower() == "true":
        c.execute("SELECT * FROM pentests ORDER BY created_at DESC")
    elif status:
        c.execute("SELECT * FROM pentests WHERE status = ? ORDER BY created_at DESC", (status,))
    else:
        c.execute("SELECT * FROM pentests WHERE status NOT IN ('pending', 'cancelled') ORDER BY created_at DESC")
    rows = c.fetchall()

    formatted = []
    for row in rows:
        p = dict(row)
        c.execute("SELECT COUNT(*) FROM pentest_pentesters WHERE pentest_id = ? AND status = 'accepted'", (p["id"],))
        pentester_count = c.fetchone()[0]
        client_name = p.get("company_name") or "Unknown"
        if p.get("client_id"):
            c.execute("SELECT name, company FROM ptaas_users WHERE id = ?", (p["client_id"],))
            client = c.fetchone()
            if client:
                client_name = client["company"] or client["name"]

        formatted.append(
            {
                "id": p["id"],
                "pentest_number": p.get("pentest_number", ""),
                "title": p.get("title", ""),
                "company_name": client_name,
                "type": p.get("type", "web"),
                "status": p.get("status", "pending"),
                "priority": p.get("priority") or "normal",
                "start_date": p.get("start_date"),
                "end_date": p.get("end_date"),
                "targets": p.get("targets"),
                "scope": p.get("scope"),
                "total_findings": p.get("total_findings") or 0,
                "critical_count": p.get("critical_count") or 0,
                "high_count": p.get("high_count") or 0,
                "medium_count": p.get("medium_count") or 0,
                "low_count": p.get("low_count") or 0,
                "pentester_count": pentester_count,
                "progress": p.get("progress") or 0,
                "created_at": p.get("created_at", ""),
            }
        )

    conn.close()
    return {"success": True, "pentests": formatted}


@api.get("/admin/pentest/{pentest_id}")
def api_admin_get_pentest(pentest_id: str, request: Request):
    require_role(request, "admin")
    conn = ptaas_db.get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM pentests WHERE id = ?", (pentest_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Pentest not found")
    p = dict(row)

    client_name = p.get("company_name") or "Unknown"
    client_email = ""
    if p.get("client_id"):
        c.execute("SELECT name, email, company FROM ptaas_users WHERE id = ?", (p["client_id"],))
        client = c.fetchone()
        if client:
            client_name = client["company"] or client["name"]
            client_email = client["email"]

    c.execute("SELECT COUNT(*) FROM pentest_pentesters WHERE pentest_id = ? AND status = 'accepted'", (pentest_id,))
    pentester_count = c.fetchone()[0]

    c.execute(
        """
        SELECT u.id, u.name, u.email, pp.role, pp.status
        FROM pentest_pentesters pp
        JOIN ptaas_users u ON pp.pentester_id = u.id
        WHERE pp.pentest_id = ?
        """,
        (pentest_id,),
    )
    pentesters = [dict(r) for r in c.fetchall()]
    conn.close()
    return {
        "success": True,
        "pentest": {
            "id": p["id"],
            "pentest_number": p.get("pentest_number", ""),
            "title": p.get("title", ""),
            "description": p.get("description") or "",
            "company_name": client_name,
            "client_name": p.get("client_name") or client_name,
            "client_email": client_email,
            "client_id": p.get("client_id"),
            "type": p.get("type", "web"),
            "status": p.get("status", "pending"),
            "priority": p.get("priority") or "normal",
            "start_date": p.get("start_date"),
            "end_date": p.get("end_date"),
            "targets": p.get("targets"),
            "scope": p.get("scope"),
            "compliance": p.get("compliance"),
            "objectives": p.get("objectives") or "",
            "technology_stack": p.get("technology_stack") or "",
            "environment_type": p.get("environment_type") or "",
            "collaboration_preference": p.get("collaboration_preference") or "",
            "sensitive_data": p.get("sensitive_data") or "[]",
            "notes": p.get("notes") or "",
            "credential_type": p.get("credential_type") or "none",
            "credentials": p.get("credentials") or "",
            "attachments": p.get("attachments") or "[]",
            "total_findings": p.get("total_findings") or 0,
            "critical_count": p.get("critical_count") or 0,
            "high_count": p.get("high_count") or 0,
            "medium_count": p.get("medium_count") or 0,
            "low_count": p.get("low_count") or 0,
            "pentester_count": pentester_count,
            "pentesters": pentesters,
            "progress": p.get("progress") or 0,
            "created_at": p.get("created_at", ""),
            "updated_at": p.get("updated_at"),
        },
        "assigned_pentesters": pentesters,
    }


@api.post("/admin/pentest/{pentest_id}/approve")
def api_admin_approve_pentest(pentest_id: str, request: Request):
    require_role(request, "admin")
    pentest = ptaas_db.get_pentest_by_id(pentest_id)
    if not pentest:
        raise HTTPException(status_code=404, detail="Pentest not found")
    prev = str(pentest.get("status") or "").lower()
    if prev != "planned":
        ptaas_db.update_pentest(pentest_id, status="planned")
        if pentest.get("client_id"):
            _notify_once(
                pentest["client_id"],
                "pentest_approved",
                "Pentest Approved!",
                f'Your pentest request "{pentest.get("title","")}" has been approved.',
                f"/client/pentest/{pentest_id}",
            )
    return {"success": True, "message": "Pentest approved successfully"}


@api.post("/admin/pentest/{pentest_id}/reject")
def api_admin_reject_pentest(pentest_id: str, request: Request):
    require_role(request, "admin")
    ptaas_db.update_pentest(pentest_id, status="cancelled")
    return {"success": True, "message": "Pentest rejected"}


@api.post("/admin/pentest/{pentest_id}/start")
def api_admin_start_pentest(pentest_id: str, request: Request):
    require_role(request, "admin")
    pentest = ptaas_db.get_pentest_by_id(pentest_id)
    if not pentest:
        raise HTTPException(status_code=404, detail="Pentest not found")
    prev = str(pentest.get("status") or "").lower()
    if prev != "active":
        ptaas_db.update_pentest(pentest_id, status="active")
        if pentest.get("client_id"):
            _notify_once(
                pentest["client_id"],
                "pentest_started",
                "Pentest Started!",
                f'Testing has begun on "{pentest.get("title","")}".',
                f"/client/pentest/{pentest_id}",
            )
        # notify assigned pentesters
        for pid in _get_accepted_pentester_ids_for_pentest(pentest_id):
            _notify_once(
                pid,
                "pentest_started",
                "Pentest Started!",
                f'Engagement "{pentest.get("title","")}" is now active.',
                f"/ptaas/pentest/{pentest_id}",
            )
    return {"success": True, "message": "Pentest started successfully"}


@api.post("/admin/pentest/{pentest_id}/pause")
def api_admin_pause_pentest(pentest_id: str, request: Request):
    require_role(request, "admin")
    pentest = ptaas_db.get_pentest_by_id(pentest_id)
    if not pentest:
        raise HTTPException(status_code=404, detail="Pentest not found")
    prev = str(pentest.get("status") or "").lower()
    if prev != "paused":
        ptaas_db.update_pentest(pentest_id, status="paused")
        if pentest.get("client_id"):
            _notify_once(
                pentest["client_id"],
                "pentest_paused",
                "Pentest Paused",
                f'Pentest "{pentest.get("title","")}" has been paused.',
                f"/client/pentest/{pentest_id}",
            )
        for pid in _get_accepted_pentester_ids_for_pentest(pentest_id):
            _notify_once(
                pid,
                "pentest_paused",
                "Pentest Paused",
                f'Engagement "{pentest.get("title","")}" has been paused.',
                f"/ptaas/pentest/{pentest_id}",
            )
    return {"success": True, "message": "Pentest paused successfully"}


@api.post("/admin/pentest/{pentest_id}/resume")
def api_admin_resume_pentest(pentest_id: str, request: Request):
    require_role(request, "admin")
    pentest = ptaas_db.get_pentest_by_id(pentest_id)
    if not pentest:
        raise HTTPException(status_code=404, detail="Pentest not found")
    prev = str(pentest.get("status") or "").lower()
    if prev != "active":
        ptaas_db.update_pentest(pentest_id, status="active")
        if pentest.get("client_id"):
            _notify_once(
                pentest["client_id"],
                "pentest_resumed",
                "Pentest Resumed",
                f'Pentest "{pentest.get("title","")}" has been resumed.',
                f"/client/pentest/{pentest_id}",
            )
        for pid in _get_accepted_pentester_ids_for_pentest(pentest_id):
            _notify_once(
                pid,
                "pentest_resumed",
                "Pentest Resumed",
                f'Engagement "{pentest.get("title","")}" has been resumed.',
                f"/ptaas/pentest/{pentest_id}",
            )
    return {"success": True, "message": "Pentest resumed successfully"}


@api.post("/admin/pentest/{pentest_id}/assign")
def api_admin_assign_pentester(pentest_id: str, request: Request, body: AdminAssignPentesterBody):
    require_role(request, "admin")
    # Ensure not already assigned
    conn = ptaas_db.get_db()
    c = conn.cursor()
    c.execute("SELECT id FROM pentest_pentesters WHERE pentest_id = ? AND pentester_id = ?", (pentest_id, body.pentester_id))
    if c.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Pentester is already assigned to this pentest")
    conn.close()

    success = ptaas_db.assign_pentester(pentest_id, body.pentester_id, body.role or "tester")
    if not success:
        raise HTTPException(status_code=400, detail="Failed to assign pentester")

    # Lead pentester field
    if (body.role or "") == "lead":
        conn = ptaas_db.get_db()
        c = conn.cursor()
        c.execute("UPDATE pentests SET lead_pentester_id = ? WHERE id = ?", (body.pentester_id, pentest_id))
        conn.commit()
        conn.close()

    # NOTE: ptaas_db.assign_pentester already creates a pentester notification (avoid duplicates here).
    pentest = ptaas_db.get_pentest_by_id(pentest_id)
    if pentest and pentest.get("client_id"):
        _notify_once(
            pentest["client_id"],
            "pentester_assigned",
            "Pentester Assigned",
            f'A pentester has been assigned to "{pentest.get("title","")}".',
            f"/client/pentest/{pentest_id}",
        )

    return {"success": True}


@api.post("/admin/pentest/{pentest_id}/archive")
def api_admin_archive_pentest(pentest_id: str, request: Request):
    require_role(request, "admin")
    ok = ptaas_db.archive_pentest(pentest_id)
    if not ok:
        raise HTTPException(status_code=400, detail="Failed to archive pentest")
    return {"success": True, "message": "Pentest archived successfully"}


@api.delete("/admin/pentest/{pentest_id}")
def api_admin_delete_pentest(pentest_id: str, request: Request):
    require_role(request, "admin")
    ok = ptaas_db.delete_pentest(pentest_id)
    if not ok:
        raise HTTPException(status_code=400, detail="Failed to delete pentest")
    return {"success": True, "message": "Pentest deleted permanently"}


# ============================================================
# PENTESTER (PTAAS) APIs
# ============================================================

def _require_pentester_assigned(pentest_id: str, pentester_id: str) -> None:
    conn = ptaas_db.get_db()
    c = conn.cursor()
    c.execute(
        "SELECT 1 FROM pentest_pentesters WHERE pentest_id = ? AND pentester_id = ? AND status = 'accepted' LIMIT 1",
        (pentest_id, pentester_id),
    )
    ok = c.fetchone() is not None
    conn.close()
    if not ok:
        raise HTTPException(status_code=403, detail="Not authorized for this pentest")


@api.get("/ptaas/pentests")
def api_ptaas_pentests(request: Request, status: str = "all"):
    u = require_role(request, "pentester")
    status_filter = None if status == "all" else status
    pentests = ptaas_db.get_pentests_for_pentester(u["id"], status_filter)
    formatted = []
    for p in pentests:
        formatted.append(
            {
                "id": p["id"],
                "title": p.get("title", ""),
                "status": p.get("status", ""),
                "type": p.get("type", ""),
                "start_date": p.get("start_date"),
                "end_date": p.get("end_date"),
                "company_name": p.get("company_name") or "",
            }
        )
    return {"success": True, "pentests": formatted}


@api.get("/ptaas/pentest/{pentest_id}")
def api_ptaas_pentest_detail(pentest_id: str, request: Request):
    u = require_role(request, "pentester")
    _require_pentester_assigned(pentest_id, u["id"])
    pentest = ptaas_db.get_pentest_by_id(pentest_id)
    if not pentest:
        raise HTTPException(status_code=404, detail="Pentest not found")

    # collaborators: client + pentesters assigned
    collaborators: list[dict] = []
    client = ptaas_db.get_user_by_id(pentest.get("client_id"))
    if client:
        collaborators.append(
            {"id": client.get("id"), "name": client.get("name") or client.get("company") or "Client", "email": client.get("email") or "", "role": "Client", "is_poc": True}
        )

    conn = ptaas_db.get_db()
    c = conn.cursor()
    c.execute(
        """
        SELECT u.id, u.name, u.email, pp.role, pp.status
        FROM pentest_pentesters pp
        JOIN ptaas_users u ON pp.pentester_id = u.id
        WHERE pp.pentest_id = ?
        ORDER BY CASE WHEN pp.role = 'lead' THEN 0 ELSE 1 END, u.name
        """,
        (pentest_id,),
    )
    for r in c.fetchall():
        collaborators.append(
            {
                "id": r["id"],
                "name": r["name"],
                "email": r["email"],
                "role": "Lead Pentester" if r["role"] == "lead" else "Pentester",
                "is_poc": r["id"] == u["id"],
            }
        )
    conn.close()

    # Parse JSON fields
    def safe_json(val, default=None):
        if val is None:
            return default
        if isinstance(val, (list, dict)):
            return val
        try:
            import json
            return json.loads(val)
        except Exception:
            return default

    return {
        "success": True,
        "pentest": {
            "id": pentest.get("id"),
            "title": pentest.get("title"),
            "pentestNumber": pentest.get("pentest_number"),
            "type": pentest.get("type"),
            "status": pentest.get("status"),
            "start_date": pentest.get("start_date"),
            "end_date": pentest.get("end_date"),
            "scope": pentest.get("scope"),
            "targets": safe_json(pentest.get("targets"), []),
            "description": pentest.get("description") or "",
            "objectives": pentest.get("objectives") or "",
            "technology_stack": pentest.get("technology_stack") or "",
            "environment_type": pentest.get("environment_type") or "",
            "collaboration_preference": pentest.get("collaboration_preference") or "",
            "sensitive_data": safe_json(pentest.get("sensitive_data"), []),
            "credential_type": pentest.get("credential_type") or "",
            "credentials": pentest.get("credentials") or "",
            "notes": pentest.get("notes") or "",
            "priority": pentest.get("priority") or "normal",
            "compliance": safe_json(pentest.get("compliance"), []),
            "attachments": safe_json(pentest.get("attachments"), []),
            "company_name": pentest.get("company_name") or "",
            "client_name": pentest.get("client_name") or "",
            "payout_total": pentest.get("payout_total") or 0,
            "required_skills": safe_json(pentest.get("required_skills"), []),
            "created_at": pentest.get("created_at") or "",
            "collaborators": collaborators,
        },
    }


@api.get("/ptaas/activity")
def api_ptaas_activity(request: Request, limit: int = 50):
    u = require_role(request, "pentester")
    items = ptaas_db.get_activity_for_user(u["id"], limit=int(limit))
    return {"success": True, "activity": items}


@api.get("/ptaas/postings")
def api_ptaas_postings(request: Request):
    require_role(request, "pentester")
    postings = ptaas_db.get_open_postings()
    return {"success": True, "postings": postings}


@api.post("/ptaas/apply/{posting_id}")
def api_ptaas_apply(posting_id: str, request: Request):
    u = require_role(request, "pentester")
    ok = ptaas_db.apply_to_posting(posting_id, u["id"])
    if not ok:
        raise HTTPException(status_code=400, detail="Failed to apply")
    return {"success": True}


@api.get("/ptaas/findings")
def api_ptaas_findings(
    request: Request,
    pentest_id: Optional[str] = None,
    severity: str = "all",
    status: str = "all",
):
    u = require_role(request, "pentester")
    if pentest_id:
        _require_pentester_assigned(pentest_id, u["id"])
        findings = ptaas_db.get_findings_for_pentest(pentest_id)
    else:
        findings = ptaas_db.get_findings_for_pentester(u["id"], None if severity == "all" else severity, None if status == "all" else status)
    return {"success": True, "findings": findings}


@api.post("/ptaas/findings")
def api_ptaas_create_finding(request: Request, body: dict):
    u = require_role(request, "pentester")
    pentest_id = str(body.get("pentest_id") or "")
    if not pentest_id:
        raise HTTPException(status_code=400, detail="pentest_id is required")
    _require_pentester_assigned(pentest_id, u["id"])
    finding = ptaas_db.create_finding(
        pentest_id=pentest_id,
        pentester_id=u["id"],
        title=body.get("title", ""),
        description=body.get("description", ""),
        severity=str(body.get("severity", "medium")).lower(),
        category=body.get("category", "other"),
        affected_url=body.get("affected_url"),
        steps_to_reproduce=body.get("steps_to_reproduce") or body.get("poc"),
        impact=body.get("impact"),
        remediation=body.get("remediation"),
    )
    if not finding:
        raise HTTPException(status_code=400, detail="Failed to create finding")

    # Notifications: client + admins + other assigned pentesters (optional)
    try:
        pentest = ptaas_db.get_pentest_by_id(pentest_id)
        title = str(finding.get("title") or "New finding")
        sev = str(finding.get("severity") or "").lower()
        msg = f'Pentester submitted a {sev} finding: "{title}".'
        if pentest and pentest.get("client_id"):
            _notify_once(
                pentest["client_id"],
                "finding_submitted",
                "New Finding Submitted",
                msg,
                f"/client/pentest/{pentest_id}",
                window_seconds=30,
            )
        for aid in _get_admin_user_ids():
            _notify_once(
                aid,
                "finding_submitted",
                "Finding Submitted",
                msg,
                f"/admin/pentests",
                window_seconds=30,
            )
        for pid in _get_accepted_pentester_ids_for_pentest(pentest_id):
            if pid != u["id"]:
                _notify_once(
                    pid,
                    "finding_submitted",
                    "Finding Submitted",
                    msg,
                    f"/ptaas/pentest/{pentest_id}",
                    window_seconds=30,
                )
    except Exception:
        pass
    return {"success": True, "finding": finding}


@api.get("/pentester/finding/{finding_id}")
def api_pentester_get_finding(finding_id: str, request: Request):
    u = require_role(request, "pentester")
    finding = ptaas_db.get_finding_by_id(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    _require_pentester_assigned(finding.get("pentest_id"), u["id"])
    return {"success": True, "finding": finding}


@api.put("/pentester/finding/{finding_id}")
def api_pentester_update_finding(finding_id: str, request: Request, body: PentesterFindingUpdateBody):
    u = require_role(request, "pentester")
    finding = ptaas_db.get_finding_by_id(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    _require_pentester_assigned(finding.get("pentest_id"), u["id"])
    fields = {k: v for k, v in body.model_dump().items() if v is not None}
    if "poc" in fields and "steps_to_reproduce" not in fields:
        fields["steps_to_reproduce"] = fields.pop("poc")
    ok = ptaas_db.update_finding_fields(finding_id, pentester_id=u["id"], **fields)
    if not ok:
        raise HTTPException(status_code=400, detail="Failed to update finding")

    # Notify client + admins that finding was updated
    try:
        updated = ptaas_db.get_finding_by_id(finding_id) or finding
        pentest_id = str(updated.get("pentest_id") or "")
        pentest = ptaas_db.get_pentest_by_id(pentest_id) if pentest_id else None
        title = str(updated.get("title") or "Finding")
        msg = f'Pentester updated finding: "{title}".'
        if pentest and pentest.get("client_id"):
            _notify_once(
                pentest["client_id"],
                "finding_updated",
                "Finding Updated",
                msg,
                f"/client/pentest/{pentest_id}",
                window_seconds=60,
            )
        for aid in _get_admin_user_ids():
            _notify_once(
                aid,
                "finding_updated",
                "Finding Updated",
                msg,
                f"/admin/pentests",
                window_seconds=60,
            )
    except Exception:
        pass
    return {"success": True}


@api.delete("/pentester/finding/{finding_id}")
def api_pentester_delete_finding(finding_id: str, request: Request):
    u = require_role(request, "pentester")
    finding = ptaas_db.get_finding_by_id(finding_id)
    ok = ptaas_db.delete_finding(finding_id, pentester_id=u["id"])
    if not ok:
        raise HTTPException(status_code=403, detail="Cannot delete finding")

    # Notify client + admins that finding was deleted (rare, but requested)
    try:
        if finding:
            pentest_id = str(finding.get("pentest_id") or "")
            pentest = ptaas_db.get_pentest_by_id(pentest_id) if pentest_id else None
            title = str(finding.get("title") or "Finding")
            msg = f'Pentester deleted finding: "{title}".'
            if pentest and pentest.get("client_id"):
                _notify_once(
                    pentest["client_id"],
                    "finding_deleted",
                    "Finding Deleted",
                    msg,
                    f"/client/pentest/{pentest_id}",
                    window_seconds=60,
                )
            for aid in _get_admin_user_ids():
                _notify_once(
                    aid,
                    "finding_deleted",
                    "Finding Deleted",
                    msg,
                    f"/admin/pentests",
                    window_seconds=60,
                )
    except Exception:
        pass
    return {"success": True}


@api.get("/ptaas/pentest/{pentest_id}/coverage")
def api_ptaas_get_coverage(pentest_id: str, request: Request):
    u = require_role(request, "pentester")
    _require_pentester_assigned(pentest_id, u["id"])
    items = ptaas_db.get_coverage_for_pentest(pentest_id)
    return {"success": True, "items": items}


@api.post("/ptaas/pentest/{pentest_id}/coverage")
def api_ptaas_init_coverage(pentest_id: str, request: Request):
    u = require_role(request, "pentester")
    _require_pentester_assigned(pentest_id, u["id"])
    # Only create if none exist
    existing = ptaas_db.get_coverage_for_pentest(pentest_id)
    if existing:
        return {"success": True, "created": 0}
    ptaas_db.create_coverage_items_for_pentest(pentest_id, "web")
    return {"success": True, "created": 1}


@api.get("/ptaas/pentest/{pentest_id}/coverage-stats")
def api_ptaas_coverage_stats(pentest_id: str, request: Request):
    u = require_role(request, "pentester")
    _require_pentester_assigned(pentest_id, u["id"])
    stats = ptaas_db.get_coverage_stats(pentest_id)
    return {"success": True, "percent": stats.get("percentage", 0), "total": stats.get("total", 0), "completed": stats.get("completed", 0)}


@api.put("/ptaas/coverage/{item_id}")
def api_ptaas_update_coverage(item_id: str, request: Request, body: CoverageUpdateBody):
    u = require_role(request, "pentester")
    ok = ptaas_db.update_coverage_item(item_id, u["id"], body.status, notes=body.notes)
    if not ok:
        raise HTTPException(status_code=400, detail="Failed to update coverage")
    return {"success": True}

# Expose APIs under both prefixes during migration
app.include_router(api, prefix="/api")
app.include_router(api, prefix="/api/v2")


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # unify error shape expected by frontend apiFetch()
    return JSONResponse({"error": str(exc.detail)}, status_code=exc.status_code)

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # prevent FastAPI's default {"detail":[...]} shape from leaking into the frontend
    return JSONResponse({"error": "Invalid request"}, status_code=400)


@app.exception_handler(sqlite3.OperationalError)
async def sqlite_exception_handler(request: Request, exc: sqlite3.OperationalError):
    return JSONResponse({"error": "Database error"}, status_code=500)


