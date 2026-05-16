"""
auth_routes.py
==============
Fast, secure auth API under /api/v2/auth.
Backwards-compatible with existing frontend expectations:
- login returns {success, user, tokens}
- refresh returns {access_token, expires_in}
Also sets HttpOnly cookies for tokens to reduce XSS exposure.
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Optional

from flask import Blueprint, jsonify, request, session, make_response

import ptaas_db
from secure_auth import JWTManager, PasswordHasher, AuditLogger, revoke_refresh_token, _get_client_ip
import time


_RL = {}


def _rate_limit(bucket: str, limit: int, window_seconds: int) -> bool:
    now = time.time()
    window_start = now - window_seconds
    q = _RL.get(bucket, [])
    q = [t for t in q if t >= window_start]
    if len(q) >= limit:
        _RL[bucket] = q
        return False
    q.append(now)
    _RL[bucket] = q
    return True


auth_bp = Blueprint("auth_v2", __name__, url_prefix="/api/v2/auth")


def init_auth_service(db_path: Optional[str] = None):
    """
    Initialize auth subsystem. Kept for compatibility with app.py.
    """
    # Ensure DB schema exists
    ptaas_db.init_ptaas_db()
    ptaas_db.ensure_security_tables()
    JWTManager.init_from_env()
    return True


def _cookie_kwargs():
    secure = (os.environ.get("FLASK_ENV") == "production") or (os.environ.get("FORCE_HTTPS_COOKIES") == "1")
    return {
        "httponly": True,
        "secure": secure,
        "samesite": "Lax",
        "path": "/",
    }


def _set_token_cookies(resp, access_token: str, refresh_token: str):
    ck = _cookie_kwargs()
    resp.set_cookie("access_token", access_token, **ck)
    resp.set_cookie("refresh_token", refresh_token, **ck)


def _clear_token_cookies(resp):
    resp.delete_cookie("access_token", path="/")
    resp.delete_cookie("refresh_token", path="/")


def _sanitize_next(next_url: str, default: str) -> str:
    """
    Only allow relative internal redirects.
    Blocks: http(s)://, //evil.com, javascript:, etc.
    """
    next_url = (next_url or "").strip()
    if not next_url:
        return default
    if next_url.startswith("//"):
        return default
    if "://" in next_url:
        return default
    if next_url.lower().startswith(("javascript:", "data:", "vbscript:")):
        return default
    if not next_url.startswith("/"):
        return default
    return next_url


@auth_bp.post("/login")
def login_v2():
    ip = _get_client_ip(request)
    if not _rate_limit(f"v2:login:{ip}", limit=20, window_seconds=60 * 10):
        return jsonify({"success": False, "error": "Too many requests"}), 429

    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").lower().strip()
    password = data.get("password") or ""
    next_url = data.get("next") or request.args.get("next") or ""

    if not email or not password:
        return jsonify({"success": False, "error": "Email and password are required"}), 400

    user = ptaas_db.get_user_by_email(email)
    if not user or not user.get("is_active", 1):
        AuditLogger.log("auth.login_failed", user_id=None, ip=_get_client_ip(request), user_agent=request.headers.get("User-Agent", ""))
        return jsonify({"success": False, "error": "Invalid email or password"}), 401

    if not PasswordHasher.verify(password, user.get("password_hash", "")):
        AuditLogger.log("auth.login_failed", user_id=user.get("id"), ip=_get_client_ip(request), user_agent=request.headers.get("User-Agent", ""))
        return jsonify({"success": False, "error": "Invalid email or password"}), 401

    # Upgrade hash if needed
    if PasswordHasher.needs_rehash(user["password_hash"]) or user["password_hash"].startswith("sha256$"):
        try:
            ptaas_db.set_user_password(user["id"], password)
        except Exception:
            pass

    # Update last login
    ptaas_db.update_user(user["id"], last_login=datetime.now().isoformat())

    # Set server-side session for template routes and legacy /api/auth/me
    session["user_id"] = user["id"]
    session["user_email"] = user["email"]
    session["user_name"] = user.get("name")
    session["user_role"] = user.get("role")

    access_token, access_payload = JWTManager.encode_token(
        user_id=user["id"], email=user["email"], role=user.get("role", "pentester"), token_type="access"
    )
    refresh_token, refresh_payload = JWTManager.encode_token(
        user_id=user["id"], email=user["email"], role=user.get("role", "pentester"), token_type="refresh"
    )

    resp = make_response(
        jsonify(
            {
                "success": True,
                "user": {
                    "id": user["id"],
                    "email": user["email"],
                    "name": user.get("name"),
                    "role": user.get("role"),
                    "company": user.get("company"),
                },
                "tokens": {
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "expires_in": JWTManager.cfg().access_ttl_seconds,
                },
                "redirect": _sanitize_next(
                    str(next_url),
                    "/app/admin/dashboard"
                    if user.get("role") == "admin"
                    else "/app/client/dashboard"
                    if user.get("role") == "client"
                    else "/app/ptaas/pentests",
                ),
            }
        )
    )
    _set_token_cookies(resp, access_token, refresh_token)
    AuditLogger.log("auth.login_success", user_id=user["id"], ip=_get_client_ip(request), user_agent=request.headers.get("User-Agent", ""))
    return resp


@auth_bp.post("/refresh")
def refresh_v2():
    ip = _get_client_ip(request)
    if not _rate_limit(f"v2:refresh:{ip}", limit=60, window_seconds=60 * 10):
        return jsonify({"success": False, "error": "Too many requests"}), 429

    data = request.get_json(silent=True) or {}
    token = data.get("refresh_token") or request.cookies.get("refresh_token") or ""
    payload = JWTManager.decode_token(token, token_type="refresh") if token else None
    if not payload:
        return jsonify({"success": False, "error": "Invalid refresh token"}), 401

    jti = str(payload.get("jti") or "")
    if jti and ptaas_db.is_token_revoked(jti):
        return jsonify({"success": False, "error": "Refresh token revoked"}), 401

    user_id = payload.get("user_id")
    user = ptaas_db.get_user_by_id(str(user_id)) if user_id else None
    if not user or not user.get("is_active", 1):
        return jsonify({"success": False, "error": "User disabled"}), 401

    access_token, _ = JWTManager.encode_token(
        user_id=user["id"], email=user["email"], role=user.get("role", "pentester"), token_type="access"
    )

    resp = make_response(jsonify({"access_token": access_token, "expires_in": JWTManager.cfg().access_ttl_seconds}))
    # Refresh endpoint can also rotate refresh token in future; for now, keep existing.
    resp.set_cookie("access_token", access_token, **_cookie_kwargs())
    return resp


@auth_bp.post("/logout")
def logout_v2():
    # Revoke refresh token if present
    refresh = request.cookies.get("refresh_token") or ""
    payload = JWTManager.decode_token(refresh, token_type="refresh") if refresh else None
    if payload and payload.get("jti"):
        ptaas_db.revoke_token(str(payload["jti"]), token_type="refresh", expires_at=str(payload.get("exp") or ""))
        revoke_refresh_token(str(payload["jti"]), expires_at=str(payload.get("exp") or ""))

    session.clear()
    resp = make_response(jsonify({"success": True, "redirect": "/"}))
    _clear_token_cookies(resp)
    return resp


@auth_bp.get("/me")
def me_v2():
    # Prefer session (server-side), fallback to access token cookie/bearer
    user_id = session.get("user_id")
    role = session.get("user_role")
    if not user_id or not role:
        token = (request.headers.get("Authorization", "").replace("Bearer ", "")) or request.cookies.get("access_token")
        payload = JWTManager.decode_token(token, token_type="access") if token else None
        if payload:
            user_id = payload.get("user_id")
            role = payload.get("role")

    if not user_id:
        return jsonify({"authenticated": False}), 401

    user = ptaas_db.get_user_by_id(str(user_id))
    if not user:
        session.clear()
        return jsonify({"authenticated": False}), 401

    return jsonify(
        {
            "authenticated": True,
            "user": {
                "id": user.get("id"),
                "email": user.get("email"),
                "name": user.get("name"),
                "role": user.get("role"),
                "company": user.get("company"),
                "is_active": user.get("is_active", 1),
                "ptaas": True,
            },
        }
    )


@auth_bp.get("/session/check")
def session_check_v2():
    # Simple check used by static session manager
    if session.get("user_id") and session.get("user_role") in ("admin", "client", "pentester"):
        user = ptaas_db.get_user_by_id(session["user_id"])
        if user and user.get("is_active", 1):
            return jsonify({"authenticated": True, "user": {"id": user["id"], "email": user["email"], "role": user["role"], "name": user.get("name")}})
    # Fallback to token
    token = request.cookies.get("access_token") or request.headers.get("Authorization", "").replace("Bearer ", "")
    payload = JWTManager.decode_token(token, token_type="access") if token else None
    if payload and payload.get("user_id"):
        user = ptaas_db.get_user_by_id(str(payload["user_id"]))
        if user and user.get("is_active", 1):
            return jsonify({"authenticated": True, "user": {"id": user["id"], "email": user["email"], "role": user["role"], "name": user.get("name")}})
    return jsonify({"authenticated": False}), 401


@auth_bp.post("/validate-password")
def validate_password_v2():
    data = request.get_json(silent=True) or {}
    password = data.get("password") or ""
    errors = []
    if len(password) < 12:
        errors.append("Password must be at least 12 characters")
    if password.lower() == password:
        errors.append("Add at least one uppercase letter")
    if not any(ch.isdigit() for ch in password):
        errors.append("Add at least one number")
    if not any(ch in "!@#$%^&*()-_=+[]{};:,.?/" for ch in password):
        errors.append("Add at least one symbol")
    strength = "strong" if not errors else "weak"
    return jsonify({"valid": not errors, "errors": errors, "strength": strength})


@auth_bp.post("/change-password")
def change_password_v2():
    if not session.get("user_id"):
        return jsonify({"success": False, "error": "Not authenticated"}), 401

    data = request.get_json(silent=True) or {}
    current_password = data.get("current_password") or ""
    new_password = data.get("new_password") or ""
    if len(new_password) < 12:
        return jsonify({"success": False, "error": "Password must be at least 12 characters"}), 400

    user = ptaas_db.get_user_by_id(session["user_id"])
    if not user:
        return jsonify({"success": False, "error": "Not authenticated"}), 401
    if not PasswordHasher.verify(current_password, user.get("password_hash", "")):
        return jsonify({"success": False, "error": "Current password is incorrect"}), 400

    ptaas_db.set_user_password(user["id"], new_password)
    AuditLogger.log("auth.password_changed", user_id=user["id"], ip=_get_client_ip(request), user_agent=request.headers.get("User-Agent", ""))
    return jsonify({"success": True})

