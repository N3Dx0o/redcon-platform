"""
secure_auth.py
==============
Security primitives for REDCON OFFENCE:
- Security headers
- Password hashing (bcrypt)
- JWT access/refresh tokens (PyJWT)
- Role-based decorators
- Token revocation + audit logging (SQLite via ptaas_db)
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any, Callable, Dict, Optional, Tuple

import jwt

try:
    import bcrypt  # type: ignore

    BCRYPT_AVAILABLE = True
except Exception:
    BCRYPT_AVAILABLE = False


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _env_bool(name: str, default: bool = False) -> bool:
    v = (os.environ.get(name) or "").strip().lower()
    if not v:
        return default
    return v in ("1", "true", "yes", "y", "on")


def is_production() -> bool:
    env = (os.environ.get("FLASK_ENV") or os.environ.get("REDCON_ENV") or "").strip().lower()
    return env == "production"


def add_security_headers(response):
    """
    Add modern baseline security headers.
    Keep this conservative to avoid breaking existing templates.
    """
    # Clickjacking / MIME sniffing
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")

    # CSP: allow self + inline for legacy templates (ideally remove 'unsafe-inline' over time)
    csp = (
        "default-src 'self'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self'; "
        "object-src 'none'; "
        "img-src 'self' data: https:; "
        "style-src 'self' 'unsafe-inline' https:; "
        "script-src 'self' 'unsafe-inline' https:; "
        "connect-src 'self' https:; "
        "upgrade-insecure-requests"
    )
    # Don’t overwrite if upstream already set a stricter one (e.g., Nginx).
    response.headers.setdefault("Content-Security-Policy", csp)

    # HSTS only when we’re sure HTTPS is in use (often behind reverse proxy/CDN).
    if is_production() and _env_bool("ENABLE_HSTS", True):
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")

    return response


class PasswordHasher:
    """
    bcrypt password hashing. In production, bcrypt MUST be available.
    """

    DEFAULT_ROUNDS = 12

    @classmethod
    def hash(cls, password: str) -> str:
        if not BCRYPT_AVAILABLE:
            if is_production():
                raise RuntimeError("bcrypt is required in production")
            # Very weak fallback; only for local/dev emergency.
            return "sha256$" + hashlib.sha256(password.encode("utf-8")).hexdigest()

        salt = bcrypt.gensalt(rounds=cls.DEFAULT_ROUNDS)
        return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

    @classmethod
    def verify(cls, password: str, stored_hash: str) -> bool:
        if stored_hash.startswith("$2") and BCRYPT_AVAILABLE:
            try:
                return bool(bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8")))
            except Exception:
                return False

        if stored_hash.startswith("sha256$"):
            # Weak legacy fallback; constant-time compare.
            digest = hashlib.sha256(password.encode("utf-8")).hexdigest()
            return hmac.compare_digest(stored_hash, "sha256$" + digest)

        # Unknown format
        return False

    @classmethod
    def needs_rehash(cls, stored_hash: str) -> bool:
        # bcrypt hash format: $2b$12$...
        if stored_hash.startswith("$2"):
            try:
                parts = stored_hash.split("$")
                if len(parts) > 2:
                    rounds = int(parts[2])
                    return rounds < cls.DEFAULT_ROUNDS
            except Exception:
                return True
        return False


@dataclass(frozen=True)
class TokenConfig:
    access_secret: str
    refresh_secret: str
    issuer: str
    audience: str
    access_ttl_seconds: int
    refresh_ttl_seconds: int
    algorithm: str = "HS256"


class JWTManager:
    _cfg: Optional[TokenConfig] = None

    @classmethod
    def init_from_env(cls) -> TokenConfig:
        access_secret = os.environ.get("JWT_SECRET") or os.environ.get("FLASK_SECRET_KEY") or ""
        refresh_secret = os.environ.get("JWT_REFRESH_SECRET") or access_secret
        if is_production() and (not access_secret or access_secret == "redcon-offence-secret-key-change-in-production"):
            raise RuntimeError("JWT_SECRET/FLASK_SECRET_KEY must be set in production")

        cfg = TokenConfig(
            access_secret=access_secret or "dev-secret-change-me",
            refresh_secret=refresh_secret or "dev-refresh-secret-change-me",
            issuer=os.environ.get("JWT_ISSUER", "redconoffence"),
            audience=os.environ.get("JWT_AUDIENCE", "redcon-platform"),
            access_ttl_seconds=int(os.environ.get("JWT_ACCESS_TTL_SECONDS", "900")),  # 15m
            refresh_ttl_seconds=int(os.environ.get("JWT_REFRESH_TTL_SECONDS", str(60 * 60 * 24 * 7))),  # 7d
        )
        cls._cfg = cfg
        return cfg

    @classmethod
    def cfg(cls) -> TokenConfig:
        return cls._cfg or cls.init_from_env()

    @classmethod
    def _base_claims(cls) -> Dict[str, Any]:
        now = _now_utc()
        return {
            "iss": cls.cfg().issuer,
            "aud": cls.cfg().audience,
            "iat": int(now.timestamp()),
        }

    @classmethod
    def encode_token(cls, *, user_id: str, email: str, role: str, token_type: str) -> Tuple[str, Dict[str, Any]]:
        now = _now_utc()
        jti = str(uuid.uuid4())
        if token_type == "access":
            ttl = cls.cfg().access_ttl_seconds
            secret = cls.cfg().access_secret
        elif token_type == "refresh":
            ttl = cls.cfg().refresh_ttl_seconds
            secret = cls.cfg().refresh_secret
        else:
            raise ValueError("invalid token_type")

        payload = {
            **cls._base_claims(),
            "sub": user_id,
            "user_id": user_id,
            "email": email,
            "role": role,
            "type": token_type,
            "jti": jti,
            "exp": int((now + timedelta(seconds=ttl)).timestamp()),
        }
        token = jwt.encode(payload, secret, algorithm=cls.cfg().algorithm)
        return token, payload

    @classmethod
    def decode_token(cls, token: str, *, token_type: Optional[str] = None) -> Optional[Dict[str, Any]]:
        try:
            # Try access secret first, then refresh secret (helps when callers pass the wrong token).
            cfg = cls.cfg()
            for secret in (cfg.access_secret, cfg.refresh_secret):
                try:
                    payload = jwt.decode(
                        token,
                        secret,
                        algorithms=[cfg.algorithm],
                        audience=cfg.audience,
                        issuer=cfg.issuer,
                        options={"require": ["exp", "iat", "iss", "aud"]},
                    )
                    if token_type and payload.get("type") != token_type:
                        return None
                    return payload
                except jwt.InvalidSignatureError:
                    continue
            return None
        except Exception:
            return None


class AuditLogger:
    """
    Minimal audit log sink (SQLite).
    """

    @staticmethod
    def log(event: str, *, user_id: Optional[str] = None, ip: str = "", user_agent: str = "", meta: Optional[Dict[str, Any]] = None):
        try:
            import ptaas_db

            ptaas_db.ensure_security_tables()
            conn = ptaas_db.get_db()
            c = conn.cursor()
            c.execute(
                """
                INSERT INTO audit_log (id, event, user_id, ip, user_agent, meta_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    event,
                    user_id,
                    ip[:256],
                    user_agent[:512],
                    (json_dumps(meta) if meta else None),
                    datetime.now().isoformat(),
                ),
            )
            conn.commit()
            conn.close()
        except Exception:
            # Never break the request on audit logging failure
            return


def json_dumps(obj: Any) -> str:
    import json

    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def _get_client_ip(request) -> str:
    # Prefer X-Forwarded-For when behind reverse proxy/CDN
    xff = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    if xff:
        return xff
    return request.remote_addr or ""


def _get_bearer_token(request) -> Optional[str]:
    auth = (request.headers.get("Authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    return None


def _is_jti_revoked(jti: str) -> bool:
    try:
        import ptaas_db

        ptaas_db.ensure_security_tables()
        conn = ptaas_db.get_db()
        c = conn.cursor()
        c.execute("SELECT 1 FROM token_blacklist WHERE jti = ?", (jti,))
        row = c.fetchone()
        conn.close()
        return bool(row)
    except Exception:
        return False


def revoke_refresh_token(jti: str, *, expires_at: Optional[str] = None):
    try:
        import ptaas_db

        ptaas_db.ensure_security_tables()
        conn = ptaas_db.get_db()
        c = conn.cursor()
        c.execute(
            """
            INSERT OR IGNORE INTO token_blacklist (jti, token_type, expires_at, created_at)
            VALUES (?, 'refresh', ?, ?)
            """,
            (jti, expires_at, datetime.now().isoformat()),
        )
        conn.commit()
        conn.close()
    except Exception:
        return


def jwt_required(fn: Callable):
    """
    Require a valid (non-revoked) access token.
    Works for JSON APIs; template routes should rely on session.
    """

    @wraps(fn)
    def wrapper(*args, **kwargs):
        from flask import jsonify, request

        token = _get_bearer_token(request) or request.cookies.get("access_token")
        if not token:
            return jsonify({"error": "Authentication required"}), 401
        payload = JWTManager.decode_token(token, token_type="access")
        if not payload:
            return jsonify({"error": "Invalid token"}), 401
        if payload.get("jti") and _is_jti_revoked(str(payload["jti"])):
            return jsonify({"error": "Token revoked"}), 401
        return fn(*args, **kwargs)

    return wrapper


def role_required(required_role: str) -> Callable:
    def decorator(fn: Callable):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            from flask import jsonify, request, session

            # Prefer session role (server-side)
            role = session.get("user_role")
            if not role:
                token = _get_bearer_token(request) or request.cookies.get("access_token")
                payload = JWTManager.decode_token(token, token_type="access") if token else None
                role = payload.get("role") if payload else None

            if role != required_role:
                return jsonify({"error": "Forbidden"}), 403
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def admin_only(fn: Callable):
    return role_required("admin")(fn)


def pentester_only(fn: Callable):
    return role_required("pentester")(fn)


def client_only(fn: Callable):
    return role_required("client")(fn)

