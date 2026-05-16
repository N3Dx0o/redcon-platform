#!/usr/bin/env python3
"""
PTaaS Database Module - Complete database schema and operations for PTaaS platform
"""

import os
import sqlite3
import uuid
import hashlib
import hmac
import re
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any

# Try to use bcrypt for secure password hashing
try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False
    print("[PTaaS DB] bcrypt not available, using SHA256 (install bcrypt for production)")

DB_PATH = os.path.join(os.path.dirname(__file__), 'ptaas.db')
PTAAS_DB_PATH = DB_PATH  # Alias for external imports

_ALLOWED_TABLES = {
    'users', 'clients', 'projects', 'assets', 'ptaas_findings',
    'rate_limits', 'sessions', 'contact_requests', 'demo_requests',
    'reports', 'project_reports', 'finding_attachments', 'asset_tags',
    'finding_tags', 'activity_log', 'notifications', 'api_keys',
    'templates', 'checklist_items', 'project_checklist',
    # internal tables used in migrations
    'pentests', 'ptaas_users',
}

def _safe_table(table: str) -> str:
    if table not in _ALLOWED_TABLES:
        raise ValueError(f"Invalid table name: {table!r}")
    return table

_ALLOWED_ASSET_COLS = {
    'name', 'type', 'url', 'ip_address', 'port', 'protocol', 'status',
    'description', 'notes', 'risk_level', 'last_scanned', 'metadata',
    'tags', 'owner', 'environment', 'criticality', 'updated_at',
    # existing allowed cols in update_asset
    'technology_stack', 'authentication_info',
}

_ALLOWED_FINDING_COLS = {
    'title', 'description', 'severity', 'status', 'cvss_score', 'cve_id',
    'remediation', 'notes', 'proof_of_concept', 'impact', 'likelihood',
    'asset_id', 'project_id', 'assigned_to', 'verified_by', 'verified_at',
    'resolved_at', 'updated_at', 'tags', 'references', 'template_id',
    # existing allowed cols in update_finding_fields
    'category', 'affected_url', 'cwe_id', 'reference_urls',
    'steps_to_reproduce', 'poc', 'attachments', 'screenshots',
}



def ensure_public_ids():
    """
    Ensure human-friendly public IDs exist:
    - pentests.public_id: PT_001, PT_002, ...
    - ptaas_findings.public_id: PT_001_001, PT_001_002, ... (scoped to pentest)

    Safe to call multiple times.
    """
    conn = get_db()
    c = conn.cursor()

    def _has_col(table: str, col: str) -> bool:
        c.execute(f"PRAGMA table_info({_safe_table(table)})")
        return any(r[1] == col for r in c.fetchall())

    # Add columns if missing
    if _has_col("pentests", "id") and not _has_col("pentests", "public_id"):
        c.execute("ALTER TABLE pentests ADD COLUMN public_id TEXT")
    if _has_col("ptaas_findings", "id") and not _has_col("ptaas_findings", "public_id"):
        c.execute("ALTER TABLE ptaas_findings ADD COLUMN public_id TEXT")

    # Indexes (best-effort)
    try:
        c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_pentests_public_id ON pentests(public_id)")
    except Exception:
        pass
    try:
        c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_public_id ON ptaas_findings(public_id)")
    except Exception:
        pass

    # Backfill pentests.public_id
    c.execute("SELECT id, created_at FROM pentests WHERE (public_id IS NULL OR public_id = '') ORDER BY created_at ASC")
    missing_p = c.fetchall()

    c.execute("SELECT public_id FROM pentests WHERE public_id IS NOT NULL AND public_id != ''")
    existing = [r[0] for r in c.fetchall()]
    max_n = 0
    for pid in existing:
        m = re.match(r"^PT_(\d+)$", str(pid))
        if m:
            try:
                max_n = max(max_n, int(m.group(1)))
            except Exception:
                pass

    n = max_n
    for r in missing_p:
        n += 1
        pub = f"PT_{n:03d}"
        c.execute("UPDATE pentests SET public_id = ? WHERE id = ?", (pub, r[0]))

    # Backfill ptaas_findings.public_id (per pentest)
    c.execute("SELECT id, public_id FROM pentests WHERE public_id IS NOT NULL AND public_id != '' ORDER BY created_at ASC")
    pentests = c.fetchall()
    for p in pentests:
        pid = p[0]
        ppub = str(p[1])
        c.execute("SELECT public_id FROM ptaas_findings WHERE pentest_id = ? AND public_id IS NOT NULL AND public_id != ''", (pid,))
        ex = [x[0] for x in c.fetchall()]
        max_f = 0
        for fx in ex:
            m = re.match(rf"^{re.escape(ppub)}_(\d+)$", str(fx))
            if m:
                try:
                    max_f = max(max_f, int(m.group(1)))
                except Exception:
                    pass

        c.execute(
            "SELECT id, created_at FROM ptaas_findings WHERE pentest_id = ? AND (public_id IS NULL OR public_id = '') ORDER BY created_at ASC",
            (pid,),
        )
        miss_f = c.fetchall()
        k = max_f
        for fr in miss_f:
            k += 1
            fpub = f"{ppub}_{k:03d}"
            c.execute("UPDATE ptaas_findings SET public_id = ? WHERE id = ?", (fpub, fr[0]))

    conn.commit()
    conn.close()


def ensure_finding_extras():
    """
    Safe, idempotent schema upgrades for findings:
    - ptaas_findings.labels (JSON array string)
    - ptaas_findings.exploitation_status (string)
    - ptaas_findings.custom_reference (string)
    """
    conn = get_db()
    c = conn.cursor()

    def _has_col(table: str, col: str) -> bool:
        c.execute(f"PRAGMA table_info({_safe_table(table)})")
        return any(r[1] == col for r in c.fetchall())

    if _has_col("ptaas_findings", "id") and not _has_col("ptaas_findings", "labels"):
        c.execute("ALTER TABLE ptaas_findings ADD COLUMN labels TEXT")
        # backfill default
        try:
            c.execute("UPDATE ptaas_findings SET labels = '[]' WHERE labels IS NULL OR labels = ''")
        except Exception:
            pass

    if _has_col("ptaas_findings", "id") and not _has_col("ptaas_findings", "exploitation_status"):
        c.execute("ALTER TABLE ptaas_findings ADD COLUMN exploitation_status TEXT")
        try:
            c.execute("UPDATE ptaas_findings SET exploitation_status = '' WHERE exploitation_status IS NULL")
        except Exception:
            pass

    if _has_col("ptaas_findings", "id") and not _has_col("ptaas_findings", "custom_reference"):
        c.execute("ALTER TABLE ptaas_findings ADD COLUMN custom_reference TEXT")
        try:
            c.execute("UPDATE ptaas_findings SET custom_reference = '' WHERE custom_reference IS NULL")
        except Exception:
            pass

    conn.commit()
    conn.close()


def ensure_finding_watchers():
    """
    Safe, idempotent schema for per-finding subscriptions (Follow/Unfollow).
    """
    conn = get_db()
    c = conn.cursor()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS finding_watchers (
            finding_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (finding_id, user_id),
            FOREIGN KEY (finding_id) REFERENCES ptaas_findings(id),
            FOREIGN KEY (user_id) REFERENCES ptaas_users(id)
        )
        """
    )
    conn.commit()
    conn.close()


def is_watching_finding(finding_id: str, user_id: str) -> bool:
    ensure_finding_watchers()
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT 1 FROM finding_watchers WHERE finding_id = ? AND user_id = ? LIMIT 1", (finding_id, user_id))
    ok = c.fetchone() is not None
    conn.close()
    return ok


def set_watching_finding(finding_id: str, user_id: str, watching: bool) -> bool:
    ensure_finding_watchers()
    conn = get_db()
    c = conn.cursor()
    if watching:
        c.execute(
            "INSERT OR IGNORE INTO finding_watchers (finding_id, user_id, created_at) VALUES (?, ?, ?)",
            (finding_id, user_id, datetime.now(timezone.utc).isoformat()),
        )
    else:
        c.execute("DELETE FROM finding_watchers WHERE finding_id = ? AND user_id = ?", (finding_id, user_id))
    conn.commit()
    conn.close()
    return True


def get_activity_for_finding(finding_id: str, limit: int = 200) -> List[Dict]:
    """
    Return activity items for a finding (joined with actor identity).
    Note: the activity table is also used for per-user feeds, so callers should dedupe.
    """
    conn = get_db()
    c = conn.cursor()
    c.execute(
        """
        SELECT a.*, u.name as user_name, u.email as user_email, u.role as user_role
        FROM activity a
        LEFT JOIN ptaas_users u ON a.user_id = u.id
        WHERE a.finding_id = ?
        ORDER BY a.created_at ASC
        LIMIT ?
        """,
        (finding_id, limit),
    )
    rows = c.fetchall()
    conn.close()
    return [dict_from_row(r) for r in rows]


def update_finding_labels(finding_id: str, labels_json: str) -> bool:
    """Set labels JSON for a finding."""
    ensure_finding_extras()
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE ptaas_findings SET labels = ? WHERE id = ?", (labels_json, finding_id))
    ok = c.rowcount > 0
    conn.commit()
    conn.close()
    return ok


def get_db():
    """Get database connection with row factory."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def dict_from_row(row):
    """Convert sqlite3.Row to dict."""
    if row is None:
        return None
    return dict(row)


def init_ptaas_db():
    """Initialize all PTaaS database tables."""
    conn = get_db()
    c = conn.cursor()

    # ============================================================
    # COVERAGE CHECKLIST TABLE - Track testing progress
    # ============================================================
    c.execute('''
        CREATE TABLE IF NOT EXISTS coverage_checklist (
            id TEXT PRIMARY KEY,
            pentest_id TEXT NOT NULL,
            category TEXT NOT NULL,
            item TEXT NOT NULL,
            description TEXT,
            status TEXT DEFAULT 'pending',
            notes TEXT,
            completed_by TEXT,
            completed_at TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (pentest_id) REFERENCES pentests(id),
            FOREIGN KEY (completed_by) REFERENCES ptaas_users(id)
        )
    ''')

    # ============================================================
    # ASSETS TABLE - Software components to be tested
    # ============================================================
    c.execute('''
        CREATE TABLE IF NOT EXISTS assets (
            id TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            description TEXT,
            url TEXT,
            environment TEXT DEFAULT 'production',
            technology_stack TEXT,
            authentication_info TEXT,
            status TEXT DEFAULT 'active',
            risk_level TEXT DEFAULT 'medium',
            created_at TEXT NOT NULL,
            updated_at TEXT,
            FOREIGN KEY (client_id) REFERENCES ptaas_users(id)
        )
    ''')

    # ============================================================
    # USERS TABLE - Extended for PTaaS
    # ============================================================
    c.execute('''
        CREATE TABLE IF NOT EXISTS ptaas_users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            name TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'pentester',  -- pentester, client, admin
            company TEXT,
            avatar TEXT,
            phone TEXT,
            country TEXT,
            timezone TEXT DEFAULT 'UTC',
            language TEXT DEFAULT 'en',

            -- Pentester specific fields
            bio TEXT,
            skills TEXT,  -- JSON array of skills
            certifications TEXT,  -- JSON array (OSCP, CEH, etc.)
            hourly_rate REAL,
            is_available INTEGER DEFAULT 1,
            auto_accept_invites INTEGER DEFAULT 0,
            total_earnings REAL DEFAULT 0,
            pentests_completed INTEGER DEFAULT 0,
            findings_submitted INTEGER DEFAULT 0,
            rating REAL DEFAULT 0,
            rating_count INTEGER DEFAULT 0,
            verified INTEGER DEFAULT 0,

            -- Client specific fields
            subscription_tier TEXT DEFAULT 'free',  -- free, starter, professional, enterprise
            credits INTEGER DEFAULT 0,
            stripe_customer_id TEXT,

            -- Social links
            linkedin TEXT,
            twitter TEXT,
            github TEXT,
            website TEXT,

            -- Notifications
            notify_email_updates INTEGER DEFAULT 1,
            notify_new_findings INTEGER DEFAULT 1,
            notify_status_updates INTEGER DEFAULT 1,
            notify_weekly_summary INTEGER DEFAULT 1,
            notify_marketing INTEGER DEFAULT 0,

            -- Security
            two_factor_enabled INTEGER DEFAULT 0,
            two_factor_secret TEXT,
            api_token TEXT,

            -- Payment
            payment_method TEXT,  -- paypal, bank, crypto
            payment_details TEXT,  -- JSON with payment info

            created_at TEXT NOT NULL,
            last_login TEXT,
            is_active INTEGER DEFAULT 1
        )
    ''')

    # User setup tokens table (for secure account setup without passwords in emails)
    c.execute('''
        CREATE TABLE IF NOT EXISTS user_setup_tokens (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            token TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used_at TEXT,
            used INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES ptaas_users(id)
        )
    ''')

    # Password reset tokens table (for secure password reset flow)
    c.execute('''
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            token TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used_at TEXT,
            used INTEGER DEFAULT 0,
            ip_address TEXT,
            user_agent TEXT,
            FOREIGN KEY (user_id) REFERENCES ptaas_users(id)
        )
    ''')

    # Rate limiting table (prevent password reset abuse)
    c.execute('''
        CREATE TABLE IF NOT EXISTS rate_limits (
            id TEXT PRIMARY KEY,
            identifier TEXT NOT NULL,  -- email or IP address
            action TEXT NOT NULL,      -- 'password_reset_request', 'login_attempt'
            attempts INTEGER DEFAULT 1,
            window_start TEXT NOT NULL,
            UNIQUE(identifier, action)
        )
    ''')

    # Back-compat migrations (SQLite doesn't support IF NOT EXISTS for columns).
    # Keep these idempotent.
    try:
        c.execute("PRAGMA table_info(ptaas_users)")
        cols = {r["name"] for r in c.fetchall()}
        if "halls_of_fame" not in cols:
            c.execute("ALTER TABLE ptaas_users ADD COLUMN halls_of_fame TEXT")  # JSON array
    except Exception:
        # Safe to ignore; table may be locked during startup, or column already exists.
        pass

    # ============================================================
    # PENTESTS TABLE - Core pentest engagements
    # ============================================================
    c.execute('''
        CREATE TABLE IF NOT EXISTS pentests (
            id TEXT PRIMARY KEY,
            pentest_number TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            description TEXT,

            -- Client info
            client_id TEXT NOT NULL,
            company_name TEXT NOT NULL,

            -- Pentest details
            type TEXT NOT NULL,  -- web, mobile, api, cloud, network, comprehensive
            scope TEXT,  -- Detailed scope description
            targets TEXT,  -- JSON array of target URLs/IPs
            credentials TEXT,  -- JSON with test credentials (encrypted in production)

            -- Status & Timeline
            status TEXT NOT NULL DEFAULT 'draft',  -- draft, pending, planned, live, remediation, completed, cancelled
            start_date TEXT,
            end_date TEXT,
            actual_start TEXT,
            actual_end TEXT,

            -- Assignment
            lead_pentester_id TEXT,
            max_pentesters INTEGER DEFAULT 3,

            -- Pricing
            credits_cost INTEGER DEFAULT 0,
            payout_total REAL DEFAULT 0,
            payout_per_finding REAL DEFAULT 0,
            bonus_critical REAL DEFAULT 500,
            bonus_high REAL DEFAULT 200,

            -- Progress
            progress INTEGER DEFAULT 0,

            -- Requirements
            required_skills TEXT,  -- JSON array
            compliance TEXT,  -- JSON array (PCI-DSS, HIPAA, SOC2, etc.)

            -- Results
            total_findings INTEGER DEFAULT 0,
            critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0,
            medium_count INTEGER DEFAULT 0,
            low_count INTEGER DEFAULT 0,
            info_count INTEGER DEFAULT 0,
            security_score INTEGER,

            -- Reports
            executive_report_url TEXT,
            technical_report_url TEXT,

            -- Extended request fields
            objectives TEXT,
            technology_stack TEXT,
            environment_type TEXT,
            collaboration_preference TEXT,
            sensitive_data TEXT,
            notes TEXT,
            priority TEXT DEFAULT 'normal',
            client_name TEXT,
            credential_type TEXT DEFAULT 'none',
            attachments TEXT,

            -- Metadata
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            created_by TEXT
        )
    ''')

    # ============================================================
    # PENTEST_PENTESTERS - Junction table for pentest assignments
    # ============================================================
    c.execute('''
        CREATE TABLE IF NOT EXISTS pentest_pentesters (
            id TEXT PRIMARY KEY,
            pentest_id TEXT NOT NULL,
            pentester_id TEXT NOT NULL,
            role TEXT DEFAULT 'tester',  -- lead, tester
            status TEXT DEFAULT 'invited',  -- invited, accepted, declined, removed
            invited_at TEXT,
            accepted_at TEXT,
            payout_amount REAL DEFAULT 0,
            findings_count INTEGER DEFAULT 0,
            hours_logged REAL DEFAULT 0,
            FOREIGN KEY (pentest_id) REFERENCES pentests(id),
            FOREIGN KEY (pentester_id) REFERENCES ptaas_users(id),
            UNIQUE(pentest_id, pentester_id)
        )
    ''')

    # ============================================================
    # POSTINGS TABLE - Available pentests for sign-up
    # ============================================================
    c.execute('''
        CREATE TABLE IF NOT EXISTS postings (
            id TEXT PRIMARY KEY,
            pentest_id TEXT,  -- Can be NULL for open postings
            title TEXT NOT NULL,
            company TEXT NOT NULL,
            description TEXT,
            type TEXT NOT NULL,
            payout REAL NOT NULL,
            duration TEXT,
            effort_hours INTEGER,
            tags TEXT,  -- JSON array
            required_skills TEXT,  -- JSON array
            max_pentesters INTEGER DEFAULT 3,
            current_pentesters INTEGER DEFAULT 0,
            status TEXT DEFAULT 'open',  -- open, closed, filled
            posted_at TEXT NOT NULL,
            closes_at TEXT,
            is_featured INTEGER DEFAULT 0,
            FOREIGN KEY (pentest_id) REFERENCES pentests(id)
        )
    ''')

    # ============================================================
    # POSTING_APPLICATIONS - Applications to postings
    # ============================================================
    c.execute('''
        CREATE TABLE IF NOT EXISTS posting_applications (
            id TEXT PRIMARY KEY,
            posting_id TEXT NOT NULL,
            pentester_id TEXT NOT NULL,
            status TEXT DEFAULT 'pending',  -- pending, approved, rejected
            cover_letter TEXT,
            applied_at TEXT NOT NULL,
            reviewed_at TEXT,
            reviewed_by TEXT,
            FOREIGN KEY (posting_id) REFERENCES postings(id),
            FOREIGN KEY (pentester_id) REFERENCES ptaas_users(id),
            UNIQUE(posting_id, pentester_id)
        )
    ''')

    # ============================================================
    # FINDINGS TABLE - Vulnerability findings
    # ============================================================
    c.execute('''
        CREATE TABLE IF NOT EXISTS ptaas_findings (
            id TEXT PRIMARY KEY,
            pentest_id TEXT NOT NULL,
            pentester_id TEXT NOT NULL,

            -- Finding details
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,  -- critical, high, medium, low, info
            cvss_score REAL,
            cvss_vector TEXT,
            category TEXT,  -- injection, xss, access_control, etc.

            -- Technical details
            affected_url TEXT,
            affected_parameter TEXT,
            poc TEXT,  -- Proof of concept
            steps_to_reproduce TEXT,
            impact TEXT,
            remediation TEXT,

            -- Evidence
            screenshots TEXT,  -- JSON array of URLs
            attachments TEXT,  -- JSON array of file URLs

            -- Status workflow
            status TEXT DEFAULT 'new',  -- new, triaged, accepted, rejected, duplicate, fixed, verified, wont_fix
            triaged_at TEXT,
            triaged_by TEXT,

            -- Client response
            client_response TEXT,
            client_priority TEXT,
            fix_eta TEXT,
            fixed_at TEXT,
            verified_at TEXT,
            verified_by TEXT,

            -- Payout
            payout_amount REAL DEFAULT 0,
            payout_status TEXT DEFAULT 'pending',  -- pending, approved, paid
            paid_at TEXT,

            -- References
            cwe_id TEXT,
            cve_id TEXT,
            reference_urls TEXT,  -- JSON array of URLs

            -- Metadata
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (pentest_id) REFERENCES pentests(id),
            FOREIGN KEY (pentester_id) REFERENCES ptaas_users(id)
        )
    ''')

    # ============================================================
    # FINDING_COMMENTS - Comments on findings
    # ============================================================
    c.execute('''
        CREATE TABLE IF NOT EXISTS finding_comments (
            id TEXT PRIMARY KEY,
            finding_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            content TEXT NOT NULL,
            is_internal INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (finding_id) REFERENCES ptaas_findings(id),
            FOREIGN KEY (user_id) REFERENCES ptaas_users(id)
        )
    ''')

    # ============================================================
    # ACTIVITY TABLE - Activity feed
    # ============================================================
    c.execute('''
        CREATE TABLE IF NOT EXISTS activity (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            pentest_id TEXT,
            finding_id TEXT,

            type TEXT NOT NULL,  -- finding_submitted, finding_accepted, pentest_started, comment_added, etc.
            title TEXT NOT NULL,
            description TEXT,
            icon TEXT,

            is_read INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,

            FOREIGN KEY (user_id) REFERENCES ptaas_users(id),
            FOREIGN KEY (pentest_id) REFERENCES pentests(id),
            FOREIGN KEY (finding_id) REFERENCES ptaas_findings(id)
        )
    ''')

    # ============================================================
    # NOTIFICATIONS TABLE
    # ============================================================
    c.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            type TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT,
            link TEXT,
            is_read INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES ptaas_users(id)
        )
    ''')

    # ============================================================
    # FEEDBACK TABLE - Client feedback on pentesters
    # ============================================================
    c.execute('''
        CREATE TABLE IF NOT EXISTS feedback (
            id TEXT PRIMARY KEY,
            pentest_id TEXT NOT NULL,
            pentester_id TEXT NOT NULL,
            client_id TEXT NOT NULL,

            -- Ratings (1-5)
            overall_rating INTEGER,
            communication_rating INTEGER,
            quality_rating INTEGER,
            timeliness_rating INTEGER,
            professionalism_rating INTEGER,

            -- Written feedback
            comment TEXT,
            strengths TEXT,  -- JSON array
            improvements TEXT,  -- JSON array

            is_public INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,

            FOREIGN KEY (pentest_id) REFERENCES pentests(id),
            FOREIGN KEY (pentester_id) REFERENCES ptaas_users(id),
            FOREIGN KEY (client_id) REFERENCES ptaas_users(id)
        )
    ''')

    # ============================================================
    # REPORTS TABLE - Generated reports
    # ============================================================
    c.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            id TEXT PRIMARY KEY,
            pentest_id TEXT NOT NULL,
            type TEXT NOT NULL,  -- executive, technical, compliance
            title TEXT NOT NULL,
            file_url TEXT,
            file_size INTEGER,

            -- Stats at time of generation
            findings_count INTEGER,
            critical_count INTEGER,
            high_count INTEGER,
            medium_count INTEGER,
            low_count INTEGER,

            generated_at TEXT NOT NULL,
            generated_by TEXT,
            downloads INTEGER DEFAULT 0,

            FOREIGN KEY (pentest_id) REFERENCES pentests(id)
        )
    ''')

    # ============================================================
    # PAYMENTS TABLE - Payment history
    # ============================================================
    c.execute('''
        CREATE TABLE IF NOT EXISTS payments (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            pentest_id TEXT,
            finding_id TEXT,

            type TEXT NOT NULL,  -- payout, bonus, credit_purchase
            amount REAL NOT NULL,
            currency TEXT DEFAULT 'USD',
            status TEXT DEFAULT 'pending',  -- pending, processing, completed, failed

            payment_method TEXT,
            transaction_id TEXT,

            description TEXT,
            created_at TEXT NOT NULL,
            completed_at TEXT,

            FOREIGN KEY (user_id) REFERENCES ptaas_users(id)
        )
    ''')

    # ============================================================
    # SESSIONS TABLE
    # ============================================================
    c.execute('''
        CREATE TABLE IF NOT EXISTS ptaas_sessions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            device TEXT,
            location TEXT,
            created_at TEXT NOT NULL,
            last_active TEXT NOT NULL,
            is_current INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES ptaas_users(id)
        )
    ''')

    # ============================================================
    # Create indexes for performance
    # ============================================================
    c.execute('CREATE INDEX IF NOT EXISTS idx_pentests_client ON pentests(client_id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_pentests_status ON pentests(status)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_findings_pentest ON ptaas_findings(pentest_id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_findings_pentester ON ptaas_findings(pentester_id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_findings_status ON ptaas_findings(status)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_activity_user ON activity(user_id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id)')

    # ============================================================
    # SECURITY TABLES (auth token revocation + audit log)
    # ============================================================
    c.execute('''
        CREATE TABLE IF NOT EXISTS token_blacklist (
            jti TEXT PRIMARY KEY,
            token_type TEXT NOT NULL,
            expires_at TEXT,
            created_at TEXT NOT NULL
        )
    ''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_token_blacklist_type ON token_blacklist(token_type)')

    c.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id TEXT PRIMARY KEY,
            event TEXT NOT NULL,
            user_id TEXT,
            ip TEXT,
            user_agent TEXT,
            meta_json TEXT,
            created_at TEXT NOT NULL
        )
    ''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id)')

    conn.commit()
    conn.close()
    print("[PTaaS DB] Database initialized successfully")


def ensure_security_tables():
    """
    Ensure security tables exist even if init_ptaas_db wasn't run (defensive).
    """
    conn = get_db()
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS token_blacklist (
            jti TEXT PRIMARY KEY,
            token_type TEXT NOT NULL,
            expires_at TEXT,
            created_at TEXT NOT NULL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id TEXT PRIMARY KEY,
            event TEXT NOT NULL,
            user_id TEXT,
            ip TEXT,
            user_agent TEXT,
            meta_json TEXT,
            created_at TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


def ensure_pentest_attachment_uploads():
    """
    Track uploaded pentest attachments with an owner to prevent forged attachment paths (IDOR).
    - path is the stored filename in uploads/pentest_attachments
    - uploader_user_id is the user who uploaded it
    - pentest_id is set when the upload is attached to a specific pentest request

    Safe to call multiple times.
    """
    conn = get_db()
    c = conn.cursor()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS pentest_attachment_uploads (
            path TEXT PRIMARY KEY,
            pentest_id TEXT,
            uploader_user_id TEXT,
            original_name TEXT,
            size INTEGER,
            content_type TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    c.execute("CREATE INDEX IF NOT EXISTS idx_pau_pentest_id ON pentest_attachment_uploads(pentest_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_pau_uploader_id ON pentest_attachment_uploads(uploader_user_id)")
    conn.commit()

    # Best-effort migration for existing rows stored only in pentests.attachments JSON
    try:
        import json

        c.execute("SELECT id, client_id, attachments, created_at FROM pentests WHERE attachments IS NOT NULL AND attachments != ''")
        rows = c.fetchall()
        for r in rows:
            pid = r["id"]
            client_id = r["client_id"]
            created_at = r["created_at"] or datetime.now().isoformat()
            try:
                arr = json.loads(r["attachments"] or "[]")
            except Exception:
                arr = []
            if not isinstance(arr, list):
                continue
            for a in arr:
                if not isinstance(a, dict):
                    continue
                path = str(a.get("path") or "").strip()
                if not path:
                    continue
                original_name = str(a.get("original_name") or a.get("name") or path)
                size = int(a.get("size") or 0) if str(a.get("size") or "").isdigit() else (a.get("size") or 0)
                content_type = str(a.get("content_type") or "")
                c.execute(
                    """
                    INSERT OR IGNORE INTO pentest_attachment_uploads
                      (path, pentest_id, uploader_user_id, original_name, size, content_type, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (path, pid, client_id, original_name, size or 0, content_type, created_at),
                )
        conn.commit()
    except Exception:
        # ignore migration failures
        pass
    finally:
        conn.close()


def register_pentest_attachment_upload(
    uploader_user_id: str, original_name: str, path: str, size: int = 0, content_type: str = ""
) -> bool:
    ensure_pentest_attachment_uploads()
    conn = get_db()
    c = conn.cursor()
    c.execute(
        """
        INSERT OR REPLACE INTO pentest_attachment_uploads
          (path, pentest_id, uploader_user_id, original_name, size, content_type, created_at)
        VALUES (?, NULL, ?, ?, ?, ?, ?)
        """,
        (
            str(path),
            str(uploader_user_id),
            str(original_name or path),
            int(size or 0),
            str(content_type or ""),
            datetime.now().isoformat(),
        ),
    )
    conn.commit()
    conn.close()
    return True


def get_pentest_attachment_upload(path: str) -> Optional[Dict[str, Any]]:
    ensure_pentest_attachment_uploads()
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM pentest_attachment_uploads WHERE path = ? LIMIT 1", (str(path),))
    row = c.fetchone()
    conn.close()
    return dict_from_row(row)


def attach_pentest_uploads_to_pentest(uploader_user_id: str, pentest_id: str, paths: List[str]) -> List[Dict[str, Any]]:
    """
    Attach previously-uploaded files (owned by uploader_user_id) to a pentest.
    Only paths that belong to uploader_user_id will be attached.
    Returns the attached upload rows as dicts.
    """
    ensure_pentest_attachment_uploads()
    conn = get_db()
    c = conn.cursor()
    out: List[Dict[str, Any]] = []
    for p in paths or []:
        p = str(p or "").strip()
        if not p:
            continue
        c.execute(
            """
            UPDATE pentest_attachment_uploads
            SET pentest_id = ?
            WHERE path = ? AND uploader_user_id = ?
            """,
            (str(pentest_id), p, str(uploader_user_id)),
        )
        c.execute(
            "SELECT * FROM pentest_attachment_uploads WHERE path = ? AND uploader_user_id = ? AND pentest_id = ? LIMIT 1",
            (p, str(uploader_user_id), str(pentest_id)),
        )
        row = c.fetchone()
        if row:
            out.append(dict(row))
    conn.commit()
    conn.close()
    return out


# ============================================================
# USER OPERATIONS
# ============================================================

def hash_password(password: str) -> str:
    """Hash a password securely using bcrypt (falls back to SHA256 if bcrypt unavailable)."""
    if BCRYPT_AVAILABLE:
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    else:
        # Fallback to SHA256 (NOT recommended for production)
        env = (os.environ.get("FLASK_ENV") or os.environ.get("REDCON_ENV") or "").strip().lower()
        if env == "production":
            raise RuntimeError("bcrypt is required in production for password hashing")
        return "sha256$" + hashlib.sha256(password.encode()).hexdigest()


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against its hash."""
    if BCRYPT_AVAILABLE and password_hash.startswith('$2'):
        # bcrypt hash
        try:
            return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
        except Exception:
            return False
    else:
        # SHA256 fallback (legacy/dev only)
        if password_hash.startswith("sha256$"):
            digest = "sha256$" + hashlib.sha256(password.encode()).hexdigest()
            return hmac.compare_digest(digest, password_hash)
        # Legacy very old format (raw sha256 hex)
        digest_hex = hashlib.sha256(password.encode()).hexdigest()
        return hmac.compare_digest(digest_hex, password_hash)


def set_user_password(user_id: str, new_password: str) -> bool:
    """Set password for a PTaaS user (bcrypt in prod)."""
    new_hash = hash_password(new_password)
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE ptaas_users SET password_hash = ? WHERE id = ?", (new_hash, user_id))
    conn.commit()
    conn.close()
    return True


def revoke_token(jti: str, token_type: str = "refresh", expires_at: str = "") -> None:
    """Persist a revoked token jti."""
    ensure_security_tables()
    conn = get_db()
    c = conn.cursor()
    c.execute(
        "INSERT OR IGNORE INTO token_blacklist (jti, token_type, expires_at, created_at) VALUES (?, ?, ?, ?)",
        (jti, token_type, expires_at, datetime.now().isoformat()),
    )
    conn.commit()
    conn.close()


def is_token_revoked(jti: str) -> bool:
    ensure_security_tables()
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT 1 FROM token_blacklist WHERE jti = ?", (jti,))
    row = c.fetchone()
    conn.close()
    return bool(row)


def create_user(email: str, password: str, name: str, role: str = 'pentester', **kwargs) -> Optional[Dict]:
    """Create a new user."""
    conn = get_db()
    c = conn.cursor()

    user_id = str(uuid.uuid4())
    now = datetime.now().isoformat()

    try:
        c.execute('''
            INSERT INTO ptaas_users (id, email, password_hash, name, role, company, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, email, hash_password(password), name, role, kwargs.get('company', ''), now))

        conn.commit()

        return get_user_by_id(user_id)
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()


def authenticate_user(email: str, password: str) -> Optional[Dict]:
    """Authenticate a user using secure password verification."""
    conn = get_db()
    c = conn.cursor()

    # First get user by email only
    c.execute('SELECT * FROM ptaas_users WHERE email = ? AND is_active = 1', (email,))
    user = c.fetchone()

    if user:
        # Verify password using the secure verify function
        if verify_password(password, user['password_hash']):
            # Update last login
            c.execute('UPDATE ptaas_users SET last_login = ? WHERE id = ?',
                      (datetime.now().isoformat(), user['id']))
            conn.commit()
            conn.close()
            return dict_from_row(user)

    conn.close()
    return None


def get_user_by_id(user_id: str) -> Optional[Dict]:
    """Get user by ID."""
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM ptaas_users WHERE id = ?', (user_id,))
    user = c.fetchone()
    conn.close()
    return dict_from_row(user)


def get_user_by_email(email: str) -> Optional[Dict]:
    """Get user by email."""
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM ptaas_users WHERE email = ?', (email,))
    user = c.fetchone()
    conn.close()
    return dict_from_row(user)


def create_user_without_password(email: str, name: str, role: str = 'client', **kwargs) -> Optional[Dict]:
    """Create a user without password (for token-based setup)."""
    conn = get_db()
    c = conn.cursor()

    user_id = str(uuid.uuid4())
    now = datetime.now().isoformat()
    # Use a placeholder password hash that cannot be used for login
    placeholder_hash = "PENDING_SETUP_" + str(uuid.uuid4())

    try:
        c.execute('''
            INSERT INTO ptaas_users (id, email, password_hash, name, role, company, created_at, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?, 1)
        ''', (user_id, email, placeholder_hash, name, role, kwargs.get('company', ''), now))

        conn.commit()
        return get_user_by_id(user_id)
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()


def create_setup_token(user_id: str) -> Optional[str]:
    """Generate a setup token for user account setup."""
    conn = get_db()
    c = conn.cursor()

    token = str(uuid.uuid4())
    token_id = str(uuid.uuid4())
    now = datetime.now().isoformat()
    expires = (datetime.now() + timedelta(hours=24)).isoformat()

    try:
        c.execute('''
            INSERT INTO user_setup_tokens (id, user_id, token, created_at, expires_at, used)
            VALUES (?, ?, ?, ?, ?, 0)
        ''', (token_id, user_id, token, now, expires))
        conn.commit()
        return token
    except Exception:
        return None
    finally:
        conn.close()


def validate_setup_token(token: str) -> Optional[Dict]:
    """Validate a setup token and return user info if valid."""
    conn = get_db()
    c = conn.cursor()

    c.execute('''
        SELECT st.*, u.email, u.name, u.role
        FROM user_setup_tokens st
        JOIN ptaas_users u ON u.id = st.user_id
        WHERE st.token = ? AND st.used = 0
    ''', (token,))

    row = c.fetchone()
    conn.close()

    if not row:
        return None

    token_data = dict(row)

    # Check if expired
    try:
        expires = datetime.fromisoformat(token_data['expires_at'])
        if datetime.now() > expires:
            return None
    except Exception:
        return None

    return token_data


def complete_setup_token(token: str, new_password: str) -> bool:
    """Mark token as used and set user's password."""
    conn = get_db()
    c = conn.cursor()

    # Validate token first
    token_data = validate_setup_token(token)
    if not token_data:
        conn.close()
        return False

    user_id = token_data['user_id']
    now = datetime.now().isoformat()

    try:
        # Update password
        c.execute('''
            UPDATE ptaas_users
            SET password_hash = ?, is_active = 1
            WHERE id = ?
        ''', (hash_password(new_password), user_id))

        # Mark token as used
        c.execute('''
            UPDATE user_setup_tokens
            SET used = 1, used_at = ?
            WHERE token = ?
        ''', (now, token))

        conn.commit()
        return True
    except Exception:
        return False
    finally:
        conn.close()


def create_password_reset_token(email: str, ip_address: str = "", user_agent: str = "") -> Optional[tuple]:
    """Generate a password reset token. Returns (token, user) or None."""
    conn = get_db()
    c = conn.cursor()

    # Get user by email (case-insensitive)
    c.execute('SELECT * FROM ptaas_users WHERE LOWER(email) = LOWER(?)', (email,))
    user = c.fetchone()

    if not user:
        conn.close()
        return None

    user_dict = dict(user)
    token = str(uuid.uuid4())
    token_id = str(uuid.uuid4())
    now = datetime.now().isoformat()
    # Password reset tokens expire in 1 hour (more secure than 24h)
    expires = (datetime.now() + timedelta(hours=1)).isoformat()

    try:
        c.execute('''
            INSERT INTO password_reset_tokens (id, user_id, token, created_at, expires_at, used, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?, 0, ?, ?)
        ''', (token_id, user_dict['id'], token, now, expires, ip_address, user_agent))
        conn.commit()
        return (token, user_dict)
    except Exception:
        return None
    finally:
        conn.close()


def validate_password_reset_token(token: str) -> Optional[Dict]:
    """Validate a password reset token and return user info if valid."""
    conn = get_db()
    c = conn.cursor()

    c.execute('''
        SELECT rt.*, u.email, u.name, u.role
        FROM password_reset_tokens rt
        JOIN ptaas_users u ON u.id = rt.user_id
        WHERE rt.token = ? AND rt.used = 0 AND u.is_active = 1
    ''', (token,))

    row = c.fetchone()
    conn.close()

    if not row:
        return None

    token_data = dict(row)

    # Check if expired
    try:
        expires = datetime.fromisoformat(token_data['expires_at'])
        if datetime.now() > expires:
            return None
    except Exception:
        return None

    return token_data


def complete_password_reset(token: str, new_password: str) -> tuple[bool, Optional[str]]:
    """Reset password using token. Returns (success, user_email)."""
    conn = get_db()
    c = conn.cursor()

    # Validate token first
    token_data = validate_password_reset_token(token)
    if not token_data:
        conn.close()
        return (False, None)

    user_id = token_data['user_id']
    user_email = token_data['email']
    now = datetime.now().isoformat()

    try:
        # Update password
        c.execute('''
            UPDATE ptaas_users
            SET password_hash = ?
            WHERE id = ?
        ''', (hash_password(new_password), user_id))

        # Mark token as used
        c.execute('''
            UPDATE password_reset_tokens
            SET used = 1, used_at = ?
            WHERE token = ?
        ''', (now, token))

        # Invalidate any other pending reset tokens for this user (security)
        c.execute('''
            UPDATE password_reset_tokens
            SET used = 1, used_at = ?
            WHERE user_id = ? AND token != ? AND used = 0
        ''', (now, user_id, token))

        conn.commit()
        return (True, user_email)
    except Exception:
        return (False, None)
    finally:
        conn.close()


def check_rate_limit(identifier: str, action: str, max_attempts: int = 3, window_minutes: int = 15) -> bool:
    """Check if action is rate-limited. Returns True if allowed, False if blocked."""
    conn = get_db()
    c = conn.cursor()

    now = datetime.now()
    window_start = (now - timedelta(minutes=window_minutes)).isoformat()

    c.execute('''
        SELECT attempts, window_start FROM rate_limits
        WHERE identifier = ? AND action = ?
    ''', (identifier, action))

    row = c.fetchone()

    if not row:
        # First attempt - create record
        c.execute('''
            INSERT INTO rate_limits (id, identifier, action, attempts, window_start)
            VALUES (?, ?, ?, 1, ?)
        ''', (str(uuid.uuid4()), identifier, action, now.isoformat()))
        conn.commit()
        conn.close()
        return True

    record = dict(row)
    record_start = datetime.fromisoformat(record['window_start'])

    # Check if window expired - reset counter
    if record_start < datetime.fromisoformat(window_start):
        c.execute('''
            UPDATE rate_limits
            SET attempts = 1, window_start = ?
            WHERE identifier = ? AND action = ?
        ''', (now.isoformat(), identifier, action))
        conn.commit()
        conn.close()
        return True

    # Within window - check attempts
    if record['attempts'] >= max_attempts:
        conn.close()
        return False  # Blocked!

    # Increment attempts
    c.execute('''
        UPDATE rate_limits
        SET attempts = attempts + 1
        WHERE identifier = ? AND action = ?
    ''', (identifier, action))
    conn.commit()
    conn.close()
    return True


def update_user(user_id: str, **kwargs) -> bool:
    """Update user fields."""
    conn = get_db()
    c = conn.cursor()

    allowed_fields = ['name', 'company', 'avatar', 'phone', 'country', 'timezone', 'language',
                     'bio', 'skills', 'certifications', 'halls_of_fame',
                     'hourly_rate', 'is_available', 'auto_accept_invites',
                     'linkedin', 'twitter', 'github', 'website',
                     'notify_email_updates', 'notify_new_findings', 'notify_status_updates',
                     'notify_weekly_summary', 'notify_marketing',
                     'payment_method', 'payment_details',
                     'last_login', 'is_active']

    updates = []
    values = []
    for key, value in kwargs.items():
        if key in allowed_fields:
            updates.append(f'{key} = ?')
            values.append(value)

    if not updates:
        return False

    values.append(user_id)
    c.execute(f'UPDATE ptaas_users SET {", ".join(updates)} WHERE id = ?', values)
    conn.commit()
    conn.close()
    return True


def regenerate_api_token(user_id: str) -> str:
    """Generate a new API token for user."""
    token = str(uuid.uuid4())
    conn = get_db()
    c = conn.cursor()
    c.execute('UPDATE ptaas_users SET api_token = ? WHERE id = ?', (token, user_id))
    conn.commit()
    conn.close()
    return token


# ============================================================
# PENTEST OPERATIONS
# ============================================================

def create_pentest(client_id: str, title: str, type: str, **kwargs) -> Dict:
    """Create a new pentest."""
    ensure_public_ids()
    conn = get_db()
    c = conn.cursor()

    # Lock to avoid duplicate sequence IDs under concurrency
    try:
        c.execute("BEGIN IMMEDIATE")
    except Exception:
        pass

    pentest_id = str(uuid.uuid4())[:8]
    now = datetime.now().isoformat()

    # Get client info - handle None case
    client = get_user_by_id(client_id)
    company_name = kwargs.get('company_name') or (client.get('company') if client else None) or 'Unknown'

    # Keep existing internal number (back-compat)
    c.execute('SELECT COUNT(*) FROM pentests')
    count = c.fetchone()[0]
    pentest_number = f'PT{35000 + count}'

    # Generate friendly public_id: #PT_01, #PT_02, ...
    c.execute("SELECT public_id FROM pentests WHERE public_id IS NOT NULL AND public_id != ''")
    existing = [r[0] for r in c.fetchall()]
    max_n = 0
    for pid in existing:
        m = re.match(r"^#?PT_(\d+)$", str(pid))
        if m:
            try:
                max_n = max(max_n, int(m.group(1)))
            except Exception:
                pass
    public_id = f"#PT_{(max_n + 1):02d}"

    c.execute('''
        INSERT INTO pentests (id, pentest_number, public_id, title, description, client_id, company_name,
                             type, scope, targets, status, start_date, end_date,
                             payout_total, required_skills, compliance, created_at, updated_at, created_by,
                             objectives, technology_stack, environment_type, collaboration_preference,
                             sensitive_data, notes, priority, client_name, credential_type, credentials, attachments)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        pentest_id, pentest_number, public_id, title, kwargs.get('description', ''),
        client_id, company_name, type, kwargs.get('scope', ''), kwargs.get('targets', '[]'),
        kwargs.get('start_date'), kwargs.get('end_date'), kwargs.get('payout_total', 0),
        kwargs.get('required_skills', '[]'), kwargs.get('compliance', '[]'),
        now, now, client_id,
        kwargs.get('objectives', ''), kwargs.get('technology_stack', ''),
        kwargs.get('environment_type', ''), kwargs.get('collaboration_preference', ''),
        kwargs.get('sensitive_data', '[]'), kwargs.get('notes', ''),
        kwargs.get('priority', 'normal'), kwargs.get('client_name', ''),
        kwargs.get('credential_type', 'none'), kwargs.get('credentials', ''),
        kwargs.get('attachments', '[]')
    ))

    conn.commit()
    conn.close()

    return get_pentest_by_id(pentest_id)


def get_pentest_by_id(pentest_id: str) -> Optional[Dict]:
    """Get pentest by ID."""
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM pentests WHERE id = ?', (pentest_id,))
    pentest = c.fetchone()
    conn.close()
    return dict_from_row(pentest)


def get_pentests_for_client(client_id: str, status: str = None) -> List[Dict]:
    """Get all pentests for a client."""
    conn = get_db()
    c = conn.cursor()

    if status and status != 'all':
        c.execute('SELECT * FROM pentests WHERE client_id = ? AND status = ? ORDER BY created_at DESC',
                  (client_id, status))
    else:
        c.execute('SELECT * FROM pentests WHERE client_id = ? ORDER BY created_at DESC', (client_id,))

    pentests = c.fetchall()
    conn.close()
    return [dict_from_row(p) for p in pentests]


def get_pentests_for_pentester(pentester_id: str, status: str = None) -> List[Dict]:
    """Get all pentests assigned to a pentester."""
    conn = get_db()
    c = conn.cursor()

    query = '''
        SELECT p.*, pp.role as assignment_role, pp.status as assignment_status
        FROM pentests p
        JOIN pentest_pentesters pp ON p.id = pp.pentest_id
        WHERE pp.pentester_id = ? AND pp.status = 'accepted'
    '''

    if status and status != 'all':
        query += ' AND p.status = ?'
        c.execute(query + ' ORDER BY p.created_at DESC', (pentester_id, status))
    else:
        c.execute(query + ' ORDER BY p.created_at DESC', (pentester_id,))

    pentests = c.fetchall()
    conn.close()
    return [dict_from_row(p) for p in pentests]


def update_pentest(pentest_id: str, **kwargs) -> bool:
    """Update pentest fields."""
    conn = get_db()
    c = conn.cursor()

    allowed_fields = ['title', 'description', 'scope', 'targets', 'status',
                     'start_date', 'end_date', 'progress', 'payout_total', 'attachments']

    updates = ['updated_at = ?']
    values = [datetime.now().isoformat()]

    for key, value in kwargs.items():
        if key in allowed_fields:
            updates.append(f'{key} = ?')
            values.append(value)

    values.append(pentest_id)
    c.execute(f'UPDATE pentests SET {", ".join(updates)} WHERE id = ?', values)
    conn.commit()
    conn.close()
    return True


def archive_pentest(pentest_id: str) -> bool:
    """Archive a pentest (soft delete by changing status to 'archived')."""
    conn = get_db()
    c = conn.cursor()

    try:
        c.execute('''
            UPDATE pentests SET status = 'archived', updated_at = ? WHERE id = ?
        ''', (datetime.now().isoformat(), pentest_id))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error archiving pentest: {e}")
        return False
    finally:
        conn.close()


def delete_pentest(pentest_id: str) -> bool:
    """Permanently delete a pentest and all related data."""
    conn = get_db()
    c = conn.cursor()

    try:
        # Delete related records first
        c.execute('DELETE FROM pentest_pentesters WHERE pentest_id = ?', (pentest_id,))
        c.execute('DELETE FROM ptaas_findings WHERE pentest_id = ?', (pentest_id,))
        c.execute('DELETE FROM activity WHERE pentest_id = ?', (pentest_id,))
        c.execute('DELETE FROM feedback WHERE pentest_id = ?', (pentest_id,))
        c.execute('DELETE FROM reports WHERE pentest_id = ?', (pentest_id,))
        c.execute('DELETE FROM payments WHERE pentest_id = ?', (pentest_id,))

        # Delete the pentest
        c.execute('DELETE FROM pentests WHERE id = ?', (pentest_id,))

        conn.commit()
        return True
    except Exception as e:
        print(f"Error deleting pentest: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()


def assign_pentester(pentest_id: str, pentester_id: str, role: str = 'tester') -> bool:
    """Assign a pentester to a pentest. When admin assigns, it's auto-accepted."""
    conn = get_db()
    c = conn.cursor()

    assignment_id = str(uuid.uuid4())
    now = datetime.now().isoformat()

    try:
        # When admin assigns, set status to 'accepted' directly (not just invited)
        c.execute('''
            INSERT INTO pentest_pentesters (id, pentest_id, pentester_id, role, status, invited_at, accepted_at)
            VALUES (?, ?, ?, ?, 'accepted', ?, ?)
        ''', (assignment_id, pentest_id, pentester_id, role, now, now))

        conn.commit()
        conn.close()

        # Create notification after closing connection to avoid lock
        create_notification(pentester_id, 'pentest_assigned', 'New Pentest Assignment',
                          'You have been assigned to a pentest', f'/ptaas/pentest/{pentest_id}')

        return True
    except sqlite3.IntegrityError:
        conn.close()
        return False


def accept_pentest_invite(pentest_id: str, pentester_id: str) -> bool:
    """Accept a pentest invitation."""
    conn = get_db()
    c = conn.cursor()

    c.execute('''
        UPDATE pentest_pentesters SET status = 'accepted', accepted_at = ?
        WHERE pentest_id = ? AND pentester_id = ?
    ''', (datetime.now().isoformat(), pentest_id, pentester_id))

    conn.commit()
    conn.close()
    return True


# ============================================================
# POSTING OPERATIONS
# ============================================================

def create_posting(pentest_id: str, **kwargs) -> Dict:
    """Create a posting for a pentest."""
    conn = get_db()
    c = conn.cursor()

    posting_id = str(uuid.uuid4())[:8]
    pentest = get_pentest_by_id(pentest_id)

    c.execute('''
        INSERT INTO postings (id, pentest_id, title, company, description, type, payout,
                             duration, effort_hours, tags, required_skills, max_pentesters,
                             status, posted_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)
    ''', (
        posting_id, pentest_id, pentest['title'], pentest['company_name'],
        kwargs.get('description', pentest['description']), pentest['type'],
        kwargs.get('payout', pentest.get('payout_total', 0)),
        kwargs.get('duration', '2 weeks'), kwargs.get('effort_hours', 40),
        kwargs.get('tags', '[]'), kwargs.get('required_skills', pentest.get('required_skills', '[]')),
        kwargs.get('max_pentesters', 3), datetime.now().isoformat()
    ))

    conn.commit()
    conn.close()

    return get_posting_by_id(posting_id)


def get_posting_by_id(posting_id: str) -> Optional[Dict]:
    """Get posting by ID."""
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM postings WHERE id = ?', (posting_id,))
    posting = c.fetchone()
    conn.close()
    return dict_from_row(posting)


def get_open_postings() -> List[Dict]:
    """Get all open postings."""
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM postings WHERE status = 'open' ORDER BY posted_at DESC")
    postings = c.fetchall()
    conn.close()
    return [dict_from_row(p) for p in postings]


def apply_to_posting(posting_id: str, pentester_id: str, cover_letter: str = '') -> bool:
    """Apply to a posting."""
    conn = get_db()
    c = conn.cursor()

    app_id = str(uuid.uuid4())

    try:
        c.execute('''
            INSERT INTO posting_applications (id, posting_id, pentester_id, cover_letter, applied_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (app_id, posting_id, pentester_id, cover_letter, datetime.now().isoformat()))

        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


# ============================================================
# FINDING OPERATIONS
# ============================================================

def create_finding(pentest_id: str, pentester_id: str, title: str, description: str,
                   severity: str, **kwargs) -> Dict:
    """Create a new finding."""
    ensure_public_ids()
    conn = get_db()
    c = conn.cursor()

    finding_id = 'F' + str(uuid.uuid4())[:6].upper()
    # Always store timestamps in UTC with timezone info to avoid client-side TZ parsing bugs.
    now = datetime.now(timezone.utc).isoformat()

    # Resolve pentest public_id (assign if missing)
    c.execute("SELECT public_id FROM pentests WHERE id = ?", (pentest_id,))
    row = c.fetchone()
    pentest_public_id = (row["public_id"] if row and row["public_id"] else "") if row else ""
    if not pentest_public_id:
        # Backfill just in case
        try:
            conn.commit()
        except Exception:
            pass
        conn.close()
        ensure_public_ids()
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT public_id FROM pentests WHERE id = ?", (pentest_id,))
        row = c.fetchone()
        pentest_public_id = (row["public_id"] if row and row["public_id"] else "") if row else ""
        if not pentest_public_id:
            pentest_public_id = "PT_000"

    # Next per-pentest sequence for finding public_id: #PT_01_01
    c.execute("SELECT public_id FROM ptaas_findings WHERE pentest_id = ? AND public_id IS NOT NULL AND public_id != ''", (pentest_id,))
    ex = [r[0] for r in c.fetchall()]
    max_f = 0
    for fx in ex:
        # Strip # from pentest_public_id for regex matching
        pentest_id_clean = pentest_public_id.lstrip('#')
        m = re.match(rf"^#?{re.escape(pentest_id_clean)}_(\d+)$", str(fx))
        if m:
            try:
                max_f = max(max_f, int(m.group(1)))
            except Exception:
                pass
    finding_public_id = f"{pentest_public_id}_{(max_f + 1):02d}"

    c.execute('''
        INSERT INTO ptaas_findings (id, public_id, pentest_id, pentester_id, title, description, severity,
                                   cvss_score, cvss_vector, category, affected_url, affected_parameter,
                                   poc, steps_to_reproduce, impact, remediation, screenshots, attachments,
                                   status, cwe_id, reference_urls, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'new', ?, ?, ?, ?)
    ''', (
        finding_id, finding_public_id, pentest_id, pentester_id, title, description, severity,
        kwargs.get('cvss_score'), kwargs.get('cvss_vector'), kwargs.get('category', 'Other'),
        kwargs.get('affected_url'), kwargs.get('affected_parameter'),
        kwargs.get('poc'), kwargs.get('steps_to_reproduce'), kwargs.get('impact'),
        kwargs.get('remediation'),
        kwargs.get('screenshots', '[]'),
        kwargs.get('attachments', '[]'),
        kwargs.get('cwe_id'), kwargs.get('reference_urls', '[]'), now, now
    ))

    # Update pentester stats in same connection
    c.execute('UPDATE ptaas_users SET findings_submitted = findings_submitted + 1 WHERE id = ?',
              (pentester_id,))

    conn.commit()
    conn.close()

    # Call nested functions AFTER closing connection to avoid locks
    update_pentest_finding_counts(pentest_id)
    create_activity(pentester_id, 'finding_submitted', f'Submitted: {title}',
                   f'{severity} severity finding', pentest_id=pentest_id, finding_id=finding_id)

    return get_finding_by_id(finding_id)


def get_finding_by_id(finding_id: str) -> Optional[Dict]:
    """Get finding by ID."""
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM ptaas_findings WHERE id = ?', (finding_id,))
    finding = c.fetchone()
    conn.close()
    return dict_from_row(finding)


def get_findings_for_pentest(pentest_id: str) -> List[Dict]:
    """Get all findings for a pentest."""
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM ptaas_findings WHERE pentest_id = ? ORDER BY created_at DESC', (pentest_id,))
    findings = c.fetchall()
    conn.close()
    return [dict_from_row(f) for f in findings]


# ============================================================
# FINDING COMMENTS
# ============================================================

def create_finding_comment(finding_id: str, user_id: str, content: str, is_internal: bool = False) -> Dict:
    """Create a comment on a finding."""
    conn = get_db()
    c = conn.cursor()
    cid = "C" + str(uuid.uuid4())[:10]
    now = datetime.now(timezone.utc).isoformat()
    c.execute(
        """
        INSERT INTO finding_comments (id, finding_id, user_id, content, is_internal, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (cid, finding_id, user_id, content, 1 if is_internal else 0, now),
    )
    conn.commit()
    conn.close()
    return get_finding_comment_by_id(cid)


def get_finding_comment_by_id(comment_id: str) -> Optional[Dict]:
    """Get a single comment by id."""
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM finding_comments WHERE id = ?", (comment_id,))
    row = c.fetchone()
    conn.close()
    return dict_from_row(row)


def get_finding_comments(finding_id: str, include_internal: bool = False) -> List[Dict]:
    """Get comments for a finding (optionally include internal)."""
    conn = get_db()
    c = conn.cursor()
    if include_internal:
        c.execute(
            """
            SELECT fc.*, u.name as user_name, u.email as user_email, u.role as user_role
            FROM finding_comments fc
            JOIN ptaas_users u ON fc.user_id = u.id
            WHERE fc.finding_id = ?
            ORDER BY fc.created_at ASC
            """,
            (finding_id,),
        )
    else:
        c.execute(
            """
            SELECT fc.*, u.name as user_name, u.email as user_email, u.role as user_role
            FROM finding_comments fc
            JOIN ptaas_users u ON fc.user_id = u.id
            WHERE fc.finding_id = ? AND COALESCE(fc.is_internal, 0) = 0
            ORDER BY fc.created_at ASC
            """,
            (finding_id,),
        )
    rows = c.fetchall()
    conn.close()
    return [dict_from_row(r) for r in rows]


def delete_finding_comment(comment_id: str) -> bool:
    """Delete a comment by id."""
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM finding_comments WHERE id = ?", (comment_id,))
    deleted = c.rowcount > 0
    conn.commit()
    conn.close()
    return deleted


def get_findings_for_pentester(pentester_id: str, severity: str = None, status: str = None) -> List[Dict]:
    """Get all findings by a pentester."""
    conn = get_db()
    c = conn.cursor()

    query = 'SELECT f.*, p.title as pentest_title FROM ptaas_findings f JOIN pentests p ON f.pentest_id = p.id WHERE f.pentester_id = ?'
    params = [pentester_id]

    if severity and severity != 'all':
        query += ' AND f.severity = ?'
        params.append(severity)

    if status and status != 'all':
        query += ' AND f.status = ?'
        params.append(status)

    query += ' ORDER BY f.created_at DESC'
    c.execute(query, params)

    findings = c.fetchall()
    conn.close()
    return [dict_from_row(f) for f in findings]


def update_finding_status(finding_id: str, status: str, user_id: str = None, **kwargs) -> bool:
    """Update finding status."""
    conn = get_db()
    c = conn.cursor()

    now = datetime.now().isoformat()

    updates = ['status = ?', 'updated_at = ?']
    values = [status, now]

    if status == 'triaged':
        updates.extend(['triaged_at = ?', 'triaged_by = ?'])
        values.extend([now, user_id])
    elif status == 'fixed':
        updates.append('fixed_at = ?')
        values.append(now)
    elif status == 'verified':
        updates.extend(['verified_at = ?', 'verified_by = ?'])
        values.extend([now, user_id])

    if 'client_response' in kwargs:
        updates.append('client_response = ?')
        values.append(kwargs['client_response'])

    values.append(finding_id)
    c.execute(f'UPDATE ptaas_findings SET {", ".join(updates)} WHERE id = ?', values)

    # Get finding info for activity (using same connection to avoid lock)
    c.execute('SELECT title, pentest_id FROM ptaas_findings WHERE id = ?', (finding_id,))
    finding_row = c.fetchone()

    # Commit and close before calling other functions that open connections
    conn.commit()
    conn.close()

    # Now create activity (after connection is closed)
    if finding_row:
        finding_title = finding_row[0] if finding_row else 'Unknown'
        pentest_id = finding_row[1] if finding_row else None
        create_activity(user_id, f'finding_{status}', f'Finding {status}: {finding_title}',
                       f'Status changed to {status}', pentest_id=pentest_id, finding_id=finding_id)

    return True


def update_pentest_finding_counts(pentest_id: str):
    """Update finding counts for a pentest."""
    conn = get_db()
    c = conn.cursor()

    c.execute('''
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
            SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
            SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
            SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low,
            SUM(CASE WHEN severity = 'info' THEN 1 ELSE 0 END) as info
        FROM ptaas_findings WHERE pentest_id = ?
    ''', (pentest_id,))

    counts = c.fetchone()

    c.execute('''
        UPDATE pentests SET total_findings = ?, critical_count = ?, high_count = ?,
                           medium_count = ?, low_count = ?, info_count = ?, updated_at = ?
        WHERE id = ?
    ''', (counts['total'], counts['critical'], counts['high'], counts['medium'],
          counts['low'], counts['info'], datetime.now().isoformat(), pentest_id))

    conn.commit()
    conn.close()


# ============================================================
# ACTIVITY & NOTIFICATIONS
# ============================================================

def create_activity(user_id: str, type: str, title: str, description: str = '',
                   pentest_id: str = None, finding_id: str = None) -> str:
    """Create an activity entry."""
    conn = get_db()
    c = conn.cursor()

    activity_id = str(uuid.uuid4())

    icons = {
        'finding_submitted': '🔍',
        'finding_accepted': '✅',
        'finding_rejected': '❌',
        'finding_triaged': '📋',
        'finding_fixed': '🔧',
        'finding_verified': '✓',
        'pentest_started': '🚀',
        'pentest_completed': '🏆',
        'comment_added': '💬',
        'payout_received': '💰'
    }

    c.execute('''
        INSERT INTO activity (id, user_id, pentest_id, finding_id, type, title, description, icon, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (activity_id, user_id, pentest_id, finding_id, type, title, description,
          icons.get(type, '📌'), datetime.now().isoformat()))

    conn.commit()
    conn.close()

    return activity_id


def get_activity_for_user(user_id: str, limit: int = 50) -> List[Dict]:
    """Get activity feed for a user."""
    conn = get_db()
    c = conn.cursor()

    c.execute('''
        SELECT * FROM activity
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT ?
    ''', (user_id, limit))

    activities = c.fetchall()
    conn.close()
    return [dict_from_row(a) for a in activities]


def create_notification(user_id: str, type: str, title: str, message: str = '', link: str = '') -> str:
    """Create a notification."""
    conn = get_db()
    c = conn.cursor()

    notif_id = str(uuid.uuid4())

    c.execute('''
        INSERT INTO notifications (id, user_id, type, title, message, link, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (notif_id, user_id, type, title, message, link, datetime.now(timezone.utc).isoformat()))

    conn.commit()
    conn.close()

    return notif_id


def get_notifications(user_id: str, unread_only: bool = False) -> List[Dict]:
    """Get notifications for a user."""
    conn = get_db()
    c = conn.cursor()

    query = 'SELECT * FROM notifications WHERE user_id = ?'
    if unread_only:
        query += ' AND is_read = 0'
    query += ' ORDER BY created_at DESC LIMIT 50'

    c.execute(query, (user_id,))
    notifications = c.fetchall()
    conn.close()
    return [dict_from_row(n) for n in notifications]


def mark_notification_read(notification_id: str) -> bool:
    """Mark a notification as read."""
    conn = get_db()
    c = conn.cursor()
    c.execute('UPDATE notifications SET is_read = 1 WHERE id = ?', (notification_id,))
    conn.commit()
    conn.close()
    return True


def mark_all_notifications_read(user_id: str) -> bool:
    """Mark all notifications as read for a user."""
    conn = get_db()
    c = conn.cursor()
    c.execute('UPDATE notifications SET is_read = 1 WHERE user_id = ?', (user_id,))
    conn.commit()
    conn.close()
    return True


# ============================================================
# FEEDBACK OPERATIONS
# ============================================================

def create_feedback(pentest_id: str, pentester_id: str, client_id: str,
                   overall_rating: int, **kwargs) -> Dict:
    """Create feedback for a pentester."""
    conn = get_db()
    c = conn.cursor()

    feedback_id = str(uuid.uuid4())

    c.execute('''
        INSERT INTO feedback (id, pentest_id, pentester_id, client_id, overall_rating,
                             communication_rating, quality_rating, timeliness_rating,
                             professionalism_rating, comment, strengths, improvements, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        feedback_id, pentest_id, pentester_id, client_id, overall_rating,
        kwargs.get('communication_rating'), kwargs.get('quality_rating'),
        kwargs.get('timeliness_rating'), kwargs.get('professionalism_rating'),
        kwargs.get('comment'), kwargs.get('strengths', '[]'), kwargs.get('improvements', '[]'),
        datetime.now().isoformat()
    ))

    # Update pentester rating
    c.execute('''
        SELECT AVG(overall_rating) as avg_rating, COUNT(*) as count
        FROM feedback WHERE pentester_id = ?
    ''', (pentester_id,))
    result = c.fetchone()

    c.execute('UPDATE ptaas_users SET rating = ?, rating_count = ? WHERE id = ?',
              (result['avg_rating'], result['count'], pentester_id))

    conn.commit()
    conn.close()

    return get_feedback_by_id(feedback_id)


def get_feedback_by_id(feedback_id: str) -> Optional[Dict]:
    """Get feedback by ID."""
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM feedback WHERE id = ?', (feedback_id,))
    feedback = c.fetchone()
    conn.close()
    return dict_from_row(feedback)


def get_feedback_for_pentester(pentester_id: str) -> List[Dict]:
    """Get all feedback for a pentester."""
    conn = get_db()
    c = conn.cursor()
    c.execute('''
        SELECT f.*, p.title as pentest_title, u.name as client_name, u.company as client_company, u.role as client_role
        FROM feedback f
        JOIN pentests p ON f.pentest_id = p.id
        JOIN ptaas_users u ON f.client_id = u.id
        WHERE f.pentester_id = ?
        ORDER BY f.created_at DESC
    ''', (pentester_id,))
    feedback = c.fetchall()
    conn.close()
    return [dict_from_row(f) for f in feedback]


# ============================================================
# REPORT OPERATIONS
# ============================================================

def create_report(pentest_id: str, type: str, title: str, file_url: str = '',
                 generated_by: str = None) -> Dict:
    """Create a report record."""
    conn = get_db()
    c = conn.cursor()

    report_id = str(uuid.uuid4())
    pentest = get_pentest_by_id(pentest_id)

    findings_count = int(pentest.get('total_findings', 0) or 0) if pentest else 0
    critical_count = int(pentest.get('critical_count', 0) or 0) if pentest else 0
    high_count = int(pentest.get('high_count', 0) or 0) if pentest else 0
    medium_count = int(pentest.get('medium_count', 0) or 0) if pentest else 0
    low_count = int(pentest.get('low_count', 0) or 0) if pentest else 0

    c.execute(
        '''
        INSERT INTO reports (
            id, pentest_id, type, title, file_url, file_size,
            findings_count, critical_count, high_count, medium_count, low_count,
            generated_at, generated_by
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''',
        (
            report_id,
            pentest_id,
            type,
            title,
            file_url,
            None,
            findings_count,
            critical_count,
            high_count,
            medium_count,
            low_count,
            datetime.now(timezone.utc).isoformat(),
            generated_by,
        ),
    )

    conn.commit()
    conn.close()

    return get_report_by_id(report_id)


def update_report_file(report_id: str, file_url: str, file_size: int) -> bool:
    """Update report file URL/size."""
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE reports SET file_url = ?, file_size = ? WHERE id = ?", (file_url, int(file_size or 0), report_id))
    ok = c.rowcount > 0
    conn.commit()
    conn.close()
    return ok


def get_latest_report_for_pentest(pentest_id: str, type: str = "full") -> Optional[Dict]:
    """Get latest report for a pentest."""
    conn = get_db()
    c = conn.cursor()
    c.execute(
        "SELECT * FROM reports WHERE pentest_id = ? AND type = ? ORDER BY generated_at DESC LIMIT 1",
        (pentest_id, type),
    )
    row = c.fetchone()
    conn.close()
    return dict_from_row(row)


def get_report_by_id(report_id: str) -> Optional[Dict]:
    """Get report by ID."""
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM reports WHERE id = ?', (report_id,))
    report = c.fetchone()
    conn.close()
    return dict_from_row(report)


def get_reports_for_pentester(pentester_id: str) -> List[Dict]:
    """Get reports for pentests the pentester worked on."""
    conn = get_db()
    c = conn.cursor()
    c.execute('''
        SELECT r.*, p.title as pentest_title
        FROM reports r
        JOIN pentests p ON r.pentest_id = p.id
        JOIN pentest_pentesters pp ON p.id = pp.pentest_id
        WHERE pp.pentester_id = ? AND pp.status = 'accepted'
        ORDER BY r.generated_at DESC
    ''', (pentester_id,))
    reports = c.fetchall()
    conn.close()
    return [dict_from_row(r) for r in reports]


# ============================================================
# PAYMENT OPERATIONS
# ============================================================

def create_payment(user_id: str, type: str, amount: float, **kwargs) -> Dict:
    """Create a payment record."""
    conn = get_db()
    c = conn.cursor()

    payment_id = str(uuid.uuid4())

    c.execute('''
        INSERT INTO payments (id, user_id, pentest_id, finding_id, type, amount,
                             currency, status, description, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
    ''', (
        payment_id, user_id, kwargs.get('pentest_id'), kwargs.get('finding_id'),
        type, amount, kwargs.get('currency', 'USD'), kwargs.get('description', ''),
        datetime.now().isoformat()
    ))

    conn.commit()
    conn.close()

    return get_payment_by_id(payment_id)


def get_payment_by_id(payment_id: str) -> Optional[Dict]:
    """Get payment by ID."""
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM payments WHERE id = ?', (payment_id,))
    payment = c.fetchone()
    conn.close()
    return dict_from_row(payment)


def get_payments_for_user(user_id: str) -> List[Dict]:
    """Get all payments for a user."""
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM payments WHERE user_id = ? ORDER BY created_at DESC', (user_id,))
    payments = c.fetchall()
    conn.close()
    return [dict_from_row(p) for p in payments]


def get_pentester_earnings(pentester_id: str) -> Dict:
    """Get earnings summary for a pentester."""
    conn = get_db()
    c = conn.cursor()

    # Total earnings
    c.execute('''
        SELECT
            COALESCE(SUM(CASE WHEN status = 'completed' THEN amount ELSE 0 END), 0) as total_earned,
            COALESCE(SUM(CASE WHEN status = 'pending' THEN amount ELSE 0 END), 0) as pending,
            COALESCE(SUM(CASE WHEN status = 'completed' AND created_at >= date('now', '-30 days') THEN amount ELSE 0 END), 0) as last_30_days
        FROM payments WHERE user_id = ? AND type = 'payout'
    ''', (pentester_id,))

    result = c.fetchone()
    conn.close()

    return {
        'total_earned': result['total_earned'] or 0,
        'pending': result['pending'] or 0,
        'last_30_days': result['last_30_days'] or 0
    }


# ============================================================
# DASHBOARD STATS
# ============================================================

def get_pentester_stats(pentester_id: str) -> Dict:
    """Get dashboard stats for a pentester."""
    conn = get_db()
    c = conn.cursor()

    # Active pentests
    c.execute('''
        SELECT COUNT(*) FROM pentests p
        JOIN pentest_pentesters pp ON p.id = pp.pentest_id
        WHERE pp.pentester_id = ? AND pp.status = 'accepted' AND p.status IN ('live', 'planned')
    ''', (pentester_id,))
    active_pentests = c.fetchone()[0]

    # Findings stats
    c.execute('''
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
            SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
            SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
            SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low,
            SUM(CASE WHEN status = 'accepted' THEN 1 ELSE 0 END) as accepted
        FROM ptaas_findings WHERE pentester_id = ?
    ''', (pentester_id,))
    findings = c.fetchone()

    # Unread notifications
    c.execute('SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0',
              (pentester_id,))
    unread_notifications = c.fetchone()[0]

    # Pending invites
    c.execute('''
        SELECT COUNT(*) FROM pentest_pentesters
        WHERE pentester_id = ? AND status = 'invited'
    ''', (pentester_id,))
    pending_invites = c.fetchone()[0]

    conn.close()

    earnings = get_pentester_earnings(pentester_id)

    return {
        'active_pentests': active_pentests,
        'total_findings': findings['total'] or 0,
        'critical_findings': findings['critical'] or 0,
        'high_findings': findings['high'] or 0,
        'medium_findings': findings['medium'] or 0,
        'low_findings': findings['low'] or 0,
        'accepted_findings': findings['accepted'] or 0,
        'acceptance_rate': round((findings['accepted'] or 0) / max(findings['total'] or 1, 1) * 100),
        'unread_notifications': unread_notifications,
        'pending_invites': pending_invites,
        **earnings
    }


def get_client_stats(client_id: str) -> Dict:
    """Get dashboard stats for a client."""
    conn = get_db()
    c = conn.cursor()

    # Pentests by status
    c.execute('''
        SELECT status, COUNT(*) as count FROM pentests
        WHERE client_id = ? GROUP BY status
    ''', (client_id,))
    status_counts = {row['status']: row['count'] for row in c.fetchall()}

    # Total findings across all pentests
    c.execute('''
        SELECT
            COALESCE(SUM(total_findings), 0) as total,
            COALESCE(SUM(critical_count), 0) as critical,
            COALESCE(SUM(high_count), 0) as high,
            COALESCE(SUM(medium_count), 0) as medium,
            COALESCE(SUM(low_count), 0) as low
        FROM pentests WHERE client_id = ?
    ''', (client_id,))
    findings = c.fetchone()

    # Credits
    c.execute('SELECT credits FROM ptaas_users WHERE id = ?', (client_id,))
    user = c.fetchone()

    # Assets count
    c.execute('SELECT COUNT(*) as cnt FROM assets WHERE client_id = ?', (client_id,))
    assets_row = c.fetchone()

    conn.close()

    return {
        'active_pentests': status_counts.get('live', 0) + status_counts.get('planned', 0),
        'completed_pentests': status_counts.get('completed', 0),
        'in_remediation': status_counts.get('remediation', 0),
        'total_findings': findings['total'] or 0,
        'critical_findings': findings['critical'] or 0,
        'high_findings': findings['high'] or 0,
        'medium_findings': findings['medium'] or 0,
        'low_findings': findings['low'] or 0,
        'credits': user['credits'] if user else 0,
        'assets_count': assets_row['cnt'] if assets_row else 0
    }


# ============================================================
# SEED DATA FOR DEMO
# ============================================================

def seed_demo_data():
    """Seed database with demo data for testing."""
    conn = get_db()
    c = conn.cursor()

    # Check if already seeded
    c.execute('SELECT COUNT(*) FROM ptaas_users')
    if c.fetchone()[0] > 0:
        conn.close()
        print("[PTaaS DB] Demo data already exists")
        return

    now = datetime.now()

    # Create demo pentester
    pentester_id = 'demo-pentester'
    c.execute('''
        INSERT INTO ptaas_users (id, email, password_hash, name, role, company, bio, skills,
                                certifications, rating, verified, country, created_at)
        VALUES (?, ?, ?, ?, 'pentester', 'REDCON OFFENCE', ?, ?, ?, 4.8, 1, 'Turkey', ?)
    ''', (
        pentester_id, 'pentester@redconoffence.com', hash_password('demo123'),
        'Demo Pentester', 'Experienced security researcher specializing in web and mobile applications.',
        '["Web Security", "Mobile Security", "API Testing", "Cloud Security"]',
        '["OSCP", "CEH", "GWAPT"]', now.isoformat()
    ))

    # Create demo client
    client_id = 'demo-client'
    c.execute('''
        INSERT INTO ptaas_users (id, email, password_hash, name, role, company, credits, created_at)
        VALUES (?, ?, ?, ?, 'client', 'TechCorp Inc.', 500, ?)
    ''', (
        client_id, 'client@example.com', hash_password('demo123'),
        'Demo Client', now.isoformat()
    ))

    # Create admin
    admin_id = 'admin'
    c.execute('''
        INSERT INTO ptaas_users (id, email, password_hash, name, role, company, created_at)
        VALUES (?, ?, ?, ?, 'admin', 'REDCON OFFENCE', ?)
    ''', (
        admin_id, 'admin@redconoffence.com', hash_password('admin123'),
        'Platform Admin', now.isoformat()
    ))

    conn.commit()

    # Create demo pentests
    pentests = [
        {
            'id': 'pt35001',
            'title': 'TechCorp E-commerce Platform',
            'type': 'comprehensive',
            'status': 'live',
            'start_date': (now - timedelta(days=5)).strftime('%Y-%m-%d'),
            'end_date': (now + timedelta(days=9)).strftime('%Y-%m-%d'),
            'progress': 65
        },
        {
            'id': 'pt35002',
            'title': 'Mobile Banking Application',
            'type': 'mobile',
            'status': 'planned',
            'start_date': (now + timedelta(days=7)).strftime('%Y-%m-%d'),
            'end_date': (now + timedelta(days=21)).strftime('%Y-%m-%d'),
            'progress': 0
        },
        {
            'id': 'pt35003',
            'title': 'Payment Gateway API',
            'type': 'api',
            'status': 'live',
            'start_date': (now - timedelta(days=10)).strftime('%Y-%m-%d'),
            'end_date': (now + timedelta(days=4)).strftime('%Y-%m-%d'),
            'progress': 80
        },
        {
            'id': 'pt35004',
            'title': 'Cloud Infrastructure Assessment',
            'type': 'cloud',
            'status': 'remediation',
            'start_date': (now - timedelta(days=20)).strftime('%Y-%m-%d'),
            'end_date': (now - timedelta(days=6)).strftime('%Y-%m-%d'),
            'progress': 100
        },
        {
            'id': 'pt35005',
            'title': 'Internal Network Pentest',
            'type': 'network',
            'status': 'completed',
            'start_date': (now - timedelta(days=45)).strftime('%Y-%m-%d'),
            'end_date': (now - timedelta(days=31)).strftime('%Y-%m-%d'),
            'progress': 100
        }
    ]

    for pt in pentests:
        c.execute('''
            INSERT INTO pentests (id, pentest_number, title, description, client_id, company_name,
                                 type, status, start_date, end_date, progress, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 'TechCorp Inc.', ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            pt['id'], f"#{pt['id'].upper()}", pt['title'],
            f"Security assessment of {pt['title']}", client_id,
            pt['type'], pt['status'], pt['start_date'], pt['end_date'], pt['progress'],
            now.isoformat(), now.isoformat()
        ))

        # Assign pentester
        c.execute('''
            INSERT INTO pentest_pentesters (id, pentest_id, pentester_id, role, status, accepted_at)
            VALUES (?, ?, ?, 'tester', 'accepted', ?)
        ''', (str(uuid.uuid4()), pt['id'], pentester_id, now.isoformat()))

    conn.commit()

    # Create demo findings
    findings = [
        {
            'pentest_id': 'pt35001',
            'title': 'SQL Injection in Product Search',
            'severity': 'critical',
            'status': 'new',
            'category': 'Injection',
            'cvss_score': 9.8
        },
        {
            'pentest_id': 'pt35001',
            'title': 'Stored XSS in User Comments',
            'severity': 'high',
            'status': 'triaged',
            'category': 'XSS',
            'cvss_score': 7.5
        },
        {
            'pentest_id': 'pt35003',
            'title': 'Broken Authentication in API',
            'severity': 'critical',
            'status': 'accepted',
            'category': 'Authentication',
            'cvss_score': 9.1
        },
        {
            'pentest_id': 'pt35003',
            'title': 'IDOR in Transaction History',
            'severity': 'high',
            'status': 'triaged',
            'category': 'Access Control',
            'cvss_score': 8.2
        },
        {
            'pentest_id': 'pt35004',
            'title': 'Exposed S3 Bucket with Sensitive Data',
            'severity': 'critical',
            'status': 'fixed',
            'category': 'Cloud Security',
            'cvss_score': 9.5
        },
        {
            'pentest_id': 'pt35004',
            'title': 'Overly Permissive IAM Policies',
            'severity': 'high',
            'status': 'fixed',
            'category': 'Cloud Security',
            'cvss_score': 8.0
        },
        {
            'pentest_id': 'pt35004',
            'title': 'Missing CloudTrail Logging',
            'severity': 'medium',
            'status': 'verified',
            'category': 'Logging',
            'cvss_score': 5.5
        }
    ]

    for i, f in enumerate(findings):
        finding_id = f'F{35000 + i}'
        c.execute('''
            INSERT INTO ptaas_findings (id, pentest_id, pentester_id, title, description, severity,
                                       status, category, cvss_score, poc, remediation, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            finding_id, f['pentest_id'], pentester_id, f['title'],
            f"Detailed description of {f['title']}. This vulnerability was discovered during routine testing.",
            f['severity'], f['status'], f['category'], f['cvss_score'],
            f"Steps to reproduce {f['title']}:\n1. Navigate to the affected endpoint\n2. Inject payload\n3. Observe the result",
            f"Recommended fix for {f['title']}",
            (now - timedelta(hours=i*5)).isoformat(), now.isoformat()
        ))

    conn.commit()  # Commit findings before updating counts
    conn.close()

    # Update finding counts (this gets its own connection)
    for pt in pentests:
        update_pentest_finding_counts(pt['id'])

    # Reconnect for remaining operations
    conn = get_db()
    c = conn.cursor()

    # Create demo postings
    postings = [
        {
            'title': 'Healthcare SaaS Platform',
            'company': 'MedTech Solutions',
            'type': 'web',
            'payout': 4500,
            'duration': '2 weeks',
            'effort_hours': 40,
            'tags': '["React", "Node.js", "PostgreSQL", "AWS", "HIPAA"]'
        },
        {
            'title': 'Crypto Trading Platform',
            'company': 'CryptoExchange Inc',
            'type': 'web',
            'payout': 6000,
            'duration': '3 weeks',
            'effort_hours': 60,
            'tags': '["Blockchain", "Smart Contracts", "API", "PCI-DSS"]'
        },
        {
            'title': 'Mobile Banking App',
            'company': 'SecureBank Corp',
            'type': 'mobile',
            'payout': 5500,
            'duration': '2 weeks',
            'effort_hours': 45,
            'tags': '["iOS", "Android", "REST API", "PCI-DSS"]'
        }
    ]

    for i, p in enumerate(postings):
        c.execute('''
            INSERT INTO postings (id, pentest_id, title, company, type, payout, duration,
                                 effort_hours, tags, status, posted_at, is_featured)
            VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)
        ''', (
            f'post{i+1}', p['title'], p['company'], p['type'], p['payout'],
            p['duration'], p['effort_hours'], p['tags'],
            (now - timedelta(hours=i*3)).isoformat(), 1 if i == 0 else 0
        ))

    # Create demo feedback
    c.execute('''
        INSERT INTO feedback (id, pentest_id, pentester_id, client_id, overall_rating,
                             communication_rating, quality_rating, timeliness_rating,
                             professionalism_rating, comment, strengths, improvements, created_at)
        VALUES (?, 'pt35005', ?, ?, 5, 5, 5, 4, 5,
                'Excellent work! Found critical vulnerabilities that our internal team missed.',
                '["Thorough testing", "Clear reports", "Professional communication"]',
                '["Slightly delayed on final report"]', ?)
    ''', (str(uuid.uuid4()), pentester_id, client_id, (now - timedelta(days=30)).isoformat()))

    # Create demo activity
    activities = [
        ('finding_submitted', 'Submitted: SQL Injection in Product Search', 'Critical severity finding'),
        ('finding_accepted', 'Finding Accepted: Exposed S3 Bucket', 'Payout: $500'),
        ('finding_fixed', 'Finding Fixed: Missing CloudTrail Logging', 'Client confirmed fix'),
        ('payout_received', 'Payout Received', '$1,200 for Cloud Infrastructure Assessment'),
    ]

    for i, (type, title, desc) in enumerate(activities):
        c.execute('''
            INSERT INTO activity (id, user_id, type, title, description, icon, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            str(uuid.uuid4()), pentester_id, type, title, desc,
            {'finding_submitted': '🔍', 'finding_accepted': '✅', 'finding_fixed': '🔧', 'payout_received': '💰'}[type],
            (now - timedelta(hours=i*2)).isoformat()
        ))

    # Create demo notifications
    c.execute('''
        INSERT INTO notifications (id, user_id, type, title, message, link, created_at)
        VALUES (?, ?, 'finding_triaged', 'Finding Triaged', 'Your finding "Stored XSS" has been triaged', '/ptaas/findings', ?)
    ''', (str(uuid.uuid4()), pentester_id, (now - timedelta(hours=1)).isoformat()))

    conn.commit()
    conn.close()

    print("[PTaaS DB] Demo data seeded successfully")
    print("[PTaaS DB] Demo accounts:")
    print("  - Pentester: pentester@redconoffence.com / demo123")
    print("  - Client: client@example.com / demo123")
    print("  - Admin: admin@redconoffence.com / admin123")




# ============================================================
# COVERAGE CHECKLIST MANAGEMENT
# ============================================================

def get_default_checklist(asset_type: str = 'web') -> List[Dict]:
    """Get default checklist items based on asset type."""
    checklists = {
        'web': [
            {'category': 'Authentication', 'items': [
                {'item': 'Password brute force protection', 'description': 'Test for account lockout and rate limiting'},
                {'item': 'Session management', 'description': 'Test session fixation, timeout, logout'},
                {'item': 'Multi-factor authentication', 'description': 'Test MFA implementation if present'},
                {'item': 'Password policy enforcement', 'description': 'Test password complexity requirements'},
            ]},
            {'category': 'Authorization', 'items': [
                {'item': 'Horizontal privilege escalation', 'description': 'Access other users data'},
                {'item': 'Vertical privilege escalation', 'description': 'Escalate to admin/higher roles'},
                {'item': 'IDOR vulnerabilities', 'description': 'Insecure direct object references'},
                {'item': 'API authorization', 'description': 'Test API endpoint access controls'},
            ]},
            {'category': 'Input Validation', 'items': [
                {'item': 'SQL Injection', 'description': 'Test all input fields for SQLi'},
                {'item': 'Cross-Site Scripting (XSS)', 'description': 'Test for reflected, stored, DOM XSS'},
                {'item': 'Command Injection', 'description': 'Test for OS command injection'},
                {'item': 'Path Traversal', 'description': 'Test for directory traversal'},
                {'item': 'File Upload', 'description': 'Test file upload restrictions'},
            ]},
            {'category': 'Cryptography', 'items': [
                {'item': 'HTTPS implementation', 'description': 'Test SSL/TLS configuration'},
                {'item': 'Sensitive data encryption', 'description': 'Verify encryption at rest'},
                {'item': 'Cookie security flags', 'description': 'Test Secure, HttpOnly, SameSite'},
            ]},
            {'category': 'Configuration', 'items': [
                {'item': 'Security headers', 'description': 'Test CSP, X-Frame-Options, HSTS'},
                {'item': 'Error handling', 'description': 'Check for information leakage'},
                {'item': 'Default credentials', 'description': 'Test for default admin credentials'},
            ]},
            {'category': 'Business Logic', 'items': [
                {'item': 'Workflow bypass', 'description': 'Test for skipping required steps'},
                {'item': 'Rate limiting bypass', 'description': 'Test rate limit implementation'},
                {'item': 'Price/quantity manipulation', 'description': 'Test e-commerce logic if applicable'},
            ]},
        ],
        'api': [
            {'category': 'Authentication', 'items': [
                {'item': 'API key security', 'description': 'Test API key exposure and rotation'},
                {'item': 'JWT validation', 'description': 'Test JWT implementation vulnerabilities'},
                {'item': 'OAuth implementation', 'description': 'Test OAuth flow security'},
            ]},
            {'category': 'Authorization', 'items': [
                {'item': 'Broken Object Level Authorization', 'description': 'BOLA/IDOR testing'},
                {'item': 'Broken Function Level Authorization', 'description': 'Admin function access'},
                {'item': 'Resource-based access control', 'description': 'Test resource ownership'},
            ]},
            {'category': 'Data Exposure', 'items': [
                {'item': 'Excessive data exposure', 'description': 'API returning too much data'},
                {'item': 'Mass assignment', 'description': 'Test for mass assignment vulnerabilities'},
                {'item': 'Sensitive data in URLs', 'description': 'Check for sensitive data in GET params'},
            ]},
            {'category': 'Rate Limiting', 'items': [
                {'item': 'API rate limiting', 'description': 'Test rate limit implementation'},
                {'item': 'Resource consumption', 'description': 'Test for DoS via resource consumption'},
            ]},
        ],
    }

    return checklists.get(asset_type, checklists['web'])


def create_coverage_items_for_pentest(pentest_id: str, asset_type: str = 'web') -> int:
    """Create default checklist items for a pentest."""
    checklist = get_default_checklist(asset_type)
    now = datetime.now().isoformat()

    conn = get_db()
    c = conn.cursor()

    count = 0
    for category in checklist:
        for item in category['items']:
            item_id = str(uuid.uuid4())[:8].upper()
            c.execute('''
                INSERT INTO coverage_checklist (id, pentest_id, category, item, description, status, created_at)
                VALUES (?, ?, ?, ?, ?, 'pending', ?)
            ''', (item_id, pentest_id, category['category'], item['item'], item['description'], now))
            count += 1

    conn.commit()
    conn.close()

    return count


def get_coverage_for_pentest(pentest_id: str) -> List[Dict]:
    """Get coverage checklist for a pentest."""
    conn = get_db()
    c = conn.cursor()

    c.execute('''
        SELECT * FROM coverage_checklist
        WHERE pentest_id = ?
        ORDER BY category, created_at
    ''', (pentest_id,))

    items = [dict(row) for row in c.fetchall()]
    conn.close()

    return items


def update_coverage_item(item_id: str, pentester_id: str, status: str, notes: str = None) -> bool:
    """Update a coverage checklist item."""
    conn = get_db()
    c = conn.cursor()

    now = datetime.now().isoformat()

    if status == 'completed':
        c.execute('''
            UPDATE coverage_checklist
            SET status = ?, notes = ?, completed_by = ?, completed_at = ?
            WHERE id = ?
        ''', (status, notes, pentester_id, now, item_id))
    else:
        c.execute('''
            UPDATE coverage_checklist
            SET status = ?, notes = ?, completed_by = NULL, completed_at = NULL
            WHERE id = ?
        ''', (status, notes, item_id))

    conn.commit()
    conn.close()

    return True


def get_coverage_stats(pentest_id: str) -> Dict:
    """Get coverage statistics for a pentest."""
    conn = get_db()
    c = conn.cursor()

    c.execute('''
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
            SUM(CASE WHEN status = 'in_progress' THEN 1 ELSE 0 END) as in_progress,
            SUM(CASE WHEN status = 'not_applicable' THEN 1 ELSE 0 END) as not_applicable,
            SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending
        FROM coverage_checklist
        WHERE pentest_id = ?
    ''', (pentest_id,))

    row = c.fetchone()
    conn.close()

    if row:
        total = row['total'] or 0
        completed = row['completed'] or 0
        return {
            'total': total,
            'completed': completed,
            'in_progress': row['in_progress'] or 0,
            'not_applicable': row['not_applicable'] or 0,
            'pending': row['pending'] or 0,
            'percentage': round((completed / total * 100) if total > 0 else 0, 1)
        }

    return {'total': 0, 'completed': 0, 'in_progress': 0, 'not_applicable': 0, 'pending': 0, 'percentage': 0}


# ============================================================
# ASSET MANAGEMENT
# ============================================================

def create_asset(client_id: str, name: str, asset_type: str, **kwargs) -> str:
    """Create a new asset."""
    asset_id = str(uuid.uuid4())[:8].upper()
    now = datetime.now().isoformat()

    conn = get_db()
    c = conn.cursor()

    c.execute('''
        INSERT INTO assets (id, client_id, name, type, description, url, environment,
                           technology_stack, authentication_info, status, risk_level, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        asset_id, client_id, name, asset_type,
        kwargs.get('description', ''),
        kwargs.get('url', ''),
        kwargs.get('environment', 'production'),
        kwargs.get('technology_stack', ''),
        kwargs.get('authentication_info', ''),
        kwargs.get('status', 'active'),
        kwargs.get('risk_level', 'medium'),
        now
    ))

    conn.commit()
    conn.close()

    return asset_id


def get_assets_for_client(client_id: str) -> List[Dict]:
    """Get all assets for a client."""
    conn = get_db()
    c = conn.cursor()

    c.execute('''
        SELECT * FROM assets
        WHERE client_id = ?
        ORDER BY created_at DESC
    ''', (client_id,))

    assets = [dict(row) for row in c.fetchall()]
    conn.close()

    return assets


def get_asset_by_id(asset_id: str) -> Optional[Dict]:
    """Get a single asset by ID."""
    conn = get_db()
    c = conn.cursor()

    c.execute('SELECT * FROM assets WHERE id = ?', (asset_id,))
    row = c.fetchone()
    conn.close()

    return dict(row) if row else None


def update_asset(asset_id: str, client_id: str = None, **fields) -> bool:
    """Update an asset. Optionally verify ownership."""
    allowed = {'name', 'type', 'description', 'url', 'environment',
               'technology_stack', 'authentication_info', 'status', 'risk_level'}

    for col in fields.keys():
        if col not in _ALLOWED_ASSET_COLS:
            raise ValueError(f"Invalid column: {col!r}")
    updates, values = [], []
    for k, v in fields.items():
        if k in allowed:
            updates.append(f"{k} = ?")
            values.append(v)

    if not updates:
        return False

    conn = get_db()
    c = conn.cursor()

    if client_id:
        c.execute("SELECT client_id FROM assets WHERE id = ?", (asset_id,))
        row = c.fetchone()
        if not row or row['client_id'] != client_id:
            conn.close()
            return False

    updates.append("updated_at = ?")
    values.append(datetime.now().isoformat())
    values.append(asset_id)

    c.execute(f"UPDATE assets SET {', '.join(updates)} WHERE id = ?", values)
    conn.commit()
    conn.close()

    return True


def delete_asset(asset_id: str, client_id: str = None) -> bool:
    """Delete an asset. Optionally verify ownership."""
    conn = get_db()
    c = conn.cursor()

    if client_id:
        c.execute("SELECT client_id FROM assets WHERE id = ?", (asset_id,))
        row = c.fetchone()
        if not row or row['client_id'] != client_id:
            conn.close()
            return False

    c.execute("DELETE FROM assets WHERE id = ?", (asset_id,))
    conn.commit()
    conn.close()

    return True


def get_asset_types() -> List[Dict]:
    """Return available asset types."""
    return [
        {'value': 'web', 'label': 'Web Application', 'icon': '🌐'},
        {'value': 'api', 'label': 'API / REST / GraphQL', 'icon': '🔌'},
        {'value': 'mobile_ios', 'label': 'Mobile - iOS', 'icon': '📱'},
        {'value': 'mobile_android', 'label': 'Mobile - Android', 'icon': '📱'},
        {'value': 'internal_network', 'label': 'Internal Network', 'icon': '🔒'},
        {'value': 'external_network', 'label': 'External Network', 'icon': '🌍'},
        {'value': 'cloud', 'label': 'Cloud Infrastructure', 'icon': '☁️'},
        {'value': 'desktop', 'label': 'Desktop Application', 'icon': '💻'},
        {'value': 'iot', 'label': 'IoT Device', 'icon': '📡'},
    ]


# ============================================================
# FINDING MANAGEMENT (Edit/Delete)
# ============================================================

def update_finding_fields(finding_id: str, pentester_id: str = None, **fields) -> bool:
    """
    Update finding fields. Pentester can only edit their own findings.
    Allowed fields: title, severity, status, description, impact, remediation,
                   category, affected_url, cvss_score, cwe_id, cve_id,
                   reference_urls, steps_to_reproduce, poc
    """
    allowed = {
        "title", "severity", "status", "description", "impact", "remediation",
        "category", "affected_url", "cvss_score", "cwe_id", "cve_id",
        "reference_urls", "steps_to_reproduce", "poc",
        # Evidence (stored as JSON strings)
        "attachments", "screenshots",
    }

    for col in fields.keys():
        if col not in _ALLOWED_FINDING_COLS:
            raise ValueError(f"Invalid column: {col!r}")
    updates, values = [], []
    for k, v in fields.items():
        if k in allowed:
            updates.append(f"{k} = ?")
            values.append(v)

    if not updates:
        return False

    conn = get_db()
    c = conn.cursor()

    # Verify ownership if pentester_id provided
    if pentester_id:
        c.execute("SELECT pentester_id FROM ptaas_findings WHERE id = ?", (finding_id,))
        row = c.fetchone()
        if not row or row['pentester_id'] != pentester_id:
            conn.close()
            return False

    # Always store timestamps in UTC with timezone info to avoid client-side TZ parsing bugs.
    now = datetime.now(timezone.utc).isoformat()
    updates.append("updated_at = ?")
    values.append(now)
    values.append(finding_id)

    c.execute(f"UPDATE ptaas_findings SET {', '.join(updates)} WHERE id = ?", values)

    c.execute("SELECT pentest_id FROM ptaas_findings WHERE id = ?", (finding_id,))
    row = c.fetchone()
    pentest_id = row['pentest_id'] if row else None

    conn.commit()
    conn.close()

    if pentest_id:
        update_pentest_finding_counts(pentest_id)

    return True


def delete_finding(finding_id: str, pentester_id: str = None) -> bool:
    """
    Delete a finding. Pentester can only delete their own findings
    that are still in 'new' or 'draft' status.
    """
    conn = get_db()
    c = conn.cursor()

    # Get finding info
    c.execute("SELECT pentester_id, pentest_id, status FROM ptaas_findings WHERE id = ?", (finding_id,))
    row = c.fetchone()

    if not row:
        conn.close()
        return False

    # Verify ownership if pentester_id provided
    if pentester_id and row['pentester_id'] != pentester_id:
        conn.close()
        return False

    # Only allow deletion of new/draft findings
    if row['status'] not in ('new', 'draft'):
        conn.close()
        return False

    pentest_id = row['pentest_id']

    c.execute("DELETE FROM ptaas_findings WHERE id = ?", (finding_id,))
    conn.commit()
    conn.close()

    # Update counts
    update_pentest_finding_counts(pentest_id)

    return True


def get_finding_states():
    """Return valid finding states and their descriptions."""
    return {
        'draft': {'label': 'Draft', 'color': 'gray', 'description': 'Finding not yet submitted'},
        'new': {'label': 'New', 'color': 'blue', 'description': 'Newly submitted, pending triage'},
        'triaged': {'label': 'Triaged', 'color': 'purple', 'description': 'Under review by security team'},
        'need_more_info': {'label': 'Need More Info', 'color': 'orange', 'description': 'Additional details requested'},
        'accepted': {'label': 'Accepted', 'color': 'green', 'description': 'Valid finding, pending fix'},
        'wont_fix': {'label': "Won't Fix", 'color': 'gray', 'description': 'Acknowledged but not fixing'},
        'duplicate': {'label': 'Duplicate', 'color': 'gray', 'description': 'Already reported'},
        'fixed': {'label': 'Fixed', 'color': 'teal', 'description': 'Fix implemented, pending verification'},
        'verified': {'label': 'Verified', 'color': 'green', 'description': 'Fix verified, finding closed'},
    }


def get_pentest_states():
    """Return valid pentest states and their descriptions."""
    return {
        'draft': {'label': 'Draft', 'color': 'gray', 'description': 'Pentest being configured'},
        'pending': {'label': 'Pending', 'color': 'yellow', 'description': 'Awaiting approval'},
        'planned': {'label': 'Planned', 'color': 'blue', 'description': 'Approved, waiting to start'},
        'live': {'label': 'Live', 'color': 'green', 'description': 'Testing in progress'},
        'remediation': {'label': 'Remediation', 'color': 'orange', 'description': 'Findings being fixed'},
        'completed': {'label': 'Completed', 'color': 'teal', 'description': 'Pentest finished'},
        'cancelled': {'label': 'Cancelled', 'color': 'red', 'description': 'Pentest cancelled'},
    }


# Initialize database when module is imported
if __name__ == '__main__':
    init_ptaas_db()
    seed_demo_data()

