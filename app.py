#!/usr/bin/env python3
"""
Security Scanner Dashboard - Legendary Edition 🔥
"""

import os
import sys
import json
import subprocess
import threading
import uuid
import shutil
import tempfile
import zipfile
from datetime import datetime, timedelta
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_from_directory, redirect, session
from urllib.parse import urlparse
from functools import wraps
from flask_cors import CORS
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
import sqlite3
import re
import time

# Import PTaaS database module
import ptaas_db

# Import secure authentication module
try:
    from auth_routes import auth_bp, init_auth_service
    from secure_auth import (
        add_security_headers, 
        jwt_required as secure_jwt_required,
        role_required,
        admin_only,
        pentester_only,
        client_only,
        PasswordHasher,
        AuditLogger
    )
    SECURE_AUTH_AVAILABLE = True
except ImportError as e:
    print(f"[WARNING] Secure auth module not available: {e}")
    print("[WARNING] Install bcrypt and PyJWT: pip install bcrypt PyJWT")
    SECURE_AUTH_AVAILABLE = False

app = Flask(__name__, static_folder='static', template_folder='templates')

# Respect reverse proxy headers (Cloudflare/Nginx) for scheme + client IP.
# This is important for secure cookies, logging, and URL generation.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

@app.route("/login")
def login_page_redirect():
    """Redirect to new platform portal."""
    return redirect("https://platform.redconoffence.com/app/portal")


@app.route("/scanner/login")
def scanner_login_page():
    """Redirect to new platform portal."""
    return redirect("https://platform.redconoffence.com/app/portal")


@app.route("/api/scanner/login", methods=["POST"])
def api_scanner_login_placeholder():
    return jsonify({"error": "Scanner backend not deployed yet."}), 410


@app.route("/scanner/dashboard")
def scanner_dashboard_placeholder():
    return redirect("/scanner/login")


# Use environment variable for secret key in production
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'redcon-offence-secret-key-change-in-production')
if os.environ.get('FLASK_ENV') == 'production' and app.secret_key == 'redcon-offence-secret-key-change-in-production':
    raise RuntimeError("FLASK_SECRET_KEY must be set in production")

# Session configuration for security
app.config['SESSION_COOKIE_SECURE'] = (os.environ.get('FLASK_ENV') == 'production') or (os.environ.get('FORCE_HTTPS_COOKIES') == '1')  # HTTPS only in prod
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent XSS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
app.config['MAX_CONTENT_LENGTH'] = int(os.environ.get('MAX_UPLOAD_BYTES', str(25 * 1024 * 1024)))  # 25MB default

# CORS must be explicitly allow-listed when credentials are enabled.
# Keep this aligned with ALLOWED_ORIGINS below.
CORS(app, supports_credentials=True, origins=list({
    'https://redconoffence.com',
    'https://www.redconoffence.com',
    'https://platform.redconoffence.com',
    'http://redconoffence.com',
    'http://www.redconoffence.com',
    'http://platform.redconoffence.com',
    'http://localhost:5000',
    'http://localhost:5050',
    'http://127.0.0.1:5000',
    'http://127.0.0.1:5050',
}))

# ------------------------------------------------------------
# Security: lightweight rate limiting (in-memory).
# Note: For multi-worker production, prefer Redis-backed limiter.
# ------------------------------------------------------------
_RL_BUCKETS = {}


def _rate_limit(bucket: str, limit: int, window_seconds: int) -> bool:
    """
    Returns True if allowed, False if rate-limited.
    """
    now = time.time()
    window_start = now - window_seconds
    q = _RL_BUCKETS.get(bucket, [])
    # keep only recent timestamps
    q = [t for t in q if t >= window_start]
    if len(q) >= limit:
        _RL_BUCKETS[bucket] = q
        return False
    q.append(now)
    _RL_BUCKETS[bucket] = q
    return True

# ------------------------------------------------------------
# Security: basic CSRF mitigation for session-cookie APIs.
# Enforces same-origin for state-changing requests for PTaaS roles.
# Remains compatible with existing templates (no CSRF token required).
# ------------------------------------------------------------
ALLOWED_ORIGINS = {
    'https://redconoffence.com',
    'https://www.redconoffence.com',
    'https://platform.redconoffence.com',
    'http://redconoffence.com',
    'http://www.redconoffence.com',
    'http://platform.redconoffence.com',
    # local dev
    'http://localhost:5000',
    'http://localhost:5050',
    'http://127.0.0.1:5000',
    'http://127.0.0.1:5050',
}

def _is_same_origin_request(req):
    origin = (req.headers.get('Origin') or '').strip()
    referer = (req.headers.get('Referer') or '').strip()

    def norm(u: str) -> str:
        try:
            p = urlparse(u)
            if not p.scheme or not p.netloc:
                return ''
            return f"{p.scheme}://{p.netloc}"
        except Exception:
            return ''

    if origin:
        return origin in ALLOWED_ORIGINS
    if referer:
        return norm(referer) in ALLOWED_ORIGINS
    # Some same-origin requests may omit Origin/Referer; allow to avoid breaking.
    return True

@app.before_request
def _csrf_same_origin_guard():
    try:
        if not request.path.startswith('/api/'):
            return None
        if request.method not in ('POST', 'PUT', 'DELETE', 'PATCH'):
            return None

        role = session.get('user_role')
        if role not in ('client', 'admin', 'pentester'):
            return None

        # Allow auth endpoints
        if request.path in ('/api/auth/login', '/api/auth/logout', '/api/auth/signup', '/api/auth/forgot-password'):
            return None

        # Prefer modern fetch metadata when available (robust even if Origin/Referer are absent)
        sec_fetch_site = (request.headers.get('Sec-Fetch-Site') or '').strip().lower()
        if sec_fetch_site == 'cross-site':
            return jsonify({'error': 'Blocked (CSRF): cross-site request'}), 403

        if not _is_same_origin_request(request):
            return jsonify({'error': 'Blocked (CSRF): invalid origin'}), 403
    except Exception:
        # Fail open to prevent accidental outages.
        return None
    return None

# ============================================================
# Email Configuration
# ============================================================
# Configure these with your SMTP provider (Gmail, SendGrid, AWS SES, etc.)
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', '')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', '')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@redconoffence.com')

mail = Mail(app)

def send_email(to, subject, html_body, text_body=None):
    """Send an email using Flask-Mail."""
    try:
        msg = Message(
            subject=subject,
            recipients=[to] if isinstance(to, str) else to,
            html=html_body,
            body=text_body or html_body
        )
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False

def send_password_reset_email(email, reset_token):
    """Send password reset email."""
    reset_url = f"https://platform.redconoffence.com/reset-password?token={reset_token}"
    html_body = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="text-align: center; border-bottom: 2px solid #c9353f; padding-bottom: 20px; margin-bottom: 20px;">
            <h1 style="color: #c9353f; margin: 0;">REDCON OFFENCE</h1>
            <p style="color: #666; margin: 5px 0 0;">Password Reset Request</p>
        </div>
        <p>You requested a password reset for your REDCON OFFENCE account.</p>
        <p>Click the button below to reset your password:</p>
        <div style="text-align: center; margin: 30px 0;">
            <a href="{reset_url}" style="background: #c9353f; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-weight: bold;">Reset Password</a>
        </div>
        <p style="color: #666; font-size: 14px;">If you didn't request this, please ignore this email.</p>
        <p style="color: #666; font-size: 14px;">This link will expire in 1 hour.</p>
        <hr style="border: none; border-top: 1px solid #ddd; margin: 30px 0;">
        <p style="color: #999; font-size: 12px; text-align: center;">REDCON OFFENCE | Unmatched Perception. Unbroken Will.</p>
    </div>
    """
    return send_email(email, "Password Reset - REDCON OFFENCE", html_body)

def send_contact_notification(name, email, company, message):
    """Send notification when someone submits contact form."""
    html_body = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #c9353f;">New Contact Form Submission</h2>
        <p><strong>Name:</strong> {name}</p>
        <p><strong>Email:</strong> {email}</p>
        <p><strong>Company:</strong> {company}</p>
        <p><strong>Message:</strong></p>
        <div style="background: #f5f5f5; padding: 15px; border-radius: 5px;">{message}</div>
    </div>
    """
    return send_email('nidal@redconoffence.com', f"New Contact: {name} from {company}", html_body)

def send_osaas_notification(request_data):
    """Send notification when someone submits PTaaS request."""
    html_body = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #c9353f;">New PTaaS Request</h2>
        <p><strong>Contact:</strong> {request_data.get('contact_name')} ({request_data.get('contact_email')})</p>
        <p><strong>Company:</strong> {request_data.get('company')}</p>
        <p><strong>Service:</strong> {request_data.get('service_type')}</p>
        <p><strong>Timeline:</strong> {request_data.get('timeline')}</p>
        <p><strong>Budget:</strong> {request_data.get('budget')}</p>
        <p><strong>Scope:</strong></p>
        <div style="background: #f5f5f5; padding: 15px; border-radius: 5px;">{request_data.get('scope')}</div>
    </div>
    """
    return send_email('nidal@redconoffence.com', f"PTaaS Request: {request_data.get('company')}", html_body)


# ============================================================
# Authentication Middleware - Role-Based Access Control
# ============================================================

def _get_auth_from_jwt():
    """Extract user info from JWT token."""
    token = None
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
    if not token:
        token = request.cookies.get('access_token')
    
    if token and SECURE_AUTH_AVAILABLE:
        from secure_auth import JWTManager
        payload = JWTManager.decode_token(token)
        if payload:
            return {
                'user_id': payload.get('user_id'),
                'email': payload.get('email'),
                'role': payload.get('role')
            }
    return None


def login_required(f):
    """Decorator to require login. Checks both session and JWT."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check session first
        if 'user_id' in session:
            return f(*args, **kwargs)
        
        # Check JWT token
        jwt_user = _get_auth_from_jwt()
        if jwt_user:
            # Populate session from JWT
            session['user_id'] = jwt_user['user_id']
            session['user_email'] = jwt_user['email']
            session['user_role'] = jwt_user['role']
            return f(*args, **kwargs)
        
        # No valid auth
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Authentication required'}), 401
        return redirect('/portal?next=' + request.path)
    return decorated_function


def client_required(f):
    """Decorator for CLIENT-ONLY routes. Strict role check."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get role from session or JWT
        user_role = session.get('user_role')
        if not user_role:
            jwt_user = _get_auth_from_jwt()
            if jwt_user:
                session['user_id'] = jwt_user['user_id']
                session['user_email'] = jwt_user['email']
                session['user_role'] = jwt_user['role']
                user_role = jwt_user['role']
        
        if not user_role:
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Authentication required'}), 401
            return redirect('/portal?role=client')
        
        if user_role != 'client':
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Client access only'}), 403
            # Redirect to correct dashboard
            if user_role == 'pentester':
                return redirect('/ptaas/pentests')
            elif user_role == 'admin':
                return redirect('/admin/dashboard')
            return redirect('/portal')
        
        return f(*args, **kwargs)
    return decorated_function


def pentester_required(f):
    """Decorator for PENTESTER-ONLY routes. Strict role check."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_role = session.get('user_role')
        if not user_role:
            jwt_user = _get_auth_from_jwt()
            if jwt_user:
                session['user_id'] = jwt_user['user_id']
                session['user_email'] = jwt_user['email']
                session['user_role'] = jwt_user['role']
                user_role = jwt_user['role']
        
        if not user_role:
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Authentication required'}), 401
            return redirect('/portal?role=pentester')
        
        if user_role != 'pentester':
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Pentester access only'}), 403
            if user_role == 'client':
                return redirect('/client/dashboard')
            elif user_role == 'admin':
                return redirect('/admin/dashboard')
            return redirect('/portal')
        
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator for ADMIN-ONLY routes. Strict role check."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_role = session.get('user_role')
        if not user_role:
            jwt_user = _get_auth_from_jwt()
            if jwt_user:
                session['user_id'] = jwt_user['user_id']
                session['user_email'] = jwt_user['email']
                session['user_role'] = jwt_user['role']
                user_role = jwt_user['role']
        
        if not user_role:
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Authentication required'}), 401
            return redirect('/portal')
        
        if user_role != 'admin':
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Admin access only'}), 403
            if user_role == 'client':
                return redirect('/client/dashboard')
            elif user_role == 'pentester':
                return redirect('/ptaas/pentests')
            return redirect('/portal')
        
        return f(*args, **kwargs)
    return decorated_function


def get_current_user():
    """Get current logged-in user from session."""
    if 'user_id' not in session:
        return None
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, email, name, company, subscription_tier FROM users WHERE id = ?', (session['user_id'],))
    user = c.fetchone()
    conn.close()
    
    if user:
        return {
            'id': user[0],
            'email': user[1],
            'name': user[2],
            'company': user[3],
            'subscription': user[4]
        }
    return None

# Error handlers to always return JSON
@app.errorhandler(Exception)
def handle_exception(e):
    # Avoid leaking internals in production.
    if os.environ.get('FLASK_ENV') == 'production':
        return jsonify({'error': 'Internal server error'}), 500
    return jsonify({'error': str(e)}), 500

@app.errorhandler(404)
def handle_404(e):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def handle_500(e):
    return jsonify({'error': 'Internal server error'}), 500

# Database setup
DB_PATH = os.path.join(os.path.dirname(__file__), 'scanner.db')
MAIN_SCRIPT = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'main.py')
VENV_PYTHON = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'venv', 'bin', 'python3')
TEMP_SCANS_DIR = os.path.join(os.path.dirname(__file__), 'temp_scans')

# Create temp directory
os.makedirs(TEMP_SCANS_DIR, exist_ok=True)

# Active scans tracking
active_scans = {}


def init_db():
    """Initialize the database."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            project_name TEXT,
            target_path TEXT,
            source_type TEXT,
            model TEXT,
            status TEXT,
            started_at TEXT,
            completed_at TEXT,
            total_findings INTEGER DEFAULT 0,
            critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0,
            medium_count INTEGER DEFAULT 0,
            low_count INTEGER DEFAULT 0,
            security_score INTEGER DEFAULT 100,
            lines_scanned INTEGER DEFAULT 0,
            files_scanned INTEGER DEFAULT 0
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT,
            title TEXT,
            description TEXT,
            file_path TEXT,
            severity INTEGER,
            exploit_scenario TEXT,
            recommendation TEXT,
            model TEXT,
            timestamp TEXT,
            category TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    ''')
    
    conn.commit()
    conn.close()


def clone_github_repo(github_url, scan_id):
    """Clone a GitHub repository to temp directory."""
    target_dir = os.path.join(TEMP_SCANS_DIR, scan_id)
    
    try:
        # Clean URL
        url = github_url.strip()
        if not url.endswith('.git'):
            url = url.rstrip('/') + '.git'
        
        # Clone the repo
        result = subprocess.run(
            ['git', 'clone', '--depth', '1', url, target_dir],
            capture_output=True,
            text=True,
            timeout=120
        )
        
        if result.returncode != 0:
            return None, result.stderr
        
        return target_dir, None
    except Exception as e:
        return None, str(e)


def save_pasted_code(code, filename, scan_id):
    """Save pasted code to a temp file."""
    target_dir = os.path.join(TEMP_SCANS_DIR, scan_id)
    os.makedirs(target_dir, exist_ok=True)
    
    file_path = os.path.join(target_dir, filename)
    with open(file_path, 'w') as f:
        f.write(code)
    
    return target_dir


def count_lines_and_files(path):
    """Count lines of code and files in a directory."""
    total_lines = 0
    total_files = 0
    
    extensions = {'.py', '.js', '.ts', '.sol', '.php', '.java', '.go', '.rs', '.c', '.cpp', '.h', '.jsx', '.tsx'}
    
    if os.path.isfile(path):
        with open(path, 'r', errors='ignore') as f:
            return len(f.readlines()), 1
    
    for root, dirs, files in os.walk(path):
        # Skip hidden and common non-code directories
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in {'node_modules', 'venv', '__pycache__', 'vendor'}]
        
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in extensions:
                total_files += 1
                try:
                    with open(os.path.join(root, file), 'r', errors='ignore') as f:
                        total_lines += len(f.readlines())
                except:
                    pass
    
    return total_lines, total_files


def calculate_security_score(findings):
    """Calculate a security score based on findings."""
    if not findings:
        return 100
    
    score = 100
    for f in findings:
        severity = f.get('severity', 5)
        if severity >= 9:
            score -= 25
        elif severity >= 7:
            score -= 15
        elif severity >= 4:
            score -= 8
        else:
            score -= 3
    
    return max(0, score)


def parse_findings_md(md_path):
    """Parse the markdown findings file into structured data."""
    findings = []
    
    if not os.path.exists(md_path):
        return findings
    
    with open(md_path, 'r') as f:
        content = f.read()
    
    # Split by finding headers
    finding_blocks = re.split(r'\n## ', content)
    
    for block in finding_blocks[1:]:
        finding = {}
        lines = block.strip().split('\n')
        
        if lines:
            finding['title'] = lines[0].strip()
        
        # Extract severity
        severity_match = re.search(r'\*\*Severity:\*\* .+ (\d+)/10', block)
        if severity_match:
            finding['severity'] = int(severity_match.group(1))
        
        # Extract file path
        file_match = re.search(r'\*\*File:\*\* `([^`]+)`', block)
        if file_match:
            finding['file_path'] = file_match.group(1)
        
        # Extract model
        model_match = re.search(r'\*\*Model:\*\* (.+)', block)
        if model_match:
            finding['model'] = model_match.group(1).strip()
        
        # Extract timestamp
        ts_match = re.search(r'\*\*Timestamp:\*\* (.+)', block)
        if ts_match:
            finding['timestamp'] = ts_match.group(1).strip()
        
        # Extract description
        desc_match = re.search(r'### Description\n(.+?)(?=\n### |\n---|\Z)', block, re.DOTALL)
        if desc_match:
            finding['description'] = desc_match.group(1).strip()
        
        # Extract exploit scenario
        exploit_match = re.search(r'### Exploit Scenario.*?\n(.+?)(?=\n### |\n---|\Z)', block, re.DOTALL)
        if exploit_match:
            finding['exploit_scenario'] = exploit_match.group(1).strip()
        
        # Extract recommendation
        rec_match = re.search(r'### Recommendation\n(.+?)(?=\n### |\n---|\Z)', block, re.DOTALL)
        if rec_match:
            finding['recommendation'] = rec_match.group(1).strip()
        
        # Categorize finding
        title_lower = finding.get('title', '').lower()
        if 'reentrancy' in title_lower:
            finding['category'] = 'Reentrancy'
        elif 'access' in title_lower or 'auth' in title_lower:
            finding['category'] = 'Access Control'
        elif 'injection' in title_lower or 'sql' in title_lower or 'xss' in title_lower:
            finding['category'] = 'Injection'
        elif 'overflow' in title_lower or 'underflow' in title_lower:
            finding['category'] = 'Arithmetic'
        elif 'signature' in title_lower or 'ecdsa' in title_lower:
            finding['category'] = 'Cryptography'
        else:
            finding['category'] = 'Logic'
        
        if finding.get('title'):
            findings.append(finding)
    
    return findings


def run_scan_thread(scan_id, target_path, project_name, model, source_type):
    """Run the scan in a background thread."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        # Update status to running
        c.execute('UPDATE scans SET status = ? WHERE id = ?', ('running', scan_id))
        conn.commit()
        
        # Count lines and files
        lines, files = count_lines_and_files(target_path)
        c.execute('UPDATE scans SET lines_scanned = ?, files_scanned = ? WHERE id = ?', 
                  (lines, files, scan_id))
        conn.commit()
        
        # Build command
        cmd = [
            VENV_PYTHON, MAIN_SCRIPT,
            target_path, model,
            '--project-name', project_name
        ]
        
        # Run the scanner
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=os.path.dirname(MAIN_SCRIPT)
        )
        
        active_scans[scan_id] = {
            'process': process,
            'output': [],
            'progress': 0
        }
        
        # Capture output and track progress
        for line in process.stdout:
            active_scans[scan_id]['output'].append(line)
            
            # Parse progress from output
            if 'step' in line.lower():
                active_scans[scan_id]['progress'] = min(
                    active_scans[scan_id]['progress'] + 2, 90
                )
            elif 'completed' in line.lower() or '✅' in line:
                active_scans[scan_id]['progress'] = min(
                    active_scans[scan_id]['progress'] + 5, 95
                )
        
        process.wait()
        
        # Parse results
        md_path = os.path.join(os.path.dirname(MAIN_SCRIPT), f'{project_name}_security_findings.md')
        findings = parse_findings_md(md_path)
        
        # Count by severity
        critical = sum(1 for f in findings if f.get('severity', 0) >= 9)
        high = sum(1 for f in findings if 7 <= f.get('severity', 0) < 9)
        medium = sum(1 for f in findings if 4 <= f.get('severity', 0) < 7)
        low = sum(1 for f in findings if f.get('severity', 0) < 4)
        
        # Calculate security score
        security_score = calculate_security_score(findings)
        
        # Update scan record
        c.execute('''
            UPDATE scans SET 
                status = ?, completed_at = ?, total_findings = ?,
                critical_count = ?, high_count = ?, medium_count = ?, low_count = ?,
                security_score = ?
            WHERE id = ?
        ''', ('completed', datetime.now().isoformat(), len(findings),
              critical, high, medium, low, security_score, scan_id))
        
        # Insert findings
        for finding in findings:
            c.execute('''
                INSERT INTO findings (scan_id, title, description, file_path, severity, 
                                     exploit_scenario, recommendation, model, timestamp, category)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (scan_id, finding.get('title'), finding.get('description'),
                  finding.get('file_path'), finding.get('severity'),
                  finding.get('exploit_scenario'), finding.get('recommendation'),
                  finding.get('model'), finding.get('timestamp'), finding.get('category')))
        
        conn.commit()
        
    except Exception as e:
        c.execute('UPDATE scans SET status = ? WHERE id = ?', (f'error: {str(e)}', scan_id))
        conn.commit()
    
    finally:
        if scan_id in active_scans:
            del active_scans[scan_id]
        conn.close()


@app.route('/')
def landing():
    """Serve the landing page or portal based on subdomain."""
    host = request.host.lower()
    
    # If accessing via platform subdomain
    if host.startswith('platform.'):
        # Check if user is already logged in via session
        if 'user_id' in session and 'user_role' in session:
            role = session.get('user_role')
            if role == 'client':
                return redirect('/client/dashboard')
            elif role == 'pentester':
                return redirect('/ptaas/pentests')
            elif role == 'admin':
                return redirect('/admin/dashboard')
        
        # Check JWT cookie
        token = request.cookies.get('access_token')
        if token and SECURE_AUTH_AVAILABLE:
            from secure_auth import JWTManager
            payload = JWTManager.decode_token(token)
            if payload:
                role = payload.get('role')
                session['user_id'] = payload.get('user_id')
                session['user_email'] = payload.get('email')
                session['user_role'] = role
                if role == 'client':
                    return redirect('/client/dashboard')
                elif role == 'pentester':
                    return redirect('/ptaas/pentests')
                elif role == 'admin':
                    return redirect('/admin/dashboard')
        
        return render_template('portal.html')
    
    return render_template('landing.html')


@app.route('/dashboard')
@login_required
def dashboard():
    """
    Legacy scanner dashboard (removed).
    Redirect users to the unified portal.
    """
    return redirect('/portal')


def _scanner_removed():
    return jsonify({'error': 'Scanner has been removed. New scanner backend will be deployed soon.'}), 410


@app.route('/api/scan', methods=['POST'])
def start_scan():
    return _scanner_removed()


@app.route('/api/scan/upload', methods=['POST'])
def upload_scan():
    return _scanner_removed()


@app.route('/api/scan/<scan_id>')
def get_scan(scan_id):
    return _scanner_removed()


@app.route('/api/scans')
def list_scans():
    return _scanner_removed()


@app.route('/api/stats')
def get_stats():
    return _scanner_removed()


@app.route('/api/scan/<scan_id>/export')
def export_scan(scan_id):
    return _scanner_removed()


@app.route('/api/scan/<scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    return _scanner_removed()


@app.route('/api/scans/clear', methods=['DELETE'])
def clear_all_scans():
    return _scanner_removed()


@app.route('/api/finding/<int:finding_id>', methods=['DELETE'])
def delete_finding(finding_id):
    return _scanner_removed()


# ============================================================
# FEATURE 1: OSaaS Request Form
# ============================================================

def init_osaas_tables():
    """Initialize OSaaS tables."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute('''
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
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE,
            password_hash TEXT,
            name TEXT,
            company TEXT,
            role TEXT DEFAULT 'user',
            created_at TEXT,
            last_login TEXT,
            subscription_tier TEXT DEFAULT 'free',
            stripe_customer_id TEXT
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id TEXT,
            created_at TEXT,
            expires_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    conn.commit()
    conn.close()


@app.route('/api/osaas/request', methods=['POST'])
def submit_osaas_request():
    """Submit an OSaaS pentest request."""
    try:
        data = request.json
        request_id = str(uuid.uuid4())[:8]
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        c.execute('''
            INSERT INTO osaas_requests 
            (id, company_name, contact_name, email, phone, service_type, 
             scope_description, target_urls, timeline, budget, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)
        ''', (
            request_id,
            data.get('company_name', ''),
            data.get('contact_name', ''),
            data.get('email', ''),
            data.get('phone', ''),
            data.get('service_type', ''),
            data.get('scope_description', ''),
            data.get('target_urls', ''),
            data.get('timeline', ''),
            data.get('budget', ''),
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
        
        # Send email notification to admin
        send_osaas_notification({
            'contact_name': data.get('contact_name', ''),
            'contact_email': data.get('email', ''),
            'company': data.get('company_name', ''),
            'service_type': data.get('service_type', ''),
            'timeline': data.get('timeline', ''),
            'budget': data.get('budget', ''),
            'scope': data.get('scope_description', '')
        })
        
        return jsonify({
            'success': True,
            'request_id': request_id,
            'message': 'Your request has been submitted. We will contact you within 24 hours.'
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/osaas/requests', methods=['GET'])
def get_osaas_requests():
    """Get all OSaaS requests (admin only)."""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT * FROM osaas_requests ORDER BY created_at DESC')
        rows = c.fetchall()
        conn.close()
        
        requests = []
        for row in rows:
            requests.append({
                'id': row[0],
                'company_name': row[1],
                'contact_name': row[2],
                'email': row[3],
                'phone': row[4],
                'service_type': row[5],
                'scope_description': row[6],
                'target_urls': row[7],
                'timeline': row[8],
                'budget': row[9],
                'status': row[10],
                'created_at': row[11],
                'notes': row[12]
            })
        
        return jsonify(requests)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================
# FEATURE 2: PDF Report Export
# ============================================================

@app.route('/api/scan/<scan_id>/pdf', methods=['GET'])
def export_scan_pdf(scan_id):
    """Export scan results as PDF."""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        # Get scan info
        c.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
        scan_row = c.fetchone()
        
        if not scan_row:
            conn.close()
            return jsonify({'error': 'Scan not found'}), 404
        
        # Get findings
        c.execute('SELECT * FROM findings WHERE scan_id = ? ORDER BY severity DESC', (scan_id,))
        findings = c.fetchall()
        conn.close()
        
        # Generate HTML for PDF
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: Arial, sans-serif; padding: 40px; color: #333; }}
                .header {{ text-align: center; border-bottom: 3px solid #c9353f; padding-bottom: 20px; margin-bottom: 30px; }}
                .logo {{ font-size: 28px; font-weight: bold; color: #c9353f; }}
                .subtitle {{ color: #666; font-size: 14px; }}
                .section {{ margin-bottom: 30px; }}
                .section-title {{ font-size: 18px; font-weight: bold; color: #c9353f; border-bottom: 1px solid #ddd; padding-bottom: 10px; margin-bottom: 15px; }}
                .stat-grid {{ display: flex; gap: 20px; margin-bottom: 20px; }}
                .stat {{ background: #f5f5f5; padding: 15px; border-radius: 8px; text-align: center; flex: 1; }}
                .stat-value {{ font-size: 24px; font-weight: bold; }}
                .stat-label {{ font-size: 12px; color: #666; }}
                .finding {{ background: #f9f9f9; border-left: 4px solid #c9353f; padding: 15px; margin-bottom: 15px; }}
                .finding-title {{ font-weight: bold; font-size: 16px; margin-bottom: 5px; }}
                .finding-severity {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
                .severity-critical {{ background: #fee; color: #c00; }}
                .severity-high {{ background: #fff3e0; color: #e65100; }}
                .severity-medium {{ background: #fff8e1; color: #f9a825; }}
                .severity-low {{ background: #e8f5e9; color: #2e7d32; }}
                .finding-meta {{ font-size: 12px; color: #666; margin: 10px 0; }}
                .finding-desc {{ margin: 10px 0; }}
                .footer {{ text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 12px; color: #666; }}
            </style>
        </head>
        <body>
            <div class="header">
                <div class="logo">REDCON OFFENCE</div>
                <div class="subtitle">Security Assessment Report</div>
            </div>
            
            <div class="section">
                <div class="section-title">Executive Summary</div>
                <p><strong>Project:</strong> {scan_row[1]}</p>
                <p><strong>Target:</strong> {scan_row[2]}</p>
                <p><strong>Date:</strong> {scan_row[6]}</p>
                <p><strong>Model:</strong> {scan_row[4]}</p>
            </div>
            
            <div class="section">
                <div class="section-title">Findings Overview</div>
                <div class="stat-grid">
                    <div class="stat">
                        <div class="stat-value" style="color: #c00;">{scan_row[8]}</div>
                        <div class="stat-label">Critical</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value" style="color: #e65100;">{scan_row[9]}</div>
                        <div class="stat-label">High</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value" style="color: #f9a825;">{scan_row[10]}</div>
                        <div class="stat-label">Medium</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value" style="color: #2e7d32;">{scan_row[11]}</div>
                        <div class="stat-label">Low</div>
                    </div>
                </div>
                <p><strong>Security Score:</strong> {scan_row[12]}/100</p>
            </div>
            
            <div class="section">
                <div class="section-title">Detailed Findings</div>
        """
        
        for finding in findings:
            severity = finding[5]
            if severity >= 9:
                sev_class = 'critical'
                sev_text = 'CRITICAL'
            elif severity >= 7:
                sev_class = 'high'
                sev_text = 'HIGH'
            elif severity >= 4:
                sev_class = 'medium'
                sev_text = 'MEDIUM'
            else:
                sev_class = 'low'
                sev_text = 'LOW'
            
            html_content += f"""
                <div class="finding">
                    <div class="finding-title">{finding[2]}</div>
                    <span class="finding-severity severity-{sev_class}">{sev_text} ({severity}/10)</span>
                    <div class="finding-meta">File: {finding[4]} | Category: {finding[10]}</div>
                    <div class="finding-desc"><strong>Description:</strong> {finding[3]}</div>
                    <div class="finding-desc"><strong>Exploit Scenario:</strong> {finding[6]}</div>
                    <div class="finding-desc"><strong>Recommendation:</strong> {finding[7]}</div>
                </div>
            """
        
        html_content += """
            </div>
            
            <div class="footer">
                <p>Generated by REDCON OFFENCE | Unmatched Perception. Unbroken Will.</p>
                <p>This report is confidential and intended for the recipient only.</p>
            </div>
        </body>
        </html>
        """
        
        # Generate PDF using WeasyPrint
        try:
            from weasyprint import HTML
            from io import BytesIO
            
            pdf_buffer = BytesIO()
            HTML(string=html_content).write_pdf(pdf_buffer)
            pdf_buffer.seek(0)
            
            from flask import Response
            return Response(
                pdf_buffer.getvalue(),
                mimetype='application/pdf',
                headers={'Content-Disposition': f'attachment; filename=REDCON-Report-{scan_id}.pdf'}
            )
        except ImportError:
            # Fallback to HTML if WeasyPrint not installed
            from flask import Response
            return Response(
                html_content,
                mimetype='text/html',
                headers={'Content-Disposition': f'attachment; filename=redcon-report-{scan_id}.html'}
            )
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================
# FEATURE 3: Authentication
# ============================================================

import hashlib
import hmac
import secrets

def hash_password(password):
    """
    Hash a password.
    - Prefer bcrypt (required in production)
    - Keep compatibility with legacy salt:sha256 format for existing users
    """
    try:
        import bcrypt  # type: ignore
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    except Exception:
        if os.environ.get('FLASK_ENV') == 'production':
            raise RuntimeError("bcrypt is required in production")
        # Legacy/dev fallback
        salt = secrets.token_hex(16)
        hashed = hashlib.sha256((password + salt).encode()).hexdigest()
        return f"{salt}:{hashed}"

def verify_password(password, password_hash):
    """Verify a password against its hash (bcrypt or legacy salt:sha256)."""
    try:
        # bcrypt
        if isinstance(password_hash, str) and password_hash.startswith('$2'):
            import bcrypt  # type: ignore
            return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

        # legacy salt:sha256
        salt, hashed = password_hash.split(':', 1)
        candidate = hashlib.sha256((password + salt).encode()).hexdigest()
        return hmac.compare_digest(candidate, hashed)
    except Exception:
        return False


def _sanitize_next_url(next_url: str, default: str) -> str:
    """
    Only allow internal relative redirects.
    """
    next_url = (next_url or '').strip()
    if not next_url:
        return default
    if next_url.startswith('//'):
        return default
    if '://' in next_url:
        return default
    if next_url.lower().startswith(('javascript:', 'data:', 'vbscript:')):
        return default
    if not next_url.startswith('/'):
        return default
    return next_url


@app.route('/api/auth/signup', methods=['POST'])
def signup():
    """Create a new user account."""
    try:
        ip = request.remote_addr or ''
        if not _rate_limit(f"auth:signup:{ip}", limit=10, window_seconds=60 * 10):
            return jsonify({'error': 'Too many requests'}), 429

        data = request.json
        email = data.get('email', '').lower().strip()
        password = data.get('password', '')
        name = data.get('name', '')
        company = data.get('company', '')
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        if len(password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400
        
        user_id = str(uuid.uuid4())[:12]
        password_hash = hash_password(password)
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        # Check if email exists
        c.execute('SELECT id FROM users WHERE email = ?', (email,))
        if c.fetchone():
            conn.close()
            return jsonify({'error': 'Email already registered'}), 400
        
        c.execute('''
            INSERT INTO users (id, email, password_hash, name, company, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, email, password_hash, name, company, datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
        
        # Set Flask session
        session['user_id'] = user_id
        session['user_email'] = email
        session['user_name'] = name
        
        return jsonify({
            'success': True,
            'user_id': user_id,
            'redirect': '/dashboard',
            'message': 'Account created successfully'
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/auth/login', methods=['POST'])
def login():
    """Login with email and password."""
    try:
        ip = request.remote_addr or ''
        if not _rate_limit(f"auth:login:{ip}", limit=20, window_seconds=60 * 10):
            return jsonify({'error': 'Too many requests'}), 429

        data = request.json
        email = data.get('email', '').lower().strip()
        password = data.get('password', '')
        
        # First try PTaaS database
        ptaas_user = ptaas_db.authenticate_user(email, password)
        
        if ptaas_user:
            # Set Flask session
            session['user_id'] = ptaas_user['id']
            session['user_email'] = email
            session['user_name'] = ptaas_user['name']
            session['user_role'] = ptaas_user['role']
            
            # Check for redirect parameter, otherwise redirect based on role
            next_url = request.args.get('next') or data.get('next') or ''
            next_url = next_url.strip() if next_url else ''
            
            # If no valid next URL, redirect based on role
            default_redirect = (
                '/app/client/dashboard' if ptaas_user['role'] == 'client'
                else '/app/admin/dashboard' if ptaas_user['role'] == 'admin'
                else '/app/ptaas/pentests'
            )
            if not next_url or next_url.startswith('/portal'):
                next_url = default_redirect
            next_url = _sanitize_next_url(next_url, default_redirect)
            
            print(f"[LOGIN] User: {email}, Role: {ptaas_user['role']}, Redirect: {next_url}")
            
            return jsonify({
                'success': True,
                'redirect': next_url,
                'user': {
                    'id': ptaas_user['id'],
                    'name': ptaas_user['name'],
                    'email': email,
                    'role': ptaas_user['role'],
                    'company': ptaas_user['company']
                }
            })
        
        # Fall back to scanner database (legacy).
        # Important: never 500 if the scanner DB isn't initialized.
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute('SELECT id, password_hash, name, subscription_tier FROM users WHERE email = ?', (email,))
            user = c.fetchone()
        except sqlite3.OperationalError as oe:
            # If the DB was empty/uninitialized, create tables and retry once.
            try:
                if 'no such table' in str(oe).lower():
                    init_osaas_tables()
                    conn = sqlite3.connect(DB_PATH)
                    c = conn.cursor()
                    c.execute('SELECT id, password_hash, name, subscription_tier FROM users WHERE email = ?', (email,))
                    user = c.fetchone()
                else:
                    user = None
            except Exception:
                user = None
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
        
        if not user or not verify_password(password, user[1]):
            return jsonify({'error': 'Invalid email or password'}), 401

        # Upgrade legacy password hashes to bcrypt on successful login
        try:
            if isinstance(user[1], str) and not user[1].startswith('$2'):
                new_hash = hash_password(password)
                c.execute('UPDATE users SET password_hash = ? WHERE id = ?', (new_hash, user[0]))
        except Exception:
            pass
        
        # Update last login
        c.execute('UPDATE users SET last_login = ? WHERE id = ?', (datetime.now().isoformat(), user[0]))
        conn.commit()
        conn.close()
        
        # Set Flask session
        session['user_id'] = user[0]
        session['user_email'] = email
        session['user_name'] = user[2]
        session['user_role'] = 'scanner_user'
        
        # Check for redirect parameter
        next_url = request.args.get('next') or data.get('next', '/dashboard')
        next_url = _sanitize_next_url(next_url, '/dashboard')
        
        return jsonify({
            'success': True,
            'redirect': next_url,
            'user': {
                'id': user[0],
                'name': user[2],
                'email': email,
                'subscription': user[3]
            }
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/auth/logout', methods=['POST'])
def logout():
    """Logout and clear session."""
    session.clear()
    return jsonify({'success': True, 'redirect': '/', 'message': 'Logged out successfully'})


@app.route('/logout')
def logout_page():
    """Logout - clear session and cookies, redirect to home."""
    # Clear Flask session
    session.clear()
    
    # Create response and clear JWT cookies
    response = redirect('/')
    response.delete_cookie('access_token', path='/')
    response.delete_cookie('refresh_token', path='/')
    
    return response


@app.route('/api/logout', methods=['POST', 'GET'])
def api_logout():
    """API logout endpoint - clears session and cookies."""
    session.clear()
    
    response = jsonify({'success': True, 'message': 'Logged out successfully'})
    response.delete_cookie('access_token', path='/')
    response.delete_cookie('refresh_token', path='/')
    
    return response


@app.route('/api/auth/forgot-password', methods=['POST'])
def forgot_password():
    """Request password reset."""
    try:
        ip = request.remote_addr or ''
        if not _rate_limit(f"auth:forgot:{ip}", limit=10, window_seconds=60 * 10):
            return jsonify({'success': True, 'message': 'If an account exists with that email, reset instructions have been sent.'})

        data = request.json
        email = data.get('email', '').lower().strip()
        
        if not email:
            return jsonify({'error': 'Email is required'}), 400
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        c.execute('SELECT id, name FROM users WHERE email = ?', (email,))
        user = c.fetchone()
        
        if user:
            # Generate reset token
            reset_token = secrets.token_urlsafe(32)
            expires_at = (datetime.now() + timedelta(hours=1)).isoformat()
            
            # Store reset token in database
            c.execute('''
                CREATE TABLE IF NOT EXISTS password_resets (
                    token TEXT PRIMARY KEY,
                    user_id TEXT,
                    email TEXT,
                    expires_at TEXT,
                    used INTEGER DEFAULT 0
                )
            ''')
            c.execute('DELETE FROM password_resets WHERE email = ?', (email,))
            c.execute('INSERT INTO password_resets (token, user_id, email, expires_at) VALUES (?, ?, ?, ?)',
                     (reset_token, user[0], email, expires_at))
            conn.commit()
            
            # Send password reset email
            send_password_reset_email(email, reset_token)
            print(f"[PASSWORD RESET] Email sent to: {email}")
        
        conn.close()
        
        # Always return success (don't reveal if email exists)
        return jsonify({
            'success': True,
            'message': 'If an account exists with that email, reset instructions have been sent.'
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/auth/me', methods=['GET'])
def get_current_user():
    """Get current user info.

    Supports:
    - Scanner portal bearer token (legacy): Authorization: Bearer <token>
    - PTaaS / platform: Flask session (session['user_id'], session['user_role'])
    """
    try:
        token = request.headers.get('Authorization', '').replace('Bearer ', '')

        # 1) Legacy scanner bearer token
        if token:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            
            c.execute('''
                SELECT u.id, u.email, u.name, u.company, u.subscription_tier, u.created_at
                FROM users u
                JOIN sessions s ON u.id = s.user_id
                WHERE s.token = ?
            ''', (token,))
            
            user = c.fetchone()
            conn.close()
            
            if not user:
                return jsonify({'error': 'Invalid or expired token'}), 401
            
            return jsonify({
                'id': user[0],
                'email': user[1],
                'name': user[2],
                'company': user[3],
                'subscription': user[4],
                'created_at': user[5],
                'role': 'scanner_user',
                'ptaas': False
            })

        # 2) PTaaS session-based auth
        user_id = session.get('user_id')
        user_role = session.get('user_role')
        if not user_id or not user_role:
            return jsonify({'error': 'Not authenticated'}), 401

        if user_role in ('client', 'admin', 'pentester'):
            u = ptaas_db.get_user_by_id(user_id)
            if not u:
                session.clear()
                return jsonify({'error': 'Not authenticated'}), 401
            return jsonify({
                'id': u.get('id'),
                'email': u.get('email'),
                'name': u.get('name'),
                'company': u.get('company'),
                'role': u.get('role'),
                'is_active': u.get('is_active', 1),
                'created_at': u.get('created_at'),
                'ptaas': True
            })

        # 3) Fallback: other session roles
        return jsonify({
            'id': user_id,
            'email': session.get('user_email'),
            'name': session.get('user_name'),
            'role': user_role,
            'ptaas': False
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================
# FEATURE 4: Subscription Management (Stripe placeholder)
# ============================================================

SUBSCRIPTION_TIERS = {
    'free': {
        'name': 'Recon',
        'price': 0,
        'scans_per_month': 5,
        'models': ['gpt-4o-mini'],
        'features': ['basic_reports', 'github_integration']
    },
    'pro': {
        'name': 'Strike',
        'price': 49,
        'scans_per_month': -1,  # Unlimited
        'models': ['gpt-4o', 'gpt-4o-mini', 'claude-3-5-sonnet-20241022'],
        'features': ['pdf_reports', 'api_access', 'priority_support', 'github_integration']
    },
    'enterprise': {
        'name': 'Arsenal',
        'price': 'custom',
        'scans_per_month': -1,
        'models': ['all'],
        'features': ['all', 'on_premise', 'sso', 'dedicated_support']
    }
}


@app.route('/api/subscription/tiers', methods=['GET'])
def get_subscription_tiers():
    """Get available subscription tiers."""
    return jsonify(SUBSCRIPTION_TIERS)


@app.route('/api/subscription/upgrade', methods=['POST'])
def upgrade_subscription():
    """Upgrade user subscription (Stripe integration placeholder)."""
    try:
        data = request.json
        tier = data.get('tier', 'pro')
        
        # In production, this would integrate with Stripe
        # For now, just return a placeholder response
        
        return jsonify({
            'success': True,
            'message': f'Subscription upgrade to {tier} initiated',
            'checkout_url': f'https://checkout.stripe.com/placeholder?tier={tier}',
            'note': 'Stripe integration coming soon!'
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================
# FEATURE 5: Client Portal Routes
# ============================================================

@app.route('/portal')
def client_portal():
    """Redirect to new platform portal."""
    return redirect('https://platform.redconoffence.com/app/portal')


@app.route('/osaas')
def osaas_page():
    """Redirect to request pentest page."""
    return redirect('/request-pentest')


@app.route('/team')
@app.route('/team/')
def team_page():
    """Team introduction page."""
    return render_template('team.html')


@app.route('/docs')
@app.route('/docs/')
@app.route('/docs/<path:subpath>')
def docs_page(subpath=None):
    """Documentation pages."""
    return render_template('docs.html')


@app.route('/admin/workflow')
def admin_workflow():
    """Redirect to new platform."""
    return redirect('https://platform.redconoffence.com/app/admin/dashboard')


# ============================================================
# Legacy PTaaS Routes - Redirect to New Platform
# ============================================================

@app.route('/pentester/dashboard')
def pentester_dashboard():
    """Redirect to new platform."""
    return redirect('https://platform.redconoffence.com/app/ptaas/pentests')


@app.route('/ptaas/pentests')
def ptaas_pentests():
    """Redirect to new platform."""
    return redirect('https://platform.redconoffence.com/app/ptaas/pentests')


@app.route('/ptaas/activity')
def ptaas_activity():
    """Redirect to new platform."""
    return redirect('https://platform.redconoffence.com/app/ptaas/activity')


@app.route('/ptaas/pentest/<pentest_id>')
def ptaas_pentest_detail(pentest_id):
    """Redirect to new platform."""
    return redirect(f'https://platform.redconoffence.com/app/ptaas/pentest/{pentest_id}')


@app.route('/ptaas/findings')
def ptaas_findings():
    """Redirect to new platform."""
    return redirect('https://platform.redconoffence.com/app/ptaas/findings')


@app.route('/ptaas/reports')
def ptaas_reports():
    """Redirect to new platform."""
    return redirect('https://platform.redconoffence.com/app/ptaas/reports')


@app.route('/ptaas/feedback')
def ptaas_feedback():
    """Redirect to new platform."""
    return redirect('https://platform.redconoffence.com/app/ptaas/feedback')


@app.route('/ptaas/profile')
def ptaas_profile():
    """Redirect to new platform."""
    return redirect('https://platform.redconoffence.com/app/ptaas/profile')


@app.route('/ptaas/settings')
def ptaas_settings():
    """Redirect to new platform."""
    return redirect('https://platform.redconoffence.com/app/ptaas/settings')


@app.route('/terms')
def terms_page():
    """Terms of Service page."""
    return render_template('terms.html')


@app.route('/privacy')
def privacy_page():
    """Privacy Policy page."""
    return render_template('privacy.html')


@app.route('/robots.txt')
def robots():
    """Serve robots.txt for SEO."""
    return send_from_directory(app.static_folder, 'robots.txt', mimetype='text/plain')


@app.route('/sitemap.xml')
def sitemap():
    """Serve sitemap.xml for SEO."""
    return send_from_directory(app.static_folder, 'sitemap.xml', mimetype='application/xml')


# ============================================================
# PTaaS API Endpoints - Database Backed
# ============================================================

def get_ptaas_user():
    """Get current user from PTaaS database."""
    if 'user_id' not in session:
        return None
    return ptaas_db.get_user_by_id(session['user_id'])


# -------------------- PENTESTER ENDPOINTS --------------------

@app.route('/api/pentester/dashboard', methods=['GET'])
@pentester_required
def api_pentester_dashboard():
    """Pentester dashboard data."""
    try:
        user_id = session.get('user_id')
        stats = ptaas_db.get_pentester_stats(user_id)
        return jsonify({
            'success': True,
            'stats': stats
        })
    except Exception as e:
        print(f"Error in api_pentester_dashboard: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/pentester/pentests', methods=['GET'])
@pentester_required
def api_pentester_pentests():
    """Get pentests for pentester (alias for /api/ptaas/pentests)."""
    try:
        user_id = session.get('user_id')
        status_filter = request.args.get('status', 'all')
        
        pentests = ptaas_db.get_pentests_for_pentester(user_id, status_filter if status_filter != 'all' else None)
        
        formatted = []
        for p in pentests:
            formatted.append({
                'id': p['id'],
                'title': p['title'],
                'pentest_number': p.get('pentest_number', ''),
                'type': p['type'],
                'status': p['status'],
                'progress': p.get('progress') or 0,
                'total_findings': p.get('total_findings') or 0,
                'start_date': p.get('start_date'),
                'end_date': p.get('end_date'),
                'company_name': p.get('company_name', '')
            })
        
        return jsonify({
            'success': True,
            'pentests': formatted
        })
    except Exception as e:
        print(f"Error in api_pentester_pentests: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/pentester/pentest/<pentest_id>', methods=['GET'])
@pentester_required
def api_pentester_pentest_detail(pentest_id):
    """Get single pentest details for pentester."""
    try:
        pentest = ptaas_db.get_pentest_by_id(pentest_id)
        if not pentest:
            return jsonify({'error': 'Pentest not found'}), 404
        return jsonify({
            'success': True,
            'id': pentest['id'],
            'title': pentest['title'],
            'type': pentest['type'],
            'status': pentest['status'],
            'scope': pentest.get('scope', ''),
            'targets': pentest.get('targets', ''),
            'description': pentest.get('description', ''),
            'start_date': pentest.get('start_date'),
            'end_date': pentest.get('end_date'),
            # Full client data for pentester
            'company_name': pentest.get('company_name', ''),
            'client_name': pentest.get('client_name', ''),
            'objectives': pentest.get('objectives', ''),
            'technology_stack': pentest.get('technology_stack', ''),
            'environment_type': pentest.get('environment_type', ''),
            'collaboration_preference': pentest.get('collaboration_preference', ''),
            'sensitive_data': pentest.get('sensitive_data', '[]'),
            'notes': pentest.get('notes', ''),
            'compliance': pentest.get('compliance', '[]'),
            'priority': pentest.get('priority', 'normal'),
            'credential_type': pentest.get('credential_type', 'none'),
            'credentials': pentest.get('credentials', '')
        })
    except Exception as e:
        print(f"Error in api_pentester_pentest_detail: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/pentester/pentest/<pentest_id>/findings', methods=['GET'])
@pentester_required
def api_pentester_pentest_findings(pentest_id):
    """Get findings for a pentest."""
    try:
        findings = ptaas_db.get_findings_for_pentest(pentest_id)
        return jsonify({
            'success': True,
            'findings': [dict(f) for f in findings] if findings else []
        })
    except Exception as e:
        print(f"Error in api_pentester_pentest_findings: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/pentester/finding', methods=['POST'])
@pentester_required
def api_pentester_submit_finding():
    """Submit a new finding."""
    try:
        user_id = session.get('user_id')
        data = request.get_json()
        
        pentest_id = data.get('pentest_id')
        if not pentest_id:
            return jsonify({'error': 'pentest_id is required'}), 400
        
        finding = ptaas_db.create_finding(
            pentest_id=pentest_id,
            pentester_id=user_id,
            title=data.get('title', 'Untitled Finding'),
            severity=data.get('severity', 'medium'),
            description=data.get('description', ''),
            poc=data.get('poc', ''),
            impact=data.get('impact', ''),
            remediation=data.get('remediation', '')
        )
        
        # Extract ID from finding dict or use directly if it's a string
        finding_id = finding.get('id') if isinstance(finding, dict) else finding
        
        return jsonify({
            'success': True,
            'finding_id': finding_id,
            'message': 'Finding submitted successfully'
        })
    except Exception as e:
        print(f"Error in api_pentester_submit_finding: {e}")
        return jsonify({'error': str(e)}), 500




@app.route('/api/pentester/finding/<finding_id>', methods=['PUT'])
@pentester_required
def api_pentester_update_finding(finding_id):
    """Update a finding (pentester can only edit their own)."""
    try:
        user_id = session.get('user_id')
        data = request.get_json()
        
        # Remove non-editable fields
        data.pop('id', None)
        data.pop('pentest_id', None)
        data.pop('pentester_id', None)
        data.pop('created_at', None)
        
        success = ptaas_db.update_finding_fields(finding_id, pentester_id=user_id, **data)
        
        if success:
            return jsonify({'success': True, 'message': 'Finding updated'})
        else:
            return jsonify({'error': 'Cannot update finding (not owner or not found)'}), 403
    except Exception as e:
        print(f"Error updating finding: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/pentester/finding/<finding_id>', methods=['DELETE'])
@pentester_required
def api_pentester_delete_finding(finding_id):
    """Delete a finding (only new/draft status, own findings only)."""
    try:
        user_id = session.get('user_id')
        
        success = ptaas_db.delete_finding(finding_id, pentester_id=user_id)
        
        if success:
            return jsonify({'success': True, 'message': 'Finding deleted'})
        else:
            return jsonify({'error': 'Cannot delete finding (not owner, not found, or already processed)'}), 403
    except Exception as e:
        print(f"Error deleting finding: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/pentester/finding/<finding_id>', methods=['GET'])
@pentester_required
def api_pentester_get_finding(finding_id):
    """Get a single finding detail."""
    try:
        finding = ptaas_db.get_finding_by_id(finding_id)
        if not finding:
            return jsonify({'error': 'Finding not found'}), 404
        
        return jsonify({'success': True, 'finding': dict(finding)})
    except Exception as e:
        print(f"Error getting finding: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/finding-states', methods=['GET'])
def api_get_finding_states():
    """Get valid finding states."""
    return jsonify({'success': True, 'states': ptaas_db.get_finding_states()})


@app.route('/api/pentest-states', methods=['GET'])
def api_get_pentest_states():
    """Get valid pentest states."""
    return jsonify({'success': True, 'states': ptaas_db.get_pentest_states()})


@app.route('/api/ptaas/pentests', methods=['GET'])
@pentester_required
def api_get_pentests():
    """Get list of pentests for the logged-in pentester."""
    try:
        user_id = session.get('user_id')
        status_filter = request.args.get('status', 'all')
        
        pentests = ptaas_db.get_pentests_for_pentester(user_id, status_filter if status_filter != 'all' else None)
        
        # Format for frontend
        formatted = []
        for p in pentests:
            formatted.append({
                'id': p['id'],
                'title': p['title'],
                'pentestNumber': p['pentest_number'],
                'type': p['type'].title(),
                'status': p['status'].title(),
                'progress': p['progress'] or 0,
                'total_findings': p['total_findings'] or 0,
                'critical_count': p['critical_count'] or 0,
                'high_count': p['high_count'] or 0,
                'medium_count': p['medium_count'] or 0,
                'low_count': p['low_count'] or 0,
                'start_date': p['start_date'],
                'end_date': p['end_date'],
                'company': p['company_name']
            })
        
        # Calculate stats
        stats = ptaas_db.get_pentester_stats(user_id)
        
        return jsonify({
            'success': True,
            'pentests': formatted,
            'stats': {
                'active': stats.get('active_pentests', 0),
                'planned': len([p for p in pentests if p['status'] == 'planned']),
                'remediation': len([p for p in pentests if p['status'] == 'remediation']),
                'completed': len([p for p in pentests if p['status'] == 'completed'])
            }
        })
    except Exception as e:
        print(f"Error in api_get_pentests: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ptaas/pentest/<pentest_id>', methods=['GET'])
@pentester_required
def api_get_pentest(pentest_id):
    """Get details of a specific pentest."""
    try:
        user_id = session.get('user_id')

        # Security: ensure the logged-in pentester is assigned to this pentest
        conn = ptaas_db.get_db()
        c = conn.cursor()
        c.execute(
            "SELECT 1 FROM pentest_pentesters WHERE pentest_id = ? AND pentester_id = ? AND status = 'accepted' LIMIT 1",
            (pentest_id, user_id),
        )
        assigned = c.fetchone() is not None
        conn.close()
        if not assigned:
            return jsonify({'error': 'Not authorized for this pentest'}), 403

        pentest = ptaas_db.get_pentest_by_id(pentest_id)
        
        if not pentest:
            return jsonify({'error': 'Pentest not found'}), 404
        
        # Get findings for this pentest
        findings = ptaas_db.get_findings_for_pentest(pentest_id)
        
        formatted_findings = [{
            'id': f['id'],
            'title': f['title'],
            'severity': f['severity'].title(),
            'status': f['status'].title(),
            'category': f['category'],
            'cvss': f['cvss_score'],
            'date': f['created_at'][:10] if f['created_at'] else ''
        } for f in findings]
        
        # Build collaborators list (client + assigned pentesters + one platform admin contact)
        collaborators = []
        try:
            client = ptaas_db.get_user_by_id(pentest.get('client_id'))
            if client:
                collaborators.append({
                    'id': client.get('id'),
                    'name': client.get('name') or client.get('company') or 'Client',
                    'email': client.get('email') or '',
                    'role': 'Client',
                    'is_poc': True
                })

            conn = ptaas_db.get_db()
            c = conn.cursor()
            c.execute('''
                SELECT u.id, u.name, u.email, pp.role, pp.status
                FROM pentest_pentesters pp
                JOIN ptaas_users u ON pp.pentester_id = u.id
                WHERE pp.pentest_id = ?
                ORDER BY CASE WHEN pp.role = 'lead' THEN 0 ELSE 1 END, u.name
            ''', (pentest_id,))
            for r in c.fetchall():
                role_label = 'Lead Pentester' if (r['role'] == 'lead') else 'Pentester'
                collaborators.append({
                    'id': r['id'],
                    'name': r['name'] or 'Pentester',
                    'email': r['email'] or '',
                    'role': role_label,
                    'is_poc': (r['role'] == 'lead')
                })

            c.execute("SELECT id, name, email FROM ptaas_users WHERE role = 'admin' AND is_active = 1 ORDER BY created_at ASC LIMIT 1")
            admin = c.fetchone()
            conn.close()
            if admin:
                collaborators.append({
                    'id': admin['id'],
                    'name': admin['name'] or 'Admin',
                    'email': admin['email'] or '',
                    'role': 'Admin',
                    'is_poc': False
                })
        except Exception as collab_err:
            print(f"[WARN] Collaborators build failed: {collab_err}")

        return jsonify({
            'success': True,
            'pentest': {
                'id': pentest['id'],
                'title': pentest['title'],
                'pentestNumber': pentest['pentest_number'],
                'type': pentest['type'].title(),
                'status': pentest['status'].title(),
                'progress': pentest['progress'] or 0,
                'description': pentest['description'],
                'scope': pentest['scope'],
                'targets': json.loads(pentest['targets']) if pentest['targets'] else [],
                'start_date': pentest['start_date'],
                'end_date': pentest['end_date'],
                'company': pentest['company_name'],
                'total_findings': pentest['total_findings'] or 0,
                'critical_count': pentest['critical_count'] or 0,
                'high_count': pentest['high_count'] or 0,
                'medium_count': pentest['medium_count'] or 0,
                'low_count': pentest['low_count'] or 0,
                'findings': formatted_findings,
                # Client-submitted details
                'client_name': pentest.get('client_name', ''),
                'objectives': pentest.get('objectives', ''),
                'technology_stack': pentest.get('technology_stack', ''),
                'environment_type': pentest.get('environment_type', ''),
                'collaboration_preference': pentest.get('collaboration_preference', ''),
                'sensitive_data': pentest.get('sensitive_data', '[]'),
                'notes': pentest.get('notes', ''),
                'priority': pentest.get('priority', 'normal'),
                'credential_type': pentest.get('credential_type', 'none'),
                'credentials': pentest.get('credentials', ''),
                'collaborators': collaborators
            }
        })
    except Exception as e:
        print(f"Error in api_get_pentest: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ptaas/findings', methods=['GET'])
@pentester_required
def api_get_findings():
    """Get list of findings for the logged-in pentester."""
    try:
        user_id = session.get('user_id')
        severity_filter = request.args.get('severity', 'all')
        status_filter = request.args.get('status', 'all')
        
        findings = ptaas_db.get_findings_for_pentester(
            user_id, 
            severity_filter if severity_filter != 'all' else None,
            status_filter if status_filter != 'all' else None
        )
        
        formatted = [{
            'id': f['id'],
            'title': f['title'],
            'description': f['description'],
            'severity': f['severity'].title(),
            'status': f['status'].title(),
            'pentestId': f['pentest_id'],
            'pentestTitle': f.get('pentest_title', ''),
            'category': f['category'],
            'date': f['created_at'][:10] if f['created_at'] else '',
            'cvss': f['cvss_score']
        } for f in findings]
        
        # Calculate stats
        all_findings = ptaas_db.get_findings_for_pentester(user_id)
        stats = {
            'critical': len([f for f in all_findings if f['severity'] == 'critical']),
            'high': len([f for f in all_findings if f['severity'] == 'high']),
            'medium': len([f for f in all_findings if f['severity'] == 'medium']),
            'low': len([f for f in all_findings if f['severity'] == 'low']),
            'info': len([f for f in all_findings if f['severity'] == 'info'])
        }
        
        return jsonify({
            'success': True,
            'findings': formatted,
            'stats': stats
        })
    except Exception as e:
        print(f"Error in api_get_findings: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ptaas/finding/<finding_id>', methods=['GET'])
@pentester_required
def api_get_finding(finding_id):
    """Get details of a specific finding."""
    try:
        finding = ptaas_db.get_finding_by_id(finding_id)
        
        if not finding:
            return jsonify({'error': 'Finding not found'}), 404
        
        pentest = ptaas_db.get_pentest_by_id(finding['pentest_id'])
        
        return jsonify({
            'success': True,
            'finding': {
                'id': finding['id'],
                'title': finding['title'],
                'description': finding['description'],
                'severity': finding['severity'].title(),
                'status': finding['status'].title(),
                'cvss': finding['cvss_score'],
                'cvssVector': finding['cvss_vector'],
                'category': finding['category'],
                'affectedUrl': finding['affected_url'],
                'affectedParameter': finding['affected_parameter'],
                'poc': finding['poc'],
                'stepsToReproduce': finding['steps_to_reproduce'],
                'impact': finding['impact'],
                'remediation': finding['remediation'],
                'cweId': finding['cwe_id'],
                'references': json.loads(finding['reference_urls']) if finding['reference_urls'] else [],
                'pentestId': finding['pentest_id'],
                'pentestTitle': pentest['title'] if pentest else '',
                'date': finding['created_at'][:10] if finding['created_at'] else '',
                'clientResponse': finding['client_response']
            }
        })
    except Exception as e:
        print(f"Error in api_get_finding: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ptaas/findings', methods=['POST'])
@pentester_required
def api_create_finding():
    """Create a new finding."""
    try:
        user_id = session.get('user_id')
        data = request.json
        
        finding = ptaas_db.create_finding(
            pentest_id=data['pentest_id'],
            pentester_id=user_id,
            title=data['title'],
            description=data['description'],
            severity=data['severity'].lower(),
            cvss_score=data.get('cvss_score'),
            cvss_vector=data.get('cvss_vector'),
            category=data.get('category', 'Other'),
            affected_url=data.get('affected_url'),
            affected_parameter=data.get('affected_parameter'),
            poc=data.get('poc'),
            steps_to_reproduce=data.get('steps_to_reproduce'),
            impact=data.get('impact'),
            remediation=data.get('remediation'),
            cwe_id=data.get('cwe_id'),
            reference_urls=json.dumps(data.get('references', []))
        )
        
        return jsonify({
            'success': True,
            'finding': finding,
            'message': 'Finding submitted successfully'
        })
    except Exception as e:
        print(f"Error in api_create_finding: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ptaas/activity', methods=['GET'])
@pentester_required
def api_get_activity():
    """Get activity feed for the logged-in user."""
    try:
        user_id = session.get('user_id')
        activities = ptaas_db.get_activity_for_user(user_id, limit=50)
        
        formatted = []
        for a in activities:
            # Calculate time ago
            created_at = a['created_at']
            if created_at:
                created = datetime.fromisoformat(created_at)
                diff = datetime.now() - created
                if diff.days > 0:
                    time_ago = f"{diff.days} days ago"
                elif diff.seconds > 3600:
                    time_ago = f"{diff.seconds // 3600} hours ago"
                else:
                    time_ago = f"{diff.seconds // 60} minutes ago"
            else:
                time_ago = "Recently"
            
            formatted.append({
                'id': a['id'],
                'type': a['type'],
                'title': a['title'],
                'description': a['description'],
                'time': time_ago,
                'icon': a['icon'] or '📌',
                'pentestId': a['pentest_id'],
                'findingId': a['finding_id']
            })
        
        return jsonify({
            'success': True,
            'activities': formatted
        })
    except Exception as e:
        print(f"Error in api_get_activity: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ptaas/apply/<posting_id>', methods=['POST'])
@pentester_required
def api_apply_posting(posting_id):
    """Apply for a pentest posting."""
    try:
        user_id = session.get('user_id')
        data = request.json or {}
        cover_letter = data.get('cover_letter', '')
        
        success = ptaas_db.apply_to_posting(posting_id, user_id, cover_letter)
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Application submitted successfully! We will review your application and get back to you.'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'You have already applied to this posting'
            }), 400
    except Exception as e:
        print(f"Error in api_apply_posting: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ptaas/stats', methods=['GET'])
@pentester_required
def api_get_ptaas_stats():
    """Get dashboard stats for the logged-in user."""
    try:
        user_id = session.get('user_id')
        user = ptaas_db.get_user_by_id(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        if user['role'] == 'pentester':
            stats = ptaas_db.get_pentester_stats(user_id)
        else:
            stats = ptaas_db.get_client_stats(user_id)
        
        return jsonify({
            'success': True,
            **stats
        })
    except Exception as e:
        print(f"Error in api_get_ptaas_stats: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ptaas/feedback', methods=['GET'])
@pentester_required
def api_get_feedback():
    """Get feedback for the logged-in pentester."""
    try:
        user_id = session.get('user_id')
        feedback = ptaas_db.get_feedback_for_pentester(user_id)
        
        formatted = []
        for f in feedback:
            formatted.append({
                'id': f['id'],
                'pentestTitle': f.get('pentest_title', ''),
                'clientName': f.get('client_name', 'Anonymous'),
                'clientCompany': f.get('client_company', ''),
                'overallRating': f['overall_rating'],
                'communicationRating': f['communication_rating'],
                'qualityRating': f['quality_rating'],
                'timelinessRating': f['timeliness_rating'],
                'professionalismRating': f['professionalism_rating'],
                'comment': f['comment'],
                'strengths': json.loads(f['strengths']) if f['strengths'] else [],
                'improvements': json.loads(f['improvements']) if f['improvements'] else [],
                'date': f['created_at'][:10] if f['created_at'] else ''
            })
        
        # Calculate averages
        if formatted:
            avg_rating = sum(f['overallRating'] for f in formatted if f['overallRating']) / len(formatted)
        else:
            avg_rating = 0
        
        return jsonify({
            'success': True,
            'feedback': formatted,
            'averageRating': round(avg_rating, 1),
            'totalReviews': len(formatted)
        })
    except Exception as e:
        print(f"Error in api_get_feedback: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ptaas/reports', methods=['GET'])
@pentester_required
def api_get_reports():
    """Get reports for pentests the pentester worked on."""
    try:
        user_id = session.get('user_id')
        reports = ptaas_db.get_reports_for_pentester(user_id)
        
        formatted = []
        for r in reports:
            formatted.append({
                'id': r['id'],
                'pentestTitle': r.get('pentest_title', ''),
                'type': r['type'].title(),
                'title': r['title'],
                'fileUrl': r['file_url'],
                'findingsCount': r['findings_count'] or 0,
                'criticalCount': r['critical_count'] or 0,
                'highCount': r['high_count'] or 0,
                'mediumCount': r['medium_count'] or 0,
                'lowCount': r['low_count'] or 0,
                'generatedAt': r['generated_at'],
                'downloads': r['downloads'] or 0
            })
        
        return jsonify({
            'success': True,
            'reports': formatted
        })
    except Exception as e:
        print(f"Error in api_get_reports: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ptaas/profile', methods=['GET'])
@pentester_required
def api_get_profile():
    """Get profile for the logged-in user."""
    try:
        user_id = session.get('user_id')
        user = ptaas_db.get_user_by_id(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({
            'success': True,
            'profile': {
                'id': user['id'],
                'email': user['email'],
                'name': user['name'],
                'role': user['role'],
                'company': user['company'],
                'avatar': user['avatar'],
                'phone': user['phone'],
                'country': user['country'],
                'timezone': user['timezone'],
                'language': user['language'],
                'bio': user['bio'],
                'skills': json.loads(user['skills']) if user['skills'] else [],
                'certifications': json.loads(user['certifications']) if user['certifications'] else [],
                'linkedin': user['linkedin'],
                'twitter': user['twitter'],
                'github': user['github'],
                'website': user['website'],
                'rating': user['rating'] or 0,
                'ratingCount': user['rating_count'] or 0,
                'totalEarnings': user['total_earnings'] or 0,
                'pentestsCompleted': user['pentests_completed'] or 0,
                'findingsSubmitted': user['findings_submitted'] or 0,
                'isAvailable': user['is_available'] == 1,
                'verified': user['verified'] == 1
            }
        })
    except Exception as e:
        print(f"Error in api_get_profile: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ptaas/profile', methods=['PUT'])
@pentester_required
def api_update_profile():
    """Update profile for the logged-in user."""
    try:
        user_id = session.get('user_id')
        data = request.json
        
        # Process skills and certifications as JSON
        if 'skills' in data and isinstance(data['skills'], list):
            data['skills'] = json.dumps(data['skills'])
        if 'certifications' in data and isinstance(data['certifications'], list):
            data['certifications'] = json.dumps(data['certifications'])
        
        success = ptaas_db.update_user(user_id, **data)
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Profile updated successfully'
            })
        else:
            return jsonify({'error': 'No valid fields to update'}), 400
    except Exception as e:
        print(f"Error in api_update_profile: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ptaas/api-token', methods=['POST'])
@pentester_required
def api_regenerate_token():
    """Regenerate API token for the logged-in user."""
    try:
        user_id = session.get('user_id')
        token = ptaas_db.regenerate_api_token(user_id)
        
        return jsonify({
            'success': True,
            'token': token
        })
    except Exception as e:
        print(f"Error in api_regenerate_token: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/notifications', methods=['GET'])
@login_required
def api_get_notifications():
    """Get notifications for the logged-in user."""
    try:
        user_id = session.get('user_id')
        unread_only = request.args.get('unread', 'false').lower() == 'true'
        
        notifications = ptaas_db.get_notifications(user_id, unread_only)
        
        formatted = []
        for n in notifications:
            # Calculate time ago
            created_at = n['created_at']
            if created_at:
                created = datetime.fromisoformat(created_at)
                diff = datetime.now() - created
                if diff.days > 0:
                    time_ago = f"{diff.days}d ago"
                elif diff.seconds > 3600:
                    time_ago = f"{diff.seconds // 3600}h ago"
                else:
                    time_ago = f"{diff.seconds // 60}m ago"
            else:
                time_ago = "Now"
            
            formatted.append({
                'id': n['id'],
                'type': n['type'],
                'title': n['title'],
                'message': n['message'],
                'link': n['link'],
                'isRead': n['is_read'] == 1,
                'time': time_ago
            })
        
        return jsonify({
            'success': True,
            'notifications': formatted,
            'count': len([n for n in notifications if n['is_read'] == 0])
        })
    except Exception as e:
        print(f"Error in api_get_notifications: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/notifications/<notification_id>/read', methods=['POST'])
@login_required
def api_mark_notification_read(notification_id):
    """Mark a notification as read."""
    try:
        ptaas_db.mark_notification_read(notification_id)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/notifications/read-all', methods=['POST'])
@login_required
def api_mark_all_notifications_read():
    """Mark all notifications as read."""
    try:
        user_id = session.get('user_id')
        ptaas_db.mark_all_notifications_read(user_id)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# -------------------- LEGACY CLIENT ROUTES - REDIRECT TO NEW PLATFORM --------------------


@app.route('/client/dashboard')
def client_dashboard():
    """Redirect to new platform."""
    return redirect('https://platform.redconoffence.com/app/client/dashboard')


@app.route('/client/pentests')
def client_pentests():
    """Redirect to new platform."""
    return redirect('https://platform.redconoffence.com/app/client/pentests')


@app.route('/client/pentest/<pentest_id>')
def client_pentest_detail(pentest_id):
    """Redirect to new platform."""
    return redirect(f'https://platform.redconoffence.com/app/client/pentest/{pentest_id}')


@app.route('/client/finding/<finding_id>')
def client_finding_detail(finding_id):
    """Redirect to new platform."""
    return redirect(f'https://platform.redconoffence.com/app/client/finding/{finding_id}')


@app.route('/client/findings')
def client_findings():
    """Redirect to new platform."""
    return redirect('https://platform.redconoffence.com/app/client/findings')


@app.route('/client/notifications')
def client_notifications():
    """Redirect to new platform."""
    return redirect('https://platform.redconoffence.com/app/client/notifications')


@app.route('/client/settings')
def client_settings():
    """Redirect to new platform."""
    return redirect('https://platform.redconoffence.com/app/client/settings')


@app.route('/client/reports')
def client_reports():
    """Redirect to new platform."""
    return redirect('https://platform.redconoffence.com/app/client/reports')


@app.route('/client/compliance')
def client_compliance():
    """Redirect to new platform."""
    return redirect('https://platform.redconoffence.com/app/client/dashboard')


@app.route('/client/billing')
def client_billing():
    """Redirect to new platform."""
    return redirect('https://platform.redconoffence.com/app/client/billing')


@app.route('/api/client/report/<pentest_id>', methods=['GET'])
@client_required
def api_get_client_report(pentest_id):
    """Generate and return executive summary report for a pentest."""
    try:
        user_id = session.get('user_id')
        
        # Get pentest details
        pentest = ptaas_db.get_pentest_by_id(pentest_id)
        if not pentest:
            return jsonify({'error': 'Pentest not found'}), 404
        
        if pentest.get('client_id') != user_id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Get findings for this pentest
        findings = ptaas_db.get_findings_for_pentest(pentest_id)
        
        # Generate executive summary
        report_html = generate_executive_summary(pentest, findings)
        
        return jsonify({
            'success': True,
            'report': report_html
        })
    except Exception as e:
        print(f"Error generating report: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/client/report/<pentest_id>/generate', methods=['POST'])
@client_required
def api_regenerate_report(pentest_id):
    """Regenerate report for a pentest."""
    # Just return success - report is generated on demand
    return jsonify({'success': True, 'message': 'Report regenerated'})


@app.route('/api/client/billing', methods=['GET'])
@client_required
def api_get_client_billing():
    """Get billing information for client."""
    try:
        user_id = session.get('user_id')
        user = ptaas_db.get_user_by_id(user_id)
        
        # Get credits from user record (or default)
        credits = user.get('credits', 0) if user else 0
        
        return jsonify({
            'success': True,
            'credits': credits,
            'company': user.get('company', '') if user else '',
            'address': user.get('address', '') if user else '',
            'transactions': []  # Would be fetched from a transactions table
        })
    except Exception as e:
        print(f"Error getting billing: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/client/purchase-credits', methods=['POST'])
@client_required
def api_purchase_credits():
    """Purchase credits (simulated)."""
    try:
        user_id = session.get('user_id')
        data = request.get_json()
        credits = data.get('credits', 0)
        
        if credits < 10:
            return jsonify({'error': 'Minimum 10 credits required'}), 400
        
        # In production, this would integrate with Stripe/payment processor
        # For now, just add credits to the user's account
        conn = ptaas_db.get_db()
        c = conn.cursor()
        
        c.execute('UPDATE ptaas_users SET credits = COALESCE(credits, 0) + ? WHERE id = ?',
                 (credits, user_id))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': f'Successfully purchased {credits} credits'
        })
    except Exception as e:
        print(f"Error purchasing credits: {e}")
        return jsonify({'error': str(e)}), 500


def generate_executive_summary(pentest, findings):
    """Generate an executive summary report for a pentest."""
    from datetime import datetime
    
    # Calculate statistics
    total = len(findings) if findings else 0
    critical = sum(1 for f in findings if f.get('severity', '').lower() == 'critical') if findings else 0
    high = sum(1 for f in findings if f.get('severity', '').lower() == 'high') if findings else 0
    medium = sum(1 for f in findings if f.get('severity', '').lower() == 'medium') if findings else 0
    low = sum(1 for f in findings if f.get('severity', '').lower() == 'low') if findings else 0
    
    # Calculate risk level
    if critical > 0:
        risk_level = "Critical"
        risk_color = "#dc2626"
    elif high > 0:
        risk_level = "High"
        risk_color = "#ea580c"
    elif medium > 0:
        risk_level = "Medium"
        risk_color = "#d97706"
    else:
        risk_level = "Low"
        risk_color = "#22c55e"
    
    # Generate findings table
    findings_table = ""
    if findings:
        for f in findings[:10]:  # Limit to 10 findings in summary
            severity = f.get('severity', 'Medium').title()
            findings_table += f"""
            <tr>
                <td>{f.get('title', 'Untitled')}</td>
                <td>{severity}</td>
                <td>{f.get('status', 'New').title()}</td>
            </tr>
            """
    
    # Build the report HTML
    report = f"""
    <h1>Executive Security Summary</h1>
    <p class="meta">
        <strong>{pentest.get('title', 'Security Assessment')}</strong><br>
        Report Generated: {datetime.now().strftime('%B %d, %Y')}<br>
        Assessment Period: {pentest.get('start_date', 'N/A')} to {pentest.get('end_date', 'N/A')}
    </p>
    
    <h2>Executive Overview</h2>
    <div class="summary-box">
        <p><strong>Overall Risk Level: <span style="color: {risk_color};">{risk_level}</span></strong></p>
        <p>REDCON OFFENCE conducted a comprehensive security assessment of {pentest.get('company_name', 'your organization')}'s 
        {pentest.get('type', 'application').title()} environment. The assessment identified <strong>{total} security findings</strong>, 
        including {critical} critical, {high} high, {medium} medium, and {low} low severity issues.</p>
    </div>
    
    <h2>Key Findings Summary</h2>
    <p>The security assessment revealed several areas requiring attention:</p>
    <table>
        <tr>
            <th>Severity</th>
            <th>Count</th>
            <th>Priority</th>
        </tr>
        <tr>
            <td style="color: #dc2626;">Critical</td>
            <td>{critical}</td>
            <td>Immediate action required</td>
        </tr>
        <tr>
            <td style="color: #ea580c;">High</td>
            <td>{high}</td>
            <td>Address within 7 days</td>
        </tr>
        <tr>
            <td style="color: #d97706;">Medium</td>
            <td>{medium}</td>
            <td>Address within 30 days</td>
        </tr>
        <tr>
            <td style="color: #22c55e;">Low</td>
            <td>{low}</td>
            <td>Address within 90 days</td>
        </tr>
    </table>
    
    <h2>Findings Detail</h2>
    <table>
        <tr>
            <th>Finding</th>
            <th>Severity</th>
            <th>Status</th>
        </tr>
        {findings_table if findings_table else '<tr><td colspan="3">No findings recorded</td></tr>'}
    </table>
    
    <h2>Recommendations</h2>
    <h3>Immediate Actions</h3>
    <p>{"Address all critical and high severity findings as a priority. These issues pose significant risk to the security posture." if critical > 0 or high > 0 else "No immediate critical actions required. Continue monitoring and address medium/low findings per schedule."}</p>
    
    <h3>Short-term Improvements</h3>
    <p>Implement security controls to address medium severity findings. Review and update security policies and procedures.</p>
    
    <h3>Long-term Strategy</h3>
    <p>Establish a continuous security testing program. Conduct regular vulnerability assessments and penetration tests to maintain security posture.</p>
    
    <h2>Conclusion</h2>
    <p>This assessment provides a snapshot of the current security posture. REDCON OFFENCE recommends addressing the identified 
    vulnerabilities according to the priority levels outlined above. Regular security assessments are essential for maintaining 
    a strong security posture in today's threat landscape.</p>
    
    <p style="margin-top: 32px; padding-top: 16px; border-top: 1px solid #ddd; font-size: 12px; color: #666;">
        <em>This report is confidential and intended only for the recipient organization. 
        Generated by REDCON OFFENCE Security Platform.</em>
    </p>
    """
    
    return report


@app.route('/api/client/notification-settings', methods=['GET'])
@client_required
def api_get_notification_settings():
    """Get notification settings for user."""
    try:
        user_id = session.get('user_id')
        
        conn = ptaas_db.get_db()
        c = conn.cursor()
        
        c.execute('SELECT settings FROM notification_settings WHERE user_id = ?', (user_id,))
        row = c.fetchone()
        conn.close()
        
        if row:
            # json is imported at top of file
            settings = json.loads(row[0])
        else:
            settings = {
                'pentest_updates': True,
                'new_findings': True,
                'critical_findings': True,
                'weekly_reports': False,
                'marketing': False
            }
        
        return jsonify({'success': True, 'settings': settings})
    except Exception as e:
        print(f"Error getting notification settings: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/client/notification-settings', methods=['POST'])
@client_required
def api_save_notification_settings():
    """Save notification settings for user."""
    try:
        user_id = session.get('user_id')
        data = request.get_json()
        
        # json is imported at top of file
        settings_json = json.dumps(data)
        
        conn = ptaas_db.get_db()
        c = conn.cursor()
        
        # Check if exists
        c.execute('SELECT id FROM notification_settings WHERE user_id = ?', (user_id,))
        if c.fetchone():
            c.execute('UPDATE notification_settings SET settings = ?, updated_at = ? WHERE user_id = ?',
                     (settings_json, datetime.now().isoformat(), user_id))
        else:
            c.execute('INSERT INTO notification_settings (id, user_id, settings, created_at, updated_at) VALUES (?, ?, ?, ?, ?)',
                     (str(uuid.uuid4()), user_id, settings_json, datetime.now().isoformat(), datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Settings saved'})
    except Exception as e:
        print(f"Error saving notification settings: {e}")
        return jsonify({'error': str(e)}), 500



# ============================================================
# ASSET MANAGEMENT APIs
# ============================================================






@app.route('/api/asset-types', methods=['GET'])
def api_get_asset_types():
    """Get available asset types."""
    return jsonify({'success': True, 'types': ptaas_db.get_asset_types()})


# -------------------- CLIENT ASSETS (CLIENT ROLE ONLY) --------------------

@app.route('/api/client/assets', methods=['GET', 'POST'])
@client_required
def api_client_assets():
    """Client asset management (Cobalt-style Assets)."""
    try:
        user_id = session.get('user_id')
        if request.method == 'GET':
            assets = ptaas_db.get_assets_for_client(user_id)
            return jsonify({'success': True, 'assets': assets})

        data = request.get_json(force=True, silent=True) or {}
        name = (data.get('name') or '').strip()
        asset_type = (data.get('type') or '').strip()
        if not name or not asset_type:
            return jsonify({'error': 'name and type are required'}), 400

        asset_id = ptaas_db.create_asset(
            client_id=user_id,
            name=name,
            asset_type=asset_type,
            description=data.get('description', ''),
            url=data.get('url', ''),
            environment=data.get('environment', 'production'),
            technology_stack=data.get('technology_stack', ''),
            authentication_info=data.get('authentication_info', ''),
            status=data.get('status', 'active'),
            risk_level=data.get('risk_level', 'medium'),
        )
        return jsonify({'success': True, 'asset_id': asset_id})
    except Exception as e:
        print(f"Error in api_client_assets: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/client/assets/<asset_id>', methods=['GET', 'PUT', 'DELETE'])
@client_required
def api_client_asset_detail(asset_id):
    """Get/update/delete a client asset (ownership enforced)."""
    try:
        user_id = session.get('user_id')
        if request.method == 'GET':
            asset = ptaas_db.get_asset_by_id(asset_id)
            if not asset or asset.get('client_id') != user_id:
                return jsonify({'error': 'Asset not found'}), 404
            return jsonify({'success': True, 'asset': asset})

        if request.method == 'DELETE':
            ok = ptaas_db.delete_asset(asset_id, client_id=user_id)
            if not ok:
                return jsonify({'error': 'Asset not found'}), 404
            return jsonify({'success': True})

        data = request.get_json(force=True, silent=True) or {}
        ok = ptaas_db.update_asset(asset_id, client_id=user_id, **data)
        if not ok:
            return jsonify({'error': 'Asset not found or not editable'}), 404
        return jsonify({'success': True})
    except Exception as e:
        print(f"Error in api_client_asset_detail: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================================
# COVERAGE CHECKLIST APIs
# ============================================================

@app.route('/api/ptaas/pentest/<pentest_id>/coverage', methods=['GET'])
@pentester_required
def api_get_coverage(pentest_id):
    """Get coverage checklist for a pentest."""
    try:
        items = ptaas_db.get_coverage_for_pentest(pentest_id)
        stats = ptaas_db.get_coverage_stats(pentest_id)
        
        # Group by category
        grouped = {}
        for item in items:
            cat = item['category']
            if cat not in grouped:
                grouped[cat] = []
            grouped[cat].append(item)
        
        return jsonify({
            'success': True,
            'coverage': grouped,
            'stats': stats
        })
    except Exception as e:
        print(f"Error getting coverage: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ptaas/pentest/<pentest_id>/coverage', methods=['POST'])
@pentester_required
def api_init_coverage(pentest_id):
    """Initialize coverage checklist for a pentest."""
    try:
        # Get pentest to determine asset type
        pentest = ptaas_db.get_pentest_by_id(pentest_id)
        asset_type = pentest.get('type', 'web') if pentest else 'web'
        
        count = ptaas_db.create_coverage_items_for_pentest(pentest_id, asset_type)
        
        return jsonify({
            'success': True,
            'message': f'Created {count} checklist items',
            'count': count
        })
    except Exception as e:
        print(f"Error initializing coverage: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ptaas/coverage/<item_id>', methods=['PUT'])
@pentester_required
def api_update_coverage(item_id):
    """Update a coverage checklist item."""
    try:
        user_id = session.get('user_id')
        data = request.get_json()
        
        status = data.get('status', 'pending')
        notes = data.get('notes', '')
        
        success = ptaas_db.update_coverage_item(item_id, user_id, status, notes)
        
        if success:
            return jsonify({'success': True, 'message': 'Item updated'})
        else:
            return jsonify({'error': 'Failed to update item'}), 400
    except Exception as e:
        print(f"Error updating coverage: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ptaas/pentest/<pentest_id>/coverage-stats', methods=['GET'])
@pentester_required
def api_get_coverage_stats(pentest_id):
    """Get coverage statistics for a pentest."""
    try:
        user_id = session.get('user_id')
        # Enforce pentester assignment (fail closed)
        conn = ptaas_db.get_db()
        c = conn.cursor()
        c.execute(
            "SELECT 1 FROM pentest_pentesters WHERE pentest_id = ? AND pentester_id = ? AND status = 'accepted' LIMIT 1",
            (pentest_id, user_id),
        )
        assigned = c.fetchone() is not None
        conn.close()
        if not assigned:
            return jsonify({'error': 'Not authorized for this pentest'}), 403

        stats = ptaas_db.get_coverage_stats(pentest_id)
        return jsonify({'success': True, 'stats': stats})
    except Exception as e:
        print(f"Error getting coverage stats: {e}")
        return jsonify({'error': str(e)}), 500




@app.route('/api/client/stats', methods=['GET'])
@client_required
def api_get_client_stats():
    """Get dashboard stats for the logged-in client."""
    try:
        user_id = session.get('user_id')
        stats = ptaas_db.get_client_stats(user_id)
        
        # Get user info
        user = ptaas_db.get_user_by_id(user_id)
        user_info = None
        if user:
            user_info = {
                'id': user.get('id'),
                'name': user.get('name', 'Client'),
                'email': user.get('email'),
                'company': user.get('company', 'Company'),
                'role': user.get('role')
            }
        
        return jsonify({
            'success': True,
            'user': user_info,
            'stats': stats,
            **stats
        })
    except Exception as e:
        print(f"Error in api_get_client_stats: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/client/pentests', methods=['GET'])
@client_required
def api_get_client_pentests():
    """Get pentests for the logged-in client."""
    try:
        user_id = session.get('user_id')
        status_filter = request.args.get('status', 'all')
        
        pentests = ptaas_db.get_pentests_for_client(user_id, status_filter if status_filter != 'all' else None)
        
        formatted = []
        for p in pentests:
            formatted.append({
                'id': p['id'],
                'title': p['title'],
                'pentest_number': p['pentest_number'],
                'type': p['type'],
                'status': p['status'].title(),
                'progress': p['progress'] or 0,
                'total_findings': p['total_findings'] or 0,
                'critical_count': p['critical_count'] or 0,
                'high_count': p['high_count'] or 0,
                'medium_count': p['medium_count'] or 0,
                'low_count': p['low_count'] or 0,
                'start_date': p['start_date'],
                'end_date': p['end_date']
            })
        
        return jsonify({
            'success': True,
            'pentests': formatted
        })
    except Exception as e:
        print(f"Error in api_get_client_pentests: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/client/findings', methods=['GET'])
@client_required
def api_get_client_findings():
    """Get findings for the logged-in client's pentests."""
    try:
        user_id = session.get('user_id')
        limit = int(request.args.get('limit', 50))
        pentest_id = request.args.get('pentest_id')
        
        all_findings = []
        
        if pentest_id:
            # Get findings for a specific pentest
            pentest = ptaas_db.get_pentest_by_id(pentest_id)
            if pentest and pentest.get('client_id') == user_id:
                findings = ptaas_db.get_findings_for_pentest(pentest_id)
                for f in findings:
                    f['pentest_title'] = pentest['title']
                    all_findings.append(f)
        else:
            # Get all pentests for this client
            pentests = ptaas_db.get_pentests_for_client(user_id)
            
            for p in pentests:
                findings = ptaas_db.get_findings_for_pentest(p['id'])
                for f in findings:
                    f['pentest_title'] = p['title']
                    all_findings.append(f)
        
        # Sort by created_at and limit
        all_findings.sort(key=lambda x: x['created_at'] or '', reverse=True)
        all_findings = all_findings[:limit]
        
        formatted = [{
            'id': f['id'],
            'title': f['title'],
            'description': f['description'],
            'severity': f['severity'],
            'status': f['status'],
            'category': f['category'],
            'affected_url': f.get('affected_url', ''),
            'pentest_title': f.get('pentest_title', ''),
            'created_at': f['created_at']
        } for f in all_findings]
        
        return jsonify({
            'success': True,
            'findings': formatted
        })
    except Exception as e:
        print(f"Error in api_get_client_findings: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/client/pentest/<pentest_id>', methods=['GET'])
@client_required
def api_get_client_pentest_detail(pentest_id):
    """Get a specific pentest detail for the client including assigned pentesters."""
    try:
        user_id = session.get('user_id')
        
        # Get the pentest
        pentest = ptaas_db.get_pentest_by_id(pentest_id)
        
        if not pentest:
            return jsonify({'error': 'Pentest not found'}), 404
        
        # Verify this pentest belongs to the client
        if pentest.get('client_id') != user_id:
            return jsonify({'error': 'Access denied'}), 403
        
        # Get assigned pentesters
        conn = ptaas_db.get_db()
        c = conn.cursor()
        c.execute("""
            SELECT u.name, u.email, pp.role, pp.status
            FROM pentest_pentesters pp
            JOIN ptaas_users u ON pp.pentester_id = u.id
            WHERE pp.pentest_id = ? AND pp.status = 'accepted'
        """, (pentest_id,))
        pentesters = [dict(row) for row in c.fetchall()]
        conn.close()
        
        return jsonify({
            'success': True,
            'pentest': pentest,
            'assigned_pentesters': pentesters
        })
    except Exception as e:
        print(f"Error in api_get_client_pentest_detail: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/client/pentest/<pentest_id>/findings', methods=['GET'])
@client_required
def api_get_client_pentest_findings(pentest_id):
    """Get findings for a specific pentest (client view)."""
    try:
        user_id = session.get('user_id')
        
        # Get the pentest to verify ownership
        pentest = ptaas_db.get_pentest_by_id(pentest_id)
        if not pentest:
            return jsonify({'error': 'Pentest not found'}), 404
        
        if pentest.get('client_id') != user_id:
            return jsonify({'error': 'Access denied'}), 403
        
        # Get findings for this pentest
        findings = ptaas_db.get_findings_for_pentest(pentest_id)
        
        formatted = []
        for f in findings:
            formatted.append({
                'id': f['id'],
                'title': f['title'],
                'severity': f['severity'],
                'status': f['status'],
                'description': f.get('description', ''),
                'category': f.get('category', ''),
                'affected_url': f.get('affected_url', ''),
                'cvss_score': f.get('cvss_score'),
                'cwe_id': f.get('cwe_id'),
                'cve_id': f.get('cve_id'),
                'created_at': f.get('created_at', ''),
                'pentester_name': f.get('pentester_name', '')
            })
        
        return jsonify({
            'success': True,
            'findings': formatted
        })
    except Exception as e:
        print(f"Error in api_get_client_pentest_findings: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/client/upload-attachments', methods=['POST'])
@client_required
def api_upload_attachments():
    """Upload attachments for pentest request."""
    try:
        import os
        
        if 'files' not in request.files:
            return jsonify({'error': 'No files provided'}), 400
        
        files = request.files.getlist('files')
        file_ids = []
        
        # Create uploads directory if it doesn't exist
        upload_dir = os.path.join(os.path.dirname(__file__), 'uploads', 'pentest_attachments')
        os.makedirs(upload_dir, exist_ok=True)
        
        for file in files:
            if file.filename:
                # Generate unique filename
                file_id = str(uuid.uuid4())
                ext = os.path.splitext(file.filename)[1]
                safe_filename = f"{file_id}{ext}"
                
                file_path = os.path.join(upload_dir, safe_filename)
                file.save(file_path)
                
                file_ids.append({
                    'id': file_id,
                    'original_name': file.filename,
                    'path': safe_filename
                })
        
        return jsonify({
            'success': True,
            'file_ids': file_ids
        })
    except Exception as e:
        print(f"Error uploading attachments: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/uploads/pentest_attachments/<filename>')
def serve_attachment(filename):
    """Serve pentest attachment files to authenticated admins."""
    # Only admins can access attachments for security
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    
    user = ptaas_db.get_user_by_id(user_id)
    if not user or user.get('role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    import os
    from flask import send_from_directory
    upload_dir = os.path.join(os.path.dirname(__file__), 'uploads', 'pentest_attachments')
    return send_from_directory(upload_dir, filename)


@app.route('/api/client/request-pentest', methods=['POST'])
@client_required
def api_request_pentest():
    """Request a new pentest."""
    try:
        user_id = session.get('user_id')
        
        # Handle both JSON and multipart form data
        if request.content_type and 'multipart/form-data' in request.content_type:
            data = request.form.to_dict()
            # Parse JSON fields that might be stringified
            # json is imported at top of file
            for field in ['sensitive_data', 'compliance']:
                if field in data and isinstance(data[field], str):
                    try:
                        data[field] = json.loads(data[field])
                    except:
                        data[field] = []
        else:
            data = request.json or {}
        
        # Get user info first
        user = ptaas_db.get_user_by_id(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Date validation - ensure start date is not in the past
        from datetime import datetime, date
        today = date.today()
        start_date = data.get('start_date')
        end_date = data.get('end_date')
        
        if start_date:
            try:
                start = datetime.strptime(start_date, '%Y-%m-%d').date()
                if start < today:
                    return jsonify({'error': 'Start date cannot be in the past'}), 400
            except ValueError:
                pass
        
        if end_date and start_date:
            try:
                end = datetime.strptime(end_date, '%Y-%m-%d').date()
                start = datetime.strptime(start_date, '%Y-%m-%d').date()
                if end < start:
                    return jsonify({'error': 'End date must be after start date'}), 400
            except ValueError:
                pass

        # Build description with additional fields
        description_parts = []
        if data.get('scope'):
            description_parts.append(f"**Scope:**\n{data.get('scope')}")
        if data.get('objectives'):
            description_parts.append(f"**Objectives:**\n{data.get('objectives')}")
        if data.get('tech_stack'):
            description_parts.append(f"**Technology Stack:**\n{data.get('tech_stack')}")
        if data.get('collaboration'):
            description_parts.append(f"**Collaboration Preference:** {data.get('collaboration')}")
        if data.get('environment'):
            description_parts.append(f"**Environment Type:** {data.get('environment')}")
        if data.get('data_types'):
            description_parts.append(f"**Sensitive Data Types:** {', '.join(data.get('data_types', []))}")
        if data.get('attachments'):
            description_parts.append(f"**Attachments:** {len(data.get('attachments', []))} files uploaded")
        
        full_description = '\n\n'.join(description_parts)
        
        # Optionally attach an existing Asset (Cobalt-style flow: assets -> pentests)
        asset_id = data.get('asset_id') or ''
        asset = None
        if asset_id:
            try:
                a = ptaas_db.get_asset_by_id(asset_id)
                if a and a.get('client_id') == user_id:
                    asset = a
            except Exception:
                asset = None

        # Create the pentest request with all fields
        pentest = ptaas_db.create_pentest(
            client_id=user_id,
            title=data.get('title') or (asset.get('name') if asset else None) or 'New Pentest Request',
            type=data.get('type') or (asset.get('type') if asset else None) or 'Web Application',
            description=full_description,
            scope=data.get('scope', ''),
            targets=json.dumps(
                (data.get('targets', '').split('\n') if data.get('targets') else [])
                or ([asset.get('url')] if asset and asset.get('url') else [])
            ),
            start_date=data.get('start_date'),
            end_date=data.get('end_date'),
            compliance=json.dumps(data.get('compliance', [])),
            company_name=user.get('company', ''),
            # Extended fields
            objectives=data.get('objectives', ''),
            technology_stack=data.get('tech_stack') or (asset.get('technology_stack') if asset else '') or '',
            environment_type=data.get('environment') or (asset.get('environment') if asset else '') or '',
            collaboration_preference=data.get('collaboration', ''),
            sensitive_data=json.dumps(data.get('sensitive_data', data.get('data_types', []))),
            notes=data.get('notes', ''),
            priority=data.get('priority', 'normal'),
            client_name=user.get('name', ''),
            credential_type=data.get('credential_type', 'none'),
            credentials=data.get('credentials_notes', ''),
            attachments=json.dumps(data.get('attachments', []))
        )
        
        if not pentest:
            return jsonify({'error': 'Failed to create pentest request'}), 500
        
        # Update status to pending (awaiting admin approval)
        ptaas_db.update_pentest(pentest['id'], status='pending')
        
        # Send notification to admin (with error handling)
        try:
            send_osaas_notification({
                'contact_name': user.get('name', 'Unknown'),
                'contact_email': user.get('email', ''),
                'company': user.get('company', 'Unknown'),
                'service_type': data.get('type', 'Web Application'),
                'timeline': f"{data.get('start_date', 'TBD')} to {data.get('end_date', 'TBD')}",
                'budget': data.get('budget', 'TBD'),
                'scope': data.get('scope', '')
            })
        except Exception as notify_err:
            print(f"Notification error (non-critical): {notify_err}")
        
        return jsonify({
            'success': True,
            'pentest': pentest,
            'message': 'Pentest request submitted successfully'
        })
    except Exception as e:
        print(f"Error in api_request_pentest: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/client/finding/<finding_id>', methods=['GET'])
@client_required
def api_get_client_finding(finding_id):
    """Get a single finding for client."""
    try:
        user_id = session.get('user_id')
        
        conn = ptaas_db.get_db()
        c = conn.cursor()
        
        # Get finding with pentester info
        c.execute('''
            SELECT f.*, u.name as pentester_name, p.client_id
            FROM ptaas_findings f
            LEFT JOIN ptaas_users u ON f.pentester_id = u.id
            LEFT JOIN pentests p ON f.pentest_id = p.id
            WHERE f.id = ?
        ''', (finding_id,))
        
        row = c.fetchone()
        conn.close()
        
        if not row:
            return jsonify({'error': 'Finding not found'}), 404
        
        finding = dict(row)
        
        # Verify client owns this pentest
        if finding.get('client_id') != user_id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        return jsonify({
            'success': True,
            'finding': finding
        })
    except Exception as e:
        print(f"Error in api_get_client_finding: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/client/finding/<finding_id>/respond', methods=['POST'])
@client_required
def api_respond_to_finding(finding_id):
    """Respond to a finding (accept, reject, etc.)."""
    try:
        user_id = session.get('user_id')
        data = request.json
        status = data.get('status')
        response = data.get('response', '')
        
        ptaas_db.update_finding_status(finding_id, status, user_id, client_response=response)
        
        return jsonify({
            'success': True,
            'message': f'Finding status updated to {status}'
        })
    except Exception as e:
        print(f"Error in api_respond_to_finding: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================================
# LEGACY ADMIN ROUTES - REDIRECT TO NEW PLATFORM
# ============================================================

@app.route('/admin/dashboard')
def admin_dashboard():
    """Redirect to new platform."""
    return redirect('https://platform.redconoffence.com/app/admin/dashboard')


@app.route('/admin/pentests')
def admin_pentests():
    """Redirect to new platform."""
    return redirect('https://platform.redconoffence.com/app/admin/pentests')


@app.route('/admin/users')
def admin_users():
    """Redirect to new platform."""
    return redirect('https://platform.redconoffence.com/app/admin/users')


@app.route('/api/admin/stats', methods=['GET'])
@admin_required
def api_admin_stats():
    """Get admin dashboard stats."""
    try:
        conn = ptaas_db.get_db()
        c = conn.cursor()
        
        # Total users
        c.execute('SELECT COUNT(*) FROM ptaas_users')
        total_users = c.fetchone()[0]
        
        # Active pentests
        c.execute("SELECT COUNT(*) FROM pentests WHERE status IN ('live', 'planned')")
        active_pentests = c.fetchone()[0]
        
        # Pending requests
        c.execute("SELECT COUNT(*) FROM pentests WHERE status = 'pending'")
        pending_requests = c.fetchone()[0]
        
        # Total findings
        c.execute('SELECT COUNT(*) FROM ptaas_findings')
        total_findings = c.fetchone()[0]
        
        # Pending payouts
        c.execute("SELECT COALESCE(SUM(amount), 0) FROM payments WHERE status = 'pending'")
        pending_payouts = c.fetchone()[0]
        
        conn.close()
        
        return jsonify({
            'success': True,
            'total_users': total_users,
            'active_pentests': active_pentests,
            'pending_requests': pending_requests,
            'total_findings': total_findings,
            'pending_payouts': pending_payouts
        })
    except Exception as e:
        print(f"Error in api_admin_stats: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/users', methods=['GET'])
@admin_required
def api_admin_users():
    """Get all users for admin."""
    try:
        limit = int(request.args.get('limit', 50))
        
        conn = ptaas_db.get_db()
        c = conn.cursor()
        c.execute('SELECT * FROM ptaas_users ORDER BY created_at DESC LIMIT ?', (limit,))
        users = c.fetchall()
        conn.close()
        
        formatted = [{
            'id': u['id'],
            'name': u['name'],
            'email': u['email'],
            'role': u['role'],
            'company': u['company'],
            'is_active': u['is_active'] == 1 if u['is_active'] is not None else True,
            'verified': u['verified'] == 1,
            'created_at': u['created_at']
        } for u in users]
        
        return jsonify({
            'success': True,
            'users': formatted
        })
    except Exception as e:
        print(f"Error in api_admin_users: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/users', methods=['POST'])
@admin_required
def api_admin_create_user():
    """Create a new user (admin only)."""
    try:
        data = request.get_json()
        
        # Validate required fields
        required = ['email', 'password', 'name', 'role']
        for field in required:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        # Normalize email to lowercase (auth system requires lowercase)
        data['email'] = data['email'].lower().strip()
        
        # Validate role
        valid_roles = ['admin', 'client', 'pentester']
        if data['role'] not in valid_roles:
            return jsonify({'error': f'Invalid role. Must be one of: {", ".join(valid_roles)}'}), 400
        
        # Validate password strength
        if len(data['password']) < 8:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400
        
        # Check if email already exists
        existing = ptaas_db.get_user_by_email(data['email'])
        if existing:
            return jsonify({'error': 'Email already registered'}), 400
        
        # Create user
        user = ptaas_db.create_user(
            email=data['email'],
            password=data['password'],
            name=data['name'],
            role=data['role'],
            company=data.get('company', '')
        )
        
        if user:
            return jsonify({
                'success': True,
                'message': 'User created successfully',
                'user': {
                    'id': user['id'],
                    'email': user['email'],
                    'name': user['name'],
                    'role': user['role'],
                    'company': user.get('company', '')
                }
            })
        else:
            return jsonify({'error': 'Failed to create user'}), 500
            
    except Exception as e:
        print(f"Error creating user: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/users/<user_id>', methods=['GET'])
@admin_required
def api_admin_get_user(user_id):
    """Get a specific user by ID."""
    try:
        user = ptaas_db.get_user_by_id(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({
            'success': True,
            'user': {
                'id': user['id'],
                'email': user['email'],
                'name': user['name'],
                'role': user['role'],
                'company': user.get('company', ''),
                'verified': user.get('verified', 0) == 1,
                'is_active': user.get('is_active', 1) == 1,
                'created_at': user.get('created_at'),
                'last_login': user.get('last_login')
            }
        })
    except Exception as e:
        print(f"Error getting user: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/users/<user_id>', methods=['PUT'])
@admin_required
def api_admin_update_user(user_id):
    """Update a user (admin only)."""
    try:
        data = request.get_json()
        
        user = ptaas_db.get_user_by_id(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Build update dict
        updates = {}
        allowed_fields = ['name', 'company', 'role', 'verified', 'is_active']
        
        for field in allowed_fields:
            if field in data:
                updates[field] = data[field]
        
        # Handle password change separately
        if data.get('password'):
            if len(data['password']) < 8:
                return jsonify({'error': 'Password must be at least 8 characters'}), 400
            # Update password hash directly
            conn = ptaas_db.get_db()
            c = conn.cursor()
            c.execute('UPDATE ptaas_users SET password_hash = ? WHERE id = ?', 
                     (ptaas_db.hash_password(data['password']), user_id))
            conn.commit()
            conn.close()
        
        # Handle role change (need direct SQL since update_user doesn't allow role changes)
        if 'role' in data:
            valid_roles = ['admin', 'client', 'pentester']
            if data['role'] not in valid_roles:
                return jsonify({'error': f'Invalid role. Must be one of: {", ".join(valid_roles)}'}), 400
            conn = ptaas_db.get_db()
            c = conn.cursor()
            c.execute('UPDATE ptaas_users SET role = ? WHERE id = ?', (data['role'], user_id))
            conn.commit()
            conn.close()
        
        # Handle verified/is_active
        if 'verified' in data or 'is_active' in data:
            conn = ptaas_db.get_db()
            c = conn.cursor()
            if 'verified' in data:
                c.execute('UPDATE ptaas_users SET verified = ? WHERE id = ?', (1 if data['verified'] else 0, user_id))
            if 'is_active' in data:
                c.execute('UPDATE ptaas_users SET is_active = ? WHERE id = ?', (1 if data['is_active'] else 0, user_id))
            conn.commit()
            conn.close()
        
        # Update other fields
        if updates:
            ptaas_db.update_user(user_id, **{k: v for k, v in updates.items() if k in ['name', 'company']})
        
        return jsonify({
            'success': True,
            'message': 'User updated successfully'
        })
    except Exception as e:
        print(f"Error updating user: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/users/<user_id>', methods=['DELETE'])
@admin_required
def api_admin_delete_user(user_id):
    """Delete/deactivate a user (admin only)."""
    try:
        user = ptaas_db.get_user_by_id(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Don't allow deleting yourself
        if user_id == session.get('user_id'):
            return jsonify({'error': 'Cannot delete your own account'}), 400
        
        permanent = request.args.get('permanent', 'false').lower() == 'true'
        
        conn = ptaas_db.get_db()
        c = conn.cursor()
        
        if permanent:
            # Permanent delete - remove all related data
            c.execute('DELETE FROM pentest_pentesters WHERE pentester_id = ?', (user_id,))
            c.execute('DELETE FROM ptaas_findings WHERE pentester_id = ?', (user_id,))
            c.execute('DELETE FROM activity WHERE user_id = ?', (user_id,))
            c.execute('DELETE FROM notifications WHERE user_id = ?', (user_id,))
            c.execute('DELETE FROM feedback WHERE pentester_id = ? OR client_id = ?', (user_id, user_id))
            c.execute('DELETE FROM payments WHERE user_id = ?', (user_id,))
            c.execute('DELETE FROM ptaas_users WHERE id = ?', (user_id,))
            message = 'User permanently deleted'
        else:
            # Soft delete - just deactivate the user
            c.execute('UPDATE ptaas_users SET is_active = 0 WHERE id = ?', (user_id,))
            message = 'User deactivated successfully'
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': message
        })
    except Exception as e:
        print(f"Error deleting user: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/users/<user_id>/toggle-active', methods=['POST'])
@admin_required
def api_admin_toggle_user_active(user_id):
    """Toggle user active status."""
    try:
        conn = ptaas_db.get_db()
        c = conn.cursor()
        
        # Get current status
        c.execute('SELECT is_active FROM ptaas_users WHERE id = ?', (user_id,))
        row = c.fetchone()
        if not row:
            conn.close()
            return jsonify({'error': 'User not found'}), 404
        
        new_status = 0 if row['is_active'] else 1
        c.execute('UPDATE ptaas_users SET is_active = ? WHERE id = ?', (new_status, user_id))
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'is_active': bool(new_status),
            'message': 'User activated' if new_status else 'User deactivated'
        })
    except Exception as e:
        print(f"Error toggling user active: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/pentesters', methods=['GET'])
@admin_required
def api_admin_pentesters():
    """Get list of all pentesters."""
    try:
        conn = ptaas_db.get_db()
        c = conn.cursor()
        
        c.execute('''
            SELECT id, email, name, company, verified, is_active, created_at
            FROM ptaas_users
            WHERE role = 'pentester'
            ORDER BY name
        ''')
        rows = c.fetchall()
        
        pentesters = []
        for row in rows:
            pentesters.append({
                'id': row['id'],
                'email': row['email'],
                'name': row['name'],
                'company': row['company'],
                'verified': bool(row['verified']),
                'is_active': bool(row['is_active']),
                'created_at': row['created_at']
            })
        
        conn.close()
        
        return jsonify({
            'success': True,
            'pentesters': pentesters
        })
    except Exception as e:
        print(f"Error getting pentesters: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/pending-requests', methods=['GET'])
@admin_required
def api_admin_pending_requests():
    """Get pending pentest requests."""
    try:
        conn = ptaas_db.get_db()
        c = conn.cursor()
        
        c.execute('''
            SELECT p.*, u.name as client_name, u.company as client_company
            FROM pentests p
            LEFT JOIN ptaas_users u ON p.client_id = u.id
            WHERE p.status = 'pending'
            ORDER BY p.created_at DESC
        ''')
        rows = c.fetchall()
        
        requests_list = []
        for row in rows:
            r = dict(row)
            requests_list.append({
                'id': r['id'],
                'pentest_number': r.get('pentest_number', ''),
                'title': r.get('title', ''),
                'type': r.get('type', 'web'),
                'scope': r.get('scope', ''),
                'targets': r.get('targets', ''),
                'description': r.get('description', ''),
                'client_name': r.get('client_name') or r.get('company_name') or 'Unknown',
                'client_company': r.get('client_company') or r.get('company_name') or 'Unknown',
                'created_at': r.get('created_at', '')
            })
        
        conn.close()
        
        return jsonify({
            'success': True,
            'requests': requests_list
        })
    except Exception as e:
        print(f"Error getting pending requests: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/pentests', methods=['GET'])
@admin_required
def api_admin_pentests():
    """Get all approved/active pentests for admin (excludes pending requests)."""
    try:
        status = request.args.get('status')
        include_all = request.args.get('all')  # Include all including pending
        
        conn = ptaas_db.get_db()
        c = conn.cursor()
        
        if include_all == 'true':
            # Get ALL pentests including pending
            c.execute('SELECT * FROM pentests ORDER BY created_at DESC')
        elif status:
            c.execute('SELECT * FROM pentests WHERE status = ? ORDER BY created_at DESC', (status,))
        else:
            # Default: exclude pending (those go in /api/admin/pending-requests)
            c.execute("SELECT * FROM pentests WHERE status NOT IN ('pending', 'cancelled') ORDER BY created_at DESC")
        
        pentests = c.fetchall()
        
        # Get pentester count for each pentest
        formatted = []
        for row in pentests:
            # Convert Row to dict
            p = dict(row)
            
            c.execute("SELECT COUNT(*) FROM pentest_pentesters WHERE pentest_id = ? AND status = 'accepted'", (p['id'],))
            pentester_count = c.fetchone()[0]
            
            # Get client info
            client_name = p.get('company_name') or 'Unknown'
            if p.get('client_id'):
                c.execute('SELECT name, company FROM ptaas_users WHERE id = ?', (p['client_id'],))
                client = c.fetchone()
                if client:
                    client_name = client['company'] or client['name']
            
            formatted.append({
                'id': p['id'],
                'pentest_number': p.get('pentest_number', ''),
                'title': p.get('title', ''),
                'company_name': client_name,
                'type': p.get('type', 'web'),
                'status': p.get('status', 'pending'),
                'priority': p.get('priority') or 'normal',
                'start_date': p.get('start_date'),
                'end_date': p.get('end_date'),
                'targets': p.get('targets'),
                'scope': p.get('scope'),
                'total_findings': p.get('total_findings') or 0,
                'critical_count': p.get('critical_count') or 0,
                'high_count': p.get('high_count') or 0,
                'medium_count': p.get('medium_count') or 0,
                'low_count': p.get('low_count') or 0,
                'pentester_count': pentester_count,
                'progress': p.get('progress') or 0,
                'created_at': p.get('created_at', '')
            })
        
        conn.close()
        
        return jsonify({
            'success': True,
            'pentests': formatted
        })
    except Exception as e:
        print(f"Error in api_admin_pentests: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/pentest/<pentest_id>', methods=['GET'])
@admin_required
def api_admin_get_pentest(pentest_id):
    """Get a single pentest by ID with full details."""
    try:
        conn = ptaas_db.get_db()
        c = conn.cursor()
        
        c.execute('SELECT * FROM pentests WHERE id = ?', (pentest_id,))
        row = c.fetchone()
        
        if not row:
            conn.close()
            return jsonify({'error': 'Pentest not found'}), 404
        
        # Convert to dict
        p = dict(row)
        
        # Get client info
        client_name = p.get('company_name') or 'Unknown'
        client_email = ''
        if p.get('client_id'):
            c.execute('SELECT name, email, company FROM ptaas_users WHERE id = ?', (p['client_id'],))
            client = c.fetchone()
            if client:
                client_name = client['company'] or client['name']
                client_email = client['email']
        
        # Get pentester count
        c.execute("SELECT COUNT(*) FROM pentest_pentesters WHERE pentest_id = ? AND status = 'accepted'", (pentest_id,))
        pentester_count = c.fetchone()[0]
        
        # Get assigned pentesters
        c.execute('''
            SELECT u.id, u.name, u.email, pp.role, pp.status 
            FROM pentest_pentesters pp
            JOIN ptaas_users u ON pp.pentester_id = u.id
            WHERE pp.pentest_id = ?
        ''', (pentest_id,))
        pentesters = [dict(row) for row in c.fetchall()]
        
        conn.close()
        
        return jsonify({
            'success': True,
            'pentest': {
                'id': p['id'],
                'pentest_number': p.get('pentest_number', ''),
                'title': p.get('title', ''),
                'description': p.get('description') or '',
                'company_name': client_name,
                'client_name': p.get('client_name') or client_name,
                'client_email': client_email,
                'client_id': p.get('client_id'),
                'type': p.get('type', 'web'),
                'status': p.get('status', 'pending'),
                'priority': p.get('priority') or 'normal',
                'start_date': p.get('start_date'),
                'end_date': p.get('end_date'),
                'targets': p.get('targets'),
                'scope': p.get('scope'),
                'compliance': p.get('compliance'),
                # Extended fields for admin to see full client request
                'objectives': p.get('objectives') or '',
                'technology_stack': p.get('technology_stack') or '',
                'environment_type': p.get('environment_type') or '',
                'collaboration_preference': p.get('collaboration_preference') or '',
                'sensitive_data': p.get('sensitive_data') or '[]',
                'notes': p.get('notes') or '',
                'credential_type': p.get('credential_type') or 'none',
                'credentials': p.get('credentials') or '',
                'attachments': p.get('attachments') or '[]',
                # Findings & progress
                'total_findings': p.get('total_findings') or 0,
                'critical_count': p.get('critical_count') or 0,
                'high_count': p.get('high_count') or 0,
                'medium_count': p.get('medium_count') or 0,
                'low_count': p.get('low_count') or 0,
                'pentester_count': pentester_count,
                'pentesters': pentesters,
                'progress': p.get('progress') or 0,
                'created_at': p.get('created_at', ''),
                'updated_at': p.get('updated_at')
            },
            'assigned_pentesters': pentesters
        })
    except Exception as e:
        print(f"Error in api_admin_get_pentest: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/pentest/<pentest_id>/start', methods=['POST'])
@admin_required
def api_admin_start_pentest(pentest_id):
    """Start a pentest (change status to active)."""
    try:
        ptaas_db.update_pentest(pentest_id, status='active')
        
        # Notify client (non-blocking)
        try:
            pentest = ptaas_db.get_pentest_by_id(pentest_id)
            if pentest:
                ptaas_db.create_notification(
                    pentest['client_id'], 
                    'pentest_started', 
                    'Pentest Started!',
                    f'Testing has begun on "{pentest["title"]}".',
                    f'/client/pentest/{pentest_id}'
                )
        except Exception as notify_err:
            print(f"Notification error (non-critical): {notify_err}")
        
        return jsonify({
            'success': True,
            'message': 'Pentest started successfully'
        })
    except Exception as e:
        print(f"Error in api_admin_start_pentest: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/pentest/<pentest_id>/pause', methods=['POST'])
@admin_required
def api_admin_pause_pentest(pentest_id):
    """Pause an active pentest."""
    try:
        ptaas_db.update_pentest(pentest_id, status='paused')
        
        # Notify client (non-blocking)
        try:
            pentest = ptaas_db.get_pentest_by_id(pentest_id)
            if pentest:
                ptaas_db.create_notification(
                    pentest['client_id'], 
                    'pentest_paused', 
                    'Pentest Paused',
                    f'Testing on "{pentest["title"]}" has been paused.',
                    f'/client/pentest/{pentest_id}'
                )
        except Exception as notify_err:
            print(f"Notification error (non-critical): {notify_err}")
        
        return jsonify({
            'success': True,
            'message': 'Pentest paused successfully'
        })
    except Exception as e:
        print(f"Error in api_admin_pause_pentest: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/pentest/<pentest_id>/resume', methods=['POST'])
@admin_required
def api_admin_resume_pentest(pentest_id):
    """Resume a paused pentest."""
    try:
        ptaas_db.update_pentest(pentest_id, status='active')
        
        # Notify client (non-blocking)
        try:
            pentest = ptaas_db.get_pentest_by_id(pentest_id)
            if pentest:
                ptaas_db.create_notification(
                    pentest['client_id'], 
                    'pentest_resumed', 
                    'Pentest Resumed',
                    f'Testing on "{pentest["title"]}" has resumed.',
                    f'/client/pentest/{pentest_id}'
                )
        except Exception as notify_err:
            print(f"Notification error (non-critical): {notify_err}")
        
        return jsonify({
            'success': True,
            'message': 'Pentest resumed successfully'
        })
    except Exception as e:
        print(f"Error in api_admin_resume_pentest: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/pentest/<pentest_id>/approve', methods=['POST'])
@admin_required
def api_admin_approve_pentest(pentest_id):
    """Approve a pending pentest."""
    try:
        ptaas_db.update_pentest(pentest_id, status='planned')
        
        # Notify client (non-blocking - don't fail if notification fails)
        try:
            pentest = ptaas_db.get_pentest_by_id(pentest_id)
            if pentest:
                ptaas_db.create_notification(
                    pentest['client_id'], 
                    'pentest_approved', 
                    'Pentest Approved!',
                    f'Your pentest request "{pentest["title"]}" has been approved.',
                    f'/client/pentest/{pentest_id}'
                )
        except Exception as notify_err:
            print(f"Notification error (non-critical): {notify_err}")
        
        return jsonify({
            'success': True,
            'message': 'Pentest approved successfully'
        })
    except Exception as e:
        print(f"Error in api_admin_approve_pentest: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/pentest/<pentest_id>/reject', methods=['POST'])
@admin_required
def api_admin_reject_pentest(pentest_id):
    """Reject a pending pentest."""
    try:
        ptaas_db.update_pentest(pentest_id, status='cancelled')
        
        return jsonify({
            'success': True,
            'message': 'Pentest rejected'
        })
    except Exception as e:
        print(f"Error in api_admin_reject_pentest: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/pentest/<pentest_id>/assign', methods=['POST'])
@admin_required
def api_admin_assign_pentester(pentest_id):
    """Assign a pentester to a pentest and notify everyone."""
    try:
        data = request.json
        pentester_id = data.get('pentester_id')
        role = data.get('role', 'tester')
        
        # Check if already assigned
        conn = ptaas_db.get_db()
        c = conn.cursor()
        c.execute("SELECT id FROM pentest_pentesters WHERE pentest_id = ? AND pentester_id = ?", (pentest_id, pentester_id))
        existing = c.fetchone()
        conn.close()
        if existing:
            return jsonify({"error": "Pentester is already assigned to this pentest"}), 400

        success = ptaas_db.assign_pentester(pentest_id, pentester_id, role)
        
        if success:
            # Get pentest and pentester info for notifications
            pentest = ptaas_db.get_pentest_by_id(pentest_id)
            pentester = ptaas_db.get_user_by_id(pentester_id)
            
            if pentest and pentester:
                # Update pentest with lead pentester if this is lead role
                if role == 'lead':
                    conn = ptaas_db.get_db()
                    c = conn.cursor()
                    c.execute("UPDATE pentests SET lead_pentester_id = ? WHERE id = ?", 
                              (pentester_id, pentest_id))
                    conn.commit()
                    conn.close()
                
                # Notify client that pentester was assigned
                client_id = pentest.get('client_id')
                if client_id:
                    ptaas_db.create_notification(
                        user_id=client_id,
                        type='pentester_assigned',
                        title='Pentester Assigned to Your Pentest',
                        message=f"{pentester.get('name', 'A pentester')} has been assigned to work on '{pentest.get('title')}'",
                        link=f"/client/pentest/{pentest_id}"
                    )
            
            return jsonify({
                'success': True,
                'message': 'Pentester assigned successfully',
                'pentester_name': pentester.get('name') if pentester else None
            })
        else:
            return jsonify({'error': 'Failed to assign pentester'}), 400
    except Exception as e:
        print(f"Error in api_admin_assign_pentester: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/pentest/<pentest_id>/archive', methods=['POST'])
@admin_required
def api_admin_archive_pentest(pentest_id):
    """Archive a pentest (soft delete)."""
    try:
        success = ptaas_db.archive_pentest(pentest_id)
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Pentest archived successfully'
            })
        else:
            return jsonify({'error': 'Failed to archive pentest'}), 400
    except Exception as e:
        print(f"Error in api_admin_archive_pentest: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/pentest/<pentest_id>', methods=['DELETE'])
@admin_required
def api_admin_delete_pentest(pentest_id):
    """Permanently delete a pentest and all related data."""
    try:
        success = ptaas_db.delete_pentest(pentest_id)
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Pentest deleted permanently'
            })
        else:
            return jsonify({'error': 'Failed to delete pentest'}), 400
    except Exception as e:
        print(f"Error in api_admin_delete_pentest: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================================
# Contact Form API
# ============================================================

@app.route('/api/contact', methods=['POST'])
def submit_contact():
    """Handle contact form submissions."""
    try:
        data = request.json
        name = data.get('name', '')
        email = data.get('email', '')
        company = data.get('company', '')
        message = data.get('message', '')
        
        if not name or not email or not message:
            return jsonify({'error': 'Name, email, and message are required'}), 400
        
        # Send notification email
        send_contact_notification(name, email, company, message)
        
        return jsonify({
            'success': True,
            'message': 'Thank you for your message. We will get back to you soon.'
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# =============================================================================
# SECURITY MIDDLEWARE
# =============================================================================

@app.after_request
def apply_security_headers(response):
    """Apply security headers to all responses."""
    if SECURE_AUTH_AVAILABLE:
        return add_security_headers(response)
    # Minimal fallback (avoid relying solely on Nginx)
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    return response


# =============================================================================
# REGISTER BLUEPRINTS
# =============================================================================

if SECURE_AUTH_AVAILABLE:
    # Register secure auth routes at /api/v2/auth
    app.register_blueprint(auth_bp)
    print("[SECURITY] ✓ Secure authentication module loaded (JWT + bcrypt)")
    # Initialize auth service at module level for Gunicorn/WSGI
    ptaas_db.init_ptaas_db()  # Ensure DB exists
    init_auth_service(ptaas_db.PTAAS_DB_PATH)
else:
    print("[SECURITY] ⚠ Using legacy authentication (upgrade recommended)")


if __name__ == '__main__':
    init_db()
    init_osaas_tables()
    
    # Initialize PTaaS database and seed demo data
    ptaas_db.init_ptaas_db()
    ptaas_db.seed_demo_data()
    
    # Initialize secure auth service if available
    if SECURE_AUTH_AVAILABLE:
        init_auth_service(ptaas_db.PTAAS_DB_PATH)
        print("[SECURITY] ✓ Auth service initialized with PTaaS database")
    
    print("")
    print("  ╔════════════════════════════════════════════════════════╗")
    print("  ║               ⚔️  REDCON OFFENCE                       ║")
    print("  ║      UNMATCHED PERCEPTION. UNBROKEN WILL.              ║")
    print("  ╠════════════════════════════════════════════════════════╣")
    print("  ║  🌐 Main Site: http://localhost:5050                   ║")
    print("  ║  📊 Scanner: /dashboard                                ║")
    print("  ║  ⚔️  PTaaS: /ptaas/pentests                            ║")
    print("  ║  👤 Portal: /portal                                    ║")
    print("  ║  🏢 Client: /client/dashboard                          ║")
    print("  ╠════════════════════════════════════════════════════════╣")
    if SECURE_AUTH_AVAILABLE:
        print("  ║  🔐 Auth API: /api/v2/auth (JWT + bcrypt)              ║")
        print("  ╠════════════════════════════════════════════════════════╣")
    print("  ║  Demo Accounts:                                        ║")
    print("  ║  • Pentester: pentester@redconoffence.com / demo123    ║")
    print("  ║  • Client: client@example.com / demo123                ║")
    print("  ║  • Admin: admin@redconoffence.com / admin123           ║")
    print("  ╠════════════════════════════════════════════════════════╣")
    print("  ║  🎯 Status: OPERATIONAL                                ║")
    if SECURE_AUTH_AVAILABLE:
        print("  ║  🔒 Security: ENHANCED (JWT + Rate Limiting)           ║")
    print("  ╚════════════════════════════════════════════════════════╝")
    print("")
    app.run(debug=True, host='0.0.0.0', port=5050)
