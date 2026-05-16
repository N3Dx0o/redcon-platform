# REDCON OFFENCE - Technical Setup Guide

## 🛠️ Complete Deployment & Configuration

---

## 📁 Project Structure

```
AI/dashboard/
├── app.py                    # Main Flask application
├── ptaas_db.py              # PTaaS database operations
├── secure_auth.py           # JWT + bcrypt authentication
├── auth_routes.py           # Secure auth API routes
├── requirements.txt         # Python dependencies
│
├── static/
│   ├── css/                 # Stylesheets
│   ├── js/
│   │   └── auth.js         # Frontend auth utilities
│   └── images/             # Logos and assets
│
├── templates/
│   ├── landing.html        # Main marketing page
│   ├── portal.html         # Login/signup page
│   ├── dashboard.html      # Scanner dashboard
│   ├── products.html       # Products page
│   ├── team.html           # Team page
│   │
│   └── ptaas/
│       ├── pentester-dashboard.html
│       ├── pentest-detail.html
│       ├── postings.html
│       ├── settings.html
│       ├── feedback.html
│       ├── client-dashboard.html
│       └── admin-dashboard.html
│
├── docs/
│   ├── PLATFORM_DOCUMENTATION.md
│   ├── SALES_PLAYBOOK.md
│   ├── OPERATIONS_GUIDE.md
│   └── TECHNICAL_SETUP.md   # This file
│
└── deploy/
    └── DEPLOYMENT.md        # VPS deployment instructions
```

---

## ⚡ Quick Start (Development)

### 1. Clone & Setup

```bash
# Clone repository
git clone https://github.com/redconoffence/platform.git
cd platform/AI/dashboard

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Environment Variables

```bash
# Create .env file
cat > .env << 'EOF'
# Flask
FLASK_ENV=development
FLASK_SECRET_KEY=your-super-secret-key-change-in-production

# JWT
JWT_SECRET_KEY=another-super-secret-key-for-jwt

# Email (optional for dev)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
MAIL_DEFAULT_SENDER=noreply@redconoffence.com

# Database
DATABASE_URL=sqlite:///ptaas.db

# OpenAI (for scanner)
OPENAI_API_KEY=sk-your-openai-key
EOF
```

### 3. Run Development Server

```bash
# Start the application
python3 app.py

# Application will be available at:
# - Main Site: http://localhost:5050
# - Scanner: http://localhost:5050/dashboard
# - PTaaS: http://localhost:5050/ptaas/pentests
# - Portal: http://localhost:5050/portal
```

---

## 🔐 Security Configuration

### Authentication Settings

```python
# In secure_auth.py - AuthConfig class

class AuthConfig:
    # JWT Settings
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', secrets.token_hex(32))
    JWT_ALGORITHM = 'HS256'
    ACCESS_TOKEN_EXPIRES = timedelta(minutes=15)  # Short-lived
    REFRESH_TOKEN_EXPIRES = timedelta(days=7)     # Long-lived
    
    # Password Policy
    MIN_PASSWORD_LENGTH = 12
    REQUIRE_UPPERCASE = True
    REQUIRE_LOWERCASE = True
    REQUIRE_NUMBERS = True
    REQUIRE_SPECIAL = True
    
    # Rate Limiting
    LOGIN_RATE_LIMIT = 5          # Max attempts
    LOGIN_RATE_WINDOW = 300       # Per 5 minutes
    LOCKOUT_DURATION = 900        # 15 minutes lockout
    
    # bcrypt work factor
    BCRYPT_ROUNDS = 12
```

### Security Headers (Auto-Applied)

```python
# Applied to all responses via middleware

X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Referrer-Policy: strict-origin-when-cross-origin
Content-Security-Policy: default-src 'self'; ...
```

---

## 🗄️ Database Schema

### PTaaS Tables

```sql
-- Users (Clients, Pentesters, Admins)
CREATE TABLE ptaas_users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    role TEXT NOT NULL,  -- 'pentester', 'client', 'admin'
    company TEXT,
    bio TEXT,
    skills TEXT,         -- JSON array
    certifications TEXT, -- JSON array
    rating REAL DEFAULT 0,
    verified INTEGER DEFAULT 0,
    is_active INTEGER DEFAULT 1,
    created_at TEXT,
    last_login TEXT
);

-- Pentests
CREATE TABLE pentests (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    type TEXT NOT NULL,  -- 'web', 'mobile', 'network', 'api', 'cloud'
    status TEXT DEFAULT 'pending',
    scope TEXT,          -- JSON object
    targets TEXT,        -- JSON array
    start_date TEXT,
    end_date TEXT,
    budget REAL,
    findings_critical INTEGER DEFAULT 0,
    findings_high INTEGER DEFAULT 0,
    findings_medium INTEGER DEFAULT 0,
    findings_low INTEGER DEFAULT 0,
    findings_info INTEGER DEFAULT 0,
    created_at TEXT,
    FOREIGN KEY (client_id) REFERENCES ptaas_users(id)
);

-- Pentest Assignments
CREATE TABLE pentest_pentesters (
    id TEXT PRIMARY KEY,
    pentest_id TEXT NOT NULL,
    pentester_id TEXT NOT NULL,
    role TEXT DEFAULT 'pentester',  -- 'lead', 'pentester'
    status TEXT DEFAULT 'invited',  -- 'invited', 'accepted', 'declined'
    payout REAL,
    assigned_at TEXT,
    FOREIGN KEY (pentest_id) REFERENCES pentests(id),
    FOREIGN KEY (pentester_id) REFERENCES ptaas_users(id)
);

-- Findings
CREATE TABLE ptaas_findings (
    id TEXT PRIMARY KEY,
    pentest_id TEXT NOT NULL,
    pentester_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL,  -- 'critical', 'high', 'medium', 'low', 'info'
    status TEXT DEFAULT 'new',
    cvss_score REAL,
    cvss_vector TEXT,
    affected_url TEXT,
    steps_to_reproduce TEXT,
    impact TEXT,
    remediation TEXT,
    cwe_id TEXT,
    created_at TEXT,
    updated_at TEXT,
    FOREIGN KEY (pentest_id) REFERENCES pentests(id),
    FOREIGN KEY (pentester_id) REFERENCES ptaas_users(id)
);

-- Postings (Open Opportunities)
CREATE TABLE postings (
    id TEXT PRIMARY KEY,
    pentest_id TEXT,
    title TEXT NOT NULL,
    company TEXT NOT NULL,
    description TEXT,
    type TEXT NOT NULL,
    payout REAL NOT NULL,
    duration TEXT,
    tags TEXT,            -- JSON array
    max_pentesters INTEGER DEFAULT 3,
    current_pentesters INTEGER DEFAULT 0,
    status TEXT DEFAULT 'open',
    posted_at TEXT,
    FOREIGN KEY (pentest_id) REFERENCES pentests(id)
);

-- Additional tables: feedback, reports, payments, activity, notifications
```

### Database Operations

```python
# Initialize database
from ptaas_db import init_ptaas_db, seed_demo_data

init_ptaas_db()      # Creates all tables
seed_demo_data()     # Adds demo users and data

# CRUD Operations
from ptaas_db import (
    create_user,
    authenticate_user,
    get_user_by_id,
    create_pentest,
    get_pentest_by_id,
    create_finding,
    get_findings_by_pentest
)
```

---

## 🔌 API Reference

### Authentication Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v2/auth/login` | POST | Authenticate, get JWT tokens |
| `/api/v2/auth/register` | POST | Register new user |
| `/api/v2/auth/refresh` | POST | Refresh access token |
| `/api/v2/auth/logout` | POST | Invalidate tokens |
| `/api/v2/auth/me` | GET | Get current user (requires token) |
| `/api/v2/auth/change-password` | POST | Change password |
| `/api/v2/auth/validate-password` | POST | Validate password strength |

### PTaaS Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/ptaas/pentests` | GET | List user's pentests |
| `/api/ptaas/pentests/<id>` | GET | Get pentest details |
| `/api/ptaas/pentests/<id>/findings` | GET | Get pentest findings |
| `/api/ptaas/findings` | POST | Submit new finding |
| `/api/ptaas/findings/<id>` | PUT | Update finding |
| `/api/ptaas/notifications` | GET | Get user notifications |
| `/api/ptaas/feedback` | GET/POST | Manage feedback |

### Request/Response Examples

**Login:**
```bash
curl -X POST https://platform.redconoffence.com/api/v2/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecureP@ss123"
  }'

# Response
{
  "success": true,
  "tokens": {
    "access_token": "eyJ...",
    "refresh_token": "eyJ...",
    "token_type": "Bearer",
    "expires_in": 900
  },
  "user": {
    "id": "...",
    "email": "...",
    "role": "pentester"
  },
  "redirect": "/ptaas/pentests"
}
```

**Authenticated Request:**
```bash
curl https://platform.redconoffence.com/api/ptaas/pentests \
  -H "Authorization: Bearer eyJ..."

# Response
{
  "pentests": [
    {
      "id": "PT001",
      "title": "Web App Assessment",
      "status": "active",
      "findings_count": 5
    }
  ]
}
```

---

## 🚀 Production Deployment

### Option 1: VPS (Recommended)

```bash
# On your VPS (Ubuntu 22.04)

# 1. Install dependencies
sudo apt update
sudo apt install python3-pip python3-venv nginx certbot python3-certbot-nginx

# 2. Clone and setup
cd /var/www
git clone https://github.com/redconoffence/platform.git
cd platform/AI/dashboard
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install gunicorn

# 3. Create systemd service
sudo cat > /etc/systemd/system/redcon.service << 'EOF'
[Unit]
Description=REDCON OFFENCE Platform
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/var/www/platform/AI/dashboard
Environment="PATH=/var/www/platform/AI/dashboard/venv/bin"
Environment="FLASK_ENV=production"
Environment="FLASK_SECRET_KEY=your-production-secret"
Environment="JWT_SECRET_KEY=your-jwt-secret"
ExecStart=/var/www/platform/AI/dashboard/venv/bin/gunicorn \
    --workers 4 \
    --bind unix:redcon.sock \
    -m 007 \
    app:app

[Install]
WantedBy=multi-user.target
EOF

# 4. Start service
sudo systemctl enable redcon
sudo systemctl start redcon

# 5. Configure Nginx
sudo cat > /etc/nginx/sites-available/redconoffence.com << 'EOF'
server {
    listen 80;
    server_name redconoffence.com www.redconoffence.com;

    location / {
        include proxy_params;
        proxy_pass http://unix:/var/www/platform/AI/dashboard/redcon.sock;
    }

    location /static {
        alias /var/www/platform/AI/dashboard/static;
    }
}
EOF

sudo ln -s /etc/nginx/sites-available/redconoffence.com /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx

# 6. SSL Certificate
sudo certbot --nginx -d redconoffence.com -d www.redconoffence.com
```

### Option 2: Docker

```dockerfile
# Dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

COPY . .

ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1

EXPOSE 5050

CMD ["gunicorn", "--bind", "0.0.0.0:5050", "--workers", "4", "app:app"]
```

```yaml
# docker-compose.yml
version: '3.8'

services:
  web:
    build: .
    ports:
      - "5050:5050"
    environment:
      - FLASK_SECRET_KEY=${FLASK_SECRET_KEY}
      - JWT_SECRET_KEY=${JWT_SECRET_KEY}
      - MAIL_SERVER=${MAIL_SERVER}
      - MAIL_USERNAME=${MAIL_USERNAME}
      - MAIL_PASSWORD=${MAIL_PASSWORD}
    volumes:
      - ./data:/app/data
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/ssl
    depends_on:
      - web
    restart: unless-stopped
```

---

## 📧 Email Configuration

### Gmail SMTP

```python
# In .env or environment variables
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password  # Use App Password, not regular password
```

### SendGrid

```python
MAIL_SERVER=smtp.sendgrid.net
MAIL_PORT=587
MAIL_USERNAME=apikey
MAIL_PASSWORD=SG.your-sendgrid-api-key
```

### AWS SES

```python
MAIL_SERVER=email-smtp.us-east-1.amazonaws.com
MAIL_PORT=587
MAIL_USERNAME=your-ses-smtp-username
MAIL_PASSWORD=your-ses-smtp-password
```

---

## 🔍 Monitoring & Logging

### Application Logs

```python
# Configure logging in app.py
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('/var/log/redcon/app.log'),
        logging.StreamHandler()
    ]
)
```

### Security Audit Logs

```python
# All security events are logged via AuditLogger
from secure_auth import AuditLogger

# Events logged:
# - LOGIN_SUCCESS
# - LOGIN_FAILED
# - LOGIN_BLOCKED (rate limited)
# - LOGOUT
# - PASSWORD_CHANGED
# - USER_REGISTERED
# - PASSWORD_MIGRATED (SHA256 → bcrypt)
```

### Monitoring Endpoints

```bash
# Health check
curl https://platform.redconoffence.com/api/health

# Rate limit status
curl https://platform.redconoffence.com/api/v2/auth/rate-limit-status
```

---

## 🔄 Backup & Recovery

### Database Backup

```bash
# Daily backup script
#!/bin/bash
DATE=$(date +%Y%m%d)
cp /var/www/platform/AI/dashboard/ptaas.db /backups/ptaas_$DATE.db
find /backups -name "ptaas_*.db" -mtime +30 -delete  # Keep 30 days
```

### Recovery

```bash
# Restore from backup
systemctl stop redcon
cp /backups/ptaas_YYYYMMDD.db /var/www/platform/AI/dashboard/ptaas.db
chown www-data:www-data /var/www/platform/AI/dashboard/ptaas.db
systemctl start redcon
```

---

## 🐛 Troubleshooting

### Common Issues

**1. "Module not found" error**
```bash
source venv/bin/activate
pip install -r requirements.txt
```

**2. "Permission denied" on socket**
```bash
sudo chown www-data:www-data /var/www/platform/AI/dashboard/redcon.sock
```

**3. "502 Bad Gateway"**
```bash
sudo systemctl status redcon
sudo journalctl -u redcon -f
```

**4. "Rate limited" during testing**
```bash
# Clear rate limit (restart app in dev)
# Or wait for LOCKOUT_DURATION (15 min default)
```

**5. Database locked**
```bash
# Stop all processes accessing the database
sudo systemctl stop redcon
# Check for locks
fuser ptaas.db
# Restart
sudo systemctl start redcon
```

---

## 📊 Performance Tuning

### Gunicorn Workers

```bash
# Rule of thumb: (2 x CPU cores) + 1
gunicorn --workers 9 --bind 0.0.0.0:5050 app:app
```

### Database Optimization

```python
# Add indexes for frequently queried fields
c.execute('CREATE INDEX IF NOT EXISTS idx_findings_pentest ON ptaas_findings(pentest_id)')
c.execute('CREATE INDEX IF NOT EXISTS idx_pentests_client ON pentests(client_id)')
c.execute('CREATE INDEX IF NOT EXISTS idx_users_email ON ptaas_users(email)')
```

### Caching (Future)

```python
# Consider adding Redis for:
# - Session storage
# - Rate limiting (distributed)
# - Token blacklisting
# - API response caching
```

---

## 📞 Support

- **Technical Issues**: tech@redconoffence.com
- **Security Reports**: security@redconoffence.com
- **Documentation**: docs.redconoffence.com

---

*Document Version: 1.0*
*Last Updated: January 2026*
*REDCON OFFENCE - Unmatched Perception. Unbroken Will.*





