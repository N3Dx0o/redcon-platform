# REDCON OFFENCE - Operations Guide

## 🎯 Running Pentests from Start to Finish

---

## 📋 Pre-Engagement Phase

### Step 1: Client Scoping Call

**Agenda:**
1. Understanding business context
2. Defining assets in scope
3. Identifying sensitive areas
4. Setting timeline and expectations
5. Discussing credentials and access

**Scoping Questionnaire:**

```
┌─────────────────────────────────────────────────────────────┐
│                 PENTEST SCOPING FORM                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│ SECTION 1: BUSINESS CONTEXT                                 │
│ ─────────────────────────────                               │
│ Company Name: _______________________                       │
│ Industry: _______________________                           │
│ Primary Contact: _______________________                    │
│ Technical Contact: _______________________                  │
│                                                             │
│ SECTION 2: TEST TYPE                                        │
│ ─────────────────────                                       │
│ □ Web Application                                           │
│ □ Mobile Application (iOS / Android)                        │
│ □ API / Web Services                                        │
│ □ Network / Infrastructure                                  │
│ □ Cloud Environment (AWS / Azure / GCP)                     │
│ □ Smart Contracts / Blockchain                              │
│                                                             │
│ SECTION 3: SCOPE DEFINITION                                 │
│ ──────────────────────────                                  │
│ In-Scope Targets:                                           │
│ • _______________________ (URL/IP)                          │
│ • _______________________ (URL/IP)                          │
│ • _______________________ (URL/IP)                          │
│                                                             │
│ Out-of-Scope:                                               │
│ • _______________________ (e.g., third-party services)      │
│ • _______________________ (e.g., production databases)      │
│                                                             │
│ SECTION 4: TEST APPROACH                                    │
│ ────────────────────────                                    │
│ □ Black Box (no prior knowledge)                            │
│ □ Grey Box (limited access/knowledge)                       │
│ □ White Box (full access, source code)                      │
│                                                             │
│ SECTION 5: CREDENTIALS                                      │
│ ──────────────────────                                      │
│ Test Accounts Provided: □ Yes □ No                          │
│ Account Types:                                              │
│ □ Admin                                                     │
│ □ Regular User                                              │
│ □ Guest/Limited                                             │
│ □ API Keys/Tokens                                           │
│                                                             │
│ SECTION 6: ENVIRONMENT                                      │
│ ──────────────────────                                      │
│ Testing Environment:                                        │
│ □ Production (CAUTION)                                      │
│ □ Staging                                                   │
│ □ Development                                               │
│ □ Dedicated Test Environment                                │
│                                                             │
│ SECTION 7: RESTRICTIONS                                     │
│ ─────────────────────                                       │
│ □ No DoS/DDoS testing                                       │
│ □ No social engineering                                     │
│ □ No physical testing                                       │
│ □ Testing window: _____ to _____ (timezone)                 │
│ □ Notify before exploiting critical vulns: □ Yes □ No       │
│                                                             │
│ SECTION 8: COMPLIANCE REQUIREMENTS                          │
│ ──────────────────────────────────                          │
│ □ SOC 2                                                     │
│ □ PCI DSS                                                   │
│ □ HIPAA                                                     │
│ □ ISO 27001                                                 │
│ □ Other: _______________________                            │
│                                                             │
│ SECTION 9: TIMELINE                                         │
│ ───────────────────                                         │
│ Preferred Start Date: _______________________               │
│ Deadline (if any): _______________________                  │
│ Duration: □ 1 week □ 2 weeks □ 3 weeks □ Custom             │
│                                                             │
│ SECTION 10: ADDITIONAL NOTES                                │
│ ────────────────────────────                                │
│ ___________________________________________________________ │
│ ___________________________________________________________ │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Step 2: Statement of Work (SOW)

**SOW Template Components:**

```
STATEMENT OF WORK
─────────────────

1. PARTIES
   Client: [Company Name]
   Provider: REDCON OFFENCE

2. ENGAGEMENT OVERVIEW
   Type: Penetration Testing
   Duration: [X] business days
   Start Date: [Date]
   End Date: [Date]

3. SCOPE OF WORK
   3.1 In-Scope Assets
       - [List all URLs, IPs, applications]
   
   3.2 Out-of-Scope
       - [List exclusions]
   
   3.3 Testing Approach
       - [Black/Grey/White Box]
   
   3.4 Methodology
       - OWASP Testing Guide v4
       - PTES (Penetration Testing Execution Standard)

4. DELIVERABLES
   - Real-time vulnerability reports via platform
   - Executive summary report
   - Technical findings report
   - Remediation recommendations
   - [X] free retests within 30 days

5. TEAM
   - Lead Pentester: [Name]
   - Supporting Pentester(s): [Names]

6. COMMUNICATION
   - Platform: REDCON OFFENCE Dashboard
   - Emergency Contact: [Phone]
   - Sync Calls: [Weekly/Daily]

7. INVESTMENT
   Total: $[Amount]
   Payment Terms: [Net-30 / Prepaid]

8. TERMS & CONDITIONS
   [Link to master services agreement]
```

### Step 3: Rules of Engagement (ROE)

**Critical Document Before Testing:**

```
RULES OF ENGAGEMENT
───────────────────

1. AUTHORIZATION
   Client hereby authorizes REDCON OFFENCE to perform 
   penetration testing on the defined scope.

   Authorized By: ___________________
   Title: ___________________
   Date: ___________________
   Signature: ___________________

2. TESTING BOUNDARIES
   
   ALLOWED:
   ✓ Vulnerability scanning
   ✓ Manual testing
   ✓ Exploitation (non-destructive)
   ✓ Data extraction (test data only)
   ✓ Authentication bypass attempts
   ✓ Privilege escalation
   
   NOT ALLOWED:
   ✗ Denial of Service attacks
   ✗ Physical security testing
   ✗ Social engineering (unless agreed)
   ✗ Testing outside defined scope
   ✗ Accessing real customer data
   ✗ Modifying production data

3. DATA HANDLING
   - All findings stored encrypted
   - Data deleted 90 days post-engagement
   - No sensitive data exfiltrated
   - Evidence screenshots redacted

4. ESCALATION PROCEDURES
   
   CRITICAL VULNERABILITY FOUND:
   1. Immediately notify client contact
   2. Pause testing in affected area
   3. Document and report via platform
   4. Wait for client acknowledgment

   INCIDENT DURING TESTING:
   1. Stop all testing immediately
   2. Call emergency contact
   3. Document timeline of events
   4. Await further instructions

5. EMERGENCY CONTACTS
   
   Client:
   - Primary: [Name] - [Phone]
   - Secondary: [Name] - [Phone]
   
   REDCON OFFENCE:
   - Operations: +1-XXX-XXX-XXXX
   - Security: security@redconoffence.com

6. TESTING WINDOW
   Days: [Mon-Fri]
   Hours: [09:00 - 18:00] [Timezone]
   
   Testing outside window requires:
   □ Written approval
   □ 24-hour notice

7. IP ADDRESSES
   Testing will originate from:
   - [IP Address 1]
   - [IP Address 2]
   
   Please whitelist these in:
   - WAF
   - IDS/IPS
   - Rate limiters

8. COMMUNICATION PROTOCOL
   - All findings via platform
   - Critical = Phone + Platform
   - Questions = Platform chat
   - Daily status updates
```

---

## 🔬 Active Testing Phase

### Day 1: Kickoff

**Pentester Checklist:**

```
□ Read all scoping documents
□ Understand business context
□ Access credentials working
□ VPN/access to environment confirmed
□ Tools prepared and updated
□ Testing environment verified
□ Communication channels tested
□ Client notified testing is starting
```

**Initial Reconnaissance:**

```
RECONNAISSANCE CHECKLIST
────────────────────────

1. PASSIVE RECON
   □ Whois lookup
   □ DNS enumeration
   □ Subdomain discovery
   □ Google dorking
   □ Shodan/Censys search
   □ Technology fingerprinting
   □ SSL/TLS certificate analysis

2. ACTIVE RECON
   □ Port scanning
   □ Service enumeration
   □ Web crawling
   □ Sitemap analysis
   □ robots.txt review
   □ API endpoint discovery
```

### Days 2-N: Testing Execution

**Daily Workflow:**

```
09:00 - Review scope and previous findings
09:30 - Begin testing session
12:00 - Document findings, lunch break
13:00 - Continue testing
15:00 - Submit any new findings
17:00 - Daily status update to client
17:30 - Plan next day's focus areas
```

**Testing Methodology (Web App):**

```
OWASP TOP 10 TESTING
────────────────────

1. INJECTION (A03:2021)
   □ SQL Injection
   □ NoSQL Injection
   □ Command Injection
   □ LDAP Injection
   □ XPath Injection
   □ Template Injection

2. BROKEN AUTHENTICATION (A07:2021)
   □ Default credentials
   □ Brute force protection
   □ Session management
   □ Password policy
   □ Multi-factor authentication
   □ Account lockout

3. SENSITIVE DATA EXPOSURE (A02:2021)
   □ Data in transit (HTTPS)
   □ Data at rest
   □ PII in responses
   □ Sensitive data in URLs
   □ Caching of sensitive data

4. XML EXTERNAL ENTITIES (A05:2021)
   □ XXE in file uploads
   □ XXE in SOAP requests
   □ XXE in SVG images

5. BROKEN ACCESS CONTROL (A01:2021)
   □ IDOR (Insecure Direct Object Reference)
   □ Privilege escalation
   □ Missing function level access control
   □ CORS misconfiguration
   □ Directory traversal

6. SECURITY MISCONFIGURATION (A05:2021)
   □ Default configurations
   □ Unnecessary features enabled
   □ Error handling reveals info
   □ Missing security headers
   □ Outdated software

7. CROSS-SITE SCRIPTING (A03:2021)
   □ Reflected XSS
   □ Stored XSS
   □ DOM-based XSS
   □ XSS in file uploads

8. INSECURE DESERIALIZATION (A08:2021)
   □ Java deserialization
   □ PHP object injection
   □ .NET deserialization

9. USING COMPONENTS WITH KNOWN VULNS (A06:2021)
   □ Outdated libraries
   □ Known CVEs
   □ Vulnerable dependencies

10. INSUFFICIENT LOGGING (A09:2021)
    □ Logging of security events
    □ Log injection
    □ Log integrity
```

### Submitting Findings

**Finding Quality Checklist:**

```
BEFORE SUBMITTING A FINDING:
────────────────────────────

□ Title is clear and specific
□ Severity is accurately assessed
□ CVSS score calculated correctly
□ Steps to reproduce are complete
□ Someone else could reproduce this
□ Screenshots/evidence attached
□ Impact clearly explained
□ Remediation is actionable
□ No false positive - verified
□ Not a duplicate of existing finding
```

**Finding Template:**

```
VULNERABILITY REPORT
────────────────────

TITLE: [Clear, specific title]

SEVERITY: [Critical/High/Medium/Low/Informational]

CVSS 3.1 SCORE: [X.X]
CVSS VECTOR: [CVSS:3.1/AV:N/AC:L/...]

CATEGORY: [Injection/XSS/Auth/etc.]
CWE: [CWE-XXX]

AFFECTED ASSET:
- URL: [https://...]
- Parameter: [name of parameter]
- Method: [GET/POST/etc.]

DESCRIPTION:
[What is the vulnerability? Be clear and concise]

STEPS TO REPRODUCE:
1. [Step 1]
2. [Step 2]
3. [Step 3]
4. [Observe the vulnerability]

PROOF OF CONCEPT:
[Screenshots, video, HTTP requests]

IMPACT:
[What could an attacker do? Be specific about 
business impact, not just technical impact]

REMEDIATION:
[How should the client fix this? Be specific]

REFERENCES:
- [Link to OWASP]
- [Link to CWE]
- [Other relevant resources]
```

---

## 📊 Severity Ratings

### CVSS 3.1 Quick Reference

| Score | Severity | Response Time |
|-------|----------|---------------|
| 9.0-10.0 | Critical | Immediate |
| 7.0-8.9 | High | 24-48 hours |
| 4.0-6.9 | Medium | 1-2 weeks |
| 0.1-3.9 | Low | 30 days |
| 0.0 | Informational | As time permits |

### When to Escalate Immediately

**CRITICAL - STOP AND CALL CLIENT:**

- Active data breach / compromise
- Remote Code Execution on production
- SQL Injection with data access
- Authentication bypass to admin
- Exposed credentials / API keys
- Ransomware / malware discovered
- Compliance violation (PII exposed)

---

## 📋 Post-Engagement Phase

### Final Report Structure

```
PENETRATION TEST REPORT
═══════════════════════

1. EXECUTIVE SUMMARY (1-2 pages)
   ─────────────────────────────
   - Engagement overview
   - Key findings summary
   - Risk rating
   - Strategic recommendations
   
   [Suitable for: C-level, Board]

2. TECHNICAL FINDINGS (Main body)
   ────────────────────────────
   - Findings organized by severity
   - Each finding includes:
     • Description
     • Evidence
     • Impact
     • Remediation
   
   [Suitable for: Security team, Developers]

3. METHODOLOGY
   ────────────
   - Testing approach
   - Tools used
   - Standards followed
   
4. SCOPE VERIFICATION
   ───────────────────
   - Assets tested
   - Coverage achieved
   - Limitations encountered

5. APPENDICES
   ──────────
   - Raw scan outputs
   - Additional evidence
   - Tool outputs
```

### Findings Review Call

**Agenda (60 min):**

```
1. INTRODUCTION (5 min)
   - Attendees
   - Agenda overview

2. EXECUTIVE SUMMARY (10 min)
   - Overall risk posture
   - Key takeaways
   - Comparison to industry

3. CRITICAL & HIGH FINDINGS (25 min)
   - Walk through each finding
   - Answer technical questions
   - Discuss remediation approaches

4. REMEDIATION ROADMAP (15 min)
   - Prioritization recommendations
   - Quick wins vs. long-term fixes
   - Resource estimation

5. Q&A & NEXT STEPS (5 min)
   - Retesting timeline
   - Ongoing engagement options
   - Contact information
```

### Retesting Process

```
CLIENT REQUESTS RETEST:
───────────────────────

1. Client marks finding as "Fixed" in platform

2. Notification sent to original pentester

3. Pentester schedules retest (within SLA)

4. Pentester verifies fix:
   □ Attempts original PoC
   □ Tests for bypasses
   □ Checks related areas

5. Updates finding status:
   □ VERIFIED - Fix confirmed
   □ PARTIAL - Some issues remain
   □ NOT FIXED - Still vulnerable
   □ REGRESSED - New issue introduced

6. Client notified of result
```

---

## 📈 Quality Assurance

### Finding Quality Review

**Before Delivery, Review:**

```
□ All findings have complete information
□ No duplicate findings
□ Severity ratings are consistent
□ Remediation advice is actionable
□ Screenshots are clear and annotated
□ No sensitive client data exposed
□ Report has been proofread
□ Executive summary is accurate
```

### Pentester Performance Metrics

| Metric | Target |
|--------|--------|
| Finding acceptance rate | > 90% |
| Average CVSS accuracy | ± 0.5 |
| Retest completion | < 48 hours |
| Client satisfaction | > 4.5/5 |
| Report quality score | > 4.0/5 |

---

## 🔧 Tools & Resources

### Standard Toolkit

```
RECONNAISSANCE:
- Nmap, Masscan
- Amass, Subfinder
- Shodan, Censys

WEB TESTING:
- Burp Suite Professional
- OWASP ZAP
- Nuclei
- SQLMap
- XSStrike

API TESTING:
- Postman
- Insomnia
- REST Client

NETWORK:
- Wireshark
- Netcat
- Responder

EXPLOITATION:
- Metasploit
- Cobalt Strike (if licensed)
- Custom scripts

REPORTING:
- Platform dashboard
- Screenshot tools
- Video recording
```

### Useful Resources

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PTES](http://www.pentest-standard.org/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [HackTricks](https://book.hacktricks.xyz/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)

---

## 🚨 Incident Response

### If Something Goes Wrong

**Immediate Actions:**

```
1. STOP all testing activities
2. DOCUMENT what happened (timestamps)
3. NOTIFY client immediately (phone)
4. NOTIFY REDCON operations team
5. DO NOT attempt to "fix" anything
6. PRESERVE all evidence/logs
7. AWAIT further instructions
```

**Incident Report Template:**

```
INCIDENT REPORT
───────────────

Date/Time: _______________
Pentester: _______________
Pentest ID: _______________

DESCRIPTION OF INCIDENT:
________________________
________________________

AFFECTED SYSTEMS:
________________________

ACTIONS TAKEN:
________________________

CURRENT STATUS:
________________________

EVIDENCE PRESERVED:
□ Screenshots
□ Logs
□ Network captures
□ Other: _________
```

---

*Document Version: 1.0*
*REDCON OFFENCE - Unmatched Perception. Unbroken Will.*





