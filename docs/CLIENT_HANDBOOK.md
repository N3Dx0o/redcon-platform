# REDCON OFFENCE - Client Handbook

## 🛡️ Your Guide to Working with REDCON OFFENCE

Welcome! This handbook explains how to get the most value from your penetration testing engagement with REDCON OFFENCE.

---

## 🎯 What is PTaaS?

**Penetration Testing as a Service (PTaaS)** is a modern approach to security testing that provides:

| Traditional Pentest | PTaaS (REDCON OFFENCE) |
|---------------------|------------------------|
| Report at the end | Real-time findings |
| One-time engagement | Continuous or on-demand |
| Single tester | Multiple specialists |
| PDF report only | Interactive dashboard |
| Weeks to start | Days to start |
| Manual scheduling | Self-service platform |

---

## 🚀 Getting Started

### Step 1: Create Your Account

1. Visit `redconoffence.com`
2. Click **"Client Login"**
3. Sign up with your company email
4. Complete your company profile:
   - Company name
   - Industry
   - Company size
   - Primary contact
   - Billing information

### Step 2: Request Your First Pentest

1. Log in to your dashboard
2. Click **"Request New Pentest"**
3. Fill out the scoping form:
   - What type of test? (Web, Mobile, API, Network, Cloud)
   - What's in scope? (URLs, IPs, applications)
   - Any restrictions?
   - When do you want to start?
   - What's your timeline?

### Step 3: Onboarding Call

After your request is submitted:
1. Our team reviews your requirements
2. We schedule a 30-minute scoping call
3. We finalize scope and pricing
4. You approve the Statement of Work
5. Testing begins!

---

## 📋 Preparing for Your Pentest

### Pre-Engagement Checklist

```
2 WEEKS BEFORE:
□ Identify testing environment (staging vs production)
□ Create test accounts (admin, user, guest)
□ Document all in-scope assets
□ List any out-of-scope systems
□ Identify stakeholders who need access

1 WEEK BEFORE:
□ Whitelist our testing IP addresses
□ Notify your SOC/security team
□ Prepare credentials and API keys
□ Confirm testing window
□ Test that credentials work

DAY BEFORE:
□ Confirm with your team testing starts tomorrow
□ Ensure 24/7 contact is available
□ Verify all access still works
```

### What We Need From You

| Item | Description | Why We Need It |
|------|-------------|----------------|
| **Test Accounts** | Credentials for different user roles | Test authorization controls |
| **Environment Access** | VPN, staging URL, etc. | Access the application |
| **Documentation** | API docs, architecture diagrams | Understand the system |
| **Testing Window** | Approved days/hours | Coordinate with your team |
| **Emergency Contact** | Phone number for criticals | Immediate escalation |

---

## 📊 Understanding Your Dashboard

### Dashboard Overview

```
┌─────────────────────────────────────────────────────────────┐
│  REDCON OFFENCE - CLIENT DASHBOARD                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Welcome, TechCorp Inc.                                     │
│                                                             │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐              │
│  │ 3 Active   │ │ 47 Total   │ │ 12 Fixed   │              │
│  │ Pentests   │ │ Findings   │ │ This Month │              │
│  └────────────┘ └────────────┘ └────────────┘              │
│                                                             │
│  ACTIVE PENTESTS                                            │
│  ─────────────────────────────────────────────              │
│  │ Web App Assessment    │ IN PROGRESS │ 5 findings │      │
│  │ ├─ 2 Critical                                     │      │
│  │ ├─ 3 High                                         │      │
│  │ └─ View Details →                                 │      │
│                                                             │
│  RECENT FINDINGS                                            │
│  ─────────────────────────────────────────────              │
│  │ 🔴 SQL Injection - Login   │ Critical │ 2h ago   │      │
│  │ 🟠 XSS in Comments         │ High     │ 5h ago   │      │
│  │ 🟡 Missing Rate Limit      │ Medium   │ 1d ago   │      │
│                                                             │
│  [+ REQUEST NEW PENTEST]                                    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Understanding Finding Statuses

| Status | Meaning | Your Action |
|--------|---------|-------------|
| **NEW** | Just submitted by pentester | Review and respond |
| **TRIAGED** | You've acknowledged it | Assign to dev team |
| **ACCEPTED** | Confirmed as valid | Schedule fix |
| **REJECTED** | False positive/not applicable | Provide reason |
| **FIXED** | You've remediated it | Request retest |
| **VERIFIED** | Pentester confirmed fix | Celebrate! 🎉 |

---

## 🔍 Reviewing Findings

### How to Review a Finding

When you receive a new finding:

1. **Read the description** - Understand what was found
2. **Review the evidence** - Check screenshots, PoC
3. **Assess the impact** - Does this apply to your context?
4. **Respond appropriately:**

```
ACCEPT - "Yes, this is a valid vulnerability"
  → Finding moves to your backlog for fixing

REJECT - "This is a false positive"
  → Provide a reason so pentester understands
  
REQUEST MORE INFO - "I need clarification"
  → Ask specific questions

MARK AS FIXED - "We've deployed a fix"
  → Pentester will verify
```

### Prioritizing Remediation

```
REMEDIATION PRIORITY MATRIX
───────────────────────────

                    EFFORT TO FIX
                    Low         High
                 ┌──────────┬──────────┐
            High │ FIX NOW  │ PLAN IT  │
    IMPACT       ├──────────┼──────────┤
            Low  │ DO LATER │ CONSIDER │
                 └──────────┴──────────┘

PRIORITY 1 (Fix within 24-48 hours):
• Critical severity
• Actively exploitable
• Data exposure risk

PRIORITY 2 (Fix within 1-2 weeks):
• High severity
• Requires authentication to exploit
• Limited impact

PRIORITY 3 (Fix within 30 days):
• Medium severity
• Difficult to exploit
• Minimal business impact

PRIORITY 4 (As time permits):
• Low/Informational
• Best practice improvements
```

---

## 📑 Reports & Documentation

### Report Types Available

| Report | Purpose | Audience |
|--------|---------|----------|
| **Executive Summary** | High-level overview | C-Suite, Board |
| **Technical Report** | Detailed findings | Security team, Developers |
| **Remediation Guide** | Step-by-step fixes | Development team |
| **Compliance Report** | Audit-ready format | Auditors, Compliance |

### What's in the Executive Summary

```
EXECUTIVE SUMMARY
─────────────────

1. ENGAGEMENT OVERVIEW
   • Scope tested
   • Methodology used
   • Testing period

2. RISK RATING: HIGH

3. KEY STATISTICS
   • 2 Critical findings
   • 5 High findings
   • 8 Medium findings
   • 12 Low findings

4. TOP RISKS
   • SQL Injection allows database access
   • Broken authentication enables account takeover
   • Missing encryption exposes sensitive data

5. RECOMMENDATIONS
   • Immediate: Address critical vulnerabilities
   • Short-term: Implement secure coding training
   • Long-term: Deploy WAF and security monitoring
```

### Downloading Reports

1. Go to your pentest detail page
2. Click **"Reports"** tab
3. Select report type
4. Choose format (PDF, DOCX, HTML)
5. Download

---

## 💰 Billing & Payments

### Payment Options

| Method | Description |
|--------|-------------|
| **Credit Card** | Visa, Mastercard, Amex via Stripe |
| **ACH Transfer** | US bank accounts |
| **Wire Transfer** | For amounts > $25,000 |
| **Invoice** | Net-30 for approved accounts |

### Pricing Models

**Option 1: One-Time Pentest**
- Fixed price based on scope
- Single engagement
- Good for: Annual assessments, compliance

**Option 2: Subscription (PTaaS)**
- Monthly/annual billing
- Credits for ongoing testing
- Good for: Continuous security, agile teams

**Option 3: Credits Package**
- Buy credits upfront
- Use as needed
- Good for: Flexible testing schedule

### Sample Pricing

| Scope | One-Time | Annual Subscription |
|-------|----------|---------------------|
| 1 Web App | $12,000 - $20,000 | $2,500/month |
| 2-3 Web Apps | $20,000 - $35,000 | $4,500/month |
| Full Platform | $35,000 - $75,000 | $8,000/month |
| Enterprise | Custom | Custom |

*Includes: Testing, reporting, 2 retests, remediation support*

---

## ✅ Best Practices

### For Maximum Value

1. **Provide complete access**
   - More access = better coverage
   - Share documentation and architecture
   - Give admin-level test accounts

2. **Stay engaged**
   - Review findings daily
   - Respond to questions quickly
   - Involve your dev team

3. **Fix issues promptly**
   - Don't let findings pile up
   - Request retests after fixes
   - Track metrics over time

4. **Communicate openly**
   - Tell us about recent changes
   - Share known issues upfront
   - Provide context on business logic

### Common Mistakes to Avoid

❌ **DON'T:**
- Ignore findings until the report
- Restrict scope too much
- Delay providing access
- Reject findings without explanation
- Wait months between retests

✅ **DO:**
- Review findings in real-time
- Allow comprehensive testing
- Prepare access beforehand
- Provide detailed feedback
- Schedule regular retests

---

## 🔄 After the Pentest

### Post-Engagement Workflow

```
PENTEST COMPLETE
      ↓
FINAL REPORT DELIVERED
      ↓
REMEDIATION PERIOD (30-90 days)
      ↓
RETEST CRITICAL/HIGH FINDINGS
      ↓
VERIFICATION COMPLETE
      ↓
COMPLIANCE ATTESTATION (if needed)
      ↓
PLAN NEXT ENGAGEMENT
```

### Retesting

**Included in your engagement:**
- 2 free retests within 30 days
- Each finding can be retested once fixed

**How to request a retest:**
1. Mark finding as "Fixed"
2. Add notes about what changed
3. Pentester receives notification
4. Retest completed within 48 hours
5. Status updated (Verified/Not Fixed)

### Continuous Security

**After your first pentest, consider:**

| Frequency | Best For |
|-----------|----------|
| Quarterly | Regulated industries, high-risk apps |
| Bi-annually | Most businesses, moderate risk |
| Annually | Low-risk, stable applications |
| On major releases | Agile/DevOps teams |

---

## 📞 Getting Help

### Support Channels

| Channel | Use For | Response Time |
|---------|---------|---------------|
| Platform Chat | General questions | < 4 hours |
| Email | Detailed inquiries | < 24 hours |
| Phone | Urgent issues | Immediate |
| Emergency Line | Critical discoveries | 24/7 |

### Contact Information

- **General Support:** support@redconoffence.com
- **Billing Questions:** billing@redconoffence.com
- **Security Concerns:** security@redconoffence.com
- **Emergency Hotline:** +1-XXX-XXX-XXXX

### Escalation Path

```
Level 1: Platform Support
   ↓ (if unresolved in 24h)
Level 2: Account Manager
   ↓ (if unresolved in 48h)
Level 3: Operations Director
   ↓ (if unresolved in 72h)
Level 4: Executive Team
```

---

## ❓ Frequently Asked Questions

**Q: How long does a pentest take?**
A: Typically 1-3 weeks depending on scope. We can start within 5 business days of contract signing.

**Q: Will testing affect our production systems?**
A: We use non-destructive testing techniques. For sensitive production systems, we recommend a staging environment.

**Q: Who sees our findings?**
A: Only you and assigned REDCON team members. Data is encrypted and access-controlled.

**Q: Can we use findings for compliance?**
A: Yes! We provide compliance-ready reports for SOC 2, PCI DSS, HIPAA, and ISO 27001.

**Q: What if we disagree with a finding?**
A: You can dispute any finding with evidence. Our team will review and make a determination.

**Q: How do we know the pentesters are qualified?**
A: All pentesters are vetted, certified (OSCP, CEH, GWAPT), and background-checked.

**Q: Is there an SLA for critical findings?**
A: Yes. Critical findings are reported within 1 hour of discovery.

---

## 📊 Measuring Success

### Key Metrics to Track

| Metric | What It Tells You |
|--------|-------------------|
| Time to remediation | How fast you fix issues |
| Finding acceptance rate | Quality of findings |
| Retest pass rate | Effectiveness of fixes |
| Findings per quarter | Security trend over time |
| Mean time to detection | How quickly issues are found |

### Quarterly Security Review

Every quarter, we recommend:
1. Review all findings and their status
2. Analyze trends (getting better or worse?)
3. Identify systemic issues
4. Plan training or process improvements
5. Set goals for next quarter

---

## 🎯 Quick Reference

### Finding Severity Guide

| Severity | Examples | Fix Timeline |
|----------|----------|--------------|
| **Critical** | RCE, SQLi, Auth bypass | 24-48 hours |
| **High** | Stored XSS, IDOR, Priv esc | 1-2 weeks |
| **Medium** | Reflected XSS, CSRF | 30 days |
| **Low** | Missing headers, info disclosure | 90 days |
| **Info** | Best practices | As capacity allows |

### Important Links

- Dashboard: `platform.redconoffence.com`
- Documentation: `docs.redconoffence.com`
- Status Page: `status.redconoffence.com`
- Security: `security.redconoffence.com`

---

*Thank you for choosing REDCON OFFENCE. We're committed to your security.*

*REDCON OFFENCE - Unmatched Perception. Unbroken Will.*





