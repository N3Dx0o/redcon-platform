# Cobalt PTaaS Process Analysis
## From Demo Call to Pentest Completion

---

## Table of Contents
1. [Sales & Client Acquisition](#1-sales--client-acquisition)
2. [Demo Call Process](#2-demo-call-process)
3. [Client Onboarding](#3-client-onboarding)
4. [The 6-Phase Pentest Lifecycle](#4-the-6-phase-pentest-lifecycle)
5. [Pentester Perspective](#5-pentester-perspective)
6. [Pricing Model](#6-pricing-model)
7. [Platform Features](#7-platform-features)
8. [How to Replicate for REDCON OFFENCE](#8-how-to-replicate-for-redcon-offence)

---

## 1. Sales & Client Acquisition

### Lead Generation Channels
- **Inbound Marketing**: SEO, content marketing, webinars, case studies
- **Outbound Sales**: Cold outreach to CISOs, Security Directors, CTOs
- **Partner Referrals**: Resellers, MSPs, consulting firms
- **Events**: Security conferences (RSA, Black Hat, DEF CON)

### Target Customer Profile
| Segment | Company Size | Annual Security Budget | Key Decision Makers |
|---------|--------------|----------------------|---------------------|
| SMB | 50-200 employees | $50K-200K | CTO, Security Manager |
| Mid-Market | 200-1000 employees | $200K-1M | CISO, VP Engineering |
| Enterprise | 1000+ employees | $1M+ | CISO, Security Team Leads |

### Initial Contact
1. **Website Form**: Client fills out "Get a Demo" form
2. **SDR Outreach**: Sales Development Rep qualifies the lead
3. **Discovery Call**: 15-30 min call to understand needs
4. **Demo Scheduling**: Book a formal platform demo

---

## 2. Demo Call Process

### Pre-Demo Preparation
- Research the prospect's company (tech stack, industry, recent news)
- Identify likely compliance requirements (SOC 2, PCI-DSS, HIPAA, ISO 27001)
- Prepare relevant case studies from similar industries

### Demo Call Structure (45-60 minutes)

#### Opening (5 min)
- Introductions and agenda setting
- Confirm attendees and their roles
- Set expectations for the call

#### Discovery Questions (10 min)
- "What's driving your interest in penetration testing?"
- "How are you currently handling security assessments?"
- "What's your testing frequency? Annual? Quarterly?"
- "Do you have compliance requirements?"
- "What types of assets need testing? (Web apps, APIs, Mobile, Cloud, Network)"

#### Platform Demo (25 min)
1. **Dashboard Overview**: Show the main interface
2. **Asset Management**: How to add and manage assets
3. **Pentest Launching**: Walk through creating a pentest request
4. **Real-Time Findings**: Show how vulnerabilities are reported live
5. **Collaboration Features**: Slack integration, comments, retesting
6. **Reporting**: Show sample reports, export options
7. **Integrations**: Jira, GitHub, Azure DevOps connections

#### Pricing Discussion (10 min)
- Explain credit-based pricing model
- Present appropriate package based on needs
- Discuss annual vs. pay-per-test options

#### Next Steps (5 min)
- Answer remaining questions
- Propose pilot/trial if applicable
- Schedule follow-up call with decision makers
- Send proposal and contract

---

## 3. Client Onboarding

### After Contract Signing

#### Week 1: Account Setup
1. **Platform Access**: Create client account, invite team members
2. **CSM Introduction**: Assign Customer Success Manager
3. **Kickoff Call**: 30-min call to plan first pentest
4. **Asset Documentation**: Client provides asset inventory

#### Week 2: First Pentest Preparation
1. **Scope Definition**: Define exact URLs, APIs, credentials
2. **Environment Prep**: Client sets up staging/test environment
3. **Credential Sharing**: Secure credential exchange
4. **Stakeholder Notification**: Alert internal teams about testing

#### Week 3+: Testing Begins
1. **Pentester Assignment**: Match pentesters to tech stack
2. **Slack Channel Creation**: Private channel for real-time comms
3. **Testing Execution**: Pentest runs for defined duration
4. **Daily Updates**: Progress updates shared with client

---

## 4. The 6-Phase Pentest Lifecycle

### Phase 1: DISCOVER
**Duration**: 1-3 days before pentest

| Activity | Owner | Deliverable |
|----------|-------|-------------|
| Attack surface mapping | Cobalt Platform | Asset inventory |
| Domain scanning | Automated tools | Subdomain list |
| Technology fingerprinting | Pentesters | Tech stack report |
| Initial reconnaissance | Pentesters | Reconnaissance notes |

### Phase 2: PLAN
**Duration**: 1-5 days

| Activity | Owner | Deliverable |
|----------|-------|-------------|
| Scope confirmation | Client + CSM | Signed scope document |
| Test credentials setup | Client | Working test accounts |
| Environment preparation | Client | Accessible test environment |
| Methodology selection | Pentesters | Testing checklist |
| Timeline confirmation | CSM | Project schedule |

### Phase 3: TEST
**Duration**: 5-14 days (depending on scope)

| Activity | Owner | Deliverable |
|----------|-------|-------------|
| Automated scanning | Pentesters | Initial scan results |
| Manual testing | Pentesters | Deep-dive findings |
| Vulnerability discovery | Pentesters | Real-time finding reports |
| Exploitation attempts | Pentesters | Proof of concepts |
| Daily standup updates | Pentesters | Progress reports |

**Testing Methodologies Used**:
- OWASP Top 10
- OWASP API Security Top 10
- PTES (Penetration Testing Execution Standard)
- NIST Cybersecurity Framework

### Phase 4: REMEDIATE
**Duration**: Ongoing during and after testing

| Activity | Owner | Deliverable |
|----------|-------|-------------|
| Finding triage | Client | Prioritized fix list |
| Developer fixes | Client Dev Team | Code patches |
| Retest requests | Client | Retest tickets |
| Verification testing | Pentesters | Pass/fail status |
| Jira/GitHub sync | Platform | Updated tickets |

### Phase 5: REPORT
**Duration**: 2-3 business days after testing ends

| Report Section | Content |
|----------------|---------|
| Executive Summary | High-level overview for leadership |
| Scope & Methodology | What was tested and how |
| Findings Summary | Table of all vulnerabilities |
| Detailed Findings | Each vuln with description, impact, remediation |
| Evidence | Screenshots, payloads, proof of concepts |
| Recommendations | Prioritized remediation roadmap |
| Appendices | Technical details, tool outputs |

**Report Formats**:
- PDF (formal report)
- HTML (interactive)
- CSV/JSON (for integrations)

### Phase 6: ANALYZE
**Duration**: Post-pentest ongoing

| Activity | Owner | Deliverable |
|----------|-------|-------------|
| Report review | Client Security Team | Action items |
| Trend analysis | Cobalt Platform | Historical comparisons |
| Risk scoring | Platform | Risk posture score |
| Next pentest planning | CSM + Client | Future test schedule |
| Compliance mapping | Platform | Compliance evidence |

---

## 5. Pentester Perspective

### Becoming a Cobalt Core Pentester

#### Requirements
- 3+ years of professional pentesting experience
- Relevant certifications (OSCP, OSWE, GPEN, CEH)
- Strong communication skills
- Background check clearance
- Technical assessment passed

#### Application Process
1. Online application with resume/portfolio
2. Technical screening (CTF-style challenges)
3. Interview with Cobalt team
4. Background verification
5. Platform onboarding and training

### Pentester Workflow

#### Receiving an Assignment
1. **Notification**: Email/Slack alert for new pentest opportunity
2. **Review Scope**: Assess if skills match the project
3. **Accept/Decline**: Choose to take the assignment
4. **Access Credentials**: Receive test account access

#### During Testing
1. **Daily Check-ins**: Update status in platform
2. **Finding Submission**: Report vulns as discovered
3. **Client Communication**: Answer questions via Slack
4. **Evidence Collection**: Screenshots, videos, PoCs

#### Compensation Model
- **Per-finding bounties**: Higher pay for critical findings
- **Base testing fee**: Guaranteed minimum for time
- **Bonuses**: Quality bonuses, client satisfaction
- **Credits**: Platform credits for future opportunities

---

## 6. Pricing Model

### Credit-Based System

| Package | Credits | Typical Use | Price Range |
|---------|---------|-------------|-------------|
| Starter | 8 credits | 1-2 pentests/year | $10K-20K |
| Professional | 16 credits | 3-4 pentests/year | $30K-50K |
| Enterprise | 32+ credits | Continuous testing | $75K-150K+ |

### Credit Consumption
| Asset Type | Credits Required | Typical Duration |
|------------|-----------------|------------------|
| Small Web App | 2-4 credits | 5-7 days |
| Medium Web App | 4-6 credits | 7-10 days |
| Large Web App | 6-10 credits | 10-14 days |
| API (small) | 2-3 credits | 3-5 days |
| API (large) | 4-6 credits | 7-10 days |
| Mobile App | 4-6 credits | 7-10 days |
| Cloud Infrastructure | 4-8 credits | 7-14 days |

### Additional Services
- **Retesting**: Often included, or 0.5 credits
- **Express Testing**: 2x credits for faster turnaround
- **Dedicated Pentester**: Premium for same tester continuity

---

## 7. Platform Features

### For Clients
- **Dashboard**: Overview of all pentests and findings
- **Asset Management**: Track all testable assets
- **Finding Management**: View, comment, retest findings
- **Reports**: Download PDF/HTML reports
- **Integrations**: Jira, GitHub, Slack, Azure DevOps
- **Compliance Mapping**: Map findings to frameworks
- **User Management**: Invite team members with roles

### For Pentesters
- **Assignment Board**: View available pentests
- **Testing Interface**: Submit findings with templates
- **Communication**: Slack integration for client chat
- **Payout Tracking**: View earnings and payment history
- **Profile Management**: Update skills and certifications

### For Admins
- **User Management**: Manage clients and pentesters
- **Pentest Oversight**: Monitor all active tests
- **Quality Assurance**: Review findings before client sees
- **Financial Management**: Track credits, payments
- **Reporting**: Platform-wide analytics

---

## 8. How to Replicate for REDCON OFFENCE

### Immediate Actions

#### Platform Development
- [x] Client Dashboard - Basic implementation done
- [x] Admin Dashboard - Basic implementation done
- [x] Pentester Dashboard - Basic implementation done
- [ ] Finding submission interface
- [ ] Real-time notification system
- [ ] Report generation (PDF)
- [ ] Integrations (Jira, Slack)

#### Sales Process
1. **Create Demo Script**: Based on above structure
2. **Build Sales Deck**: Highlight differentiators
3. **Pricing Page**: Define credit packages
4. **Contract Templates**: Legal agreements ready

#### Pentester Recruitment
1. **Job Postings**: LinkedIn, InfoSec job boards
2. **Vetting Process**: Technical challenges
3. **Onboarding Training**: Platform usage, methodology
4. **Payment System**: Reliable payout mechanism

### Differentiators for REDCON OFFENCE
| Cobalt | REDCON OFFENCE (Suggested) |
|--------|---------------------------|
| Global pentester pool | Regional expertise (Turkey/Middle East focus) |
| Credit-based pricing | Flexible project-based or subscription |
| Generic methodologies | Industry-specific playbooks |
| Standard reporting | Compliance-focused reports (KVKK, BDDK) |

### 90-Day Launch Roadmap

#### Month 1: Foundation
- Week 1-2: Finalize platform features
- Week 3-4: Create sales materials, pricing

#### Month 2: Go-to-Market
- Week 1-2: Recruit 3-5 core pentesters
- Week 3-4: Soft launch with 2-3 pilot clients

#### Month 3: Scale
- Week 1-2: Gather feedback, iterate
- Week 3-4: Full launch, marketing push

---

## Summary

Cobalt's success comes from:
1. **Streamlined Process**: Clear 6-phase lifecycle
2. **Platform-Centric**: Everything in one place
3. **Real-Time Collaboration**: Slack + platform integration
4. **Flexible Pricing**: Credits allow budget control
5. **Quality Pentesters**: Vetted global talent pool
6. **Compliance Focus**: Reports map to frameworks

To compete, REDCON OFFENCE should focus on:
1. **Regional Expertise**: Turkey/Middle East market knowledge
2. **Personal Touch**: Smaller team = better relationships
3. **Compliance Specialization**: KVKK, BDDK, local regulations
4. **Competitive Pricing**: Undercut enterprise pricing
5. **Fast Turnaround**: Agile, responsive service

---

*Document Created: January 2026*
*For Internal Use - REDCON OFFENCE*




