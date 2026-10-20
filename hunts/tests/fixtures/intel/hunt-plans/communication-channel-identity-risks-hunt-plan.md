# Hunt Plan: communication-channel-identity-risks

## Environment Profile

| Context | Value |
|---------|-------|
| SIEM / Data Platform | Unknown |
| EDR Platform | Unknown |
| Environment Type | Unknown |
| Industry Vertical | Unknown |
| Approximate Log Retention | Unknown |
| Hunt Maturity Level | Unknown |

> ⚠️ **Environment not yet captured.** Every environment field above is `Unknown` (see `./threat-hunting/environment-profile.md`). All data-source names, query syntax, and the feasibility assessment below are written generically/with placeholders as a result. **Run the `gather` skill standalone before hunt execution** to replace these with real values — the Feasibility Assessment in this plan is CONDITIONAL specifically because of this gap (see Story-level and Epic-level caveats below).

---

## Epic: [HUNT-2026-001] Identity Abuse Through Trusted Communication Channels

### Hypothesis

We hypothesize that adversaries may be abusing trusted enterprise collaboration platforms (Microsoft Teams, Slack, and developer-facing tooling reached via chat-platform social engineering) to conduct identity phishing, webhook-based credential exfiltration/MFA removal, and supply-chain-adjacent malware delivery within our environment — evidenced by (1) external/guest-tenant messages impersonating IT support or leadership that solicit credentials or MFA approval, (2) anomalous outbound webhook traffic to collaboration-platform notification endpoints (e.g., `hooks.slack.com`) from non-chat-client processes or appliances, and (3) package-manager/archive-extraction activity on developer endpoints producing unexpected child processes shortly after external chat-platform contact — in [SIEM / EDR / Identity provider audit logs — pending environment `gather`], which we will validate by querying up to 90 days of available collaboration-platform, network-egress, and endpoint telemetry within a 10-business-day execution window.

*(This Epic-level statement is decomposed into three independently-scored Stories below — each tests one component of the hypothesis. Actor is intentionally unspecified at the Epic level: while the triggering intel names APT29, a DPRK-nexus cluster (naming contested — see report Open Questions), and unattributed/contested-attribution actors, the underlying behaviors are hunted actor-agnostically, consistent with "most good hunts are actor-agnostic" guidance.)*

### Triggering Event

- **Type:** CTI (Cyber Threat Intelligence)
- **Source:** `./threat-hunting/intel-reports/communication-channel-identity-risks-report.md`, itself derived from Unit 42, "Identity Abuse Through Trusted Communication Channels" (2026-08-20) — https://unit42.paloaltonetworks.com/communication-channel-identity-risks/
- **Date Received:** 2026-09-05
- **Classification:** TLP:CLEAR (public vendor blog)
- **Relevance to Organization:** [FILL IN: confirm — this hunt assumes the organization uses Microsoft Teams, Slack, and/or Google Workspace for collaboration and has developers who consume open-source/npm packages, since the underlying report's five incidents all involve these platforms. If any of these platforms are not in use, drop the corresponding Story.] The report's own telemetry claim — endpoint alerts tied to collaboration-tool abuse have more than quadrupled in 12 months, with 99% of alerts being chat/voice phishing — indicates this is an active, growing vector industry-wide, independent of any single actor's targeting of this organization specifically.

### Initial Research Summary

**Internal Sources Reviewed:**
- [ ] Previous hunt reports: [FILL IN: none on file / list if any exist]
- [ ] Architecture documentation: [FILL IN: collaboration-platform tenant architecture, federation/guest-access configuration]
- [ ] Detection coverage: [FILL IN: existing rules for Teams/Slack phishing, webhook egress, or npm supply-chain abuse, if any]
- [ ] Asset inventory: [FILL IN: developer workstation population, network/security appliances with SaaS-webhook integrations]

**External Sources Reviewed:**
- [x] MITRE ATT&CK: T1566.003, T1566.002, T1656, T1078.004, T1585.001/.002, T1608, T1204.001/.002, T1195.001/.002, T1219, T1574.002, T1036.005, T1557, T1539, T1567.004, T1102.002, T1053.005, T1556.006, T1133, T1071.001 (full mapping and evidence in the analysis file)
- [x] Threat reports: Unit 42 (anchor), Microsoft Security Blog (Midnight Blizzard/Teams), Fireblocks blog, Google GTIG (UNC1069), CISA alerts (Poland/FortiGate, Axios), CERT Polska
- [ ] Sigma rules: [FILL IN — hand off to `detection-engineer` for Stage 4; not authored here]
- [x] Threat actor profiles: APT29/Midnight Blizzard (High confidence), "Contagious Interview" DPRK cluster (Moderate, victim-assessed), UNC1069/possibly Sapphire Sleet (contested naming — see below), unattributed (Linux Foundation item), contested FSB/Sandworm (CERT Polska broader campaign)

**Key Findings from Research:**
1. None of the five source incidents involve a patchable CVE — all are technique/feature abuse or credential-hygiene failures. This hunt plan is behavioral/telemetry-based throughout; there is no corresponding "patch and done" mitigation.
2. Two open attribution contradictions exist in the underlying intel and should not be resolved by this hunt plan: (a) the Axios compromise actor is named UNC1069 by Google GTIG vs. "Sapphire Sleet" in a separate unverified report; (b) the CERT Polska broader campaign is attributed to FSB by CERT Polska vs. Sandworm/GRU by ESET. Hunts here are written actor-agnostically so they remain valid regardless of how these resolve.
3. The environment profile is entirely `Unknown`, so this hunt plan cannot state real data-source names or confirm retention/tooling — see Feasibility Assessment.

### Feasibility Assessment

| Criterion | Status | Notes |
|---|---|---|
| Data Availability | **CONDITIONAL** | SIEM/EDR/identity-provider platform is `Unknown` — cannot confirm Teams/Slack audit logs, egress/proxy logs, or EDR process-creation telemetry are actually ingested. Per `telemetry-gap-assessment.md` decision rules, an unscored/unknown visibility component defaults to CONDITIONAL rather than automatic NO-GO, since it is plausible (not confirmed absent) that this telemetry exists. |
| Data Quality | **CONDITIONAL** | Cannot assess field completeness, parsing, or consistency without knowing the platform. |
| Team Skillset | Unknown | [FILL IN: does the hunt team have experience with M365/Teams/Slack audit log analysis, proxy/firewall log analysis, and EDR process-tree analysis?] |
| Timeline | GO (estimated) | Moderate complexity, 3 Stories, some unknowns → **3-5 days execution per Story once environment is confirmed**, ~10 business days total for the Epic. |
| Tooling | Unknown | [FILL IN: SIEM/EDR console access and query permissions for the hunt team] |

**OVERALL DECISION: CONDITIONAL**

**Mandatory caveat (per `telemetry-gap-assessment.md`):**
> Findings from this hunt plan are bounded by unconfirmed visibility into collaboration-platform audit logs, network egress/proxy logs, and endpoint process-creation telemetry across the full in-scope asset population. A negative result from any Story does **not** establish absence of the hunted behavior outside whatever coverage is actually confirmed once the environment profile is completed. **Run `gather` standalone and re-score this Feasibility Assessment before executing any Story.**

**Assumptions/Conditions:**
- Assumes the organization actively uses at least one of Microsoft Teams, Slack, or Google Workspace for collaboration (Story 1, 2).
- Assumes developers in the organization consume npm or other open-source packages, or conduct external interviews/collaboration via chat platforms (Story 3). If not applicable, deprioritize Story 3.
- Assumes at least 90 days of log retention is achievable for the relevant sources; if actual retention is shorter, reduce the analysis window accordingly and document the reduced window in the Story's Acceptance Criteria.

### Scope

**Target Environment:**
- [ ] Production servers
- [ ] Workstations/endpoints (developer population specifically, for Story 3)
- [ ] Cloud infrastructure (AWS/Azure/GCP) — [FILL IN if environment type is cloud-native/hybrid]
- [ ] Network perimeter (egress/proxy/firewall, for Story 2)
- [ ] DMZ
- [x] Collaboration platform tenant(s) — Microsoft 365/Teams and/or Slack Enterprise Grid and/or Google Workspace [FILL IN which are actually in use]
- [ ] Other: [FILL IN: any network/security appliances (VPN, firewall) with native SaaS webhook/notification integrations, per the CERT Polska pattern in Story 2]

**Time Window:** Last 90 days from hunt kickoff, or the maximum retained window if shorter than 90 days [FILL IN once retention is confirmed] ([X] days)

**In-Scope Assets:**
- Microsoft Teams / Slack / Google Workspace tenant(s) and their audit/activity logs
- Identity provider sign-in logs (Entra ID / Okta / Google Workspace admin) for correlation
- Network egress points (firewall/proxy) capable of resolving destination `hooks.slack.com` or equivalent SaaS webhook endpoints
- Developer endpoint population (EDR-covered)
- Network/security appliances (VPN concentrators, firewalls) with native chat-platform integrations, if any exist

**Explicit Exclusions:**
- OT/ICS environments — not implicated by any of the five source incidents; exclude unless the organization's environment type (once confirmed) includes OT/ICS with similar SaaS-webhook integrations, in which case re-scope Story 2 to include it under the OT-specific feasibility checks in `domain-telemetry-matrix.md`.
- Email-based phishing — explicitly out of scope; the triggering intel and this hunt are scoped to chat/collaboration-platform vectors specifically, per the report's framing that this is a distinct, growing vector from email.

### Objectives

**Primary Objectives:**
1. Determine whether any external/guest-tenant identity has sent IT-support- or leadership-impersonation messages soliciting credentials or MFA approval within the analysis window (Story 1).
2. Determine whether any non-chat-client process, server, or network/security appliance has posted to a collaboration-platform webhook endpoint (e.g., `hooks.slack.com`) outside of an approved, inventoried integration (Story 2).
3. Determine whether any developer endpoint shows a package-manager/archive-extraction process spawning an anomalous child process or connection following external chat-platform contact (Story 3).

**Secondary Objectives:**
1. Produce an inventory of all current external-federation/guest-access configurations across in-scope collaboration platforms, regardless of hunt findings (supports Mitigate recommendations in the intel report).
2. Produce an inventory of all approved SaaS webhook integrations on network/security appliances, regardless of hunt findings.

**Success Metrics:**
- [ ] Hypothesis (each Story component) validated or invalidated with evidence
- [ ] All three Stories completed within the estimated timeline, or explicitly re-scoped/backlogged with reasons recorded
- [ ] Findings documented per outcome category (New Hunt Idea / Analytics-Detection / Security Incident / Written Report / Visibility Gap / Security Control Issue)
- [ ] Report delivered to stakeholders; any Analytics/Detection outcome handed off to `detection-engineer`

### MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic |
|---|---|---|
| T1566.003 | Phishing: Spearphishing via Service | Initial Access |
| T1566.002 | Phishing: Spearphishing Link | Initial Access |
| T1656 | Impersonation | Resource Development / Defense Evasion |
| T1078.004 | Valid Accounts: Cloud Accounts | Initial Access / Persistence / Privilege Escalation / Defense Evasion |
| T1585.001 / T1585.002 | Establish Accounts: Social Media / Email Accounts | Resource Development |
| T1608 | Stage Capabilities | Resource Development |
| T1204.001 / T1204.002 | User Execution: Malicious Link / Malicious File | Execution |
| T1195.001 | Supply Chain Compromise: Compromise Software Dependencies and Development Tools | Initial Access |
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Initial Access |
| T1219 | Remote Access Software | Command and Control |
| T1574.002 | Hijack Execution Flow: DLL Side-Loading | Persistence / Privilege Escalation / Defense Evasion |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Defense Evasion |
| T1557 | Adversary-in-the-Middle | Credential Access / Collection |
| T1539 | Steal Web Session Cookie | Credential Access |
| T1567.004 | Exfiltration Over Web Service: Exfiltration Over Webhook | Exfiltration |
| T1102.002 | Web Service: Bidirectional Communication | Command and Control |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Execution / Persistence |
| T1556.006 | Modify Authentication Process: Multi-Factor Authentication | Credential Access / Persistence / Defense Evasion |
| T1133 | External Remote Services | Initial Access / Persistence |
| T1071.001 | Application Layer Protocol: Web Protocols | Command and Control |

### Data Sources Required

| Data Source | Platform | Key Fields | Retention |
|---|---|---|---|
| Collaboration-platform audit/activity log (Teams/Slack/Google Workspace) | [FILL IN: M365 Unified Audit Log / Slack Enterprise Grid audit / Google Workspace audit — pending `gather`] | external/guest sender flag, message content metadata, link/URL, recipient count, timestamp | [FILL IN] |
| Identity provider sign-in/audit log | [FILL IN: Entra ID / Okta / Google Workspace admin — pending `gather`] | user, source IP/ASN, device ID, MFA result, conditional access result, timestamp | [FILL IN] |
| Network egress / proxy / firewall log | [FILL IN: pending `gather`] | destination host (hooks.slack.com or equivalent), source IP/process, HTTP method, user-agent, timestamp | [FILL IN] |
| Endpoint process-creation telemetry | [FILL IN: EDR — CrowdStrike/SentinelOne/Defender for Endpoint/Sysmon — pending `gather`] | parent process, child process, command line, hash, network connection, timestamp | [FILL IN] |
| Scheduled task creation/modification | [FILL IN: Windows Event ID 4698/4702, or native appliance task logs (e.g., FortiGate scripting engine logs) — pending `gather`] | task name, command, creator account, schedule, timestamp | [FILL IN] |
| npm/package-manager install activity (if separately logged) | [FILL IN: CI/CD logs, developer endpoint EDR — pending `gather`] | package name, version, source registry, installing user/host, timestamp | [FILL IN] |

### References

- `./threat-hunting/intel-reports/communication-channel-identity-risks-report.md`
- `./threat-hunting/intel-analysis/communication-channel-identity-risks-analysis.md`
- Unit 42 — "Identity Abuse Through Trusted Communication Channels" — https://unit42.paloaltonetworks.com/communication-channel-identity-risks/
- Microsoft Security Blog — "Midnight Blizzard conducts targeted social engineering over Microsoft Teams" — https://www.microsoft.com/en-us/security/blog/2023/08/02/midnight-blizzard-conducts-targeted-social-engineering-over-microsoft-teams/
- Fireblocks — "Disrupting a Recruiting Impersonation Scam" — https://www.fireblocks.com/blog/contagious-interview-recruiting-scam
- Google Cloud Blog / GTIG — UNC1069 — https://cloud.google.com/blog/topics/threat-intelligence/unc1069-targets-cryptocurrency-ai-social-engineering
- CISA Alert — "Supply Chain Compromise Impacts Axios Node Package Manager" — https://www.cisa.gov/news-events/alerts/2026/04/20/supply-chain-compromise-impacts-axios-node-package-manager
- CERT Polska — Incident Report, Energy Sector, December 2025 — https://cert.pl/en/posts/2026/01/incident-report-energy-sector-2025/
- CISA Alert — "Poland Energy Sector Cyber Incident Highlights OT and ICS Security Gaps" — https://www.cisa.gov/news-events/alerts/2026/02/10/poland-energy-sector-cyber-incident-highlights-ot-and-ics-security-gaps
- MITRE ATT&CK Enterprise — https://attack.mitre.org/

### Linked Stories

- [HUNT-2026-001-S1] External IT-Support/Leadership Impersonation via Teams/Slack
- [HUNT-2026-001-S2] Anomalous Webhook Egress to Collaboration-Platform Notification Endpoints
- [HUNT-2026-001-S3] Post-Chat-Engagement Package-Manager/Archive Execution on Developer Endpoints

---

## Story: [HUNT-2026-001-S1] External IT-Support/Leadership Impersonation via Teams/Slack

### Parent Epic
HUNT-2026-001

### Objective
Determine whether any external/guest identity on our Microsoft Teams or Slack tenant(s) has sent unsolicited IT-support- or leadership-impersonation messages containing credential-harvesting links to internal users, and whether any such message was followed by an anomalous authentication event.

### Hypothesis Component

**Hypothesis (SMART):** We hypothesize that an adversary may be impersonating IT support or organizational leadership via external/guest access on Microsoft Teams or Slack to harvest credentials or MFA approvals, evidenced by external-tenant or guest-account messages containing links sent to multiple internal users in Microsoft 365 Unified Audit Log / Teams activity logs (or Slack Enterprise Grid audit logs), which we can validate by querying up to 90 days of collaboration-platform audit logs for external-sender-to-multiple-recipient messaging patterns correlated with subsequent sign-in events, within a 5-day execution window.

```
ID:                 HUNT-2026-001-S1
ABLE decomposition
  Actor:            Unspecified — actor-agnostic (informed by APT29/Midnight Blizzard reporting)
  Behavior:         External/guest identity sending unsolicited IT-support or leadership-themed
                    messages containing links, at volume, to multiple internal users
  Location:         M365 Teams tenant external-federation boundary / Slack Enterprise Grid guest boundary
  Evidence:         Teams/Slack audit "message posted" events flagged external/guest + link,
                    correlated with a subsequent sign-in event from a new device/ASN

ATT&CK:             T1566.003 (Spearphishing via Service) / T1656 (Impersonation) / T1078.004 (Valid Accounts: Cloud)
Pyramid level:      TTP
Data components:    Application Log: Application Log Content (Teams/Slack audit);
                    Logon Session: Logon Session Creation (identity provider sign-in log)
Expected malicious: External/guest sender not on a verified partner allowlist; message contains a
                    link/domain not previously seen in the tenant; followed within hours by a
                    successful interactive sign-in from a new device or ASN for the recipient
Expected benign:    External messages from verified, allowlisted federated partners/vendors with
                    no subsequent anomalous sign-in
Disprovable:        Y — zero qualifying external-sender-link messages correlated with an anomalous
                    sign-in across the full analysis window
Priority:           High — identity phishing via collaboration platforms is the report's dominant
                    vector (99% of Unit 42's cited alerts)
```

**Rubric score:** Specificity 3 · Testability 2 (query path defined; expected volume not yet known — depends on tenant size and external-federation posture) · Falsifiability 3 · Relevance 3 · Pyramid 3 = **14 → GO** (no dimension at 1)

### Methodology

**Phase 1: Data Collection**
1. Confirm which collaboration platform(s) are in scope (Teams, Slack, Google Workspace) and pull tenant-wide external-federation/guest-access configuration.
2. Export collaboration-platform audit events for the analysis window, filtered to messages sent by external or guest identities to two or more internal recipients.
3. Export identity-provider sign-in logs for the same window and recipient population, for correlation.

**Phase 2: Analysis**
1. Enrich external-sender messages with link/domain reputation and first-seen-in-tenant status.
2. Join message events to sign-in events by recipient + timestamp (within a configurable window, e.g. 24 hours after message receipt).
3. Rank results by recipient count, sender novelty, and link novelty; triage highest-risk first.

**Phase 3: Validation**
1. For each candidate, confirm whether the external sender is a legitimate, allowlisted partner/vendor.
2. For confirmed non-legitimate senders, correlate with any subsequent MFA-approval or password-reset activity for the targeted recipient(s).
3. Document true/false positive determination per candidate.

### Data Sources

| Source | Fields Required | Query Location |
|---|---|---|
| Teams/Slack/Google Workspace audit log | timestamp, sender identity, sender tenant/guest flag, recipient(s), message link/URL, link domain | [FILL IN: SIEM index or native platform audit console] |
| Identity provider sign-in log | timestamp, user, source IP, ASN, device ID, MFA result | [FILL IN: SIEM index or IdP console] |

### Detection Logic

Primary Query (pseudocode — adapt to actual SIEM syntax once confirmed via `gather`):
```
collaboration_audit_events
| where sender.is_external == true OR sender.is_guest == true
| where message.contains_link == true
| summarize recipient_count = dcount(recipient) by sender, link_domain, bin(timestamp, 1h)
| where recipient_count >= 2
| join kind=leftouter (
    signin_events
    | where result == "success"
    | where is_new_device == true OR is_new_asn == true
  ) on $left.recipient == $right.user
| where signin_events.timestamp between (message.timestamp .. message.timestamp + 24h)
```

Sigma Rule (structural placeholder — hand off to `detection-engineer` for a production rule):
```yaml
title: External Collaboration-Platform Message Preceding Anomalous Sign-In
status: experimental
description: Detects an external/guest collaboration-platform message containing a link, sent to multiple internal recipients, followed by an anomalous sign-in for a recipient.
logsource:
    product: [FILL IN — m365 | slack | gworkspace]
    service: audit
detection:
    selection:
        sender.external: true
        message.has_link: true
    condition: selection
falsepositives:
    - Legitimate external vendor/partner communication not yet allowlisted
level: medium
tags:
    - attack.initial-access
    - attack.t1566.003
    - attack.t1656
```

### Expected Outcomes

**If Malicious Activity Present:**
- External/guest sender not on any partner allowlist, using a first-seen link domain, with a recipient subsequently completing a new-device/new-ASN sign-in
- Escalate to IR per incident response plan

**If Hypothesis Invalid:**
- All external-sender-with-link messages in the window trace to allowlisted, legitimate partners, with no anomalous sign-in correlation
- Document as negative finding, close Story

### Acceptance Criteria
- [ ] Data sources validated and accessible (pending `gather`)
- [ ] Queries executed across full time window (or reduced window if retention is shorter — document the actual window used)
- [ ] Results triaged (true/false positive determination)
- [ ] Findings documented with evidence
- [ ] Tasks created for outcomes

### Linked Tasks (Outcomes)
- [HUNT-2026-001-S1-T1] Visibility Gap: Environment/telemetry unconfirmed (see below)
- [HUNT-2026-001-S1-T2] Analytics/Detection: hand off to `detection-engineer` if validated

---

## Story: [HUNT-2026-001-S2] Anomalous Webhook Egress to Collaboration-Platform Notification Endpoints

### Parent Epic
HUNT-2026-001

### Objective
Determine whether any network/security appliance, server, or non-chat-client process is posting to a collaboration-platform webhook endpoint (e.g., `hooks.slack.com`) outside of an approved, inventoried integration — the pattern documented in the CERT Polska December 2025 incident (privileged credential exfiltration + MFA/2FA removal via a FortiGate-native Slack webhook, on a weekly scheduled task).

### Hypothesis Component

**Hypothesis (SMART):** We hypothesize that a compromised network appliance, server, or scheduled task may be exfiltrating privileged credentials or disabling MFA via native collaboration-platform webhook integrations, evidenced by outbound HTTPS POST requests to `hooks.slack.com` (or equivalent) originating from non-chat-client processes or appliances, in firewall/proxy egress logs and endpoint process-to-network telemetry, which we can validate by querying up to 90 days of egress logs for webhook-endpoint destinations excluding known chat-client processes, cross-referenced with scheduled-task creation events, within a 5-day execution window.

```
ID:                 HUNT-2026-001-S2
ABLE decomposition
  Actor:            Unspecified — actor-agnostic (informed by the CERT Polska Dec 2025 pattern;
                    broader-campaign attribution to FSB vs. Sandworm/GRU is contested and irrelevant
                    to this behavioral hunt)
  Behavior:         Webhook POST to a collaboration-platform notification endpoint from a non-chat-
                    client process/appliance, co-occurring with scheduled-task-driven credential
                    harvesting or MFA/2FA removal
  Location:         Network egress (firewall/proxy) + endpoint/appliance layer
  Evidence:         Proxy/firewall log entries destined to hooks.slack.com (or equivalent) with a
                    non-browser/non-chat-client user-agent or source process, co-occurring with a
                    new/modified scheduled task and/or an MFA-configuration-change audit event

ATT&CK:             T1567.004 (Exfiltration Over Webhook) / T1102.002 (Web Service: Bidirectional
                    Communication) / T1053.005 (Scheduled Task) / T1556.006 (Modify Authentication
                    Process: MFA)
Pyramid level:      TTP
Data components:    Network Traffic: Network Traffic Content (proxy/firewall);
                    Scheduled Job: Scheduled Job Creation
Expected malicious: hooks.slack.com (or equivalent) POST from a server/appliance IP with no
                    approved integration on file, or from an unexpected process, co-occurring with
                    a new/modified scheduled task and an MFA-configuration-change event
Expected benign:    Webhook POST from an approved, inventoried CI/CD or monitoring integration with
                    no associated MFA/credential-configuration change
Disprovable:        Y — all webhook-endpoint egress in the window resolves to inventoried, approved
                    integrations with no co-occurring MFA/credential change
Priority:           High — direct match to a documented incident pattern; MFA/2FA removal is a
                    severe, high-impact outcome regardless of actor attribution
```

**Rubric score:** Specificity 3 · Testability 2 · Falsifiability 3 · Relevance 3 · Pyramid 3 = **14 → GO** (no dimension at 1)

### Methodology

**Phase 1: Data Collection**
1. Inventory all currently approved SaaS webhook integrations on network/security appliances and servers (this doubles as Epic Secondary Objective 2).
2. Export firewall/proxy egress logs for the analysis window, filtered to destinations matching known collaboration-platform webhook domains (`hooks.slack.com` and equivalents for Teams/Google Workspace, if applicable).
3. Export scheduled-task creation/modification events (Windows Event ID 4698/4702, or native appliance task/scripting-engine logs) for the same window and asset population.

**Phase 2: Analysis**
1. Exclude egress events matching the approved-integration inventory from Phase 1.
2. For remaining events, identify source process/appliance and check for a co-occurring new/modified scheduled task on the same asset within the analysis window.
3. Check for any MFA-configuration-change or privileged-credential-access audit event on the same asset/account in the same window.

**Phase 3: Validation**
1. For each candidate, confirm business justification (or lack thereof) for the webhook integration with the asset owner.
2. Confirm whether any associated MFA/credential change was authorized.
3. Document true/false positive determination.

### Data Sources

| Source | Fields Required | Query Location |
|---|---|---|
| Firewall/proxy egress log | timestamp, source IP/process, destination host, HTTP method, user-agent | [FILL IN: SIEM index — pending `gather`] |
| Scheduled task creation/modification log | timestamp, host, task name, command, creator account | [FILL IN: Windows Event Log / appliance-native log — pending `gather`] |
| Identity/MFA configuration audit log | timestamp, account, MFA status change, actor | [FILL IN: IdP or appliance admin audit — pending `gather`] |

### Detection Logic

Primary Query (pseudocode — adapt to actual SIEM syntax once confirmed):
```
egress_logs
| where destination_host in ("hooks.slack.com", <other known webhook domains>)
| where source_process NOT IN (approved_integration_inventory)
| join kind=inner (
    scheduled_task_events
    | where event_type in ("created", "modified")
  ) on $left.source_host == $right.host
| where scheduled_task_events.timestamp between (egress.timestamp - 7d .. egress.timestamp + 7d)
```

Sigma Rule (structural placeholder — hand off to `detection-engineer` for a production rule):
```yaml
title: Unapproved Webhook Egress to Collaboration-Platform Endpoint
status: experimental
description: Detects outbound traffic to a collaboration-platform webhook endpoint from a process or appliance not on the approved-integration inventory.
logsource:
    category: proxy
detection:
    selection:
        destination.host|contains: 'hooks.slack.com'
    filter:
        source.process|in: [FILL IN: approved integration list]
    condition: selection and not filter
falsepositives:
    - Newly onboarded, legitimate integration not yet added to the inventory
level: high
tags:
    - attack.exfiltration
    - attack.t1567.004
    - attack.t1556.006
```

### Expected Outcomes

**If Malicious Activity Present:**
- Unapproved webhook egress co-occurring with a new/modified scheduled task and an unauthorized MFA-configuration change
- Escalate to IR per incident response plan

**If Hypothesis Invalid:**
- All webhook egress traces to approved, inventoried integrations with no co-occurring credential/MFA change
- Document as negative finding, close Story

### Acceptance Criteria
- [ ] Data sources validated and accessible (pending `gather`)
- [ ] Queries executed across full time window
- [ ] Results triaged (true/false positive determination)
- [ ] Findings documented with evidence
- [ ] Tasks created for outcomes

### Linked Tasks (Outcomes)
- [HUNT-2026-001-S2-T1] Security Control Issue: Unapproved/uninventoried webhook integrations (if found)
- [HUNT-2026-001-S2-T2] Analytics/Detection: hand off to `detection-engineer` if validated

---

## Story: [HUNT-2026-001-S3] Post-Chat-Engagement Package-Manager/Archive Execution on Developer Endpoints

### Parent Epic
HUNT-2026-001

### Objective
Determine whether any developer or open-source-maintainer endpoint shows a package-manager (`npm install`), source-control (`git clone`), or archive-extraction (RAR) utility spawning an unexpected child process or network connection, in temporal proximity to external chat-platform contact (e.g., a recruitment/interview lure or a staged-workspace approach) — the pattern documented in the Fireblocks and Axios npm incidents.

### Hypothesis Component

**Hypothesis (SMART):** We hypothesize that developers or open-source maintainers may be socially engineered via chat-platform recruitment or collaboration lures into executing malicious payloads via `npm install`, `git clone`, or RAR-archive extraction, evidenced by process-creation events showing package-manager or archive-extraction utilities spawning network connections or unexpected child processes (e.g., a sideloaded `lpk.dll` or an unexpected binary) shortly after external chat-platform contact, in EDR process-creation and network-connection telemetry correlated with chat-platform message logs, which we can validate by querying up to 90 days of endpoint telemetry for this process-lineage pattern within a 5-day execution window.

```
ID:                 HUNT-2026-001-S3
ABLE decomposition
  Actor:            "Contagious Interview"/DPRK-nexus cluster-informed (naming contested between
                    UNC1069 and Sapphire Sleet across sources — hunt is actor-agnostic in execution)
  Behavior:         npm/git/archive-extraction utility spawning an unexpected child process or
                    outbound connection, temporally linked to external chat-platform contact
  Location:         Developer endpoints; source-control/package-manager tooling
  Evidence:         EDR process-creation events (parent: node.exe/npm/WinRAR/cmd.exe → unexpected
                    child, e.g. rundll32.exe loading a renamed/sideloaded DLL, or a new unsigned
                    binary); correlated chat-platform message logs showing external contact in the
                    preceding days

ATT&CK:             T1204.002 (User Execution: Malicious File) / T1195.001 & T1195.002 (Supply
                    Chain Compromise) / T1574.002 (DLL Side-Loading) / T1036.005 (Masquerading) /
                    T1219 (Remote Access Software)
Pyramid level:      TTP
Data components:    Process: Process Creation; Command: Command Execution;
                    Network Traffic: Network Connection Creation
Expected malicious: npm/git/archive tool spawning a process outside its normal baseline (e.g.,
                    PowerShell, rundll32 loading a sideloaded DLL, or a new persistent binary)
                    within minutes of installation, on a host with recent external chat-platform
                    contact
Expected benign:    Standard build/CI process trees with no anomalous child processes, no external
                    chat-platform contact preceding the activity
Disprovable:        Y — no qualifying anomalous process-lineage pattern found across the full
                    analysis window of developer endpoint telemetry
Priority:           Medium-High — supply-chain impact is severe, but targeting scope (developers/
                    OSS maintainers) is narrower than Stories 1-2
```

**Rubric score:** Specificity 3 · Testability 2 · Falsifiability 3 · Relevance 3 · Pyramid 3 = **14 → GO** (no dimension at 1)

### Methodology

**Phase 1: Data Collection**
1. Identify the in-scope developer/maintainer endpoint population.
2. Export EDR process-creation telemetry for that population for the analysis window, filtered to parent processes matching package-manager, source-control, or archive-extraction utilities.
3. Export chat-platform message logs for the same population for external-sender contact in the preceding 14 days of any flagged process event.

**Phase 2: Analysis**
1. Build a baseline of normal child-process patterns for npm/git/WinRAR on the in-scope population.
2. Flag deviations: child processes outside the baseline, especially DLL loads with mismatched name/location (masquerading), or new outbound connections immediately following install/extraction.
3. Correlate flagged hosts/users against chat-platform external-contact events in the preceding window.

**Phase 3: Validation**
1. For each candidate, retrieve the specific file/DLL/package involved and check hash/name against known-bad indicators (see analysis file IOC table — noting most are `[UNVERIFIED SOURCE]` and require independent confirmation before being treated as ground truth).
2. Confirm with the user/developer whether the chat-platform contact and subsequent install were part of a legitimate business process (e.g., an actual internal recruiting test) or unsolicited/external.
3. Document true/false positive determination.

### Data Sources

| Source | Fields Required | Query Location |
|---|---|---|
| EDR process-creation telemetry | timestamp, parent process, child process, command line, hash, network connection | [FILL IN: EDR console/API — pending `gather`] |
| Chat-platform audit log | timestamp, sender identity, external/guest flag, recipient | [FILL IN: pending `gather`] |

### Detection Logic

Primary Query (pseudocode — adapt to actual EDR/SIEM syntax once confirmed):
```
process_events
| where parent_process in ("npm.exe", "node.exe", "git.exe", "WinRAR.exe", "unrar.exe")
| where child_process NOT IN (baseline_expected_children)
| where child_process in ("rundll32.exe", "powershell.exe", "cmd.exe") OR is_network_connection == true
| join kind=leftouter (
    collaboration_audit_events | where sender.is_external == true
  ) on $left.host_user == $right.recipient
| where collaboration_audit_events.timestamp between (process_events.timestamp - 14d .. process_events.timestamp)
```

Sigma Rule (structural placeholder — hand off to `detection-engineer` for a production rule):
```yaml
title: Anomalous Child Process from Package-Manager or Archive Utility
status: experimental
description: Detects a package-manager, source-control, or archive-extraction utility spawning an unexpected child process consistent with DLL side-loading or RAT installation.
logsource:
    category: process_creation
    product: [FILL IN — windows | macos | linux]
detection:
    selection:
        ParentImage|endswith:
            - '\npm.exe'
            - '\node.exe'
            - '\git.exe'
            - '\WinRAR.exe'
        Image|endswith:
            - '\rundll32.exe'
            - '\powershell.exe'
    condition: selection
falsepositives:
    - Legitimate build/CI tooling with an unusual but authorized process tree
level: high
tags:
    - attack.execution
    - attack.t1204.002
    - attack.t1574.002
    - attack.t1195.001
```

### Expected Outcomes

**If Malicious Activity Present:**
- A package-manager/archive utility spawns a masquerading DLL load or unexpected binary, on a host with recent external chat-platform contact from an unverified sender
- Escalate to IR per incident response plan; treat as a potential supply-chain compromise (check whether any internally-maintained packages were touched by the affected developer)

**If Hypothesis Invalid:**
- No qualifying process-lineage anomalies found, or all flagged events trace to authorized internal testing/CI activity
- Document as negative finding, close Story

### Acceptance Criteria
- [ ] Data sources validated and accessible (pending `gather`)
- [ ] Queries executed across full time window
- [ ] Results triaged (true/false positive determination)
- [ ] Findings documented with evidence
- [ ] Tasks created for outcomes

### Linked Tasks (Outcomes)
- [HUNT-2026-001-S3-T1] New Hunt Idea: baseline npm/git process-tree behavior across the full developer fleet (see below)
- [HUNT-2026-001-S3-T2] Analytics/Detection: hand off to `detection-engineer` if validated

---

## Task: [HUNT-2026-001-S1-T1] Visibility Gap: Environment/Telemetry Unconfirmed

### Parent Story
HUNT-2026-001-S1 (applies equally to S2, S3, and the Epic as a whole)

### Outcome Category
Visibility Gap

### Description
The environment profile (`./threat-hunting/environment-profile.md`) has every field — SIEM/data platform, EDR platform, environment type, industry vertical, log retention, hunt maturity — marked `Unknown`. This hunt plan could not be written against real data-source names or confirmed retention, and the Feasibility Assessment above is CONDITIONAL specifically because of this gap.

### Impact
- **Hunt Impact:** All three Stories in this Epic are written with placeholder data-source names and generic pseudocode; none can be executed as-is.
- **Detection Impact:** No technique in the MITRE ATT&CK Mapping table can be scored for actual visibility (DeTT&CT 0-5 scale) until the environment is known.
- **MITRE Coverage:** All 19 mapped techniques are affected.

### Remediation
**Recommended Fix:** Run the `gather` skill standalone to interview the user and populate `./threat-hunting/environment-profile.md` with real SIEM/EDR/environment/retention/maturity values, then re-run the Feasibility Assessment (Step 4) for this Epic before any Story is executed.

**Owner:** [FILL IN: hunt team lead]
**Priority:** P1 — blocks execution of all three Stories

---

## Task: [HUNT-2026-001-S1-T2] Analytics/Detection: External-Sender-Link-to-Anomalous-Sign-In Correlation

### Parent Story
HUNT-2026-001-S1

### Outcome Category
Analytics/Detection

### Description
If Story 1 validates the hypothesis (or even on a clean/negative result, given the high relevance of this vector per the triggering intel), the correlation query in Story 1's Detection Logic section is a strong candidate for a standing detection.

### Detection Artifact
Type: SIEM Correlation Rule (structural placeholder — see Story 1's Sigma placeholder)

### Recommended Action
- [ ] Submit to detection engineering pipeline via the `detection-engineer` skill (Stage 4 of this pipeline)
- [ ] Assign to: [FILL IN: Detection Engineer]
- [ ] Target deployment: [FILL IN]

---

## Task: [HUNT-2026-001-S2-T1] Security Control Issue: Webhook Integration Inventory Gap

### Parent Story
HUNT-2026-001-S2

### Outcome Category
Security Control Issue

### Description
Phase 1 of Story 2's methodology requires building an inventory of approved SaaS webhook integrations on network/security appliances. If no such inventory currently exists (likely, given the environment profile is entirely unknown), this is itself a control gap independent of hunt findings — it is what allowed the CERT Polska-pattern incident to go undetected via "this looks like normal chat notification traffic."

### Evidence
[FILL IN once Phase 1 data collection confirms whether an inventory exists]

### Risk Assessment
- Likelihood: Medium (native SaaS integrations on network appliances are commonly enabled by default and rarely inventoried)
- Impact: High (this exact gap enabled privileged credential exfiltration and MFA removal in the CERT Polska incident)
- Risk Rating: High (pending confirmation)

### Recommended Remediation
- Build and maintain a standing inventory of all SaaS webhook/notification integrations on network and security appliances
- Restrict or disable such integrations where not explicitly required for operations (per the intel report's Mitigate recommendations)

**Owner:** [FILL IN]
**Target Date:** [FILL IN]

---

## Task: [HUNT-2026-001-S2-T2] Analytics/Detection: Unapproved Webhook Egress

### Parent Story
HUNT-2026-001-S2

### Outcome Category
Analytics/Detection

### Description
If Story 2 validates the hypothesis, the unapproved-webhook-egress query is a strong, low-noise standing-detection candidate (per the intel report's Detect recommendations, T1567.004 was flagged as a "strong standing-detection candidate").

### Detection Artifact
Type: SIEM Correlation Rule (structural placeholder — see Story 2's Sigma placeholder)

### Recommended Action
- [ ] Submit to detection engineering pipeline via the `detection-engineer` skill (Stage 4)
- [ ] Assign to: [FILL IN: Detection Engineer]
- [ ] Target deployment: [FILL IN]

---

## Task: [HUNT-2026-001-S3-T1] New Hunt Idea: Fleet-Wide npm/git Process-Tree Baseline

### Parent Story
HUNT-2026-001-S3

### Outcome Category
New Hunt Idea

### Description
Story 3 requires establishing a baseline of normal child-process behavior for npm/git/archive tools before anomalies can be reliably flagged (per the hypothesis-rubric's "benign baseline unstated → run the baseline first as an EDA hunt" guidance). If this baseline does not already exist, it should be run as its own exploratory (EDA) hunt ahead of or alongside Story 3.

### Rationale
Without a baseline, Story 3's detection logic risks either high false-positive volume (flagging legitimate build tooling) or missed detections (an overly narrow "expected benign" definition).

### Suggested Approach
- Trigger Type: Emerging from current hunt
- Estimated Complexity: Medium
- Recommended Priority: P2 — should precede or run in parallel with Story 3 execution

### Action
Add to hunt backlog for near-term sprint planning, ideally scheduled before or alongside Story 3.

---

## Task: [HUNT-2026-001-S3-T2] Analytics/Detection: Anomalous Package-Manager Child Process

### Parent Story
HUNT-2026-001-S3

### Outcome Category
Analytics/Detection

### Description
If Story 3 validates the hypothesis, the DLL side-loading/masquerading detection logic is a strong standing-detection candidate per the intel report's Detect recommendations (T1574.002/T1036.005 flagged as strong candidates).

### Detection Artifact
Type: EDR/SIEM Correlation Rule (structural placeholder — see Story 3's Sigma placeholder)

### Recommended Action
- [ ] Submit to detection engineering pipeline via the `detection-engineer` skill (Stage 4)
- [ ] Assign to: [FILL IN: Detection Engineer]
- [ ] Target deployment: [FILL IN]
