# Hunt Plan: russian-webmail-espionage

## Environment Profile

| Context | Value |
|---------|-------|
| SIEM / Data Platform | Unknown |
| EDR Platform | Unknown |
| Environment Type | Unknown |
| Industry Vertical | Unknown |
| Approximate Log Retention | Unknown |
| Hunt Maturity Level | Unknown |

> ⚠️ **Environment not yet captured.** Every environment field above is `Unknown` (see `./threat-hunting/environment-profile.md`, shared across pipeline runs — unchanged since the `communication-channel-identity-risks` run). All data-source names, query syntax, and the feasibility assessment below are written generically/with placeholders as a result. **Run the `gather` skill standalone before hunt execution** to replace these with real values.

---

## Epic: [HUNT-2026-002] Russian Global Webmail Espionage — CL-STA-1114/Void Blizzard/LAUNDRY BEAR Zimbra Exploitation (CVE-2025-66376)

### Hypothesis

We hypothesize that adversaries — most likely CL-STA-1114/Void Blizzard/LAUNDRY BEAR, though the underlying CVE (CVE-2025-66376) has also been separately reported exploited by a distinct actor (APT28/Forest Blizzard), so this hunt is written actor-agnostically — may be exploiting our Zimbra Collaboration Suite deployment (if any) via a zero-click, client-side stored-XSS chain to hijack authenticated webmail sessions and exfiltrate credentials, MFA scratch codes, and up to 90 days of email/search history, evidenced by (1) inbound email containing the SVG-onload/CSS-@import exploit pattern, (2) network egress to the actor's rotating C2 infrastructure or newly-registered lookalike domains, and (3) anomalous privileged ZimbraAccount SOAP API calls (notably `GetScratchCodesRequest`) firing without corresponding legitimate user action — in [mail-gateway/ZCS application logs, network egress/DNS logs, and ZCS audit logs — pending environment `gather`], which we will validate by querying up to 90 days of available telemetry within a 10-business-day execution window.

*(Decomposed into three independently-scored Stories below. This Epic assumes the organization runs Zimbra Collaboration Suite — if it does not, this Epic is not applicable and should be closed as Not Applicable rather than executed; confirm this as the very first action before any Story below.)*

### Triggering Event

- **Type:** CTI (Cyber Threat Intelligence) — also carries elements of **Vulnerability Disclosure**, since a specific, CISA KEV-listed, actively-exploited CVE with a fix already available underlies this hunt
- **Source:** `./threat-hunting/intel-reports/russian-webmail-espionage-report.md`, derived from Unit 42, "Russian Global Webmail Espionage" (2026-07-23) — https://unit42.paloaltonetworks.com/russian-webmail-espionage/ — and CISA Joint Advisory AA26-204A
- **Date Received:** 2026-09-06
- **Classification:** TLP:CLEAR (public vendor blog + public government advisory)
- **Relevance to Organization:** [FILL IN: confirm whether the organization runs Zimbra Collaboration Suite at all — this entire Epic is inapplicable if not.] If ZCS is in use: this is a CISA KEV-listed vulnerability under active, confirmed exploitation by a state-sponsored actor, with a patch available since November 2025 — any unpatched instance is a live, high-priority exposure independent of whether this specific hunt finds prior compromise.

### Initial Research Summary

**Internal Sources Reviewed:**
- [ ] Previous hunt reports: [FILL IN: none on file from this pipeline besides `HUNT-2026-001` (communication-channel-identity-risks), which is unrelated]
- [ ] Architecture documentation: [FILL IN: confirm ZCS deployment topology, version, and whether Classic UI or Modern UI is in use — the CSS `@import` sanitization flaw is reported specific to Classic UI]
- [ ] Detection coverage: [FILL IN: existing rules for webmail-XSS, C2 domain matching, or ZCS SOAP API monitoring, if any]
- [ ] Asset inventory: [FILL IN: number of ZCS instances/versions in use, patch status]

**External Sources Reviewed:**
- [x] MITRE ATT&CK: T1566.001/.002, T1203, T1190 (contested/secondary), T1059.007, T1027.017, T1027.013, T1539, T1555.003, T1556.006, T1082, T1119, T1185, T1114.002, T1041, T1048.002/.003, T1071.001, T1583.003 (full mapping and evidence in the analysis file)
- [x] Threat reports: Unit 42 (anchor), CISA AA26-204A, Microsoft (Void Blizzard origin disclosure), Proofpoint (TA488), SecurityWeek/Seqrite Labs (Operation GhostMail/APT28)
- [ ] Sigma rules: [FILL IN — hand off to `detection-engineer` for Stage 4; not authored here]
- [x] Threat actor profiles: CL-STA-1114/Void Blizzard/LAUNDRY BEAR (High confidence, same actor); Russian state-nexus (High confidence); FSB-specific link via 2026 Obrezko/Yutek-NN indictment (Moderate confidence, unadjudicated); TA488 equivalence (Reported, contested); APT28/Forest Blizzard as a separate actor also exploiting the same CVE (Moderate confidence)

**Key Findings from Research:**
1. This is a **patchable vulnerability** (ZCS 10.0.18/10.1.13, November 2025) that is **CISA KEV-listed** with confirmed active exploitation — unlike the prior `communication-channel-identity-risks` hunt, a Mitigate action (patching) exists here and should not be deprioritized relative to hunting for prior compromise.
2. The exploit is **client-side** (executes inside an already-authenticated browser session, ATT&CK T1203) rather than a server compromise (T1190) — this materially changes where telemetry should be sought: browser/session and ZCS application-layer logs, not server-exploitation indicators.
3. **CVE-2025-66376 has been exploited by more than one actor** (CL-STA-1114/Void Blizzard/LAUNDRY BEAR per CISA/Unit 42, and separately APT28/Forest Blizzard per SecurityWeek/Seqrite Labs) — hunts here are written to detect the technique/infrastructure pattern, not to assume a single actor's involvement if something is found.
4. The environment profile is entirely `Unknown` — this hunt plan cannot state real data-source names, and critically **cannot confirm whether the organization even runs Zimbra at all**. This is the single largest open question blocking this Epic (see Feasibility Assessment).

### Feasibility Assessment

| Criterion | Status | Notes |
|---|---|---|
| Data Availability | **CONDITIONAL** | SIEM/EDR/mail-gateway platform is `Unknown`, and — more fundamentally — whether Zimbra Collaboration Suite is even deployed in this environment is unconfirmed. If ZCS is not in use, this entire Epic should be closed as Not Applicable rather than pursued as CONDITIONAL. |
| Data Quality | **CONDITIONAL** | Cannot assess whether ZCS audit logging captures SOAP method names (required for Story 3), whether mail-gateway content inspection retains raw message HTML (required for Story 1), or DNS/egress log field completeness (required for Story 2), without confirming the platform. |
| Team Skillset | Unknown | [FILL IN: does the hunt team have experience with ZCS administration/log analysis specifically? This is a less commonly hunted platform than M365/Google Workspace.] |
| Timeline | GO (estimated) | Moderate complexity, 3 Stories → **3-5 days execution per Story once environment/ZCS-usage is confirmed**, ~10 business days total for the Epic. |
| Tooling | Unknown | [FILL IN: SIEM/EDR console access; ZCS admin console access; a passive-DNS/domain-registration enrichment source for Story 2] |

**OVERALL DECISION: CONDITIONAL**

**Mandatory caveat (per `telemetry-gap-assessment.md`):**
> Findings from this hunt plan are bounded by unconfirmed visibility into mail-gateway/ZCS content-inspection logs, network egress/DNS logs, and ZCS SOAP/application audit logs across the full in-scope asset population — and, more fundamentally, by unconfirmed deployment of Zimbra Collaboration Suite in this environment at all. A negative result from any Story does **not** establish absence of the hunted behavior outside whatever coverage is actually confirmed. **First confirm ZCS is in use; then run `gather` standalone and re-score this Feasibility Assessment before executing any Story.**

**Assumptions/Conditions:**
- Assumes the organization runs Zimbra Collaboration Suite. **If not, close this Epic as Not Applicable rather than executing any Story** — do not force-fit the hunt to an unrelated webmail platform.
- Assumes at least 90 days of log retention is achievable for mail-gateway, DNS/egress, and ZCS audit sources; if actual retention is shorter, reduce the analysis window accordingly.
- Assumes ZCS audit/application logging can be configured to capture SOAP method names if it does not already — this may itself require a configuration change before Story 3 is executable (see Story 3's own Visibility Gap risk).

### Scope

**Target Environment:**
- [ ] Production servers — specifically any hosting Zimbra Collaboration Suite
- [ ] Workstations/endpoints — users with Zimbra webmail access
- [ ] Cloud infrastructure (AWS/Azure/GCP) — [FILL IN if ZCS is self-hosted vs. cloud-hosted]
- [x] Network perimeter (egress/proxy/firewall, DNS — for Story 2)
- [ ] DMZ — [FILL IN if ZCS is internet-facing directly or behind a reverse proxy/mail gateway]
- [x] Mail gateway / email security layer (for Story 1)
- [ ] Other: [FILL IN]

**Time Window:** Last 90 days from hunt kickoff, or the maximum retained window if shorter ([X] days) — chosen to match the actor's own stated 90-day email/search-history exfiltration scope and to cover the full period since the Zimbra-specific campaign began (July 2025) if retention allows reaching that far back.

**In-Scope Assets:**
- Zimbra Collaboration Suite instance(s) — mail store and application/audit logs
- Mail gateway / email security product — content-inspection logs capturing raw message HTML
- Network egress points (firewall/proxy) and DNS resolver logs
- Identity/credential systems tied to Zimbra accounts (for post-compromise credential-rotation scoping, not primary hunt telemetry)

**Explicit Exclusions:**
- Any non-Zimbra webmail platform (Exchange/OWA, Google Workspace) — out of scope for this specific Epic, though the related Roundcube CVEs noted in the intel report suggest a similar hunt may be worth scoping separately for Roundcube if in use (flagged as a Hunt Opportunity, not executed here).
- The actor's separate, earlier AiTM/Evilginx campaign against Exchange Online/Graph (Microsoft, May 2025) — different infrastructure, different technique, out of scope for this Epic.

### Objectives

**Primary Objectives:**
1. Determine whether any inbound email exhibiting the CVE-2025-66376 SVG-onload/CSS-@import exploit pattern has reached a Zimbra user's mailbox within the analysis window (Story 1).
2. Determine whether any host or webmail session has communicated with the actor's published C2 infrastructure or a newly-registered, thematically-consistent lookalike domain (Story 2).
3. Determine whether any ZimbraAccount SOAP API call consistent with credential/MFA-scratch-code theft has fired without corresponding legitimate user action (Story 3).

**Secondary Objectives:**
1. Confirm current ZCS patch level across all instances, independent of hunt findings — this is a direct Mitigate action regardless of what the hunt finds.
2. Produce a passive-DNS/domain-registration enrichment capability (if not already available) as a byproduct of Story 2, reusable for future infrastructure-rotation-pattern hunts.

**Success Metrics:**
- [ ] ZCS deployment status confirmed (in use / not in use) before Story execution begins
- [ ] Hypothesis (each Story component) validated or invalidated with evidence
- [ ] All three Stories completed within the estimated timeline, or explicitly re-scoped/backlogged with reasons recorded
- [ ] Findings documented per outcome category
- [ ] Report delivered to stakeholders; any Analytics/Detection outcome handed off to `detection-engineer`; patch status escalated as a Security Control Issue if any instance is found unpatched

### MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic |
|---|---|---|
| T1566.001 / T1566.002 | Phishing: Spearphishing Attachment / Link | Initial Access |
| T1203 | Exploitation for Client Execution | Execution |
| T1190 *(contested/secondary — see analysis Open Questions)* | Exploit Public-Facing Application | Initial Access |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Execution |
| T1027.017 | Obfuscated Files or Information: SVG Smuggling | Defense Evasion |
| T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | Defense Evasion |
| T1539 | Steal Web Session Cookie | Credential Access |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Credential Access |
| T1556.006 | Modify Authentication Process: Multi-Factor Authentication | Credential Access |
| T1082 | System Information Discovery | Discovery |
| T1119 | Automated Collection | Collection |
| T1185 | Browser Session Hijacking | Collection |
| T1114.002 | Email Collection: Remote Email Collection | Collection |
| T1041 | Exfiltration Over C2 Channel | Exfiltration |
| T1048.002 / T1048.003 | Exfiltration Over Alternative Protocol (Non-C2 / DNS) | Exfiltration |
| T1071.001 | Application Layer Protocol: Web Protocols | Command and Control |
| T1583.003 | Acquire Infrastructure: Virtual Private Server | Resource Development |

### Data Sources Required

| Data Source | Platform | Key Fields | Retention |
|---|---|---|---|
| Mail-gateway content-inspection log (or ZCS mail-store log) | [FILL IN — pending `gather` and ZCS-usage confirmation] | raw message HTML/body, sender, SVG/CSS content markers, recipient | [FILL IN] |
| DNS query log | [FILL IN — pending `gather`] | client IP/host, queried domain, response, timestamp | [FILL IN] |
| Network egress / proxy / firewall log | [FILL IN — pending `gather`] | source host, destination IP/domain, port, protocol, timestamp | [FILL IN] |
| Domain registration / passive DNS enrichment | [FILL IN: e.g., WHOIS/RDAP lookup, a passive-DNS service — not yet confirmed available] | domain age, registrar, first-seen date | N/A (external enrichment, not a retained log) |
| ZCS application/SOAP audit log | [FILL IN — pending `gather`; also pending confirmation that SOAP method names are captured at all] | account, SOAP method name (e.g., `GetScratchCodesRequest`), timestamp, source IP/session | [FILL IN] |
| Identity/credential system (for scoping remediation, not primary hunt telemetry) | [FILL IN] | account, last password/MFA change | [FILL IN] |

### References

- `./threat-hunting/intel-reports/russian-webmail-espionage-report.md`
- `./threat-hunting/intel-analysis/russian-webmail-espionage-analysis.md`
- Unit 42 — "Russian Global Webmail Espionage" — https://unit42.paloaltonetworks.com/russian-webmail-espionage/
- CISA Joint Advisory AA26-204A — https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-204a
- CISA KEV Catalog — CVE-2025-66376 — https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2025-66376
- Microsoft Security Blog — Void Blizzard (2025-05-27) — https://www.microsoft.com/en-us/security/blog/2025/05/27/new-russia-affiliated-actor-void-blizzard-targets-critical-sectors-for-espionage/
- Proofpoint — TA488 — https://www.proofpoint.com/us/blog/threat-insight/ta488-targets-zimbra-mailservers-half-click-exploits
- MITRE ATT&CK Enterprise — https://attack.mitre.org/

### Linked Stories

- [HUNT-2026-002-S1] Inbound SVG-Onload/CSS-@import Exploit Email Detection (CVE-2025-66376)
- [HUNT-2026-002-S2] C2 Infrastructure and Lookalike-Domain Egress Detection
- [HUNT-2026-002-S3] Anomalous ZimbraAccount SOAP API Calls (MFA Scratch-Code Theft)

---

## Story: [HUNT-2026-002-S1] Inbound SVG-Onload/CSS-@import Exploit Email Detection (CVE-2025-66376)

### Parent Epic
HUNT-2026-002

### Objective
Determine whether any inbound email matching the CVE-2025-66376 exploit pattern (an SVG element with a populated `onload` attribute, and/or a CSS `@import` directive used to smuggle the exploit past sanitization) has reached a Zimbra user's mailbox within the analysis window.

### Hypothesis Component

**Hypothesis (SMART):** We hypothesize that adversaries may be delivering CVE-2025-66376 exploit emails containing SVG elements with populated `onload` attributes or CSS `@import` directives to Zimbra Collaboration Suite users, evidenced by mail-gateway content-inspection logs (or ZCS mail-store logs, if gateway inspection of raw HTML is unavailable) capturing messages matching these patterns, which we can validate by querying up to 90 days of that telemetry, within a 5-day execution window.

```
ID:                 HUNT-2026-002-S1
ABLE decomposition
  Actor:            CL-STA-1114/Void Blizzard/LAUNDRY BEAR-informed, but actor-agnostic — the same
                    CVE has also been reported exploited by APT28/Forest Blizzard
  Behavior:         Delivery of a crafted HTML/SVG email exploiting CVE-2025-66376's CSS @import
                    sanitization bypass, targeting Zimbra Classic UI
  Location:         Mail gateway / ZCS mail store, inbound mail flow
  Evidence:         Raw message HTML matching an SVG element with a populated onload attribute
                    and/or a CSS @import directive; sender reputation/novelty as secondary enrichment

ATT&CK:             T1566.001/.002 (Phishing) / T1203 (Exploitation for Client Execution) /
                    T1027.017 (SVG Smuggling) / T1027.013 (Encoded Payload)
Pyramid level:      Tool/TTP — this is the exploit's core delivery mechanism, not a swappable
                    incidental detail; an adversary using this specific CVE cannot avoid this HTML
                    structure without changing the exploit entirely
Data components:    Application Log: Application Log Content (mail-gateway content inspection or
                    ZCS mail-store log)
Expected malicious: A message containing an SVG element with a non-empty onload attribute, or a
                    CSS @import referencing an external/unusual domain, from an external or
                    unverified sender, addressed to a ZCS Classic UI user
Expected benign:    Legitimate marketing/newsletter HTML email using SVG purely for static image
                    rendering (no onload) or using standard, well-known CSS delivery (no @import to
                    an unusual domain)
Disprovable:        Y — zero matching messages across the full analysis window
Priority:           High — this is the delivery mechanism for a CISA KEV-listed, actively
                    exploited vulnerability with a confirmed impact chain
```

**Rubric score:** Specificity 3 · Testability 2 (query path defined; depends on whether mail-gateway/ZCS logging retains raw HTML body content, which is unconfirmed) · Falsifiability 3 · Relevance 3 · Pyramid 3 = **14 → GO** (no dimension at 1)

### Methodology

**Phase 1: Data Collection**
1. Confirm whether a mail-gateway/email-security product performs content inspection and retains raw message HTML, or whether this must instead be sourced from ZCS's own mail-store logs.
2. Export inbound message records for the analysis window, filtered to messages containing an `<svg>` tag with a non-empty `onload` attribute, or a `@import` CSS directive.
3. Enrich matches with sender domain reputation/novelty (first-seen-in-tenant) and recipient's ZCS UI mode (Classic vs. Modern), since the flaw is reported specific to Classic UI.

**Phase 2: Analysis**
1. Triage matches for known-legitimate senders (newsletter/marketing platforms) vs. unknown/external senders.
2. Cross-reference sender domains and any embedded links against the published C2 domain list (Story 2's indicator set) for a quick-win correlation.
3. Rank by recipient risk (privileged accounts, government/defense-relevant roles) if role data is available.

**Phase 3: Validation**
1. For high-risk matches, retrieve the full message and manually confirm the exploit pattern (obfuscated Base64/XOR-encoded payload inside the SVG/CSS) rather than a benign false-positive structure.
2. For any confirmed match, determine whether the recipient's ZCS session showed any follow-on anomalous activity (cross-reference with Story 3).
3. Document true/false positive determination.

### Data Sources

| Source | Fields Required | Query Location |
|---|---|---|
| Mail-gateway content-inspection log or ZCS mail-store log | timestamp, sender, recipient, raw HTML body, SVG/CSS markers | [FILL IN — pending `gather`] |

### Detection Logic

Primary Query (pseudocode — adapt to actual mail-gateway/SIEM syntax once confirmed via `gather`):
```
inbound_mail_events
| where message.body contains "<svg" and message.body matches /onload\s*=\s*["'][^"']+["']/
    or message.body matches /@import/
| where sender.is_external == true or sender.reputation == "unknown"
| project timestamp, sender, recipient, matched_pattern, message_id
```

Sigma Rule (structural placeholder — hand off to `detection-engineer` for a production rule):
```yaml
title: Inbound Email Matching CVE-2025-66376 SVG-Onload/CSS-Import Exploit Pattern
status: experimental
description: Detects an inbound email containing an SVG element with a populated onload attribute or a CSS @import directive, consistent with the CVE-2025-66376 Zimbra exploit chain.
logsource:
    category: [FILL IN — mail gateway / application]
detection:
    selection:
        message.body|re: '<svg[^>]*onload\s*=\s*["\'][^"\']+["\']'
    selection_alt:
        message.body|contains: '@import'
    condition: selection or selection_alt
falsepositives:
    - Legitimate HTML newsletters/marketing email using SVG for static rendering without onload execution
level: high
tags:
    - attack.initial_access
    - attack.execution
    - attack.t1203
    - attack.t1027.017
```

### Expected Outcomes

**If Malicious Activity Present:**
- A message matching the exploit pattern from an external/unverified sender is confirmed via manual review of the decoded payload
- Escalate to IR per incident response plan; treat the recipient's account as potentially compromised regardless of whether they "clicked" anything, given the zero-click nature of this exploit

**If Hypothesis Invalid:**
- No qualifying messages found in the window, or all matches trace to legitimate, verified newsletter/marketing senders with no onload execution
- Document as negative finding, close Story — but still recommend patching per the Epic's Mitigate action regardless of this Story's outcome

### Acceptance Criteria
- [ ] ZCS deployment and UI mode (Classic/Modern) confirmed
- [ ] Data sources validated and accessible (pending `gather`)
- [ ] Queries executed across full time window
- [ ] Results triaged (true/false positive determination)
- [ ] Findings documented with evidence
- [ ] Tasks created for outcomes

### Linked Tasks (Outcomes)
- [HUNT-2026-002-S1-T1] Security Control Issue: ZCS patch status (see below)
- [HUNT-2026-002-S1-T2] Analytics/Detection: hand off to `detection-engineer` if validated

---

## Story: [HUNT-2026-002-S2] C2 Infrastructure and Lookalike-Domain Egress Detection

### Parent Epic
HUNT-2026-002

### Objective
Determine whether any host or webmail session has communicated with the actor's published C2 infrastructure, or with a newly-registered domain matching the actor's observed naming/registration pattern (short-lived infrastructure, average ~35-day lifetime, thematically branded around "email analytics"/"Zimbra" terminology).

### Hypothesis Component

**Hypothesis (SMART):** We hypothesize that a compromised Zimbra webmail session or host may be communicating with newly-registered, thematically-consistent C2 domains characteristic of CL-STA-1114/Void Blizzard's infrastructure pattern (e.g., containing "zimbra," "mail," "analytics," or similar collaboration/analytics-branded terms) — in addition to the nine specific published indicators — evidenced by DNS query logs and proxy/firewall egress logs showing connections from ZCS-related network segments to domains registered within the last 60 days matching this naming pattern, which we can validate by querying up to 90 days of DNS/egress logs plus a domain-age/registration enrichment lookup, within a 5-day execution window.

```
ID:                 HUNT-2026-002-S2
ABLE decomposition
  Actor:            CL-STA-1114/Void Blizzard/LAUNDRY BEAR — actor-agnostic in execution given the
                    multi-actor CVE exploitation noted in the intel
  Behavior:         A host/session communicates with a short-lived, thematically-branded C2 domain
                    consistent with the actor's observed infrastructure-acquisition pattern (T1583.003),
                    not merely a static published indicator
  Location:         Network egress / DNS, ZCS-hosting network segment
  Evidence:         DNS/egress log entries to a domain <60 days old, matching a webmail-analytics
                    naming theme, from a ZCS-related host, absent from any legitimate-vendor allowlist;
                    the nine published indicators are used as a seed/training set and checked directly
                    as a fast first-pass, not as the sole detection basis

ATT&CK:             T1583.003 (Acquire Infrastructure: VPS) / T1071.001 (Web Protocols) /
                    T1041 (Exfiltration Over C2 Channel) / T1048.002 & .003 (Exfil over
                    non-C2/DNS protocol)
Pyramid level:      TTP — anchored on the actor's infrastructure-acquisition *pattern* (thematic
                    naming + short registration age) rather than only the nine specific,
                    already-rotating domains, per the rubric's guidance to re-anchor above
                    hash/IP/domain-only matching
Data components:    Network Traffic: Network Traffic Content (DNS, proxy/firewall);
                    domain registration/passive-DNS enrichment
Expected malicious: Connection to a domain younger than ~60 days, matching the naming theme, from a
                    ZCS-related host, with no legitimate business justification and not on any
                    approved-vendor allowlist
Expected benign:    Connection to an established, legitimate email-analytics/mail-hygiene SaaS
                    vendor already on an allowlist, or a domain with normal registration age and
                    no thematic overlap
Disprovable:        Y — no qualifying connections in the window, and all nine published indicators
                    show zero hits
Priority:           High — this is the actor's confirmed exfiltration channel; a hit here means
                    data has already left the environment
```

**Rubric score:** Specificity 3 · Testability 2 (query path defined; requires a domain-age/registration enrichment source not yet confirmed available) · Falsifiability 3 · Relevance 3 · Pyramid 3 = **14 → GO** (no dimension at 1)

### Methodology

**Phase 1: Data Collection**
1. Run a fast, direct first-pass match of DNS/egress logs against the nine published C2 IPs/domains from the intel report (quick win, acknowledging this decays as the actor rotates infrastructure).
2. Identify a domain-age/registration enrichment source (WHOIS/RDAP bulk lookup, a passive-DNS service, or an existing threat-intel platform capability) if one is not already available.
3. Export DNS/egress logs for the analysis window, filtered to destinations from ZCS-hosting network segments (or, if segment-level filtering isn't feasible, tenant-wide).

**Phase 2: Analysis**
1. Enrich all unique destination domains with registration age.
2. Flag domains younger than ~60 days whose name contains any of: "zimbra," "mail," "email," "analytic," "webmail," "collab," or close variants/typosquats of legitimate mail-hygiene vendors.
3. Cross-reference flagged domains against Story 1's sender-domain findings for a corroborating signal.

**Phase 3: Validation**
1. For each flagged domain, confirm it is not an approved, inventoried vendor (e.g., a legitimate email-analytics SaaS product).
2. For non-legitimate flagged domains, pull full connection history (volume, timing, destination paths) to assess for exfiltration-consistent patterns (e.g., periodic beaconing, large outbound transfers).
3. Document true/false positive determination.

### Data Sources

| Source | Fields Required | Query Location |
|---|---|---|
| DNS query log | client host, queried domain, timestamp | [FILL IN — pending `gather`] |
| Network egress / proxy / firewall log | source host, destination IP/domain, port, protocol, bytes transferred, timestamp | [FILL IN — pending `gather`] |
| Domain registration / passive DNS enrichment | domain, registration date, registrar | [FILL IN: external enrichment source — not yet confirmed available] |

### Detection Logic

Primary Query (pseudocode — adapt to actual SIEM syntax once confirmed):
```
dns_and_egress_events
| where destination_domain in (known_c2_list)  // fast first-pass, nine published indicators
    or (destination_domain matches /zimbra|mail|email|analytic|webmail|collab/i
        and domain_age(destination_domain) < 60d
        and destination_domain not in (approved_vendor_allowlist))
| project timestamp, source_host, destination_domain, domain_age, bytes_transferred
```

Sigma Rule (structural placeholder — hand off to `detection-engineer` for a production rule):
```yaml
title: Egress to Zimbra-Espionage C2 Infrastructure or Thematic Lookalike Domain
status: experimental
description: Detects DNS/egress traffic to CL-STA-1114/Void Blizzard published C2 infrastructure, or to a newly-registered domain matching the actor's observed naming pattern.
logsource:
    category: dns
detection:
    selection_known:
        dst_domain:
            - 'analyticemailmeter.com'
            - 'emailanalytics.com.ua'
            - 'istc-cloud.com'
            - 'mailnalysis.com'
            - 'synacorzimbra.nl'
            - 'zimbra-metadata.com'
            - 'zimbrastat.com'
            - 'zimbrasoft.com.ua'
            - 'zmailanalytics.com'
    condition: selection_known
falsepositives:
    - None expected for the known-indicator selection (static match); the lookalike-pattern
      enrichment (domain age + naming theme) requires separate tuning and is not expressible
      in this static Sigma selection alone — see Methodology Phase 2 for that logic
level: critical
tags:
    - attack.command_and_control
    - attack.exfiltration
    - attack.t1071.001
    - attack.t1041
    - attack.t1583.003
```

### Expected Outcomes

**If Malicious Activity Present:**
- A ZCS-related host/session communicates with a known indicator or a young, thematically-matching, non-allowlisted domain, with connection patterns consistent with data exfiltration
- Escalate to IR per incident response plan; treat as an active, in-progress exfiltration event given the actor's documented behavior

**If Hypothesis Invalid:**
- No connections to known indicators, and no qualifying young/thematic domains found
- Document as negative finding, close Story

### Acceptance Criteria
- [ ] A domain-age/registration enrichment capability is confirmed available (or built) before Phase 2
- [ ] Data sources validated and accessible (pending `gather`)
- [ ] Queries executed across full time window
- [ ] Results triaged (true/false positive determination)
- [ ] Findings documented with evidence
- [ ] Tasks created for outcomes

### Linked Tasks (Outcomes)
- [HUNT-2026-002-S2-T1] Hunt Opportunity: standing infrastructure-rotation-pattern hunt (see below)
- [HUNT-2026-002-S2-T2] Analytics/Detection: hand off to `detection-engineer` if validated

---

## Story: [HUNT-2026-002-S3] Anomalous ZimbraAccount SOAP API Calls (MFA Scratch-Code Theft)

### Parent Epic
HUNT-2026-002

### Objective
Determine whether any account shows a `GetScratchCodesRequest` (or similarly privileged, bulk-collection) ZimbraAccount SOAP API call firing without corresponding legitimate user-driven UI action — the specific, documented MFA-bypass mechanism in this campaign.

### Hypothesis Component

**Hypothesis (SMART):** We hypothesize that an adversary may be abusing a hijacked, already-authenticated Zimbra webmail browser session to invoke privileged ZimbraAccount SOAP API methods (specifically `GetScratchCodesRequest`, or a bulk mail-search/export call covering up to 90 days of history) shortly after a user opens a new email, evidenced by ZCS SOAP/application audit logs showing these API calls without a corresponding, expected user-driven UI action, which we can validate by querying up to 90 days of ZCS audit logs (if SOAP method names are captured) correlated with mail-open events, within a 5-day execution window.

```
ID:                 HUNT-2026-002-S3
ABLE decomposition
  Actor:            CL-STA-1114/Void Blizzard/LAUNDRY BEAR-informed, actor-agnostic
  Behavior:         A privileged ZimbraAccount SOAP call (GetScratchCodesRequest, or a bulk
                    email-search/export call) fires without a corresponding legitimate user UI
                    interaction, in temporal proximity to a mail-open event
  Location:         ZCS application/audit log layer
  Evidence:         SOAP method name in ZCS audit log, timestamp correlation with a mail-open
                    event, absence of the expected human-driven UI navigation sequence that would
                    normally precede such a call
ATT&CK:             T1556.006 (MFA) / T1539 (Session Cookie) / T1555.003 (Browser Credentials) /
                    T1185 (Browser Session Hijacking) / T1119 (Automated Collection) /
                    T1114.002 (Remote Email Collection)
Pyramid level:      TTP — this is the single most specific, most invariant observable in the
                    entire chain: the adversary's objective (MFA-bypass via scratch-code theft)
                    cannot be achieved without this exact API call, regardless of how the
                    upstream delivery/injection mechanism varies
Data components:    Application Log: Application Log Content (ZCS SOAP/audit log)
Expected malicious: GetScratchCodesRequest (or a bulk email-search/export call retrieving a large,
                    unusual volume of historical mail) firing within seconds of a message-open
                    event, for an account with no legitimate, user-initiated reason to
                    programmatically pull scratch codes at that moment
Expected benign:    A legitimate, user-initiated 2FA-scratch-code regeneration performed through
                    the normal account-settings UI flow (with the expected preceding UI-navigation
                    events present in the log), or normal ad hoc search activity spread out over
                    time rather than an immediate bulk pull
Disprovable:        Y — no qualifying SOAP call pattern found across the full analysis window
Priority:           High — the single most severe and specific observable in the attack chain;
                    a confirmed hit represents active MFA compromise
```

**Rubric score:** Specificity 3 · Testability 2 (entirely contingent on whether ZCS audit logging captures SOAP method names at all — unconfirmed, and may require a logging configuration change before this Story is executable) · Falsifiability 3 · Relevance 3 · Pyramid 3 = **14 → GO** (no dimension at 1)

### Methodology

**Phase 1: Data Collection**
1. **Confirm ZCS audit/application logging actually captures SOAP method names** — this is a prerequisite check, not an assumption; if it does not, this Story cannot proceed as written and should instead produce a Visibility Gap outcome recommending a logging configuration change.
2. If confirmed, export ZimbraAccount SOAP audit events for the analysis window, filtered to `GetScratchCodesRequest` and any bulk mail-search/export method calls.
3. Export corresponding UI-navigation/session events for the same accounts and window, to establish what a "normal" preceding sequence looks like.

**Phase 2: Analysis**
1. For each `GetScratchCodesRequest` (or bulk-export) event, check for the expected preceding UI-navigation sequence (e.g., a user navigating to Account Settings before a legitimate scratch-code regeneration).
2. Flag events with no such preceding sequence, or where the call fires within seconds of a message-open event.
3. Cross-reference flagged accounts/sessions against Story 1 (did this account receive a matching exploit email?) and Story 2 (did this session's host communicate with known/lookalike C2?) for corroboration.

**Phase 3: Validation**
1. For each flagged account, interview the user (out-of-band) to confirm whether they recall requesting new scratch codes at that time.
2. If not confirmed by the user, treat as a credential/MFA-compromise incident.
3. Document true/false positive determination.

### Data Sources

| Source | Fields Required | Query Location |
|---|---|---|
| ZCS application/SOAP audit log | account, SOAP method name, timestamp, source IP/session ID | [FILL IN — pending `gather` and a logging-capability confirmation] |
| ZCS UI-navigation/session event log (if separately available) | account, page/action navigated, timestamp | [FILL IN — pending `gather`] |

### Detection Logic

Primary Query (pseudocode — adapt to actual SIEM/ZCS-log syntax once confirmed):
```
zcs_soap_events
| where soap_method == "GetScratchCodesRequest" or soap_method in (bulk_export_methods)
| join kind=leftouter (
    zcs_ui_events | where action == "navigate_account_settings"
  ) on $left.account == $right.account
| where isnull(zcs_ui_events.timestamp)
    or zcs_ui_events.timestamp > soap_events.timestamp - 2m  // no preceding nav within 2 min
```

Sigma Rule (structural placeholder — hand off to `detection-engineer` for a production rule):
```yaml
title: ZimbraAccount GetScratchCodesRequest Without Preceding User Navigation
status: experimental
description: Detects a ZimbraAccount SOAP GetScratchCodesRequest (MFA scratch-code retrieval) firing without a corresponding, expected preceding user-navigation event — consistent with session-hijacking-driven MFA bypass.
logsource:
    category: application
    product: [FILL IN — zimbra]
detection:
    selection:
        soap_method: 'GetScratchCodesRequest'
    filter_expected_nav:
        preceding_navigation: 'account_settings'
        preceding_navigation_window: '<= 2m'
    condition: selection and not filter_expected_nav
falsepositives:
    - A legitimate user regenerating scratch codes through an unusual but authorized workflow (e.g., an admin-assisted reset) not captured by the navigation-event filter
level: critical
tags:
    - attack.credential_access
    - attack.t1556.006
    - attack.t1185
```

### Expected Outcomes

**If Malicious Activity Present:**
- A `GetScratchCodesRequest` (or bulk-export call) fires with no legitimate preceding navigation, for an account also implicated by Story 1 (received the exploit email) and/or Story 2 (host contacted known/lookalike C2)
- Escalate to IR per incident response plan as a confirmed credential/MFA-compromise incident; force-rotate credentials and reissue scratch codes for the affected account immediately

**If Hypothesis Invalid:**
- No qualifying SOAP call pattern found, or all matches trace to confirmed, user-acknowledged legitimate scratch-code regenerations
- Document as negative finding, close Story

### Acceptance Criteria
- [ ] ZCS SOAP-method-name logging capability confirmed present (or a configuration change made to enable it) before proceeding
- [ ] Data sources validated and accessible (pending `gather`)
- [ ] Queries executed across full time window
- [ ] Results triaged (true/false positive determination)
- [ ] Findings documented with evidence
- [ ] Tasks created for outcomes

### Linked Tasks (Outcomes)
- [HUNT-2026-002-S3-T1] Visibility Gap: ZCS SOAP-method-name logging unconfirmed (see below)
- [HUNT-2026-002-S3-T2] Analytics/Detection: hand off to `detection-engineer` if validated

---

## Task: [HUNT-2026-002-S1-T1] Security Control Issue: ZCS Patch Status

### Parent Story
HUNT-2026-002-S1 (applies to the Epic as a whole)

### Outcome Category
Security Control Issue

### Description
Independent of whatever this hunt finds regarding prior exploitation, CVE-2025-66376 is a CISA KEV-listed, actively-exploited vulnerability with a fix available since November 2025. If any in-scope ZCS instance is running a version prior to 10.0.18/10.1.13, that is itself a critical, standing control gap that should be remediated immediately regardless of hunt outcome.

### Evidence
[FILL IN once the Epic's Secondary Objective 1 (confirm ZCS patch level across all instances) is executed]

### Risk Assessment
- Threat Scenario: An unpatched ZCS instance remains exploitable by any actor using this now-public technique (not just CL-STA-1114 — recall the CVE has been separately exploited by APT28/Forest Blizzard too).
- Likelihood: High (per CISA KEV listing, active exploitation is confirmed industry-wide)
- Impact: High (full mailbox compromise, MFA bypass, 90 days of email/search history exposure)
- Risk Rating: Critical if any instance is confirmed unpatched

### Recommended Remediation
**Immediate Actions:** Confirm ZCS version across all instances; patch to 10.0.18/10.1.13 or later immediately if any instance is below that version.
**Compensating Controls (if patching is delayed):** Restrict/disable Classic UI if the flaw is confirmed specific to it; block the published C2 indicators at the network layer as an interim measure.

### Owner Assignment
- Control Owner: [FILL IN]
- Remediation Owner: [FILL IN]
- Target Date: [FILL IN — should be immediate/urgent given KEV status]
- Tracking Ticket: [FILL IN]

---

## Task: [HUNT-2026-002-S1-T2] Analytics/Detection: Exploit Email Pattern Match

### Parent Story
HUNT-2026-002-S1

### Outcome Category
Analytics/Detection

### Description
If Story 1 validates the hypothesis, the SVG-onload/CSS-@import pattern match is a strong, technique-invariant standing-detection candidate (this observable is core to the exploit mechanism itself, not swappable).

### Detection Artifact
Type: Mail-gateway/SIEM correlation rule (structural placeholder — see Story 1's Sigma placeholder)

### Recommended Action
- [ ] Submit to detection engineering pipeline via the `detection-engineer` skill (Stage 4)
- [ ] Assign to: [FILL IN]
- [ ] Target deployment: [FILL IN]

---

## Task: [HUNT-2026-002-S2-T1] Hunt Opportunity: Standing Infrastructure-Rotation-Pattern Hunt

### Parent Story
HUNT-2026-002-S2

### Outcome Category
Hunt Opportunity

### Description
Story 2's core insight — hunting the actor's infrastructure-acquisition *pattern* (thematic naming + short registration age) rather than only a static, decaying indicator list — generalizes beyond this specific campaign. This is worth formalizing as a recurring, scheduled hunt/detection independent of this Epic.

### Proposed Hypothesis
We hypothesize that any actor using short-lived, thematically-branded C2 infrastructure (average lifetime <60 days) targeting our organization's collaboration/webmail platforms can be surfaced by a recurring hunt correlating newly-registered domain age against a maintained list of platform-relevant naming themes, evidenced by DNS/egress logs enriched with domain-registration data, validated by a monthly scheduled query.

### Relevance Assessment
- Threat Likelihood: Medium-High (this specific actor has already demonstrated this pattern; other actors targeting webmail platforms plausibly do too)
- Business Impact: High
- Detection Gap: Yes — no evidence a standing capability like this exists yet

### Recommended Priority
**Priority:** P2 — valuable independent of whether Story 2 finds active compromise in this specific hunt
**Recommended Sprint:** Backlog, pending environment `gather` and confirmation of an enrichment data source

### Owner Assignment
- Backlog Owner: [FILL IN: hunt team lead]
- Tracking Ticket: [FILL IN]

---

## Task: [HUNT-2026-002-S2-T2] Analytics/Detection: C2 Infrastructure Match

### Parent Story
HUNT-2026-002-S2

### Outcome Category
Analytics/Detection

### Description
The static known-indicator match (Sigma selection in Story 2) is a quick-win, low-effort standing detection to deploy immediately, even while it decays with the actor's ~35-day infrastructure rotation; the lookalike-pattern logic (Phase 2) is a separate, higher-value detection to develop alongside the Hunt Opportunity above.

### Detection Artifact
Type: SIEM/DNS correlation rule (structural placeholder — see Story 2's Sigma placeholder)

### Recommended Action
- [ ] Submit to detection engineering pipeline via the `detection-engineer` skill (Stage 4)
- [ ] Assign to: [FILL IN]
- [ ] Target deployment: Immediate for the static-indicator selection; near-term for the lookalike-pattern logic

---

## Task: [HUNT-2026-002-S3-T1] Visibility Gap: ZCS SOAP-Method-Name Logging Unconfirmed

### Parent Story
HUNT-2026-002-S3

### Outcome Category
Visibility Gap

### Description
Story 3's entire methodology depends on ZCS audit/application logging capturing SOAP method names (e.g., `GetScratchCodesRequest`) at a queryable granularity. This has not been confirmed and may not be enabled by default.

### Impact Assessment
**Hunt Impact:** If this logging is not captured, Story 3 cannot execute as written and the single most specific, most severe observable in the entire attack chain (MFA scratch-code theft) becomes undetectable after the fact.
**Detection Impact:** T1556.006 cannot be detected via this mechanism without this logging.
**MITRE Coverage Impact:**
| Technique ID | Technique Name | Detection Capability |
|---|---|---|
| T1556.006 | Modify Authentication Process: MFA | UNCONFIRMED — pending logging-capability confirmation |
| T1539, T1185, T1119, T1114.002 | Credential/session/collection techniques dependent on the same log source | UNCONFIRMED |

### Remediation Recommendation
**Technical Solution:** Confirm ZCS's audit-logging configuration options; enable SOAP-method-name capture if it exists but is not currently enabled.
**Effort Estimate:** Low-Medium (a configuration change, if supported; potentially Medium-High if the current ZCS version/edition does not support this granularity at all, which would itself be a more significant gap)
**Priority:** P1 — blocks the single most severe detection in this Epic

### Owner Assignment
- Remediation Owner: [FILL IN: ZCS administrator/platform team]
- Target Date: [FILL IN]
- Tracking Ticket: [FILL IN]

---

## Task: [HUNT-2026-002-S3-T2] Analytics/Detection: Anomalous Scratch-Code Retrieval

### Parent Story
HUNT-2026-002-S3

### Outcome Category
Analytics/Detection

### Description
If Story 3 validates the hypothesis (and the prerequisite logging gap above is closed), this is the single highest-priority detection in this Epic — it is the most technique-invariant, highest-severity observable available.

### Detection Artifact
Type: ZCS/SIEM correlation rule (structural placeholder — see Story 3's Sigma placeholder)

### Recommended Action
- [ ] Submit to detection engineering pipeline via the `detection-engineer` skill (Stage 4)
- [ ] Assign to: [FILL IN]
- [ ] Target deployment: [FILL IN — high priority once the Visibility Gap above is closed]
