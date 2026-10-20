# Hunt Plan: apt29-past-year

## Environment Profile

| Context | Value |
|---------|-------|
| SIEM / Data Platform | Unknown |
| EDR Platform | Unknown |
| Environment Type | Unknown |
| Industry Vertical | Unknown |
| Approximate Log Retention | Unknown |
| Hunt Maturity Level | Unknown |

> ⚠️ **Environment context is entirely unpopulated.** `./threat-hunting/environment-profile.md` has no recorded SIEM/EDR platform, environment type, industry vertical, retention, or maturity level. Every query, field name, and feasibility judgment below is written generically/pseudocode-style and marked `[FILL IN: ...]` where a real platform choice would change it. **Run the `gather` skill standalone before this plan is executed** — feasibility below is provisional, not a real GO decision.

Domain selection per `references/domain-telemetry-matrix.md`: this hunt spans three domains — **Identity (cloud IdP)** (Story 1), **Endpoint** (Story 2), and **Network/edge** (Story 3) — reflecting the intel report's finding that APT29's past-year tradecraft is identity- and infrastructure-centric rather than concentrated in one telemetry domain.

---

## Epic: [HUNT-2026-029] APT29 / Midnight Blizzard — Cloud-Identity Abuse & CaptiveCrunch Campaign Hunt

```
================================================================================
EPIC: [HUNT-2026-029] APT29 / Midnight Blizzard — Cloud-Identity Abuse & CaptiveCrunch Campaign Hunt
================================================================================

LABELS: threat-hunt, threat-informed (TIO), high-priority
COMPONENTS: Threat Hunting
SPRINT: [FILL IN: Sprint Name/Number]
STORY POINTS: [FILL IN: Total estimated points — see per-Story estimates below]

--------------------------------------------------------------------------------
HYPOTHESIS
--------------------------------------------------------------------------------
We hypothesize that APT29/Midnight Blizzard-linked actors (including the moderate-
confidence sub-clusters UNC6293, UNC7005/Storm-2945, and the CaptiveCrunch
operators) may have established initial access, credential access, or persistence
in our environment over the past 12 months via cloud-identity abuse and/or
CaptiveCrunch-related tooling, evidenced by anomalous OAuth device-code or
application-specific-password (ASP) authentication events, CornFlake/ChocoShell
endpoint artifacts, or network connections to known CaptiveCrunch C2
infrastructure, in Entra ID sign-in/audit logs, EDR endpoint telemetry, and
DNS/proxy logs. We will validate this by executing three targeted sub-hunts
(device-code/ASP anomaly detection, endpoint malware-artifact hunting, and C2
infrastructure correlation) across a 90-day lookback, within a 10-business-day
execution window (2026-09-08 to 2026-09-19).

--------------------------------------------------------------------------------
TRIGGERING EVENT
--------------------------------------------------------------------------------
Type:           CTI
Source:         ./threat-hunting/intel-reports/apt29-past-year-report.md (this pipeline's own intel-report output)
Date Received:  2026-09-07
Classification: TLP:CLEAR (all sourcing is open-source vendor/government reporting)

Relevance to Organization:
APT29/Midnight Blizzard is a persistently active, SVR-attributed espionage actor
targeting government, diplomatic, defense, NGO, think-tank, and cloud/tech-sector
organizations. Its past-year tradecraft (OAuth device-code phishing, ASP abuse,
CaptiveCrunch hotel/venue Wi-Fi hijacking) is not vertical-specific — any
organization with traveling staff, M365/Entra ID tenancy, or diplomatic/policy-
adjacent work is plausibly in scope. [FILL IN: state explicitly whether this
organization's industry vertical/executive travel profile increases or decreases
relevance once environment-profile.md's Industry Vertical field is populated.]

--------------------------------------------------------------------------------
INITIAL RESEARCH SUMMARY
--------------------------------------------------------------------------------
Internal Sources Reviewed:
- [ ] Previous hunt reports: None on record — this is the first hunt against this actor in this pipeline instance
- [ ] Architecture documentation: [FILL IN — not available to this pipeline run]
- [ ] Detection coverage: [FILL IN — no existing detection-coverage map supplied]
- [ ] Asset inventory: [FILL IN — crown-jewel/traveler-population inventory not supplied]

External Sources Reviewed:
- [x] MITRE ATT&CK: G0016 (APT29) — full technique set cross-referenced in intel-analysis
- [x] Threat reports: Microsoft MSTIC (CaptiveCrunch, Storm-2372, Teams vishing), Google GTIG (ICE RELIC/UNC6293/UNC7005/UNC5976), CISA AA24-057A, AWS Security Blog, Volexity, Trend Micro, Check Point Research (flagged unverified)
- [x] Sigma rules: none found publicly published for CaptiveCrunch or GRAPELOADER/WINELOADER as of this analysis — detection-engineer stage will need to author from behavioral evidence
- [x] Threat actor profiles: full actor profile in ./threat-hunting/intel-analysis/apt29-past-year-analysis.md

Key Findings from Research:
1. APT29's past-year initial access is overwhelmingly cloud-identity/OAuth-abuse and phishing-driven, not CVE-driven (no confirmed CVE exploitation attributed to APT29 in the past 12 months).
2. The CaptiveCrunch campaign (Storm-2945/UNC7005, disclosed Jul 2026) hijacked hotel/venue captive-portal Wi-Fi worldwide to deliver CornFlake (Go RAT) and ChocoShell (PowerShell infostealer) with documented, distinctive service-masquerade and AMSI-bypass behaviors.
3. Sub-cluster attribution to APT29/SVR proper is moderate confidence, not certain — UNC5976 in particular may belong to a different Russian intelligence service. Findings should be reported as "APT29/Midnight-Blizzard-adjacent," not asserted as definitive APT29 activity, unless corroborated.

--------------------------------------------------------------------------------
FEASIBILITY ASSESSMENT
--------------------------------------------------------------------------------
| Criterion        | Status        | Notes                                                                                                    |
|-------------------|--------------|----------------------------------------------------------------------------------------------------------|
| Data Availability | CONDITIONAL  | Cannot be scored — SIEM/EDR platform and log retention are `Unknown` in environment-profile.md. Assumed available pending confirmation: Entra ID sign-in/audit logs, EDR process/service/PowerShell telemetry, DNS/proxy logs. |
| Data Quality      | CONDITIONAL  | Unscored for the same reason. [FILL IN once gather is run: field completeness for device-code grant type, PowerShell script-block logging (Event ID 4104 or EDR equivalent) enabled.] |
| Team Skillset     | CONDITIONAL  | Unknown — Hunt Maturity Level not recorded. Story methodology below assumes intermediate SIEM-query and EDR-console proficiency. |
| Timeline          | GO           | Moderate complexity, three parallel Stories with defined queries — estimated 3-5 days execution per Story, fits a 10-business-day sprint. |
| Tooling           | CONDITIONAL  | SIEM/EDR platform Unknown — cannot confirm query-language syntax or console access. Pseudocode/generic query logic provided below; translate to platform-native syntax once known. |

OVERALL DECISION: CONDITIONAL

Assumptions/Conditions:
- Findings are bounded by unknown visibility and unknown device/log completeness across an unconfirmed asset scope. **A negative result from this plan as currently scoped does not establish absence of APT29 activity** — it only reflects the specific queries and data sources assumed above. (Mandatory CONDITIONAL caveat per `references/telemetry-gap-assessment.md`.)
- This plan assumes an M365/Entra ID tenant is in use (Stories 1 and 2 reference Entra ID / Windows-endpoint telemetry specifically). [FILL IN: confirm identity provider and endpoint OS mix — if not Microsoft-centric, Story 1 and portions of Story 2 need re-scoping to the actual IdP/EDR.]
- Re-run the `gather` skill standalone and re-score this Feasibility section before hunt execution begins.

--------------------------------------------------------------------------------
SCOPE DEFINITION
--------------------------------------------------------------------------------
Target Environment:
- [x] Cloud infrastructure / identity (M365 / Entra ID tenant) — Story 1
- [x] Workstations/endpoints (traveling-staff laptops especially) — Story 2
- [x] Network perimeter (DNS, proxy, egress) — Story 3
- [ ] Production servers — out of scope unless Story 2 findings indicate lateral movement
- [ ] OT/ICS — not applicable to this threat's known TTPs

Time Window: 2025-09-08 to 2026-09-07 (90-day rolling lookback recommended for initial pass within this 12-month window; extend to full 12 months if retention allows — see Data Availability caveat)

In-Scope Assets:
- All Entra ID tenant users, with priority on executives, government-affairs, policy, and any staff with recent international/conference travel (CaptiveCrunch relevance)
- Windows endpoints (laptops) with recent VPN/Wi-Fi connections outside the corporate network in the past 90 days
- Egress network telemetry (DNS resolvers, web proxies, firewalls) for the same population

Explicit Exclusions:
- OT/ICS environments (no ATT&CK-for-ICS techniques identified in the intel analysis for this actor)
- Non-Windows endpoints, pending confirmation of EDR coverage for other OS — [FILL IN once EDR Platform is known]

--------------------------------------------------------------------------------
OBJECTIVES
--------------------------------------------------------------------------------
Primary Objectives:
1. Determine whether any Entra ID/M365 accounts show device-code or ASP authentication anomalies consistent with APT29-linked cloud-identity abuse in the past 90 days (Story 1).
2. Determine whether any endpoint shows CornFlake/ChocoShell-consistent artifacts (service masquerade, AMSI tampering, VSS deletion) in the past 90 days (Story 2).

Secondary Objectives:
1. Identify any DNS/network connections to known CaptiveCrunch or GRAPELOADER/WINELOADER infrastructure, or to newly-registered lookalike Microsoft domains, in the past 90 days (Story 3).
2. Characterize the organization's baseline device-code/ASP usage rate, to reduce false positives in any resulting standing detection.

Success Metrics:
- [ ] Hypothesis validated or invalidated with evidence for each of the three Stories
- [ ] All three Stories completed within the 10-business-day window
- [ ] Findings documented per AIMOD2 outcome category (see Tasks below)
- [ ] Report delivered to stakeholders per the `hunt-validator` stage

--------------------------------------------------------------------------------
MITRE ATT&CK MAPPING
--------------------------------------------------------------------------------
| Technique ID | Technique Name                                          | Tactic                          |
|--------------|----------------------------------------------------------|----------------------------------|
| T1204.001    | User Execution: Malicious Link                            | Initial Access                  |
| T1621        | Multi-Factor Authentication Request Generation            | Credential Access                |
| T1528        | Steal Application Access Token                             | Credential Access                |
| T1543.003    | Create or Modify System Process: Windows Service          | Persistence                     |
| T1036        | Masquerading                                               | Defense Evasion                 |
| T1562.001    | Impair Defenses: Disable or Modify Tools                   | Defense Evasion                 |
| T1548.002    | Abuse Elevation Control Mechanism: Bypass UAC              | Privilege Escalation / Defense Evasion |
| T1070.004    | Indicator Removal: File Deletion (VSS deletion)            | Defense Evasion                 |
| T1071.001    | Application Layer Protocol: Web Protocols                 | Command and Control             |
| T1665        | Hide Infrastructure                                        | Command and Control             |
| T1566.001    | Phishing: Spearphishing Attachment                         | Initial Access                  |

--------------------------------------------------------------------------------
DATA SOURCES REQUIRED
--------------------------------------------------------------------------------
| Data Source                              | Platform            | Key Fields                                                          | Retention   |
|-------------------------------------------|----------------------|----------------------------------------------------------------------|-------------|
| Entra ID Sign-in Logs                     | [FILL IN: IdP/SIEM]  | userPrincipalName, authenticationProtocol, deviceCode, ipAddress, location, userAgent | [FILL IN]   |
| Entra ID Audit Logs                       | [FILL IN: IdP/SIEM]  | activityDisplayName ("Add application-specific password"), initiatedBy, targetResources | [FILL IN]   |
| EDR Process Creation / Service Install    | [FILL IN: EDR]       | ImageFileName, ServiceName, ParentImage, CommandLine, user           | [FILL IN]   |
| EDR PowerShell Script-Block Logging       | [FILL IN: EDR/Sysmon]| ScriptBlockText, EventID 4104, host, user                            | [FILL IN]   |
| DNS Resolution Logs                       | [FILL IN: SIEM]      | query_name, query_type, client_ip, timestamp                         | [FILL IN]   |
| Proxy / Firewall Egress Logs              | [FILL IN: SIEM]      | dest_domain, dest_ip, sni, bytes_out, client_ip                      | [FILL IN]   |

--------------------------------------------------------------------------------
REFERENCES
--------------------------------------------------------------------------------
- ./threat-hunting/intel-analysis/apt29-past-year-analysis.md
- ./threat-hunting/intel-reports/apt29-past-year-report.md
- Microsoft Security Blog — CaptiveCrunch: https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/
- Microsoft Security Blog — Storm-2372 device code phishing: https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/
- Google Cloud Blog — Distinct Clusters Target Individuals of Interest to Russia: https://cloud.google.com/blog/topics/threat-intelligence/distinct-clusters-target-individuals-of-interest-to-russia
- MITRE ATT&CK G0016 — APT29: https://attack.mitre.org/groups/G0016/
- CISA AA24-057A: https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-057a

--------------------------------------------------------------------------------
LINKED STORIES
--------------------------------------------------------------------------------
- [HUNT-2026-029-S1] Device-Code / ASP Authentication Anomaly Hunt
- [HUNT-2026-029-S2] CornFlake / ChocoShell Endpoint Artifact Hunt
- [HUNT-2026-029-S3] CaptiveCrunch / GRAPELOADER-WINELOADER Infrastructure Correlation Hunt

================================================================================
```

---

## Story: [HUNT-2026-029-S1] Device-Code / ASP Authentication Anomaly Hunt

```
================================================================================
STORY: [HUNT-2026-029-S1] Device-Code / ASP Authentication Anomaly Hunt
================================================================================

PARENT EPIC: [HUNT-2026-029]
LABELS: threat-hunt-story, t1621, t1528, identity-idp
ASSIGNEE: [FILL IN: Hunter name]
STORY POINTS: [FILL IN — estimate 3-5 days per Feasibility Timeline guide]
SPRINT: [FILL IN]

--------------------------------------------------------------------------------
OBJECTIVE
--------------------------------------------------------------------------------
Determine whether any user account in the tenant has completed an OAuth
device-code authentication flow or created an application-specific password
under circumstances consistent with APT29-linked phishing (e.g., following an
unsolicited IT-support contact, or from an anomalous ASN/user-agent) in the
past 90 days.

--------------------------------------------------------------------------------
HYPOTHESIS COMPONENT (scored per hypothesis-rubric.md)
--------------------------------------------------------------------------------
ID:                 HUNT-2026-029-S1
Hypothesis (SMART): We hypothesize that an adversary linked to APT29/Midnight
                    Blizzard sub-clusters may be using Microsoft Entra ID OAuth
                    device-code or application-specific-password (ASP)
                    authentication flows to bypass MFA and gain persistent
                    mailbox access, evidenced by device-code grant-type sign-ins
                    with a user-agent/ASN combination never seen before for that
                    user, or first-time ASP-creation events, in Entra ID sign-in
                    and audit logs, which we will validate by baselining 90 days
                    of per-user device-code/ASP usage and flagging first-seen
                    device-code+anomalous-ASN combinations in the trailing 30
                    days, within a 5-day execution window.

ABLE decomposition
  Actor:            APT29/Midnight Blizzard and moderate-confidence sub-clusters (UNC6293, Storm-2372/CozyLarch-adjacent)
  Behavior:         OAuth device-code / ASP authentication abuse to bypass MFA
  Location:         Entra ID tenant, all mailbox-holding accounts
  Evidence:         Device-code grant-type sign-in event with first-seen ASN/user-agent for that principal; first-time ASP-creation audit event

ATT&CK:             T1204.001 (User Execution: Malicious Link) / T1621 (MFA Request Generation) / T1528 (Steal Application Access Token)
Pyramid level:      TTP
Data components:    Cloud audit logs: user authentication; application logs: application log content
Expected malicious: A device-code sign-in completing from an ASN/geolocation/user-agent combination never previously seen for that account, immediately followed by mailbox rule creation, mail-forwarding-rule creation, or unusual mailbox search/export activity
Expected benign:    Device-code sign-ins from IT-managed kiosk/shared-device flows, or ASNs already associated with the user's normal travel/VPN pattern and no follow-on mailbox abuse
Disprovable:        Y — all device-code/ASP events across the 90-day window resolve to previously-seen ASN/user-agent combinations with no follow-on mailbox anomalies
Priority:           High — identity is APT29's primary documented access vector this year; executive/policy mailboxes are the plausible crown jewel

Score: Specificity 3 · Testability 3 · Falsifiability 3 · Relevance 3 · Pyramid 3 = 15 → GO

--------------------------------------------------------------------------------
METHODOLOGY
--------------------------------------------------------------------------------
Phase 1: Data Collection
1. Export all Entra ID sign-in log events for the past 90 days where authenticationProtocol/protocol indicates device-code flow (or equivalent field in [FILL IN: SIEM]).
2. Export all Entra ID audit log events for "Add application-specific password" (or IdP-equivalent event) for the same window.
3. Build a 90-day-prior baseline (day -180 to day -90) of each in-scope user's typical ASN/user-agent combinations for comparison.

Phase 2: Analysis
1. Join device-code sign-in events against each user's baseline; flag first-seen ASN/user-agent combinations.
2. Join ASP-creation events against the same baseline; flag any first-time ASP creation for accounts that have never used one before.
3. For every flagged event, pull the subsequent 24 hours of mailbox-rule, mail-forwarding-rule, and mailbox-search/export activity for that account.

Phase 3: Validation
1. Correlate flagged accounts against the traveler/executive population identified in Scope.
2. Interview account owners for flagged events where feasible (did they knowingly authorize a device-code flow, e.g., via a legitimate kiosk/shared-device sign-in?).
3. Document each flagged event as true positive, false positive, or indeterminate.

--------------------------------------------------------------------------------
DATA SOURCES
--------------------------------------------------------------------------------
| Source                    | Fields Required                                                        | Query Location        |
|----------------------------|-------------------------------------------------------------------------|------------------------|
| Entra ID Sign-in Logs      | timestamp, userPrincipalName, authenticationProtocol, ipAddress, asn, userAgent, deviceCode | [FILL IN: SIEM index/workspace] |
| Entra ID Audit Logs        | timestamp, activityDisplayName, initiatedBy, targetResources           | [FILL IN: SIEM index/workspace] |
| M365 Unified Audit Log     | timestamp, Operation (New-InboxRule, Set-Mailbox -ForwardingSmtpAddress, mailbox search/export), UserId | [FILL IN: SIEM index/workspace] |

--------------------------------------------------------------------------------
DETECTION LOGIC
--------------------------------------------------------------------------------
Primary Query (platform-agnostic pseudocode — translate to [FILL IN: KQL/SPL/Elastic DSL] once SIEM platform is confirmed):
```
SigninLogs
| where AuthenticationProtocol == "deviceCode"
| join kind=leftanti (
    SigninLogs
    | where TimeGenerated between (ago(180d) .. ago(90d))
    | summarize KnownASNUA = make_set(strcat(ASN, "|", UserAgent)) by UserPrincipalName
  ) on UserPrincipalName
| where TimeGenerated > ago(30d)
| where strcat(ASN, "|", UserAgent) !in (KnownASNUA)
| project TimeGenerated, UserPrincipalName, ASN, UserAgent, IPAddress, Location
```

Sigma Rule (draft — hand off to detection-engineer for platform translation):
```yaml
title: Entra ID Device-Code Sign-In with First-Seen ASN/User-Agent
status: experimental
description: Detects OAuth device-code authentication completing from a network/user-agent combination not previously seen for the account, consistent with APT29/Midnight-Blizzard-style device-code phishing
logsource:
    product: azure
    service: signinlogs
detection:
    selection:
        AuthenticationProtocol: deviceCode
    condition: selection and not previously_seen_asn_ua
falsepositives:
    - Legitimate kiosk/shared-device or CLI-based device-code sign-ins
    - Users on a new corporate VPN egress not yet baselined
level: high
tags:
    - attack.credential_access
    - attack.t1621
    - attack.t1528
```

--------------------------------------------------------------------------------
EXPECTED OUTCOMES
--------------------------------------------------------------------------------
If Malicious Activity Present:
- Device-code sign-in from a never-before-seen ASN/user-agent, followed within 24h by mailbox-rule or forwarding-rule creation
- Correlation of the sign-in source IP/ASN with any of the CaptiveCrunch/GRAPELOADER-WINELOADER infrastructure from Story 3
- Action: Escalate to IR per incident response plan; treat as a potential **Security Incident** outcome (see Tasks)

If Hypothesis Invalid:
- All device-code/ASP events in the window resolve to previously-seen ASN/user-agent combinations, or to explainable IT-managed flows
- No follow-on mailbox anomalies for any flagged account
- Action: Document as negative finding; consider as a **Detection Opportunity** outcome (baseline is now established for a standing rule) rather than closing with no artifact

--------------------------------------------------------------------------------
ACCEPTANCE CRITERIA
--------------------------------------------------------------------------------
- [ ] Data sources validated and accessible (pending environment-profile confirmation)
- [ ] Queries executed across the full 90-day window
- [ ] Results triaged (true/false positive determination) for every flagged account
- [ ] Findings documented with evidence
- [ ] Tasks created for outcomes (detection, gap, incident, etc.)

--------------------------------------------------------------------------------
LINKED TASKS (Outcomes)
--------------------------------------------------------------------------------
- [HUNT-2026-029-T1] Analytics/Detection: Device-code anomaly Sigma rule
- [HUNT-2026-029-T2] Visibility Gap: [PENDING EXECUTION]

================================================================================
```

---

## Story: [HUNT-2026-029-S2] CornFlake / ChocoShell Endpoint Artifact Hunt

```
================================================================================
STORY: [HUNT-2026-029-S2] CornFlake / ChocoShell Endpoint Artifact Hunt
================================================================================

PARENT EPIC: [HUNT-2026-029]
LABELS: threat-hunt-story, t1543.003, t1562.001, endpoint
ASSIGNEE: [FILL IN: Hunter name]
STORY POINTS: [FILL IN — estimate 3-5 days]
SPRINT: [FILL IN]

--------------------------------------------------------------------------------
OBJECTIVE
--------------------------------------------------------------------------------
Determine whether any Windows endpoint shows artifacts consistent with the
CornFlake RAT or ChocoShell infostealer — specifically the "svchost32"/"Cloud
Sync Service" masquerade, AMSI-tampering, UAC-bypass chain, or post-exfiltration
Volume Shadow Copy deletion — in the past 90 days, with priority on endpoints
that recently connected to non-corporate (hotel/conference/airport) Wi-Fi.

--------------------------------------------------------------------------------
HYPOTHESIS COMPONENT (scored per hypothesis-rubric.md)
--------------------------------------------------------------------------------
ID:                 HUNT-2026-029-S2
Hypothesis (SMART): We hypothesize that CaptiveCrunch-linked malware (CornFlake
                    RAT / ChocoShell infostealer) may be present on endpoints
                    that recently connected to hotel, conference-venue, or
                    airport Wi-Fi, evidenced by a Windows service or scheduled
                    task named "svchost32" with DisplayName "Cloud Sync
                    Service", in-memory PowerShell execution performing an
                    AMSI.dll patch (AmsiScanBuffer byte-patch signature), or
                    Volume Shadow Copy deletion via vssadmin/wmic shortly after
                    a suspicious PowerShell session, in EDR process-creation,
                    service-installation, and PowerShell script-block
                    telemetry, which we will validate by querying all endpoint
                    telemetry for the past 90 days for this
                    service-name/masquerade + AMSI-tamper + VSS-delete
                    co-occurrence pattern, within a 5-day execution window.

ABLE decomposition
  Actor:            Storm-2945/UNC7005 (CaptiveCrunch operators, moderate-confidence APT29 sub-cluster)
  Behavior:         CornFlake/ChocoShell installation, AMSI bypass, anti-forensic VSS deletion
  Location:         Windows endpoints, especially traveling-staff laptops
  Evidence:         Service named "svchost32"/"Cloud Sync Service"; AMSI-patch byte pattern in PowerShell process memory; vssadmin/wmic shadowcopy delete co-occurring with a flagged PowerShell session

ATT&CK:             T1543.003 (Windows Service) / T1036 (Masquerading) / T1562.001 (Impair Defenses) / T1548.002 (Bypass UAC) / T1070.004 (Indicator Removal — VSS)
Pyramid level:      Tool / TTP
Data components:    Process: process creation; Command: command execution; Service: service creation; Process: OS API execution (AMSI)
Expected malicious: A newly created service/scheduled task named "svchost32" or DisplayName "Cloud Sync Service" not present in the organization's known-software baseline, temporally correlated with an AMSI-tamper indicator and/or a shadow-copy deletion command
Expected benign:    No such service/task name exists anywhere in the environment (this is not a legitimate Windows or common third-party service name); if PowerShell AMSI-adjacent activity is found, it resolves to known EDR/AV self-testing or approved red-team tooling
Disprovable:        Y — no host in the 90-day window has a service/task matching this name pattern, and no AMSI-tamper + VSS-delete co-occurrence exists
Priority:           High — CaptiveCrunch is this year's largest, most novel APT29-attributed campaign; endpoint compromise here implies direct credential/session-token theft

Score: Specificity 3 · Testability 3 · Falsifiability 3 · Relevance 3 · Pyramid 3 = 15 → GO

--------------------------------------------------------------------------------
METHODOLOGY
--------------------------------------------------------------------------------
Phase 1: Data Collection
1. Query EDR service-installation/creation telemetry for service name "svchost32" or DisplayName containing "Cloud Sync" across all Windows endpoints, 90-day window.
2. Query EDR PowerShell script-block or AMSI-provider telemetry for known AMSI-bypass indicators (reflection-based `System.Management.Automation.AmsiUtils` field patching, or direct byte-patch of `AmsiScanBuffer`).
3. Query EDR/Sysmon process telemetry for `vssadmin delete shadows` / `wmic shadowcopy delete` command lines.
4. Cross-reference the host list with any available Wi-Fi/VPN connection logs showing non-corporate SSID or captive-portal association in the prior 7 days of each candidate event.

Phase 2: Analysis
1. Flag any host with the service/task name match — treat as high-confidence regardless of co-occurrence (this name pattern has no legitimate use case).
2. For AMSI-tamper and VSS-deletion hits without the service-name match, require temporal co-occurrence (same host, within a 1-hour window) before flagging.
3. Pull full process-ancestry chain and network connections for every flagged host.

Phase 3: Validation
1. Isolate and forensically image any host with a confirmed service-name match before further triage, per IR containment procedure.
2. Compare recovered file hashes (if binary present) against the CornFlake/ChocoShell SHA-256 values in the intel-analysis IOC table.
3. Document confirmed/ruled-out status for every flagged host.

--------------------------------------------------------------------------------
DATA SOURCES
--------------------------------------------------------------------------------
| Source                              | Fields Required                                                    | Query Location        |
|---------------------------------------|-----------------------------------------------------------------------|------------------------|
| EDR Service/Scheduled-Task Telemetry | timestamp, host, ServiceName, DisplayName, ImagePath, CreatedBy       | [FILL IN: EDR console/index] |
| EDR PowerShell Script-Block Logging  | timestamp, host, ScriptBlockText, ParentImage, user                   | [FILL IN: EDR console/index] |
| EDR Process Creation                 | timestamp, host, CommandLine (vssadmin/wmic patterns), ParentImage    | [FILL IN: EDR console/index] |
| Wi-Fi/VPN Connection Logs (if available) | timestamp, host, SSID/network-name, public-IP, geolocation         | [FILL IN — may not exist; flag as Visibility Gap if absent] |

--------------------------------------------------------------------------------
DETECTION LOGIC
--------------------------------------------------------------------------------
Primary Query (platform-agnostic pseudocode):
```
DeviceEvents
| where ActionType == "ServiceInstalled"
| where ServiceName =~ "svchost32" or DisplayName has "Cloud Sync"
| union (
    DeviceProcessEvents
    | where ProcessCommandLine has_any ("vssadmin delete shadows", "wmic shadowcopy delete")
  )
| union (
    DeviceEvents
    | where ActionType == "AmsiProviderLoaded" or ProcessCommandLine has "AmsiScanBuffer"
  )
| project Timestamp, DeviceName, ActionType, ServiceName, ProcessCommandLine
```

Sigma Rule (draft — hand off to detection-engineer):
```yaml
title: CornFlake-Style Service Masquerade (svchost32 / Cloud Sync Service)
status: experimental
description: Detects a service or scheduled task named "svchost32" with a "Cloud Sync Service" display name, matching the CaptiveCrunch/CornFlake persistence mechanism reported by Microsoft (Jul 2026)
logsource:
    category: service_creation
    product: windows
detection:
    selection:
        ServiceName: svchost32
        ServiceDisplayName|contains: 'Cloud Sync'
    condition: selection
falsepositives:
    - None known — this service name/display-name pairing has no legitimate enterprise use case
level: critical
tags:
    - attack.persistence
    - attack.defense_evasion
    - attack.t1543.003
    - attack.t1036
```

--------------------------------------------------------------------------------
EXPECTED OUTCOMES
--------------------------------------------------------------------------------
If Malicious Activity Present:
- Confirmed "svchost32"/"Cloud Sync Service" service on one or more hosts, ideally with a recovered binary matching a known CornFlake/ChocoShell hash
- AMSI-tamper and VSS-deletion co-occurring on the same host within a short window
- Action: Escalate immediately to IR — this is a high-confidence **Security Incident** outcome, not a benign-explainable pattern

If Hypothesis Invalid:
- No host in the 90-day window has the service/task name pattern
- Any AMSI-adjacent or VSS-deletion activity found resolves to known, approved tooling (backup software, EDR self-test, authorized red-team exercise)
- Action: Document as negative finding; retain the query as a standing **Analytics/Detection** artifact for ongoing monitoring

--------------------------------------------------------------------------------
ACCEPTANCE CRITERIA
--------------------------------------------------------------------------------
- [ ] Data sources validated and accessible
- [ ] Queries executed across the full 90-day window on all in-scope Windows endpoints
- [ ] Results triaged (true/false positive determination)
- [ ] Findings documented with evidence
- [ ] Tasks created for outcomes

--------------------------------------------------------------------------------
LINKED TASKS (Outcomes)
--------------------------------------------------------------------------------
- [HUNT-2026-029-T3] Analytics/Detection: CornFlake service-masquerade Sigma rule
- [HUNT-2026-029-T4] Visibility Gap: [PENDING EXECUTION — Wi-Fi/VPN correlation data may not exist]

================================================================================
```

---

## Story: [HUNT-2026-029-S3] CaptiveCrunch / GRAPELOADER-WINELOADER Infrastructure Correlation Hunt

```
================================================================================
STORY: [HUNT-2026-029-S3] CaptiveCrunch / GRAPELOADER-WINELOADER Infrastructure Correlation Hunt
================================================================================

PARENT EPIC: [HUNT-2026-029]
LABELS: threat-hunt-story, t1071.001, t1665, network
ASSIGNEE: [FILL IN: Hunter name]
STORY POINTS: [FILL IN — estimate 1-2 days, this is the most IOC-driven/fastest Story]
SPRINT: [FILL IN]

--------------------------------------------------------------------------------
OBJECTIVE
--------------------------------------------------------------------------------
Determine whether any host in the environment has resolved or connected to
known CaptiveCrunch C2 infrastructure, GRAPELOADER/WINELOADER staging domains,
or newly-registered lookalike Microsoft domains (`*ms365*`, `*owa*` patterns)
in the past 90 days.

--------------------------------------------------------------------------------
HYPOTHESIS COMPONENT (scored per hypothesis-rubric.md)
--------------------------------------------------------------------------------
ID:                 HUNT-2026-029-S3
Hypothesis (SMART): We hypothesize that hosts in our environment may be
                    beaconing to CaptiveCrunch C2 infrastructure (ms365-device
                    [.]com, ms365-live[.]com, m365-owa[.]com, owa-ms365[.]com,
                    and associated IPs) or to the GRAPELOADER/WINELOADER
                    staging domains, or to newly-registered domains matching
                    the same lookalike-Microsoft naming pattern, evidenced by
                    DNS resolution or outbound HTTP/TLS connections to these
                    exact domains/IPs or to typosquat-pattern matches, in DNS
                    resolver logs, proxy/firewall logs, and TLS SNI telemetry,
                    which we will validate by querying 90 days of DNS and
                    proxy logs for exact-match and pattern-match hits, within a
                    3-day execution window.

ABLE decomposition
  Actor:            Storm-2945/UNC7005 (CaptiveCrunch); historical GRAPELOADER/WINELOADER operators
  Behavior:         C2 beaconing / phishing-page retrieval to known and lookalike infrastructure
  Location:         Network egress (DNS resolvers, web proxies, firewalls)
  Evidence:         DNS query or TLS SNI matching a listed domain, or matching the `*ms365*`/`*owa*` lookalike pattern for a domain not in the organization's known-good allowlist

ATT&CK:             T1071.001 (Web Protocols) / T1665 (Hide Infrastructure) / T1566.001 (Spearphishing Attachment, for the GRAPELOADER/WINELOADER lineage)
Pyramid level:      Domain / IP (exact-match) supplemented by a pattern-based (typosquat) check one level up the Pyramid
Data components:    Network traffic: network traffic content; Network traffic: network connection creation
Expected malicious: A DNS/proxy hit against one of the named domains/IPs, or a newly-registered domain matching the lookalike-Microsoft naming convention that is not on the organization's SSO/allowlist
Expected benign:    No hits against the named list; any `*ms365*`/`*owa*` pattern match resolves to a known, allowlisted Microsoft or partner domain
Disprovable:        Y — zero DNS/proxy/TLS hits against the named IOC list and no unexplained lookalike-pattern domain in 90 days
Priority:           Medium-High — fastest Story to execute (pure log lookup), directly actionable, but IOC-level evidence ages quickly; treat a clean result as time-bound, not permanent assurance

Score: Specificity 3 · Testability 3 · Falsifiability 3 · Relevance 3 · Pyramid 2 = 14 → GO
(Pyramid scores 2, not 3, because the primary check is IOC/domain-level; the supplementary lookalike-pattern check partially offsets this but does not raise it to TTP level. Per the hypothesis-rubric anti-pattern table, this Story's findings should feed Story 1/2's TTP-level hunts rather than stand alone as the program's only defense against this actor.)

--------------------------------------------------------------------------------
METHODOLOGY
--------------------------------------------------------------------------------
Phase 1: Data Collection
1. Query DNS resolver logs for exact matches against: ms365-device[.]com, ms365-live[.]com, m365-owa[.]com, owa-ms365[.]com, ophibre[.]com, bravecup[.]com, bakenhof[.]com, silry[.]com, findcloudflare[.]com, cloudflare.redirectpartners[.]com.
2. Query proxy/firewall/TLS-SNI logs for the same domain list plus the IP list: 31.57.243[.]154, 38.146.28[.]75, 38.146.28[.]132, 104.194.159[.]150, 107.189.26[.]194, 213.145.86[.]112.
3. Run a secondary pattern query for any newly-registered (past 90 days, via passive DNS/threat-intel enrichment if available) domain matching `*ms365*` or `*owa*` that is not already in the corporate SSO allowlist.

Phase 2: Analysis
1. Any exact-match hit is treated as high-confidence and escalated immediately.
2. Pattern-match hits are triaged against the known-good Microsoft/partner domain allowlist; only unexplained residuals are flagged.

Phase 3: Validation
1. For any flagged host, pull the full session (source host, user, referrer, payload if proxied) to determine if a phishing page was rendered or a payload retrieved.
2. Cross-reference flagged hosts/users against Story 1 (identity anomalies) and Story 2 (endpoint artifacts) for corroboration.

--------------------------------------------------------------------------------
DATA SOURCES
--------------------------------------------------------------------------------
| Source                  | Fields Required                                  | Query Location        |
|--------------------------|---------------------------------------------------|------------------------|
| DNS Resolver Logs       | timestamp, query_name, client_ip, response_ip     | [FILL IN: SIEM index] |
| Proxy / Firewall Logs   | timestamp, dest_domain, dest_ip, sni, client_ip, user | [FILL IN: SIEM index] |
| Passive DNS / TI enrichment (if available) | domain registration date, resolving IPs | [FILL IN — may not exist; flag as Visibility Gap if absent] |

--------------------------------------------------------------------------------
DETECTION LOGIC
--------------------------------------------------------------------------------
Primary Query (platform-agnostic pseudocode):
```
DnsEvents
| where Name in (
    "ms365-device.com", "ms365-live.com", "m365-owa.com", "owa-ms365.com",
    "ophibre.com", "bravecup.com", "bakenhof.com", "silry.com",
    "findcloudflare.com", "cloudflare.redirectpartners.com"
  )
  or ipv4_lookup in (
    "31.57.243.154", "38.146.28.75", "38.146.28.132",
    "104.194.159.150", "107.189.26.194", "213.145.86.112"
  )
| project TimeGenerated, Computer, Name, ClientIP

// Supplementary lookalike-pattern check
DnsEvents
| where Name matches regex @"(ms365|owa)" 
| where Name !in (KnownGoodAllowlist)
```

Sigma Rule (draft — hand off to detection-engineer):
```yaml
title: DNS/Proxy Hit Against Known CaptiveCrunch or GRAPELOADER/WINELOADER Infrastructure
status: experimental
description: Detects DNS resolution or proxy connection to domains/IPs published in Microsoft's CaptiveCrunch report or Check Point's GRAPELOADER/WINELOADER report
logsource:
    category: dns
detection:
    selection:
        query|contains:
            - 'ms365-device.com'
            - 'ms365-live.com'
            - 'm365-owa.com'
            - 'owa-ms365.com'
            - 'ophibre.com'
            - 'bravecup.com'
            - 'bakenhof.com'
            - 'silry.com'
    condition: selection
falsepositives:
    - None expected — these are actor-registered domains with no legitimate use
level: critical
tags:
    - attack.command_and_control
    - attack.t1071.001
```

--------------------------------------------------------------------------------
EXPECTED OUTCOMES
--------------------------------------------------------------------------------
If Malicious Activity Present:
- Confirmed DNS/proxy hit against a listed domain or IP, with an identifiable source host/user
- Action: Escalate to IR immediately — this is a **Security Incident** outcome; correlate with Stories 1 and 2 for scope

If Hypothesis Invalid:
- Zero hits against the exact IOC list and no unexplained lookalike-pattern domains
- Action: Document as negative finding; note explicitly this is time-bound (IOCs age) — recommend re-running this Story's query against updated IOC feeds on a recurring cadence rather than treating this as permanent clearance

--------------------------------------------------------------------------------
ACCEPTANCE CRITERIA
--------------------------------------------------------------------------------
- [ ] Data sources validated and accessible
- [ ] Queries executed across the full 90-day window
- [ ] Results triaged
- [ ] Findings documented with evidence
- [ ] Tasks created for outcomes

--------------------------------------------------------------------------------
LINKED TASKS (Outcomes)
--------------------------------------------------------------------------------
- [HUNT-2026-029-T5] Analytics/Detection: CaptiveCrunch IOC-match Sigma rule
- [HUNT-2026-029-T6] New Hunt Idea: [PENDING EXECUTION]

================================================================================
```

---

## Tasks (Outcome Placeholders)

All Tasks below are placeholders created during planning per the hunt-planner Output Checklist. They are marked `[PENDING EXECUTION]` and will be populated by the `hunt-validator` skill once the corresponding detection has been built (`detection-engineer`) and tested.

```
================================================================================
TASK: [HUNT-2026-029-T1] Analytics/Detection: Device-Code Anomaly Rule
================================================================================
PARENT STORY: [HUNT-2026-029-S1]
CATEGORY: Analytics/Detection
LABELS: hunt-outcome, detection-engineering
DESCRIPTION: [PENDING EXECUTION] — hand the Story 1 Sigma draft to the detection-engineer skill once Story 1 findings are validated.
RECOMMENDED ACTION:
- [ ] Submit to detection-engineer (Stage 4)
- [ ] Assign to: [FILL IN: Detection Engineer]
- [ ] Target deployment: [FILL IN]
================================================================================

================================================================================
TASK: [HUNT-2026-029-T2] Visibility Gap: Baseline ASN/User-Agent Data Completeness
================================================================================
PARENT STORY: [HUNT-2026-029-S1]
CATEGORY: Visibility Gap
LABELS: hunt-outcome, visibility-gap
DESCRIPTION: [PENDING EXECUTION] — populate if the 90-day sign-in baseline cannot be built due to short retention or missing ASN enrichment (environment-profile.md currently shows Unknown retention).
IMPACT: [PENDING EXECUTION]
REMEDIATION: [PENDING EXECUTION]
================================================================================

================================================================================
TASK: [HUNT-2026-029-T3] Analytics/Detection: CornFlake Service-Masquerade Rule
================================================================================
PARENT STORY: [HUNT-2026-029-S2]
CATEGORY: Analytics/Detection
LABELS: hunt-outcome, detection-engineering
DESCRIPTION: [PENDING EXECUTION] — hand the Story 2 Sigma draft to the detection-engineer skill once Story 2 findings are validated.
RECOMMENDED ACTION:
- [ ] Submit to detection-engineer (Stage 4)
- [ ] Assign to: [FILL IN: Detection Engineer]
- [ ] Target deployment: [FILL IN]
================================================================================

================================================================================
TASK: [HUNT-2026-029-T4] Visibility Gap: Wi-Fi/VPN Connection Correlation Data
================================================================================
PARENT STORY: [HUNT-2026-029-S2]
CATEGORY: Visibility Gap
LABELS: hunt-outcome, visibility-gap
DESCRIPTION: [PENDING EXECUTION] — populate if no data source exists to correlate endpoints with non-corporate Wi-Fi/captive-portal connections; this would materially limit Story 2's traveler-targeting scope.
IMPACT: [PENDING EXECUTION]
REMEDIATION: [PENDING EXECUTION]
================================================================================

================================================================================
TASK: [HUNT-2026-029-T5] Analytics/Detection: CaptiveCrunch IOC-Match Rule
================================================================================
PARENT STORY: [HUNT-2026-029-S3]
CATEGORY: Analytics/Detection
LABELS: hunt-outcome, detection-engineering
DESCRIPTION: [PENDING EXECUTION] — hand the Story 3 Sigma draft to the detection-engineer skill once Story 3 findings are validated. Note: IOC-based rule will need a recurring feed-refresh process since domain/IP indicators age quickly.
RECOMMENDED ACTION:
- [ ] Submit to detection-engineer (Stage 4)
- [ ] Assign to: [FILL IN: Detection Engineer]
- [ ] Target deployment: [FILL IN]
================================================================================

================================================================================
TASK: [HUNT-2026-029-T6] New Hunt Idea: [PENDING EXECUTION]
================================================================================
PARENT STORY: [HUNT-2026-029-S3]
CATEGORY: New Hunt Idea
LABELS: hunt-outcome, new-hunt-idea
DESCRIPTION: [PENDING EXECUTION] — populate with any follow-on hypothesis surfaced during Story 3 execution (e.g., a newly observed lookalike-domain pattern not yet in the IOC list).
SUGGESTED APPROACH:
- Trigger Type: Emerging from current hunt
- Estimated Complexity: [FILL IN]
- Recommended Priority: [FILL IN]
================================================================================
```
