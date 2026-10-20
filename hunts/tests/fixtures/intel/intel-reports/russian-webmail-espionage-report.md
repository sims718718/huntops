# Actionable Intel Report: Russian Global Webmail Espionage (CL-STA-1114 / Void Blizzard / LAUNDRY BEAR)

## Executive Summary

Unit 42 has documented an ongoing, Russia-linked cyberespionage campaign — tracked as CL-STA-1114 by Unit 42, Void Blizzard by Microsoft, and LAUNDRY BEAR by the Dutch AIVD/MIVD — exploiting a Zimbra Collaboration Suite (ZCS) stored cross-site scripting vulnerability (CVE-2025-66376) to compromise webmail accounts with **zero user interaction beyond opening an email**. A crafted HTML/SVG message injects obfuscated JavaScript that silently harvests CSRF tokens, email credentials, two-factor authentication scratch codes, system details, and up to 90 days of email and search history, exfiltrating it to a rotating set of C2 infrastructure (average lifetime ~35 days per node). Targets span government, defense, transportation, and financial-sector organizations across NATO member states, Ukraine, CIS countries, and Africa. A patch exists (ZCS 10.0.18/10.1.13, November 2025) and the CVE is CISA KEV-listed, yet exploitation continues against unpatched instances. This is a client-side, session-hijacking technique — not a server compromise — so detection and response should focus on browser/session telemetry and ZCS application logs, not traditional server-exploitation indicators, and any organization running Zimbra should verify patch status immediately given active exploitation.

## Key Judgments

1. CL-STA-1114, Void Blizzard, and LAUNDRY BEAR are the same tracked actor, assessed as Russian state-sponsored at high confidence by Microsoft, the Dutch AIVD/MIVD, and Unit 42 independently, based on victimology. **Confidence: High**
2. CVE-2025-66376 is a patched (Nov 2025), CISA KEV-listed (Mar 2026), client-side stored-XSS vulnerability in Zimbra Classic UI — exploitation continues against organizations that have not applied the fix. **Confidence: High**
3. This is a zero-click, session-hijacking technique: the malicious JavaScript executes inside the victim's already-authenticated webmail session, meaning traditional "did the user click something" phishing training will not prevent it — patching and browser/application-layer telemetry are the controlling defenses. **Confidence: High**
4. A specific attribution link to Russia's FSB (via a named individual, Denis Obrezko, and company Yutek-NN) surfaced in a 2026 U.S. federal indictment — this is a meaningful new data point but rests on unadjudicated criminal allegations, not yet independently corroborated by a technical vendor. **Confidence: Moderate**
5. The same CVE (CVE-2025-66376) has been separately reported as exploited by a *different* Russian-aligned actor, APT28/Forest Blizzard, against a Ukrainian target ("Operation GhostMail") — meaning exploitation of this vulnerability should not be treated as a single-actor signature during hunting/detection. **Confidence: Moderate**
6. A related actor designation, TA488 (Proofpoint), is only a *reported*, not confirmed, alias for this cluster — Proofpoint itself states it lacked high confidence in the link from its own telemetry, and TA488 has separately been associated with China-aligned indicators in other reporting. **Confidence: Low (deliberately unresolved)**

## Actor / Campaign Overview

| Aspect | Assessment |
|---|---|
| **Names** | CL-STA-1114 (Unit 42) = Void Blizzard (Microsoft) = LAUNDRY BEAR (Dutch AIVD/MIVD) — confirmed same actor, High confidence |
| **Contested alias** | TA488 (Proofpoint) — Reported only; Proofpoint could not independently confirm at high confidence, and TA488 has separate China-aligned associations elsewhere in Proofpoint's reporting |
| **Sponsor** | Russian state-sponsored (High confidence, multi-vendor/government); FSB-specific link via a 2026 indictment of Denis Obrexko/Yutek-NN (Moderate confidence — unadjudicated) |
| **Motivation** | Espionage / intelligence collection |
| **Active since** | At least April 2024 (Microsoft); possibly 2023 per the 2026 indictment |
| **Victimology** | Government, defense, transportation/aviation, healthcare, telecom/IT, media, NGOs, education — concentrated in NATO states and Ukraine; 11+ U.S. companies named in the 2026 indictment |
| **Prior/parallel TTPs** | Password spraying and pass-the-cookie against M365/Entra (pre-2025); Evilginx-based AiTM phishing against Exchange Online/Graph with typosquatted Entra domains (from April 2025) — a **separate campaign and infrastructure set** from the Zimbra activity below |

Full actor tradecraft detail, including all confidence caveats, is in the underlying analysis (`./threat-hunting/intel-analysis/russian-webmail-espionage-analysis.md`).

## MITRE ATT&CK Coverage

| Technique ID | Technique Name | Tactic | Do we have visibility? |
|---|---|---|---|
| T1566.001 / T1566.002 | Phishing: Spearphishing Attachment / Link | Initial Access | Unknown — see hunt-planner Step 0 |
| T1203 | Exploitation for Client Execution | Execution | Unknown — see hunt-planner Step 0 |
| T1190 *(contested/secondary mapping)* | Exploit Public-Facing Application | Initial Access | Unknown — see hunt-planner Step 0 |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Execution | Unknown — see hunt-planner Step 0 |
| T1027.017 | Obfuscated Files or Information: SVG Smuggling | Defense Evasion | Unknown — see hunt-planner Step 0 |
| T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | Defense Evasion | Unknown — see hunt-planner Step 0 |
| T1539 | Steal Web Session Cookie | Credential Access | Unknown — see hunt-planner Step 0 |
| T1555.003 | Credentials from Password Stores: Web Browsers | Credential Access | Unknown — see hunt-planner Step 0 |
| T1556.006 | Modify Authentication Process: Multi-Factor Authentication | Credential Access | Unknown — see hunt-planner Step 0 |
| T1082 | System Information Discovery | Discovery | Unknown — see hunt-planner Step 0 |
| T1119 | Automated Collection | Collection | Unknown — see hunt-planner Step 0 |
| T1185 | Browser Session Hijacking | Collection | Unknown — see hunt-planner Step 0 |
| T1114.002 | Email Collection: Remote Email Collection | Collection | Unknown — see hunt-planner Step 0 |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | Unknown — see hunt-planner Step 0 |
| T1048.002 / T1048.003 | Exfiltration Over Alternative Protocol (Non-C2 / DNS) | Exfiltration | Unknown — see hunt-planner Step 0 |
| T1071.001 | Application Layer Protocol: Web Protocols | Command and Control | Unknown — see hunt-planner Step 0 |
| T1583.003 | Acquire Infrastructure: Virtual Private Server | Resource Development | Unknown — see hunt-planner Step 0 |

*(The environment profile on file has all fields marked `Unknown` — SIEM/EDR/environment context has not yet been captured. Visibility cannot be assessed until `gather` is run standalone with real values.)*

## Indicators of Compromise

Only Confirmed/Reported-confidence IOCs are carried forward; full detail (including the separate, non-overlapping May-2025 AiTM infrastructure set) is in the analysis file.

| Type | Value | Confidence | Source |
|---|---|---|---|
| IPv4 (C2) | 37.120.247[.]228 | Confirmed | Unit 42, Jul 2026 |
| IPv4 (C2) | 64.226.124[.]190 | Confirmed | Unit 42, Jul 2026 |
| IPv4 (C2) | 104.248.134[.]194 | Confirmed | Unit 42, Jul 2026 |
| IPv4 (C2) | 185.86.79[.]95 | Confirmed | Unit 42, Jul 2026 |
| IPv4 (C2) | 193.238.152[.]66 | Confirmed | Unit 42, Jul 2026 |
| IPv4 (C2) | 194.156.103[.]193 | Confirmed | Unit 42, Jul 2026 |
| IPv4 (C2) | 216.252.238[.]18 | Confirmed | Unit 42, Jul 2026 |
| IPv4 (C2) | 216.252.238[.]64 | Confirmed | Unit 42, Jul 2026 |
| IPv4 (C2) | 216.252.238[.]104 | Confirmed | Unit 42, Jul 2026 |
| Domain (C2) | analyticemailmeter[.]com | Confirmed | Unit 42, Jul 2026 |
| Domain (C2) | emailanalytics[.]com[.]ua | Confirmed | Unit 42, Jul 2026 |
| Domain (C2) | istc-cloud[.]com | Confirmed | Unit 42, Jul 2026 |
| Domain (C2) | mailnalysis[.]com | Confirmed | Unit 42, Jul 2026 |
| Domain (C2) | synacorzimbra[.]nl | Confirmed | Unit 42, Jul 2026 |
| Domain (C2) | zimbra-metadata[.]com | Confirmed | Unit 42, Jul 2026 |
| Domain (C2) | zimbrastat[.]com | Confirmed | Unit 42, Jul 2026 |
| Domain (C2) | zimbrasoft[.]com[.]ua | Confirmed | Unit 42, Jul 2026 |
| Domain (C2) | zmailanalytics[.]com | Confirmed | Unit 42, Jul 2026 |
| Domain (compromised, phishing distribution) | isofts.kiev[.]ua | Confirmed | CISA AA26-204A |
| Domain (compromised, phishing distribution) | navs.edu[.]ua | Confirmed | CISA AA26-204A |
| Email (infra procurement) | ivanka.zurabishvili@proton[.]me | Confirmed | CISA AA26-204A |
| Email (infra procurement) | zmul1@buildandconsulting[.]com | Confirmed | CISA AA26-204A |
| Email (infra procurement) | garrysmithme@pinmx[.]net | Confirmed | CISA AA26-204A |
| Email (infra procurement) | hostingclient@pinmx[.]net | Confirmed | CISA AA26-204A |
| Email (phishing sender) | c.laurent.ejfa@proton[.]me | Confirmed | CISA AA26-204A; Proofpoint |
| Email (phishing sender) | j.moreau.epsc@proton[.]me | Confirmed | CISA AA26-204A; Proofpoint |
| Email (phishing sender) | liberty.insights@proton[.]me | Confirmed | CISA AA26-204A; Proofpoint |
| SHA-256 (exploit email sample) — *verify hash length against original CISA package before use* | 98df604ecc57f884a2e6ce3266a0013ad64455cac48442c2312cfa4765007aa | Reported | CISA AA26-204A; Proofpoint |
| SHA-256 (exploit email sample) — *same caveat* | 60db9abae75cd8ccc49dd7ea5feb41677566dcd442f12ebc5745ffd2810fb87 | Reported | CISA AA26-204A; Proofpoint |
| SHA-256 (exploit email sample) — *same caveat* | b1f5beb1175fc5c7d1806a2f0d900eb124c54f0286c5c52b66eea7a6633adb1 | Reported | CISA AA26-204A; Proofpoint |
| SHA-256 (exploit email sample) — *same caveat* | 1517b3caa495f6c4e832df9c75fc94667e3c233773f7fa4e056d5e30e5ead76 | Reported | CISA AA26-204A; Proofpoint |
| X.509 cert hash — SHA-1 (C2 TLS) | 2e4f314bc9943cab5005d6fde0b271c74d47bc9d | Reported | CISA AA26-204A |
| X.509 cert hash — SHA-1 | 50a87d926621dd06389ba50d86e0ff574ed713a8 | Reported | CISA AA26-204A |
| X.509 cert hash — SHA-1 | c5a72420e7bb308d078e62128430897f82194c95 | Reported | CISA AA26-204A |
| X.509 cert hash — SHA-1 | 8959c4d29e29f02ea94ea8bb21c8df2594c5549d | Reported | CISA AA26-204A |
| X.509 cert hash — SHA-1 | 62eb76432597694edb01c1fe57aab0cfe03a7178 | Reported | CISA AA26-204A |
| X.509 cert hash — SHA-1 | cddf5c3be1e07f28140aed165b929bf2d614922a | Reported | CISA AA26-204A |
| X.509 cert hash — SHA-1 | 18b3ad442ce73cc8656d51d75bbd7c855f2cb7e8 | Reported | CISA AA26-204A |
| X.509 cert hash — SHA-1 | 1b25041ececf2457eef0270fc1d785cec8ec8ded | Reported | CISA AA26-204A |
| X.509 cert hash — SHA-1 | e4fe6466a4f9a4249fe330651e914e45bbdca44a | Reported | CISA AA26-204A |
| X.509 cert hash — SHA-1 | b6b77c9a455225d525834a403ca9ef5481ed044 | Reported | CISA AA26-204A |

**Important:** A separate, non-overlapping infrastructure set (AiTM/Evilginx phishing domains and a distinct file hash) belongs to an *earlier, different* Void Blizzard campaign against Exchange Online/Graph (Microsoft, May 2025) — see the analysis file for that set. Do not merge the two into one blocklist without distinguishing which campaign each indicator supports.

## Recommended Actions

### Hunt
1. Hunt for Zimbra Classic UI sessions that rendered an inbound email containing an SVG element with a populated `onload` attribute and/or CSS `@import` directives, evidenced by ZCS mail-store/application logs or a mail-gateway content-inspection log capturing raw message HTML, to identify any user who may have been exposed to the CVE-2025-66376 exploit chain even without further action.
2. Hunt for outbound HTTPS or DNS traffic from hosts running a Zimbra webmail session to any of the nine confirmed C2 domains/IPs above (and watch for newly-registered, thematically similar domains — e.g., containing "zimbra," "mail," "analytics" — given the actor's ~35-day infrastructure rotation), evidenced by DNS logs, proxy/firewall egress logs, or NetFlow.
3. Hunt for anomalous ZimbraAccount SOAP API calls — specifically `GetScratchCodesRequest` or unusual `localStorage`/CSRF-token-adjacent access patterns — occurring shortly after a user opened a new email, evidenced by ZCS application/audit logs if available at that granularity.

### Detect
- **Strong standing-detection candidates**: T1556.006 (a `GetScratchCodesRequest` SOAP call is a highly specific, low-noise signal if ZCS audit logging captures SOAP method names); network-layer C2 matching against the nine published domains/IPs (T1071.001/T1041) as an interim signature-based control pending patching.
- **Needs a hunt first** (broad/noisy as stated): T1203/T1027.017 (SVG-with-onload or CSS-`@import`-in-email detection generically will have significant false positives from legitimate marketing/newsletter HTML email and requires a hunt-derived baseline before a standing rule); T1119/T1185 (automated browser-session collection behavior is hard to distinguish from legitimate webmail API usage without a baseline).

### Mitigate
- **Patch immediately**: upgrade Zimbra Collaboration Suite to 10.0.18 or 10.1.13 or later — a fix for CVE-2025-66376 has existed since November 2025, and the vulnerability is CISA KEV-listed with active exploitation confirmed. This is the single highest-leverage action available given the intel.
- If patching cannot occur immediately, apply any vendor-published interim mitigation and consider disabling or restricting the Classic UI in favor of the modern UI if the CSS `@import` sanitization flaw is specific to Classic UI (confirm against the vendor advisory).
- Force-rotate credentials and reissue 2FA scratch codes for any account that accessed Zimbra webmail during a window where an unpatched instance could have been exposed, given the campaign's specific harvesting of scratch codes as an MFA-bypass mechanism.
- Block the nine published C2 IPs/domains and the CISA-published X.509 certificate hashes at the network layer as an interim, signature-based compensating control (acknowledging ~35-day infrastructure churn means this decays quickly and is not a substitute for patching).

## Confidence and Sourcing

This report is built entirely on the completed `intel-analysis` stage (`./threat-hunting/intel-analysis/russian-webmail-espionage-analysis.md`) — the analysis stage was **not** skipped. Overall confidence in the report's core framing (a Russia-linked actor exploiting a real, patchable Zimbra CVE for zero-click webmail espionage) is **High**, resting on a primary vendor source (Unit 42) independently corroborated by a US-government joint advisory (CISA AA26-204A) and Microsoft/Dutch-government reporting on the actor's broader identity. Confidence in several secondary claims is lower and should not be overstated downstream — carried forward from the analysis's Open Questions and Gaps:

1. **TA488 equivalence to this actor is contested/unresolved** — Proofpoint itself could not confirm at high confidence from its own telemetry, and TA488 has separately been associated with China-aligned indicators elsewhere in Proofpoint's own reporting. Treat any TA488-sourced finding as Reported, not Confirmed, for this actor.
2. **CVE-2025-66376 CVSS scoring discrepancy** (6.1 vs. 7.2 across sources) is unresolved — the 7.2 figure may be a conflation with the mechanistically similar Roundcube CVE-2025-68461 rather than a second genuine scoring.
3. **Multi-actor exploitation of the same CVE**: CVE-2025-66376 has been separately reported as exploited by APT28/Forest Blizzard in a distinct campaign ("Operation GhostMail") against a different target. Exploitation of this CVE alone should not be treated as attribution to CL-STA-1114/Void Blizzard/LAUNDRY BEAR specifically.
4. **FSB-specific attribution (Yutek-NN/Obrezko) is Moderate confidence** — it stems from an unadjudicated 2026 U.S. criminal indictment, not yet corroborated by a dedicated technical vendor writeup.
5. **The client-side (T1203), not server-side (T1190), nature of the exploit** is an important scoping distinction confirmed by CISA's authoritative ATT&CK mapping — hunt and detection work should prioritize browser/session and application-log telemetry over server-exploitation indicators.
6. **The DNS exfiltration channel (T1048.003)** cited in CISA's broader mapping for this actor is not fully confirmed to apply to this exact Zimbra campaign iteration versus a different iteration of the actor's tooling.
7. **IOC hash-length caveat**: four CISA-sourced SHA-256 values rendered at 63 hex characters during research (likely a transcription artifact) — verify against the original CISA PDF/STIX package before operational use.
8. **Two non-overlapping infrastructure generations exist for this actor** (the Zimbra-specific set here, and an earlier, separate AiTM/Evilginx set from May 2025) — do not merge them into a single indicator set without distinguishing which campaign each supports.
9. **Environment visibility is entirely unassessed** — the environment profile on file (shared across this pipeline's runs) has every field marked `Unknown`. The ATT&CK Coverage table above cannot be scored for actual visibility until `gather` is run standalone with real values; `hunt-planner` should treat this as an open input at its Step 0.

## Appendix: Full Source List

- Unit 42 — "Russian Global Webmail Espionage" (2026-07-23) — https://unit42.paloaltonetworks.com/russian-webmail-espionage/
- CISA Joint Advisory AA26-204A — https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-204a
- CISA Known Exploited Vulnerabilities Catalog — https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2025-66376
- Microsoft Security Blog — "New Russia-affiliated actor Void Blizzard targets critical sectors for espionage" (2025-05-27) — https://www.microsoft.com/en-us/security/blog/2025/05/27/new-russia-affiliated-actor-void-blizzard-targets-critical-sectors-for-espionage/
- Help Net Security — Microsoft/Dutch AIVD-MIVD Void Blizzard/LAUNDRY BEAR disclosure coverage — https://www.helpnetsecurity.com/2025/05/27/microsoft-dutch-security-agencies-lift-veil-on-laundry-bear-void-blizzard-cyber-espionage-group/
- Proofpoint — "TA488 Targets Zimbra Mailservers with Half-Click Exploits" — https://www.proofpoint.com/us/blog/threat-insight/ta488-targets-zimbra-mailservers-half-click-exploits
- The Record (Recorded Future News) — reporting on the Denis Obrezko/Yutek-NN indictment — https://therecord.media/hacker-linked-to-void-blizzard-faces-charges
- SentinelOne Vulnerability Database — CVE-2025-66376 — https://www.sentinelone.com/vulnerability-database/cve-2025-66376/
- Tenable — CVE-2025-66376 — https://www.tenable.com/cve/CVE-2025-66376
- SecurityWeek — "Russian APT Exploits Zimbra Vulnerability Against Ukraine" — https://www.securityweek.com/russian-apt-exploits-zimbra-vulnerability-against-ukraine/
- Canadian Centre for Cyber Security AL25-007 (CVE-2025-49113) — https://www.cyber.gc.ca/en/alerts-advisories/vulnerability-impacting-roundcube-webmail-cve-2025-49113
- The Hacker News — CISA adds actively exploited Roundcube flaws — https://thehackernews.com/2026/02/cisa-adds-two-actively-exploited.html
- BleepingComputer — CISA Roundcube flaws exploited — https://www.bleepingcomputer.com/news/security/cisa-recently-patched-roundcube-flaws-now-exploited-in-attacks/
- MITRE ATT&CK Enterprise — https://attack.mitre.org/
