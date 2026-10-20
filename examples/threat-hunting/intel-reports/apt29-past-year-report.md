# Actionable Intel Report: APT29 / Midnight Blizzard Activity, Past 12 Months (Sept 2025–Sept 2026)

## Executive Summary

APT29 (Cozy Bear / Midnight Blizzard / SVR-attributed; rebranded "ICE RELIC" by Google in July 2026) has spent the past year moving further away from malware-first intrusions and toward abuse of legitimate cloud-identity features — OAuth device-code phishing, application-specific-password theft, and MFA-bypassing token capture — to get into government, diplomatic, defense, NGO, and think-tank environments. The year's standout campaign, **CaptiveCrunch** (disclosed by Microsoft July 2026), hijacked hotel and conference-venue Wi-Fi captive portals worldwide to redirect traveling targets into credential-harvesting pages and deliver two new tools: a Go-based RAT (**CornFlake**) and an in-memory PowerShell infostealer (**ChocoShell**). No CVE or unpatched-software exploit drives this activity — it is phishing- and identity-abuse-driven, which means the most effective response is hunting and detecting on identity/authentication behavior and traveler-network exposure, not patch management. Because the organization's SIEM/EDR stack and hunt maturity are not yet recorded (`environment-profile.md` is fully `Unknown`), the actions below should be treated as a checklist to validate once that intake is completed.

## Key Judgments

1. APT29-linked clusters have shifted decisively to cloud-identity abuse (OAuth device-code phishing, token theft) as the dominant initial-access method, largely supplanting malware-first intrusion. — **High**
2. The CaptiveCrunch campaign (hotel/venue captive-portal hijacking, CornFlake/ChocoShell malware) is the most significant and novel APT29-attributed activity of the past year. — **High**
3. Attribution of the year's sub-clusters (UNC6293, UNC7005/Storm-2945, UNC5976) to APT29/SVR proper is only **moderate confidence** per the vendors' own language — one cluster (UNC5976) may belong to a different Russian intelligence service entirely. — **Moderate**
4. No CVE or software vulnerability has been confirmed as an APT29 initial-access vector in the past 12 months; the actor's tradecraft is presently phishing/identity-centric rather than exploit-driven. — **Moderate** (absence-of-evidence finding; could reflect reduced reporting rather than a true operational shift)
5. Microsoft assesses that AI-assisted tooling supported a "significant portion" of the CaptiveCrunch campaign's infrastructure — the first such attribution to this actor. — **Moderate**
6. No new joint US/UK/allied government advisory naming APT29 was published in this window; all significant sourcing in the past year is vendor-driven (Microsoft, Google GTIG), which introduces a lag/coverage gap relative to government confirmation. — **High** (as an observed reporting gap, not a claim about actor activity)

## Actor / Campaign Overview

APT29 is attributed with high confidence to Russia's SVR foreign intelligence service, active since at least 2008, historically responsible for the DNC intrusion and the 2020 SolarWinds/Sunburst supply-chain compromise. It is tracked under many aliases (Cozy Bear, Midnight Blizzard, NOBELIUM, The Dukes, UNC2452/2652) and was renamed **ICE RELIC** by Google GTIG in July 2026. Targeting remains focused on governments, diplomatic missions, defense industrial base, think tanks, NGOs, and cloud/technology providers, concentrated in Europe, the US, Ukraine, NATO members, and (newly this year) Armenia.

The past year's activity fragments across several GTIG-tracked sub-clusters linked to APT29 at moderate confidence: **UNC6293** (small-scale ASP/OAuth phishing of diplomats and academics), **UNC7005 / Storm-2945** (the CaptiveCrunch operators, later pivoting to commodity infostealer delivery via WhatsApp device-linking and Google Cloud OAuth abuse), and **UNC5976** (OAuth phishing with heavier malware use, possibly a *different* Russian service). The headline campaign, **CaptiveCrunch**, compromised shared Wi-Fi infrastructure at hotels, conference centers, and airports to intercept traveling government/defense/NGO personnel — a mass-scale, supply-chain-adjacent access strategy reminiscent of SolarWinds' "compromise the aggregation point" logic, but applied to physical network infrastructure instead of software.

Objectives throughout remain strategic political/intelligence collection, not financial gain.

## MITRE ATT&CK Coverage

| Technique ID | Technique Name | Tactic | Do we have visibility? |
|---|---|---|---|
| T1189 | Drive-by Compromise | Initial Access | Unknown — see hunt-planner Step 0 |
| T1566.002 | Phishing: Spearphishing Link | Initial Access | Unknown — see hunt-planner Step 0 |
| T1566.001 | Phishing: Spearphishing Attachment | Initial Access | Unknown — see hunt-planner Step 0 |
| T1204.002 | User Execution: Malicious File | Execution / Initial Access | Unknown — see hunt-planner Step 0 |
| T1204.001 | User Execution: Malicious Link | Initial Access | Unknown — see hunt-planner Step 0 |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Execution | Unknown — see hunt-planner Step 0 |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | Execution | Unknown — see hunt-planner Step 0 |
| T1543.003 | Create or Modify System Process: Windows Service | Persistence | Unknown — see hunt-planner Step 0 |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | Persistence | Unknown — see hunt-planner Step 0 |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Persistence | Unknown — see hunt-planner Step 0 |
| T1548.002 | Abuse Elevation Control Mechanism: Bypass UAC | Privilege Escalation / Defense Evasion | Unknown — see hunt-planner Step 0 |
| T1112 | Modify Registry | Defense Evasion | Unknown — see hunt-planner Step 0 |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Defense Evasion | Unknown — see hunt-planner Step 0 |
| T1036.004/.005 | Masquerading | Defense Evasion | Unknown — see hunt-planner Step 0 |
| T1027 | Obfuscated Files or Information | Defense Evasion | Unknown — see hunt-planner Step 0 |
| T1497 | Virtualization/Sandbox Evasion | Defense Evasion | Unknown — see hunt-planner Step 0 |
| T1070.004 | Indicator Removal: File Deletion / VSS deletion | Defense Evasion | Unknown — see hunt-planner Step 0 |
| T1555.003 | Credentials from Password Stores: Web Browsers | Credential Access | Unknown — see hunt-planner Step 0 |
| T1528 | Steal Application Access Token | Credential Access | Unknown — see hunt-planner Step 0 |
| T1621 | Multi-Factor Authentication Request Generation (device-code/MFA-flow abuse) | Credential Access | Unknown — see hunt-planner Step 0 |
| T1056.004 | Input Capture: Keylogging | Collection | Unknown — see hunt-planner Step 0 |
| T1115 | Clipboard Data | Collection | Unknown — see hunt-planner Step 0 |
| T1113 | Screen Capture | Collection | Unknown — see hunt-planner Step 0 |
| T1123 | Audio Capture | Collection | Unknown — see hunt-planner Step 0 |
| T1125 | Video Capture | Collection | Unknown — see hunt-planner Step 0 |
| T1005 | Data from Local System | Collection | Unknown — see hunt-planner Step 0 |
| T1120 | Peripheral Device Discovery | Discovery | Unknown — see hunt-planner Step 0 |
| T1071.001 | Application Layer Protocol: Web Protocols | Command and Control | Unknown — see hunt-planner Step 0 |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | Command and Control | Unknown — see hunt-planner Step 0 |
| T1008 | Fallback Channels | Command and Control | Unknown — see hunt-planner Step 0 |
| T1572 | Protocol Tunneling | Command and Control | Unknown — see hunt-planner Step 0 |
| T1090 | Proxy (.002 External / .003 Multi-hop) | Command and Control | Unknown — see hunt-planner Step 0 |
| T1665 | Hide Infrastructure | Command and Control | Unknown — see hunt-planner Step 0 |
| T1195.002 | Supply Chain Compromise: Software Supply Chain | Initial Access | Unknown — see hunt-planner Step 0 |
| T1021.001 | Remote Services: RDP | Lateral Movement / Initial Access | Unknown — see hunt-planner Step 0 |
| T1030 | Data Transfer Size Limits | Exfiltration | Unknown — see hunt-planner Step 0 |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | Unknown — see hunt-planner Step 0 |
| T1020 | Automated Exfiltration | Exfiltration | Unknown — see hunt-planner Step 0 |

## Indicators of Compromise

| Type | Value | Confidence | Source |
|---|---|---|---|
| Malware family | GRAPELOADER (initial-stage loader/fingerprinting tool) | Reported | Check Point Research |
| Malware family | WINELOADER (modular backdoor, RC4-packed) | Reported | Check Point Research; Zscaler ThreatLabz |
| File name | wine.zip / wine.exe / ppcore.dll / vmtools.dll / AppvIsvSubsystems64.dll | Reported | Check Point Research |
| Persistence path / registry key | `C:\Users\User\AppData\Local\POWERPNT\wine.exe`; `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` value "POWERPNT" | Reported | Check Point Research |
| C2/phishing domains | ophibre[.]com, bravecup[.]com, bakenhof[.]com, silry[.]com | Reported | Check Point Research |
| Phishing domains | findcloudflare[.]com, cloudflare.redirectpartners[.]com | Reported | AWS Security Blog |
| Malware family | CornFlake — Go-based Windows RAT (keylog, clipboard/screenshot/audio/video capture, credential theft, exfil) | Reported | Microsoft — CaptiveCrunch |
| File hash (SHA256) | 918fa52ae45ed60ba7cc8bdc99c3cbe9ab92e0375ec31fc05d0d4513be11c59 (CornFlake) | Reported | Microsoft — CaptiveCrunch |
| Malware family | ChocoShell — in-memory PowerShell infostealer (browser cookies, SSO tokens, Wi-Fi creds; AMSI bypass, UAC escalation) | Reported | Microsoft — CaptiveCrunch |
| File hash (SHA256) | be99857449d2856dd5a84e21c8a3d5e0e01456adb44062ddec5a6b4970d8d4 (ChocoShell) | Reported | Microsoft — CaptiveCrunch |
| Tool/component | FruitStone — web C2 operator panel masquerading as "CloudSync Console" | Reported | Microsoft — CaptiveCrunch |
| C2/AitM domains | ms365-device[.]com, ms365-live[.]com, m365-owa[.]com, owa-ms365[.]com | Reported | Microsoft — CaptiveCrunch |
| IP addresses | 31.57.243[.]154, 38.146.28[.]75, 38.146.28[.]132, 104.194.159[.]150, 107.189.26[.]194, 213.145.86[.]112 | Reported | Microsoft — CaptiveCrunch |
| Beacon paths | /t/pixel.gif?m=<status>, /cdn/chunks/polyfill-7e2b.min.js, /t/event | Reported | Microsoft — CaptiveCrunch |
| Registry key / process | `HKLM\SYSTEM\CurrentControlSet\Services\svchost32` ("Cloud Sync Service"); `%APPDATA%\svchost32\svchost32.exe` | Reported | Microsoft — CaptiveCrunch |

*Note: Check Point-sourced hashes showed digit-count irregularities during extraction and require re-verification against the original report before operational blocklist/YARA use (see analysis Source Reputation Notes). Inferred-confidence historical tooling (Cobalt Strike, CozyDuke, FOGGYWEB/MAGICWEB) is omitted here — see the full analysis if needed.*

## Recommended Actions

### Hunt

1. Hunt for OAuth device-code or application-specific-password authentication flows completed shortly after a user reports (or logs show) an unsolicited IT-support contact via Teams/email/phone, evidenced by Entra ID/Azure AD sign-in logs showing device-code grant type paired with anomalous user-agent or geolocation, in the identity provider's sign-in/audit logs.
2. Hunt for endpoint processes matching CornFlake/ChocoShell behavioral fingerprints — a service or scheduled task named to mimic "svchost32"/"Cloud Sync Service" combined with in-memory PowerShell execution, AMSI-tampering API calls, and VSS deletion — evidenced by EDR process-creation, service-installation, and PowerShell script-block logs on endpoints, especially laptops recently connected to hotel/conference/airport Wi-Fi.
3. Hunt for outbound DNS/HTTP connections to newly-registered lookalike Microsoft domains (`*ms365*`, `*owa*` patterns) or to the specific CaptiveCrunch C2 IPs/domains listed above, evidenced by DNS resolution logs, proxy/firewall logs, and TLS SNI records.

### Detect

- **Strong standing-detection candidates** (specific enough, low-noise as documented): the CornFlake/ChocoShell service-masquerading pattern (T1543.003/T1036), the specific known C2 domains/IPs and beacon URI paths (T1071.001), and the AMSI-bypass + UAC-bypass chain (T1562.001/T1548.002) — these have concrete IOCs and distinctive behavioral signatures suitable for Sigma/EDR rules.
- **Needs a hunt first, too broad as stated:** OAuth device-code authentication (T1204.001/T1621) and generic PowerShell execution (T1059.001) are legitimate, high-volume features in most environments — a standing detection without tuned baselines (expected device-code usage, expected PowerShell callers) will be noisy. Scope a hunt to characterize normal usage before building the rule.
- Drive-by/watering-hole compromise (T1189) and RDP-based lateral movement (T1021.001) currently lack durable atomic IOCs in this reporting window and should remain hunt-driven rather than rule-driven until fresh infrastructure indicators emerge.

### Mitigate

- No CVE or unpatched-software exploit was confirmed as an APT29 initial-access vector in this window (see analysis's Related CVEs/Advisories table) — there is no specific patch to prioritize from this intel cycle.
- Configuration-level mitigations directly implied by the intel: restrict or closely monitor OAuth device-code and application-specific-password authentication flows tenant-wide (block if not required for business use); require managed/compliant devices for M365 authentication when traveling; treat hotel/conference/airport Wi-Fi as untrusted (mandate VPN/DoH for traveling staff) given the CaptiveCrunch captive-portal vector.
- Legacy note: CVE-2023-42793 (JetBrains TeamCity) remains the most durable CVE ever tied to APT29 — if any internet-facing TeamCity instances are still unpatched, remediate as a standing hygiene item, though it falls outside this year's reporting window.

## Confidence and Sourcing

Overall confidence in this report is **Moderate-to-High**: the underlying intel-analysis stage was completed in full (not skipped), drawing on primary sources (CISA, MITRE ATT&CK, Microsoft MSTIC, Google GTIG, AWS Security Blog) corroborated by secondary vendor and press coverage. The main confidence caveats, carried forward from the analysis's Open Questions and Gaps:

1. Naming/attribution fragmentation — GTIG's rebrand to "ICE RELIC" plus three sub-clusters (UNC6293, UNC7005/Storm-2945, UNC5976) linked to APT29 at only moderate confidence means this report describes a loose federation of SVR-linked (and possibly SVR-adjacent) activity, not a single monolithic campaign.
2. UNC5976 may belong to a *different* Russian intelligence service entirely — treat as unconfirmed APT29 until independently verified.
3. Device-code phishing attribution nuance — Microsoft tracks this primarily under the distinct Storm-2372 cluster, not "Midnight Blizzard" proper; Volexity separately links a related cluster (CozyLarch) to APT29. This linkage should be sanity-checked before it drives high-priority detection engineering.
4. Government reporting lag — no fresh joint government advisory naming APT29 was published in the past 12 months; all significant in-window sourcing is vendor-driven.
5. No CVE-driven initial access confirmed for APT29 in-window — independently reinforced by both the TTP and CVE-correlation research angles.
6. Check Point-sourced IOCs (GRAPELOADER/WINELOADER) need hash verification before operational use.
7. Two Zimbra CVEs and one Arista VeloCloud CVE surfaced during research with superficial APT29 associations but were verified to have **no** confirmed APT29 attribution — documented in the analysis specifically to prevent false-positive reappearance downstream.
8. No public mutex names, YARA rules, or Sigma rule IDs were found for CaptiveCrunch or GRAPELOADER/WINELOADER — the detection-engineer stage will need to derive rules from behavioral/IOC evidence rather than adapt an existing public rule.

Additionally, this report's **MITRE ATT&CK Coverage** visibility column is entirely `Unknown` because `./threat-hunting/environment-profile.md` has no recorded SIEM/EDR platform, environment type, or log retention — the user should run the `gather` skill standalone to populate real values before the hunt-planner stage finalizes feasibility assessments.

## Appendix: Full Source List

- [CISA AA24-057A — SVR Cyber Actors Adapt Tactics for Initial Cloud Access](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-057a)
- [CISA AA26-204A — Russian State-Supported Cyber Actors Conduct Phishing Campaign Targeting Zimbra (attributed to Laundry Bear/Void Blizzard, not APT29)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-204a)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [MITRE ATT&CK — G0016 APT29](https://attack.mitre.org/groups/G0016/)
- [Microsoft Security Blog — CaptiveCrunch: Midnight Blizzard targets travelers worldwide (Jul 31, 2026)](https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/)
- [Microsoft Security Blog — Help on the line: how a Microsoft Teams support call led to compromise (Mar 16, 2026)](https://www.microsoft.com/en-us/security/blog/2026/03/16/help-on-the-line-how-a-microsoft-teams-support-call-led-to-compromise/)
- [Microsoft Security Blog — Storm-2372 conducts device code phishing campaign (Feb 13, 2025)](https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/)
- [Google Cloud Blog — Distinct Clusters Target Individuals of Interest to Russia](https://cloud.google.com/blog/topics/threat-intelligence/distinct-clusters-target-individuals-of-interest-to-russia)
- [Google Cloud Blog — Updated Cyber Threat Actor Naming System](https://cloud.google.com/blog/topics/threat-intelligence/updated-cyber-threat-actor-naming-system)
- [AWS Security Blog — Amazon disrupts watering hole campaign by Russia's APT29](https://aws.amazon.com/blogs/security/amazon-disrupts-watering-hole-campaign-by-russias-apt29/)
- [Volexity — Multiple Russian Threat Actors Targeting Microsoft Device Code Authentication](https://www.volexity.com/blog/2025/02/13/multiple-russian-threat-actors-targeting-microsoft-device-code-authentication/)
- [Trend Micro — Earth Koshchei Coopts Red Team Tools in Complex RDP Attacks](https://www.trendmicro.com/en_us/research/24/l/earth-koshchei.html)
- [The Record (Recorded Future News) — Russian hackers using red team tools for large-scale espionage](https://therecord.media/russian-hackers-red-team-espionage)
- [Check Point Research — Renewed APT29 Phishing Campaign Against European Diplomats](https://research.checkpoint.com/2025/apt29-phishing-campaign/) — `[UNVERIFIED SOURCE]`
- [Zscaler ThreatLabz — WINELOADER Analysis](https://www.zscaler.com/blogs/security-research/european-diplomats-targeted-apt29-cozy-bear-wineloader)
- [The Hacker News — Amazon Disrupts APT29 Watering Hole Campaign](https://thehackernews.com/2025/08/amazon-disrupts-apt29-watering-hole.html) — `[UNVERIFIED SOURCE]` (secondary write-up)
- [The Hacker News — Device Code Phishing Hits 340+ Microsoft 365 Orgs (Mar 2026)](https://thehackernews.com/2026/03/device-code-phishing-hits-340-microsoft.html) — `[UNVERIFIED SOURCE]`
- [The Hacker News — APT29 Deploys GRAPELOADER Malware](https://thehackernews.com/2025/04/apt29-deploys-grapeloader-malware.html) — `[UNVERIFIED SOURCE]`
- [The Hacker News — Suspected Russian Hackers Abuse Google OAuth and WhatsApp Linking](https://thehackernews.com/2026/08/suspected-russian-hackers-abuse-google.html) — `[UNVERIFIED SOURCE]`
- [BetaNews — CaptiveCrunch: Midnight Blizzard targets hotel Wi-Fi](https://betanews.com/article/captivecrunch-midnight-blizzard-hotel-wifi/) — `[UNVERIFIED SOURCE]`
- [SecurityWeek — Google Adopts New Threat Actor Naming System](https://www.securityweek.com/google-adopts-new-threat-actor-naming-system/) — `[UNVERIFIED SOURCE]`
- [SecurityWeek — Hackers Target Zimbra Servers in Active Exploitation Campaign](https://www.securityweek.com/hackers-target-zimbra-servers-in-active-exploitation-campaign/) — `[UNVERIFIED SOURCE]`
- [SecurityWeek — Critical Arista VeloCloud Orchestrator Vulnerability Exploited as Zero-Day](https://www.securityweek.com/critical-arista-velocloud-orchestrator-vulnerability-exploited-as-zero-day/) — `[UNVERIFIED SOURCE]`
- [Help Net Security — Zimbra CVE-2026-73570 compromised instances](https://www.helpnetsecurity.com/2026/08/25/zimbra-cve-2026-73570-compromised/) — `[UNVERIFIED SOURCE]`
- [Mitiga — Microsoft Breach by Midnight Blizzard (APT29)](https://www.mitiga.io/blog/microsoft-breach-by-midnight-blizzard-apt29-what-happened-and-what-now) — `[UNVERIFIED SOURCE]`
