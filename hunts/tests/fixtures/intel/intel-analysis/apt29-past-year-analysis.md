# Intel Analysis: apt29-past-year

## Source Material

No document was supplied by the user; the request ("apt29 over the past year") was researched entirely via web sources by four parallel research angles (Actor Profile, ATT&CK/TTP Mapping, IOC Extraction, Related CVE/Advisory Correlation), scoped to activity and reporting from roughly September 2025 through September 2026 (today's date: 2026-09-07). Where a campaign's foundational reporting fell just outside that window (e.g., Feb–Apr 2025) but describes tooling/tradecraft still active or directly precursor to in-window activity, it is included and marked as background/lineage.

Primary sources consulted across all four angles:
- CISA: [AA24-057A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-057a), [AA26-204A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-204a), [KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- MITRE ATT&CK: [G0016 — APT29](https://attack.mitre.org/groups/G0016/)
- Microsoft Security Blog: [CaptiveCrunch (Jul 31, 2026)](https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/), [Help on the line (Mar 16, 2026)](https://www.microsoft.com/en-us/security/blog/2026/03/16/help-on-the-line-how-a-microsoft-teams-support-call-led-to-compromise/), [Storm-2372 device code phishing (Feb 13, 2025)](https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/)
- Google Cloud Blog (GTIG/Mandiant): [Distinct Clusters Target Individuals of Interest to Russia](https://cloud.google.com/blog/topics/threat-intelligence/distinct-clusters-target-individuals-of-interest-to-russia), [Updated Cyber Threat Actor Naming System](https://cloud.google.com/blog/topics/threat-intelligence/updated-cyber-threat-actor-naming-system)
- AWS Security Blog: [Amazon disrupts watering hole campaign by Russia's APT29](https://aws.amazon.com/blogs/security/amazon-disrupts-watering-hole-campaign-by-russias-apt29/)
- Volexity: [Multiple Russian Threat Actors Targeting Microsoft Device Code Authentication](https://www.volexity.com/blog/2025/02/13/multiple-russian-threat-actors-targeting-microsoft-device-code-authentication/)
- Trend Micro: [Earth Koshchei Coopts Red Team Tools in Complex RDP Attacks](https://www.trendmicro.com/en_us/research/24/l/earth-koshchei.html)
- Check Point Research: [Renewed APT29 Phishing Campaign Against European Diplomats](https://research.checkpoint.com/2025/apt29-phishing-campaign/) — `[UNVERIFIED SOURCE — not on curated high-reputation list, though a generally well-regarded vendor]`
- Secondary/aggregator coverage (The Hacker News, SecurityWeek, BetaNews, Mitiga, Help Net Security, The Record) — `[UNVERIFIED SOURCE]` where cited standalone; used mainly to corroborate primary-source claims above.

## Actor Profile

**Attribution/Sponsorship:** APT29 is attributed with high confidence by US, UK, and allied governments to Russia's Foreign Intelligence Service (SVR). This attribution is reaffirmed in the most recent joint government advisory framing (CISA/NCSC-UK [AA24-057A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-057a), Feb 2024) and remains the operating assumption in all 2025–2026 vendor reporting. **No new joint government advisory specific to APT29 was published in the Sept 2025–Sept 2026 window** — the most recent government-attributed advisory is still the Feb 2024 one, a notable gap: government reporting has lagged vendor reporting this cycle.

**Aliases:** Cozy Bear (CrowdStrike), Midnight Blizzard / NOBELIUM (Microsoft), The Dukes, UNC2452/UNC2652 (Mandiant, historical/SolarWinds-era), Cloaked Ursa, BlueBravo (Recorded Future), plus historical designations (IRON RITUAL, YTTRIUM, CozyDuke, Dark Halo) — [MITRE ATT&CK G0016](https://attack.mitre.org/groups/G0016/).

**Naming development in the past year:** In July 2026, Google Threat Intelligence Group (GTIG) overhauled its actor-naming taxonomy and rebranded APT29 as **ICE RELIC**, cross-referencing prior UNC designations under the new name — [Google Cloud Blog](https://cloud.google.com/blog/topics/threat-intelligence/updated-cyber-threat-actor-naming-system). GTIG's ICE RELIC reporting tracks several operational sub-clusters this year at **moderate confidence** (not certainty):
- **UNC6293** — initial-access focused, moderate-confidence link to ICE RELIC/APT29.
- **UNC7005** (= Microsoft's **Storm-2945**) — the sub-cluster behind CaptiveCrunch; moderate-confidence link.
- **UNC5976** — authentication/OAuth-focused; GTIG assesses this as *possibly a distinct Russian intelligence service*, not APT29/SVR. Treated here as **not confirmed APT29** — see Open Questions.

**Historical context (brief background):** Active since at least 2008. Notable prior operations include the 2015–16 DNC intrusion, the 2020 SolarWinds/Sunburst supply-chain compromise (UNC2452/Dark Halo), COVID-19 vaccine-research targeting, sustained diplomatic-phishing operations, and the January 2024 compromise of Microsoft's own corporate email environment (senior leadership mailboxes).

**Targeting patterns and sectors:** Governments, foreign ministries, embassies/diplomatic missions, defense industrial base, think tanks, NGOs, academia, aerospace, healthcare, energy, and cloud/technology providers; per CISA's 2024 baseline, expanded to aviation, education, law enforcement, and local/state government finance departments. Geography skews to Europe, the US, Ukraine, NATO members, and (per 2026 GTIG reporting) Armenia.

**Notable campaigns, past year (Sept 2025–Sept 2026):**

| Campaign / Cluster | Vendor | Timeframe | Summary |
|---|---|---|---|
| GRAPELOADER/WINELOADER "wine-tasting" phishing | Check Point Research | Jan–Apr 2025 (reported Apr 15, 2025; background/lineage) | Phishing impersonating a European MFA with wine-tasting invitations, delivering the GRAPELOADER loader and WINELOADER modular backdoor via DLL side-loading against European MFAs/embassies. |
| UNC6293 Application-Specific-Password / OAuth phishing | GTIG / Volexity | Jun, Oct, Dec 2025; Jun 2026 | Small-scale, highly targeted phishing tricking diplomats/academics into generating ASPs or OAuth codes that bypass MFA, impersonating the US State Dept. and European security-conference organizers. |
| Microsoft Teams "IT support" vishing | Microsoft MSTIC | Through late 2025–Mar 2026 | Impersonation of IT help-desk staff over Teams chat/voice, using compromised M365 tenants to register lookalike domains and harvest credentials/device-code tokens. |
| **CaptiveCrunch** (Storm-2945/UNC7005) | Microsoft MSTIC; corroborated by ReliaQuest, GTIG | Feb 2026 (AI-augmented phishing begins) → Jul 31, 2026 (full disclosure) | Largest campaign of the year: compromise of hospitality-sector captive-portal Wi-Fi (hotels, conference centers, airports) worldwide, DNS/HTTP traffic manipulation redirecting travelers to doppelganger Microsoft domains for AitM device-code/OAuth phishing; delivered ClickFix-style lures dropping Windows RATs (CornFlake) and a PowerShell infostealer (ChocoShell). Microsoft states AI-assisted tooling supported a "significant portion" of campaign infrastructure. |
| UNC7005 malware-as-a-service pivot | GTIG | Apr–Aug 2026 | Broadened to infostealer delivery via commodity MaaS (VIDAR, ATOMIC/AtomicStealer, ENGINELIGHT, CHERRYPIE/ChocoShell); began abusing WhatsApp device-linking and Google Cloud OAuth projects for token harvesting against US academics and diplomats. |
| UNC5976 (unconfirmed APT29 link) | GTIG | Mar–Aug 2026 | OAuth phishing via fake file-sharing pages, dedicated post-compromise infrastructure, heavier malware footprint than other clusters — GTIG flags this as *possibly a different* Russian intelligence service. |

**Objectives:** Strategic/political intelligence collection (espionage) — diplomatic, government-policy, defense, and technology targets — not financial gain. The historical "access broker" pattern from SolarWinds recurs this year in a new form: CaptiveCrunch's hijacking of hospitality Wi-Fi functions as a mass-scale interception point against traveling government/defense/NGO personnel, a supply-chain-adjacent vector rather than a single-target compromise.

**Recent shifts in tradecraft (last 12 months):**
1. **Cloud/identity-centric operations over malware** — sustained OAuth device-code phishing, ASP abuse, and token theft largely supplanting malware-first initial access.
2. **AI-augmented operations** — Microsoft explicitly attributes AI-assisted malware/infrastructure generation to Storm-2945 since Feb 2026, a first for confirmed APT29-linked tradecraft.
3. **Novel infrastructure target: captive portals/hospitality Wi-Fi** — a genuinely new access vector, extending prior watering-hole tradecraft (compromised websites) to physical network infrastructure.
4. **Collaboration-platform abuse** — sustained pivot to Microsoft Teams chat/voice phishing impersonating IT help desks.
5. **Fragmentation into multiple GTIG-tracked sub-clusters** with varying OPSEC quality (UNC7005 assessed as having "poorer OPSEC" than UNC6293), suggesting organizational diversification or an overlapping contractor ecosystem.

**Confidence note:** All vendor-reported 2025–2026 clusters (UNC6293, UNC7005/Storm-2945, CaptiveCrunch) are linked to APT29/ICE RELIC/Midnight Blizzard at **moderate confidence** per the vendors' own language, not certainty. This nuance should carry through to the hunt plan and detections rather than being treated as confirmed APT29 attribution.

## ATT&CK / TTP Mapping

| Technique ID | Technique Name | Tactic | Evidence |
|---|---|---|---|
| T1189 | Drive-by Compromise | Initial Access | CaptiveCrunch hijacked hotel/venue captive-portal Wi-Fi to serve fake update prompts and malware to travelers ([Microsoft](https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/)). |
| T1566.002 | Phishing: Spearphishing Link | Initial Access | APT29 compromised legitimate websites, injecting JS redirecting ~10% of visitors to Cloudflare-themed phishing pages (Aug 2025) ([AWS](https://aws.amazon.com/blogs/security/amazon-disrupts-watering-hole-campaign-by-russias-apt29/)). |
| T1566.001 | Phishing: Spearphishing Attachment | Initial Access | GRAPELOADER/WINELOADER wine-tasting lures delivered ZIP attachments with DLL-sideloaded payloads ([Check Point](https://research.checkpoint.com/2025/apt29-phishing-campaign/)). |
| T1204.002 | User Execution: Malicious File | Execution / Initial Access | CaptiveCrunch used ClickFix-style prompts for victims to manually run malicious commands ([Microsoft](https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/)). |
| T1204.001 | User Execution: Malicious Link | Initial Access | Device-code/OAuth-code phishing requires the victim to click a link and enter an attacker-supplied code; 340+ orgs affected as of Mar 2026 ([Microsoft](https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/); [THN](https://thehackernews.com/2026/03/device-code-phishing-hits-340-microsoft.html)). |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Execution | ChocoShell is a PowerShell-based infostealer executed entirely in-memory (Microsoft, CaptiveCrunch). |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | Execution | CornFlake installer/UAC-bypass chain invokes cmd.exe (Microsoft, CaptiveCrunch). |
| T1543.003 | Create or Modify System Process: Windows Service | Persistence | CornFlake installs as a fake "svchost32" service with a watchdog (Microsoft, CaptiveCrunch). |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | Persistence | GRAPELOADER used `HKCU\...\Run` value "POWERPNT"; CaptiveCrunch payloads also use Run-key persistence ([Check Point](https://research.checkpoint.com/2025/apt29-phishing-campaign/); Microsoft). |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Persistence | Named scheduled tasks used as a persistence watchdog in the CaptiveCrunch toolset; consistent with MITRE's longstanding G0016 entry ([MITRE ATT&CK](https://attack.mitre.org/groups/G0016/)). |
| T1548.002 | Abuse Elevation Control Mechanism: Bypass UAC | Privilege Escalation / Defense Evasion | ChocoShell uses a 3-stage silent UAC bypass (SilentCleanup, wsreset.exe, sdclt.exe COM hijack) (Microsoft, CaptiveCrunch). |
| T1112 | Modify Registry | Defense Evasion | UAC-bypass registry modifications deleted post-execution to reduce forensic traces (Microsoft, CaptiveCrunch). |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Defense Evasion | ChocoShell performs AMSI tampering via .NET reflection (Microsoft, CaptiveCrunch). |
| T1036.004/.005 | Masquerading | Defense Evasion | CornFlake's "svchost32" service name and fake OS/app update dialogs masquerade as legitimate processes (Microsoft, CaptiveCrunch). |
| T1027 | Obfuscated Files or Information | Defense Evasion | CornFlake (Go) uses `garble` symbol randomization and XOR/Base64 string encoding; watering-hole JS also Base64-obfuscated (Microsoft; AWS). |
| T1497 | Virtualization/Sandbox Evasion | Defense Evasion | ChocoShell performs timing-based VM/sandbox detection before executing (Microsoft, CaptiveCrunch). |
| T1070.004 | Indicator Removal: File Deletion / VSS deletion | Defense Evasion | ChocoShell deletes Volume Shadow Copies post-exfiltration (Microsoft, CaptiveCrunch). |
| T1555.003 | Credentials from Password Stores: Web Browsers | Credential Access | CornFlake and ChocoShell harvest browser-stored credentials/session cookies (SYSTEM-token impersonation to bypass Chrome App-Bound Encryption; Firefox SQLite access) (Microsoft, CaptiveCrunch). |
| T1528 | Steal Application Access Token | Credential Access | CaptiveCrunch and device-code phishing both target M365/Entra SSO and WAM tokens for persistent cloud access (Microsoft, both reports). |
| T1621 | Multi-Factor Authentication Request Generation (device-code/MFA-flow abuse) | Credential Access | Abuse of Microsoft Entra ID's legitimate device-code auth flow to obtain a valid, MFA-satisfying token without a traditional prompt to the victim's device (Microsoft, Storm-2372; THN Mar 2026). |
| T1056.004 | Input Capture: Keylogging | Collection | CornFlake implements Raw-Input-API keystroke capture (Microsoft, CaptiveCrunch). |
| T1115 | Clipboard Data | Collection | CornFlake monitors clipboard with SHA-256 dedup of captured content (Microsoft, CaptiveCrunch). |
| T1113 | Screen Capture | Collection | CornFlake takes idle-triggered and on-demand screenshots (Microsoft, CaptiveCrunch). |
| T1123 | Audio Capture | Collection | CornFlake records microphone audio via WASAPI (Microsoft, CaptiveCrunch). |
| T1125 | Video Capture | Collection | CornFlake captures webcam video via Media Foundation (Microsoft, CaptiveCrunch). |
| T1005 | Data from Local System | Collection | CornFlake performs an 18-category host-intelligence sweep plus Outlook MRU/file-system monitoring (Microsoft, CaptiveCrunch). |
| T1120 | Peripheral Device Discovery | Discovery | CornFlake monitors/scans connected USB drives (Microsoft, CaptiveCrunch). |
| T1071.001 | Application Layer Protocol: Web Protocols | Command and Control | CornFlake uses a custom JSON protocol over HTTP/HTTPS with ECDH P-256-encrypted sessions (Microsoft, CaptiveCrunch). |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | Command and Control | ECDH key exchange with SHA-256 session-key derivation secures CornFlake C2 traffic (Microsoft, CaptiveCrunch). |
| T1008 | Fallback Channels | Command and Control | CornFlake beacon profiles include DNS-based fallback domains (Microsoft, CaptiveCrunch). |
| T1572 | Protocol Tunneling | Command and Control | "FruitStone" operator panel supports a multi-proxy relay architecture with TLS-connection tracking (Microsoft, CaptiveCrunch). |
| T1090 | Proxy (.002 External / .003 Multi-hop) | Command and Control | The "Earth Koshchei" rogue-RDP campaign (lineage, late 2024/early 2025) used ~193 proxy servers plus TOR/commercial/residential proxies in front of 34 rogue RDP servers ([Trend Micro](https://www.trendmicro.com/en_us/research/24/l/earth-koshchei.html)). |
| T1665 | Hide Infrastructure | Command and Control | APT29 rapidly migrated watering-hole redirect infrastructure across hosting providers, mimicking a Cloudflare domain once blocked (AWS). |
| T1195.002 | Supply Chain Compromise: Software Supply Chain | Initial Access | Historical baseline (SolarWinds/SUNBURST); **no new supply-chain compromise reported in the Sept 2025–Sept 2026 window** — included for completeness only ([MITRE ATT&CK](https://attack.mitre.org/groups/G0016/)). |
| T1021.001 | Remote Services: RDP | Lateral Movement / Initial Access | "Earth Koshchei" rogue-RDP campaign used malicious `.rdp` config files connecting outbound to attacker-controlled RDP servers, exposing victim file systems/clipboard via RDP redirection ([Trend Micro](https://www.trendmicro.com/en_us/research/24/l/earth-koshchei.html)). |
| T1030 | Data Transfer Size Limits | Exfiltration | CornFlake throttles exfiltration to ~1,000 files or 500MB per cycle (Microsoft, CaptiveCrunch). |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | CornFlake exfiltrates GZip-compressed, Base64-wrapped JSON over its C2 channel (Microsoft, CaptiveCrunch). |
| T1020 | Automated Exfiltration | Exfiltration | CornFlake performs real-time file monitoring with automated upload of matched extensions (Microsoft, CaptiveCrunch). |

*Note: device-code phishing (T1204.001, T1621) is tracked by Microsoft primarily under the distinct cluster Storm-2372, not "Midnight Blizzard" proper; Volexity separately attributes a related-but-distinct cluster it calls CozyLarch to APT29 using the same technique. Included here as APT29-adjacent tradecraft at moderate confidence — see Open Questions.*

## Indicators of Compromise (IOCs)

| Type | Value | Confidence | Source |
|---|---|---|---|
| Malware family | GRAPELOADER (initial-stage loader/fingerprinting tool) | Reported | [Check Point Research](https://research.checkpoint.com/2025/apt29-phishing-campaign/) `[UNVERIFIED SOURCE]` |
| Malware family | WINELOADER (modular backdoor, RC4-packed) | Reported | [Check Point](https://research.checkpoint.com/2025/apt29-phishing-campaign/) `[UNVERIFIED SOURCE]`; [Zscaler ThreatLabz](https://www.zscaler.com/blogs/security-research/european-diplomats-targeted-apt29-cozy-bear-wineloader) |
| File name | wine.zip / wine.exe (legit PPT exe, DLL side-load) / ppcore.dll (GRAPELOADER) / vmtools.dll (WINELOADER) / AppvIsvSubsystems64.dll (decoy) | Reported | [Check Point](https://research.checkpoint.com/2025/apt29-phishing-campaign/) `[UNVERIFIED SOURCE]` |
| File hash (SHA256) | GRAPELOADER/WINELOADER samples per Check Point — **digit-count irregularities found in automated extraction; re-verify against original report before operational use** | Reported (needs verification) | [Check Point](https://research.checkpoint.com/2025/apt29-phishing-campaign/) `[UNVERIFIED SOURCE]` |
| Persistence path / registry key | `C:\Users\User\AppData\Local\POWERPNT\wine.exe`; `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` value "POWERPNT" | Reported | [Check Point](https://research.checkpoint.com/2025/apt29-phishing-campaign/) `[UNVERIFIED SOURCE]` |
| C2/phishing domains | ophibre[.]com, bravecup[.]com, bakenhof[.]com, silry[.]com | Reported | [Check Point](https://research.checkpoint.com/2025/apt29-phishing-campaign/) `[UNVERIFIED SOURCE]` |
| Phishing domains | findcloudflare[.]com, cloudflare.redirectpartners[.]com | Reported | [AWS Security Blog](https://aws.amazon.com/blogs/security/amazon-disrupts-watering-hole-campaign-by-russias-apt29/) (via [THN](https://thehackernews.com/2025/08/amazon-disrupts-apt29-watering-hole.html) `[UNVERIFIED SOURCE]` for secondary write-up) |
| Technique/tradecraft | Injected obfuscated JS redirecting ~10% of watering-hole visitors to actor infrastructure | Reported | [AWS Security Blog](https://aws.amazon.com/blogs/security/amazon-disrupts-watering-hole-campaign-by-russias-apt29/) |
| Malware family | CornFlake — Go-based Windows RAT (keylog, clipboard/screenshot/audio/video capture, credential theft, exfil) | Reported | [Microsoft — CaptiveCrunch](https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/) |
| File hash (SHA256) | 918fa52ae45ed60ba7cc8bdc99c3cbe9ab92e0375ec31fc05d0d4513be11c59 (CornFlake, first seen 2026-07-03) | Reported | Microsoft — CaptiveCrunch |
| Malware family | ChocoShell — in-memory PowerShell infostealer (browser cookies, SSO tokens, Wi-Fi creds; AMSI bypass, UAC escalation) | Reported | Microsoft — CaptiveCrunch |
| File hash (SHA256) | be99857449d2856dd5a84e21c8a3d5e0e01456adb44062ddec5a6b4970d8d4 (ChocoShell, first seen 2026-07-10) | Reported | Microsoft — CaptiveCrunch |
| Tool/component | FruitStone — web C2 operator panel masquerading as "CloudSync Console" (Acuity Systems branding) | Reported | Microsoft — CaptiveCrunch |
| C2/AitM domains | ms365-device[.]com, ms365-live[.]com, m365-owa[.]com, owa-ms365[.]com | Reported | Microsoft — CaptiveCrunch |
| IP addresses | 31.57.243[.]154, 38.146.28[.]75, 38.146.28[.]132, 104.194.159[.]150, 107.189.26[.]194, 213.145.86[.]112 | Reported | Microsoft — CaptiveCrunch |
| Beacon paths | /t/pixel.gif?m=<status>, /cdn/chunks/polyfill-7e2b.min.js, /t/event | Reported | Microsoft — CaptiveCrunch |
| Registry key / process | `HKLM\SYSTEM\CurrentControlSet\Services\svchost32` (DisplayName "Cloud Sync Service"); `%APPDATA%\svchost32\svchost32.exe` | Reported | Microsoft — CaptiveCrunch |
| Execution pattern | ClickFix-style cmd.exe/PowerShell lures; abuse of WinGet DSC host process ("ConfigurationRemotingServer") | Reported | Microsoft — CaptiveCrunch |
| Delivery lure | Malware disguised as browser/OS updates via hijacked hotel/venue captive-portal DNS/HTTP manipulation | Reported | Microsoft — CaptiveCrunch; [BetaNews](https://betanews.com/article/captivecrunch-midnight-blizzard-hotel-wifi/) `[UNVERIFIED SOURCE]` |
| Tool (historical/background) | Cobalt Strike Beacon; CozyDuke/"Duke" family implants; FOGGYWEB, MAGICWEB (AD FS-targeting) | Inferred — no fresh 2025-2026 sighting confirmed in sources reviewed | [MITRE ATT&CK G0016](https://attack.mitre.org/groups/G0016/); [CISA AA24-057A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-057a) |

**Cross-check against ATT&CK mapping:** CornFlake and ChocoShell IOCs map cleanly to the Collection (T1056.004/T1115/T1113/T1123/T1125/T1005), Credential Access (T1555.003), Persistence (T1543.003/T1053.005), Defense Evasion (T1548.002/T1112/T1562.001/T1036/T1027/T1497/T1070.004), and C2 (T1071.001/T1573.001/T1008/T1572) rows above. GRAPELOADER/WINELOADER IOCs map to T1566.001, T1547.001. No IOC in this table is orphaned from a mapped technique; conversely, several mapped techniques (T1189, T1204.001/.002, T1621, T1528, T1090, T1021.001, T1665, T1195.002) currently have no durable atomic IOC (domain/hash) attached — they rely on TTP-level/behavioral detection instead, which should be reflected in the hunt plan.

## Related CVEs / Advisories

| CVE/Advisory | Summary | Relevance |
|---|---|---|
| No CVE — Microsoft "CaptiveCrunch" (2026-07-31) | Storm-2945/Midnight Blizzard compromised shared hotel/venue captive-portal infrastructure to redirect guests to phishing pages and deliver CornFlake/ChocoShell | Most significant primary-source APT29 reporting in-window; initial access via infrastructure compromise + abuse of a legitimate auth feature, not a patchable flaw |
| No CVE — Microsoft "Storm-2372 device code phishing" (2025-02-13) + Volexity corroboration | At least three Russian clusters abusing Microsoft's OAuth device-code flow via fake Teams/meeting invites | Direct tradecraft precursor to CaptiveCrunch's 2026 device-code phishing; establishes continuity of this non-CVE technique |
| No CVE — AWS/Amazon watering-hole disruption (2025-08) | Amazon disrupted an APT29 watering-hole operation also abusing device-code authentication | Reinforces that 2025–2026 initial-access tooling centers on identity/auth abuse, not software CVEs |
| CVE-2023-42793 (JetBrains TeamCity auth bypass) — CISA KEV | Historically and repeatedly cited as exploited by APT29 for mass server compromise (Dec 2023 joint advisory) | Outside the 12-month window but the most durable CVE ever formally attributed to APT29; no newer CVE has replaced it |
| AA24-057A (CISA/NCSC-UK, 2024-02-26) | Describes APT29's shift to cloud-native authentication targeting over on-prem CVE exploitation | Outside the window but explains *why* 2025–2026 campaigns are CVE-light and identity-centric |
| CVE-2025-66376 (Zimbra stored XSS) + AA26-204A (2026-07-23) | Attributed by CISA/NSA/FBI to **Laundry Bear / Void Blizzard (CL-STA-1114/TA488)** | **Not APT29** — explicitly disambiguated; frequently confused with APT29 in secondary reporting. One vendor speculated Russian-intelligence sourcing of the exploit but did not tie it to APT29 `[UNVERIFIED SOURCE]` |
| CVE-2026-73570 (Zimbra SNMP unauth RCE) — CISA KEV, Aug 2026 | Actively exploited (270+ compromised instances per CERT Polska/Shadowserver) | **No attribution to any specific actor.** Included only because Zimbra is a repeatedly-targeted platform by Russian-nexus actors historically; **do not conflate with APT29** |
| CVE-2026-16812 (Arista VeloCloud Orchestrator unauth OS command injection, CVSS 10.0) — CISA KEV | Critical zero-day, actively exploited; Arista has not disclosed actor attribution | Initial automated search summaries incorrectly implied an APT29 link — **verified against primary reporting and found no such attribution exists**. Listed to correct this false lead |

**Key finding:** Unlike many APT actors, APT29's confirmed activity in this 12-month window is overwhelmingly phishing- and identity-abuse-driven rather than CVE-driven. No CISA KEV entry, NVD CVE, or vendor patch advisory in the window is confirmed by a primary source to be directly exploited by APT29 itself. This absence is itself a meaningful finding, corroborating the Actor Profile and ATT&CK sections' assessment of a cloud-identity/OAuth-centric operating tempo.

## Source Reputation Notes

- **Check Point Research** (GRAPELOADER/WINELOADER campaign, all associated hashes/domains/file paths) is flagged `[UNVERIFIED SOURCE]` by the researching agent — not on the framework's curated high-reputation source list, though a generally well-regarded commercial vendor. The reported SHA-256 hashes additionally showed digit-count irregularities during automated extraction and require manual re-verification against the original report before any operational (blocklist/YARA) use.
- **The Hacker News, BetaNews, SecurityWeek, Mitiga, Help Net Security, The Record** — used only as secondary corroboration/aggregator coverage of primary vendor or government reporting; flagged `[UNVERIFIED SOURCE]` wherever cited without an underlying primary source.
- A claim of an APT29 iOS zero-day ("Operation SmoothOperator," citing a non-standard/likely-fabricated "CVE-2025-1234") sourced from `blog.cybernytronx.com` could not be corroborated by any curated source and is assessed as very likely low-quality/AI-generated content. **Excluded entirely from this analysis; flagged here only as a rejected lead.**
- Claims linking APT29 to VMware ESXi TOCTOU flaws (CVE-2025-22224/22225/22226) were found only in secondary blog summaries with no confirming primary source (Broadcom's own advisory does not attribute exploitation to APT29). **Not included in the CVE table pending stronger sourcing.**
- CISA, MITRE ATT&CK, Microsoft, Google Cloud/GTIG, AWS Security Blog, and Volexity are treated as high-reputation/primary throughout this analysis.

## Open Questions and Gaps

1. **Naming/attribution fragmentation:** GTIG's July 2026 rebrand of APT29 to "ICE RELIC," combined with three actively-tracked sub-clusters (UNC6293, UNC7005/Storm-2945, UNC5976) reported at only *moderate confidence* to the parent actor, means "APT29 activity over the past year" is less a single coherent campaign set than a loose federation of Russian-SVR-linked (and possibly SVR-adjacent) clusters. Downstream hunt planning should treat CaptiveCrunch/Storm-2945 findings as high-confidence-adjacent but not identical to classic APT29 attribution.
2. **UNC5976 is explicitly flagged by GTIG as possibly a *different* Russian intelligence service**, not SVR/APT29. It is included in the Actor Profile for completeness but should **not** be treated as confirmed APT29 in any downstream detection or hunt hypothesis without independent confirmation.
3. **Device-code phishing attribution nuance:** Microsoft tracks this technique primarily under the distinct cluster Storm-2372, not "Midnight Blizzard" proper. Volexity separately links a related-but-distinct cluster (CozyLarch) to APT29. The Actor Profile, TTP, and IOC angles all treat this as APT29-adjacent at moderate confidence — a human analyst should sanity-check this linkage before it drives high-priority detection engineering.
4. **Government reporting lag:** No fresh joint US/UK/allied government advisory specifically naming APT29 was published in the past 12 months (the last remains Feb 2024's AA24-057A), even though vendor reporting (Microsoft, GTIG) was prolific. This is worth noting as a coverage gap rather than an indication of reduced activity.
5. **No CVE-driven initial access confirmed for APT29 in-window** — reinforced independently by both the ATT&CK/TTP and CVE-correlation research angles (no contradiction here, but flagged as a notable negative finding: hunt/detection focus should weight identity- and phishing-based TTPs far more heavily than vulnerability-scanning or patch-gap hunting for this actor).
6. **Check Point-sourced IOCs (GRAPELOADER/WINELOADER) need hash verification** before any blocklist/YARA operational use — flagged consistently by the IOC and reputation-notes findings.
7. **Two CVEs (Zimbra CVE-2025-66376/AA26-204A and CVE-2026-73570) and one CVE (Arista VeloCloud CVE-2026-16812) surfaced during research with superficial APT29 associations in secondary sources but were verified to have no confirmed APT29 attribution.** These are documented above specifically to prevent their reappearing as false positives in later pipeline stages.
8. **No mutex names, YARA rules, or published Sigma rule identifiers** were found for the CaptiveCrunch or GRAPELOADER/WINELOADER toolsets in the sources reviewed — the `detection-engineer` stage will need to derive detection logic from the behavioral/IOC evidence above rather than adapting an existing public rule.
