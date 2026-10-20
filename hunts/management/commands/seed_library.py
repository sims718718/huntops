"""Seed the task library with reference material.

Two kinds, both read-only once seeded (hunters duplicate to make one theirs):

  curated - hand-written SPL worked examples showing how to build out a task
  sigma   - breadth, generated from SigmaHQ's rules-threat-hunting collection

Re-running never clobbers an edit: existing seed keys are skipped unless --force.
Techniques are attached last so the Sigma auto-attach picks up vetted rules for them.
"""

import yaml
from django.core.management.base import BaseCommand

from hunts.models import DataSource, LibraryTask, SigmaRule, Technique

CURATED = [
    {
        "seed_key": "kerberoasting-rc4",
        "title": "Kerberoasting: accounts requesting many RC4 service tickets",
        "techniques": ["T1558.003"],
        "data_sources": ["WinEventLog:Security"],
        "query": """index=wineventlog sourcetype="WinEventLog:Security" EventCode=4769
    Ticket_Encryption_Type=0x17
    Service_Name!="krbtgt" Service_Name!="*$"
| stats count dc(Service_Name) as service_count values(Service_Name) as services
        min(_time) as first_seen max(_time) as last_seen
        by Account_Name, Client_Address
| where service_count >= 5
| convert ctime(first_seen) ctime(last_seen)
| sort - service_count""",
        "expected_positive": (
            "One account requesting RC4 (0x17) service tickets for many distinct SPNs in a "
            "short window, often from a workstation rather than a server."
        ),
        "expected_benign": (
            "Most accounts request a handful of SPNs, steadily, from their own host. Legacy "
            "applications that genuinely negotiate RC4 show a stable, small service list."
        ),
        "notes": (
            "Start by baselining service_count over 30 days before fixing the >= 5 threshold - "
            "in most estates the 95th percentile is 2-3. Exclude vulnerability scanners and "
            "backup accounts by Client_Address, not by Account_Name, or you blind yourself to "
            "a compromised scanner account. Domain controllers still issuing RC4 at all is a "
            "finding in its own right (Security Control Issue), separate from any hunt result."
        ),
    },
    {
        "seed_key": "dcsync",
        "title": "DCSync: directory replication requested by a non-DC account",
        "techniques": ["T1003.006"],
        "data_sources": ["WinEventLog:Security"],
        "query": """index=wineventlog sourcetype="WinEventLog:Security" EventCode=4662
    (Properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*"
     OR Properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*"
     OR Properties="*89e95b76-444d-4c62-991a-0facbeda640c*")
    Account_Name!="*$"
| stats count min(_time) as first_seen values(Object_Name) as objects
        by Account_Name, host
| convert ctime(first_seen)""",
        "expected_positive": (
            "A user account (not ending in $) requesting the DS-Replication-Get-Changes GUIDs. "
            "Almost always credential theft - Mimikatz lsadump::dcsync or equivalent."
        ),
        "expected_benign": (
            "Domain controller computer accounts replicating with each other, which the "
            "Account_Name!=\"*$\" filter already removes."
        ),
        "notes": (
            "The three GUIDs are Get-Changes, Get-Changes-All and Get-Changes-In-Filtered-Set. "
            "Known false positives worth allow-listing explicitly rather than broadly: Azure AD "
            "Connect (MSOL_*) and some backup or migration tooling. Requires object access "
            "auditing on the domain object - if this returns literally nothing, verify auditing "
            "is on before recording the hunt as clean, or you will log a Visibility Gap as a "
            "clean result."
        ),
    },
    {
        "seed_key": "lsass-access",
        "title": "LSASS process access with credential-dumping rights",
        "techniques": ["T1003.001"],
        "data_sources": ["Sysmon:EventID 10"],
        "query": """index=sysmon EventCode=10 TargetImage="*\\\\lsass.exe"
| eval access=lower(GrantedAccess)
| search access IN ("0x1010","0x1410","0x1438","0x143a","0x1f0fff","0x1fffff","0x1410")
| stats count values(access) as granted values(CallTrace) as call_trace
        min(_time) as first_seen by host, SourceImage, SourceUser
| convert ctime(first_seen)
| sort - count""",
        "expected_positive": (
            "An unexpected SourceImage opening lsass with 0x1010/0x1410 (read memory), "
            "especially with an unbacked or suspicious CallTrace containing UNKNOWN frames."
        ),
        "expected_benign": (
            "EDR agents, antivirus, and some monitoring tools legitimately read lsass "
            "continuously from a consistent, signed SourceImage path."
        ),
        "notes": (
            "The CallTrace field is what separates a real hit from noise - unbacked memory "
            "(UNKNOWN) in the trace is far more suspicious than the access mask alone. "
            "Baseline SourceImage first; in most estates fewer than ten binaries ever touch "
            "lsass. Sysmon config must include ProcessAccess for lsass or this returns nothing."
        ),
    },
    {
        "seed_key": "encoded-powershell",
        "title": "Encoded PowerShell command lines",
        "techniques": ["T1059.001", "T1027"],
        "data_sources": ["WinEventLog:Security", "Sysmon:EventID 1"],
        "query": """index=sysmon EventCode=1 Image IN ("*\\\\powershell.exe","*\\\\pwsh.exe")
| rex field=CommandLine "(?i)\\s-e(nc|ncoded|ncodedcommand|c)?\\s+(?<encoded>[A-Za-z0-9+/=]{24,})"
| where isnotnull(encoded)
| stats count values(CommandLine) as command_lines min(_time) as first_seen
        by host, User, ParentImage
| convert ctime(first_seen)
| sort - count""",
        "expected_positive": (
            "Base64 payloads launched by an unusual parent - Office, wscript, a service host, "
            "or a scheduled task - rather than by an administrator's own shell."
        ),
        "expected_benign": (
            "Configuration management (SCCM, Intune, Ansible) and some installers routinely "
            "use -EncodedCommand from a consistent parent process."
        ),
        "notes": (
            "Encoding is not itself malicious, which is why this pivots on ParentImage rather "
            "than alerting on the encoding. Decode with "
            "`| eval decoded=replace(base64decode(encoded),\"\\x00\",\"\")` if your deployment "
            "has a base64 command available. Script block logging (4104) catches what process "
            "creation misses - if you have it, hunt both and compare coverage."
        ),
    },
    {
        "seed_key": "scheduled-task-lolbin",
        "title": "Scheduled tasks registered to run an interpreter or LOLBin",
        "techniques": ["T1053.005"],
        "data_sources": ["WinEventLog:Security"],
        "query": """index=wineventlog sourcetype="WinEventLog:Security" EventCode=4698
| rex field=Task_Content "<Command>(?<task_command>[^<]+)</Command>"
| rex field=Task_Content "<Arguments>(?<task_args>[^<]+)</Arguments>"
| search task_command IN ("*powershell*","*pwsh*","*cmd.exe*","*rundll32*","*mshta*",
                          "*wscript*","*cscript*","*regsvr32*","*curl*","*certutil*")
| stats count min(_time) as first_seen by host, Account_Name, Task_Name, task_command, task_args
| convert ctime(first_seen)""",
        "expected_positive": (
            "A task created by a user account (not SYSTEM or an install process) whose action "
            "is an interpreter with an encoded or remote argument."
        ),
        "expected_benign": (
            "Software installers and management agents create tasks constantly - they cluster "
            "on a small number of task names appearing across many hosts at once."
        ),
        "notes": (
            "Frequency is the discriminator: a task name appearing on one host once is far more "
            "interesting than the same name on 400 hosts. Add "
            "`| eventstats dc(host) as host_count by Task_Name | where host_count < 5` to make "
            "that explicit. Requires the Object Access > Other Object Access Events subcategory."
        ),
    },
    {
        "seed_key": "rare-service-install",
        "title": "Rare service installations (PsExec-style lateral movement)",
        "techniques": ["T1543.003", "T1569.002"],
        "data_sources": ["WinEventLog:System"],
        "query": """index=wineventlog sourcetype="WinEventLog:System" EventCode=7045 earliest=-30d
| stats count dc(host) as host_count values(host) as hosts min(_time) as first_seen
        by Service_Name, Service_File_Name, Service_Start_Type
| where host_count <= 3
| convert ctime(first_seen)
| sort host_count, - count""",
        "expected_positive": (
            "A service with a random or pseudo-random name, an executable in a temp/user-writable "
            "path, or a command line embedding an interpreter, present on very few hosts."
        ),
        "expected_benign": (
            "Vendor agents and drivers appear on many hosts with a stable name - the rarity "
            "filter removes them."
        ),
        "notes": (
            "This is a frequency-analysis hunt, not a signature: the value is in the long tail, "
            "so resist adding name-based filters. PsExec creates PSEXESVC, PAExec creates "
            "PAExec-*, and Impacket's smbexec uses a randomly-named service - all land here "
            "naturally. Widen earliest to -90d if your estate is small."
        ),
    },
    {
        "seed_key": "wmi-event-subscription",
        "title": "WMI permanent event subscription persistence",
        "techniques": ["T1546.003"],
        "data_sources": ["Sysmon:EventID 19", "Sysmon:EventID 20", "Sysmon:EventID 21"],
        "query": """index=sysmon EventCode IN (19,20,21)
| stats count values(EventNamespace) as namespace values(Name) as names
        values(Query) as queries values(Destination) as consumers
        min(_time) as first_seen by host, EventCode, User
| convert ctime(first_seen)
| sort - first_seen""",
        "expected_positive": (
            "EventID 20 (consumer) referencing ActiveScriptEventConsumer or "
            "CommandLineEventConsumer, paired with a 21 (binding) tying it to a timer or "
            "process-start filter."
        ),
        "expected_benign": (
            "Monitoring and inventory products register subscriptions legitimately, usually at "
            "install time and identically across the estate."
        ),
        "notes": (
            "Permanent WMI subscriptions are rare enough in most environments that this hunt is "
            "close to exhaustive - review every one rather than thresholding. The consumer "
            "(EventID 20) carries the payload, so it is the highest-value of the three. If your "
            "Sysmon config omits WmiEvent, this returns nothing and the honest outcome is a "
            "Visibility Gap."
        ),
    },
    {
        "seed_key": "run-key-persistence",
        "title": "Registry Run key persistence written by an unusual process",
        "techniques": ["T1547.001"],
        "data_sources": ["Sysmon:EventID 13"],
        "query": """index=sysmon EventCode=13 earliest=-30d
    (TargetObject="*\\\\CurrentVersion\\\\Run\\\\*"
     OR TargetObject="*\\\\CurrentVersion\\\\RunOnce\\\\*")
| stats count dc(host) as host_count values(Details) as written_value
        min(_time) as first_seen by Image, TargetObject
| where host_count <= 3
| convert ctime(first_seen)
| sort host_count""",
        "expected_positive": (
            "A Run key written by an interpreter, a browser download path, or a binary in "
            "AppData, on very few hosts."
        ),
        "expected_benign": (
            "Installers and updaters write Run keys on many hosts with consistent values."
        ),
        "notes": (
            "Pivot on Image (who wrote it), not on the key path - every estate has hundreds of "
            "legitimate Run entries and almost none of them are written by powershell.exe. "
            "Details holds the value written, which is where a suspicious path shows up."
        ),
    },
    {
        "seed_key": "office-spawns-shell",
        "title": "Office application spawning a shell or scripting host",
        "techniques": ["T1204.002", "T1566.001"],
        "data_sources": ["Sysmon:EventID 1"],
        "query": """index=sysmon EventCode=1
    ParentImage IN ("*\\\\winword.exe","*\\\\excel.exe","*\\\\powerpnt.exe",
                    "*\\\\outlook.exe","*\\\\msaccess.exe","*\\\\onenote.exe")
    Image IN ("*\\\\cmd.exe","*\\\\powershell.exe","*\\\\pwsh.exe","*\\\\wscript.exe",
              "*\\\\cscript.exe","*\\\\mshta.exe","*\\\\rundll32.exe","*\\\\regsvr32.exe",
              "*\\\\bitsadmin.exe","*\\\\certutil.exe","*\\\\curl.exe")
| stats count values(CommandLine) as command_lines min(_time) as first_seen
        by host, User, ParentImage, Image
| convert ctime(first_seen)
| sort - first_seen""",
        "expected_positive": (
            "Any hit deserves review. Macro and exploit chains almost always cross this "
            "parent/child boundary on the way to their payload."
        ),
        "expected_benign": (
            "A small number of business macros legitimately shell out - they recur on the same "
            "hosts with the same command line."
        ),
        "notes": (
            "One of the highest signal-to-noise hunts on Windows, which makes it a good "
            "candidate to promote to a production detection (Analytics/Detection outcome) "
            "rather than re-hunt. Build the allow-list from the recurring command lines you "
            "find, and record them in the hunt notes so the next analyst does not re-triage "
            "the same macros."
        ),
    },
    {
        "seed_key": "lolbin-download",
        "title": "certutil / bitsadmin used to download a remote file",
        "techniques": ["T1105", "T1218"],
        "data_sources": ["Sysmon:EventID 1"],
        "query": """index=sysmon EventCode=1
    ((Image="*\\\\certutil.exe" AND (CommandLine="*-urlcache*" OR CommandLine="*-decode*"
                                    OR CommandLine="*-verifyctl*"))
     OR (Image="*\\\\bitsadmin.exe" AND CommandLine="*/transfer*"))
| stats count values(CommandLine) as command_lines min(_time) as first_seen
        by host, User, Image, ParentImage
| convert ctime(first_seen)
| sort - first_seen""",
        "expected_positive": (
            "certutil -urlcache -split -f pulling a remote file, or bitsadmin /transfer writing "
            "to a user-writable path. -decode without a download is staging an already-dropped "
            "payload."
        ),
        "expected_benign": (
            "certutil has legitimate certificate uses, but -urlcache and -decode are rare in "
            "normal administration."
        ),
        "notes": (
            "This is deliberately narrow - the LOLBin surface is enormous and a broad version "
            "of this hunt drowns. Treat it as a template: LOLBAS lists the full inventory, and "
            "the right move is a separate task per binary family rather than one giant query. "
            "Add the destination path from CommandLine to spot staging directories."
        ),
    },
    {
        "seed_key": "privileged-group-change",
        "title": "Membership changes to privileged directory groups",
        "techniques": ["T1098", "T1078.002"],
        "data_sources": ["WinEventLog:Security"],
        "query": """index=wineventlog sourcetype="WinEventLog:Security"
    EventCode IN (4728,4732,4756)
    Group_Name IN ("Domain Admins","Enterprise Admins","Schema Admins","Administrators",
                   "Backup Operators","Account Operators","Server Operators",
                   "Group Policy Creator Owners")
| table _time, host, Subject_Account_Name, Member_Account_Name, Group_Name
| sort - _time""",
        "expected_positive": (
            "An addition made outside a change window, by an account that does not normally "
            "administer groups, or adding an account that is not a known admin identity."
        ),
        "expected_benign": (
            "Scheduled, ticketed administrative changes made by the identity team."
        ),
        "notes": (
            "Volume here is low enough to review every event, which makes this a good hunt to "
            "run on a recurring schedule. The real value is the join against your change "
            "record: an addition with no corresponding ticket is the finding. Consider adding "
            "removals (4729/4733/4757) - attackers clean up after themselves."
        ),
    },
    {
        "seed_key": "beaconing-jitter",
        "title": "Beaconing: outbound connections with machine-regular intervals",
        "techniques": ["T1071.001", "T1573"],
        "data_sources": ["Proxy logs", "Network Traffic:Network Connection Creation"],
        "query": """index=proxy earliest=-7d
| bin _time span=1s
| sort 0 src_ip, dest_domain, _time
| streamstats current=f last(_time) as previous_time by src_ip, dest_domain
| eval interval = _time - previous_time
| where isnotnull(interval) AND interval > 0
| stats count as connections avg(interval) as avg_interval stdev(interval) as jitter
        dc(bytes_out) as distinct_sizes by src_ip, dest_domain
| where connections > 50 AND jitter < 60 AND avg_interval > 30
| eval jitter_ratio = round(jitter / avg_interval, 3)
| sort jitter_ratio
| head 100""",
        "expected_positive": (
            "A host contacting one domain on a near-fixed interval for hours, with little "
            "variation in payload size. Low jitter_ratio is the signal."
        ),
        "expected_benign": (
            "Software update checks, telemetry, NTP, monitoring agents and CDN keep-alives are "
            "all machine-regular by design and dominate the top of these results."
        ),
        "notes": (
            "This is a statistical baselining task, not a signature - the output is a ranked "
            "list to triage, not alerts. Expect to spend the first run building an allow-list "
            "of legitimate periodic destinations; that list is the durable artefact, so record "
            "it in the hunt findings. Modern C2 adds jitter deliberately, so treat a clean "
            "result as 'no low-jitter beaconing', not 'no C2' - overstating that is how a hunt "
            "report misleads."
        ),
    },
]


class Command(BaseCommand):
    help = "Seed the task library with curated SPL examples and Sigma-derived entries."

    def add_arguments(self, parser):
        parser.add_argument("--force", action="store_true", help="Refresh entries that already exist")
        parser.add_argument("--skip-sigma", action="store_true", help="Curated examples only")

    def handle(self, *args, **options):
        curated = self._seed(CURATED, "curated", options["force"])
        self.stdout.write(self.style.SUCCESS(f"Curated examples: {curated} written"))

        if options["skip_sigma"]:
            return
        derived = self._seed(self._sigma_specs(), "sigma", options["force"])
        self.stdout.write(self.style.SUCCESS(f"Sigma-derived entries: {derived} written"))

    def _sigma_specs(self):
        """SigmaHQ's threat-hunting collection: broader, lower-fidelity queries written for
        hunting rather than alerting - exactly what belongs in a starting library."""
        specs = []
        for rule in SigmaRule.objects.filter(collection="rules-threat-hunting").prefetch_related(
            "techniques"
        ):
            detection = ""
            try:
                parsed = yaml.safe_load(rule.raw_yaml) or {}
                detection = yaml.safe_dump(
                    {"logsource": parsed.get("logsource", {}), "detection": parsed.get("detection", {})},
                    sort_keys=False,
                )
            except yaml.YAMLError:
                detection = rule.raw_yaml

            notes = [rule.description.strip()] if rule.description else []
            notes.append(
                f"Sigma rule {rule.title} by {rule.author or 'unknown author'} ({rule.license}). "
                "The query field holds Sigma detection logic, not a runnable SPL search - "
                "translate it for your platform before use."
            )
            specs.append(
                {
                    "seed_key": f"sigma:{rule.rule_id}",
                    "title": rule.title,
                    "techniques": [t.attack_id for t in rule.techniques.all()],
                    "data_sources": [
                        v for v in [rule.logsource_product, rule.logsource_service,
                                    rule.logsource_category] if v
                    ],
                    "query": detection,
                    "expected_positive": "",
                    "expected_benign": "",
                    "notes": "\n\n".join(notes),
                    "sigma_rule": rule,
                }
            )
        return specs

    def _seed(self, specs, provenance, force):
        written = 0
        for spec in specs:
            existing = LibraryTask.objects.filter(seed_key=spec["seed_key"]).first()
            if existing and not force:
                continue

            entry = existing or LibraryTask()
            entry.seed_key = spec["seed_key"]
            entry.provenance = provenance
            entry.title = spec["title"][:300]
            entry.hunting_tool = "Splunk" if provenance == "curated" else ""
            entry.query = spec["query"]
            entry.expected_positive = spec["expected_positive"]
            entry.expected_benign = spec["expected_benign"]
            entry.notes = spec["notes"]
            entry.save()

            # After save(): an unsaved row has no pk to hang a relation on.
            entry.data_sources.set(
                DataSource.objects.get_or_create(name=name)[0]
                for name in spec["data_sources"]
            )

            techniques = Technique.objects.filter(attack_id__in=spec["techniques"])
            entry.techniques.set(techniques)  # fires Sigma auto-attach for these techniques
            if spec.get("sigma_rule"):
                entry.sigma_rules.add(spec["sigma_rule"])
            written += 1
        return written
