# HuntOps

A self-hosted web app for **planning, tracking and executing threat hunts**, built around the
[Unified Threat Hunting Process](https://github.com/sims718718/UnifiedThreatHunting) (UTHP).
It ships pre-populated with the MITRE ATT&CK Enterprise knowledge base and the SigmaHQ detection
rules, turns threat intel into hunt backlog, and keeps a reusable library of hunt tasks that can
live in git as YAML ("detection as code").

- **Hunts** walk a fixed lifecycle (backlog → scoping → feasibility review → approved → in progress →
  documenting → reported → archived) with a feasibility gate, on a list and a Kanban board.
- **Objectives and tasks** hold the methodology, queries, expected results, Sigma rules and data
  sources for each hunt, and record findings and typed outcomes.
- **Intel intake** imports runs of the companion
  [agentic threat intel framework](https://github.com/sims718718/agentic-threat-intel-framework)
  and turns them into hunt seeds, hunts and suggested objectives.
- **Task library** is a searchable set of reusable hunt tasks (curated, Sigma-derived and your own),
  exportable to and importable from YAML.
- **Coverage and metrics** show which ATT&CK techniques you have hunted, found clean, or found gaps
  in, and how the hunt programme is performing.

Server-rendered Django + Postgres with a little htmx. No JavaScript build step, no external
services at runtime, and every importer has an offline mode, so it works air-gapped.

## Contents

- [Quick start](#quick-start)
- [Load the content](#load-the-content)
- [Try the examples](#try-the-examples)
- [How it works](#how-it-works)
- [Importing intel and hunts from the threat intel framework](#importing-intel-and-hunts-from-the-threat-intel-framework)
- [Task library as code](#task-library-as-code)
- [Roles and permissions](#roles-and-permissions)
- [Configuration and deployment](#configuration-and-deployment)
- [Development](#development)
- [Credits and licences](#credits-and-licences)

## Quick start

You need Docker with Compose. Nothing else is installed on the host.

```bash
git clone <this repository> huntops
cd huntops
docker compose up --build
```

The first start builds the image, starts Postgres 16 and runs the migrations. HuntOps is then at
**http://localhost:8001** (the container listens on 8000; the compose file publishes it on 8001 so it
doesn't collide with other tools that like port 8000).

Create your first account in a second terminal:

```bash
docker compose exec web python manage.py createsuperuser
```

Then sign in. The superuser can do everything; see [Roles and permissions](#roles-and-permissions)
for giving everyone else a sensible role.

The project directory is mounted into the container, so code changes reload automatically and any
file you put in the checkout is visible to the commands below as `/app/<path>`.

<details>
<summary>Running without Docker</summary>

You need Python 3.12 and a reachable Postgres.

```bash
pip install -r requirements.txt
export POSTGRES_HOST=localhost POSTGRES_DB=huntops POSTGRES_USER=huntops POSTGRES_PASSWORD=huntops
python manage.py migrate
python manage.py runserver
```

Drop the `docker compose exec web` prefix from every command in this README.
</details>

## Load the content

A fresh database has no ATT&CK data, no Sigma rules and no library. Load them once, in this order
(each command is idempotent, so re-running later just refreshes):

```bash
docker compose exec web python manage.py seed_roles       # the five user groups
docker compose exec web python manage.py import_attack    # MITRE ATT&CK Enterprise (STIX)
docker compose exec web python manage.py import_sigma     # SigmaHQ rules, linked to techniques
docker compose exec web python manage.py seed_library     # curated + Sigma-derived library tasks
```

`import_attack` and `import_sigma` download from GitHub by default. **Air-gapped?** Fetch the files
on a connected machine, copy them into your checkout, and point the commands at them:

```bash
# enterprise-attack.json from https://github.com/mitre-attack/attack-stix-data
docker compose exec web python manage.py import_attack --file /app/enterprise-attack.json
# a SigmaHQ checkout or the master.zip from https://github.com/SigmaHQ/sigma
docker compose exec web python manage.py import_sigma --path /app/sigma-master.zip
```

Hunts pin the ATT&CK version that was current when they were created. Sigma rules are searchable
with Postgres full-text search, and attaching a technique to a task automatically suggests the
matching stable/test-status Sigma rules and ATT&CK data sources.

## Try the examples

Two worked example hunts ship with the project, built from a real run of the intel framework
(APT29 / Midnight Blizzard, past year):

```bash
docker compose exec web python manage.py seed_examples
```

This imports the intel run (see `examples/threat-hunting/`) and creates two hunts from it. Run it
after the content above so their techniques and Sigma rules resolve; it is safe to run again and
will not duplicate or overwrite hunts that exist.

| Hunt | What it shows |
|---|---|
| **APT29 / Midnight Blizzard — Cloud-Identity Abuse & CaptiveCrunch Campaign Hunt** | A fully planned, **approved** hunt: trigger, hypothesis, competing hypotheses, the five-part feasibility assessment (decision: CONDITIONAL), scope and exclusions, a date window, and three objectives, each with methodology, expected malicious/benign outcomes and a task carrying a query, reference procedure, data sources and auto-attached Sigma rules. |
| **Device-code / ASP authentication after an unsolicited IT-support contact** | The fast path: a **backlog** hunt *promoted from an intel seed*, with the intel report's techniques inherited and one objective forked from a hunt-plan Story. Open the linked intel report to see the seed marked "promoted". |

They take the next free hunt numbers, so on a fresh install they appear as `HUNT-001` and
`HUNT-002`. Use them to explore the hunt page, the board, the technique coverage heatmap and the
Markdown hunt report; delete them whenever you like.

## How it works

### The object model

```
Hunt ── Objective ── Task ── Outcome
  │                   │
  │                   └── Sigma rules, data sources, ATT&CK techniques, evidence, comments
  └── Intel report (optional) ── hunt seeds, hunt-plan stories
```

- **Hunt**: one investigation. Carries the trigger, hypothesis, feasibility assessment, scope,
  owner/analysts, priority, dates and the lifecycle `status`. Hunt types are Exploratory,
  Hypothesis-Based, Threat-Informed and Purple-Informed.
- **Objective**: a question the hunt answers, with its methodology and what a malicious vs. benign
  result would look like.
- **Task**: the unit of execution: a hunting tool, a query, a reference procedure, expected
  positive/benign results, the techniques, data sources and Sigma rules it relates to, and, once run,
  a status (Not started / In progress / Executed), a result (True positive / False positive /
  Inconclusive / No result) and findings.
- **Outcome**: what the hunt produced. A task or hunt can record several, each one of: New Hunt Idea,
  Analytics/Detection, Security Incident, Written Report, Visibility Gap, Security Control Issue.

Human-readable IDs are derived, not stored: `HUNT-003`, `HUNT-003-O1-T2`, `TASKLIB-012`, `INTEL-001`.
Changes to hunts and tasks are recorded in an audit history.

### The hunt lifecycle

Hunts move left to right across a Kanban **board** (drag a card, or use the stage selector on the
hunt). The one hard rule is the **feasibility gate**: a hunt cannot advance past *Feasibility
review* unless its feasibility decision is GO or CONDITIONAL, or a Hunt Lead records an override
with a reason. Rejected moves explain themselves inline.

### Pages

| Page | Purpose |
|---|---|
| **Dashboard** | What needs attention, the active hunts, and a coverage summary. |
| **Hunts / Board** | Filterable list (stage tabs, owner, priority, search) and the Kanban view. |
| **Intel** | Imported intel reports, their hunt seeds, indicators, CVEs and ATT&CK techniques. |
| **Task library** | Reusable hunt tasks; fork one into a hunt, or promote a finished task into the library. |
| **ATT&CK** | Browse techniques with procedure examples, mitigations, Sigma rules, ready-made library tasks, your own coverage and the intel that cites them. |
| **Coverage** | An ATT&CK heatmap classifying each technique as never hunted, hunted clean, gap or detection; `?intel=1` overlays techniques that appear in intel but have not been hunted. |
| **Metrics** | Hunt programme trends, filterable, with an exportable Markdown report. |
| **Admin site** | Users, groups and raw data at `/admin/`. |

### Reusable content vs. executed work

A **library task** is a template. Forking it into a hunt copies its fields onto a new task with **no
live link back**, so editing the library later never rewrites a hunt you already ran; the task
remembers where it came from. Going the other way, any task can be promoted into the library. The
curated and Sigma-derived entries are read-only reference material: duplicate one to make your own.

### Exports

Every hunt has a Markdown **hunt report** and every task a Markdown **handoff** (for a detection
engineer), plus the metrics report. They are plain text, ready to paste into a ticket or wiki.

## Importing intel and hunts from the threat intel framework

HuntOps is the workbench; the
[agentic threat intel framework](https://github.com/sims718718/agentic-threat-intel-framework)
is the producer. It is a Claude Code plugin that turns raw threat intelligence (a CVE, an actor name,
an ATT&CK technique, a URL, a report) into an assessed intel analysis, a decision-ready intel report
and a Jira-structured hunt plan. HuntOps imports those files, keeps the actionable parts as
structured data, and lets you turn them into hunts with a click.

```
framework (Claude Code)                          HuntOps
───────────────────────                          ──────────────────────────────────────────
/run-hunt-pipeline <CVE | actor | URL | …>
  ├─ intel-analysis ──► <slug>-analysis.md  ───►  Intel report: sources, judgments, gaps
  ├─ intel-report   ──► <slug>-report.md    ───►  Intel report: techniques, IOCs, CVEs, hunt seeds
  └─ hunt-planner   ──► <slug>-hunt-plan.md ───►  Hunt-plan stories (suggested objectives)
                                                         │
                          promote a seed ◄───────────────┘  → a Threat-Informed hunt, linked back
                          attach a story  ───────────────►  → an objective + task on that hunt
```

### 1. Produce a run with the framework

Install the plugin once (from a clone of its repository, see its README for details):

```bash
git clone https://github.com/sims718718/agentic-threat-intel-framework.git
claude plugin marketplace add ./agentic-threat-intel-framework
claude plugin install threat-intel-hunt-framework@threat-intel-hunt-framework
```

Then, in the project where you want the output, run it with one input:

```
/run-hunt-pipeline CVE-2026-41205
/run-hunt-pipeline "APT29 activity in the past year"
```

It writes everything under `./threat-hunting/` in that project. HuntOps reads three of the folders,
all keyed by the run's slug (kebab-case, e.g. `apt29-past-year`):

```
threat-hunting/
├── intel-reports/<slug>-report.md       required: what makes an intel report in HuntOps
├── intel-analysis/<slug>-analysis.md    optional: source reputation notes, open questions, quality gate
└── hunt-plans/<slug>-hunt-plan.md       optional: the Stories that become suggested objectives
```

The other framework outputs (environment profile, hunt logs, detections, hunt reports, validations)
are not imported: you run and record the hunt in HuntOps, and its report export covers the write-up.

### 2. Import it into HuntOps

**From the command line.** Copy the `threat-hunting` folder into your HuntOps checkout so the
container can see it (the checkout is mounted at `/app`; the folder is git-ignored so your intel is never committed), then:

```bash
docker compose exec web python manage.py import_intel --dir /app/threat-hunting --dry-run   # parse and report, write nothing
docker compose exec web python manage.py import_intel --dir /app/threat-hunting             # import every run with a report
docker compose exec web python manage.py import_intel --dir /app/threat-hunting --slug apt29-past-year   # one run
```

The command prints per-run counts (techniques, indicators, CVEs, seeds, stories) and warns about
techniques that are not in your ATT&CK data and about any section it could not map.

**From the browser.** Open **Intel → Import**. There is one upload field per file because the
framework writes them to three different folders and a browser file picker can only select within one:
choose the `-report.md` (required), and the `-analysis.md` and `-hunt-plan.md` if you have them. You get
a preview of what will be created or updated, and nothing is written until you confirm.

Both routes work offline. Only local files are read.

### 3. What you get

Each run becomes an **intel report** (`INTEL-001`, …) containing:

- the executive summary, key judgments, actor overview, recommended detect/mitigate actions,
  confidence and sourcing, source reputation notes and open questions;
- the **ATT&CK techniques** it cites, each with the evidence and the report's "do we have visibility?"
  note. Techniques not in your ATT&CK import are kept and flagged rather than dropped;
- **indicators** (with their confidence labels), **CVEs / advisories**, and the TLP and quality-gate
  status;
- **hunt seeds**: the report's recommended hunts, one row each;
- **stories**: the hunt plan's `## Story:` sections (both the plain-heading and the Jira-block
  layouts), with their methodology, expected malicious/benign results, detection query and data sources.

### 4. Turn it into hunts

- **Promote seeds.** On the intel report, tick one or more open seeds and **Promote**. HuntOps creates a
  Threat-Informed hunt linked to the report (trigger, source link, the plan's hypothesis and the
  report's techniques filled in) and opens its edit form so you can trim the techniques and fix the
  title. The seed shows as *promoted* and points at the hunt. Dismiss a seed with a reason if it is not
  worth hunting.
- **Attach stories as objectives.** A hunt linked to intel shows a **Suggested objectives** panel. Attach
  a story and it becomes an Objective carrying the story's methodology and expected outcomes, with one
  task holding the primary detection query, the techniques from the story's `ATT&CK:` line and its
  data-source table (new log sources are created as team-defined). Like the library, this is a copy: a
  later re-import never rewrites the hunt.
- **See what you already did.** Hunt detail lists prior hunts on the same techniques, and the coverage
  heatmap's `?intel=1` view highlights techniques that intel mentions but nobody has hunted.

### Re-importing

Importing the same slug again is safe and is how you pick up a re-run of the framework: the report's
techniques, indicators, CVEs and stories are replaced, while seed decisions are **reconciled by
text**, so seeds you promoted or dismissed keep their status and seeds that vanished from the report
while still open are marked *stale*. A re-import never touches a hunt.

## Task library as code

Team-built library tasks export to YAML (one file per task with a stable `id`), live in a git
repository, are reviewed in pull requests, and import back, with a preview first. HuntOps never talks to
the repository; a person or a CI job moves the files.

```bash
docker compose exec web python manage.py export_library --dir /app/library          # write <id>.yml per task
docker compose exec web python manage.py import_library --dir /app/library --dry-run
docker compose exec web python manage.py import_library --dir /app/library
```

The same actions are in the UI (**Task library → Export YAML / Import YAML**). The format, import
rules (the repo wins on conflicts, errors block the whole import, warnings never do) and sample GitHub
Actions and GitLab CI jobs are in [`docs/library-as-code.md`](docs/library-as-code.md).

## Roles and permissions

`seed_roles` creates five groups; assign users to them in the admin site (superusers bypass all of this).

| Role | Can |
|---|---|
| **Hunter** | View everything; create and edit hunts, objectives, tasks, library tasks, outcomes, evidence and comments. |
| **Hunt Lead** | Everything a Hunter can, plus manage intel, delete, and **override the feasibility gate**. |
| **Detection Engineer** | View everything; edit tasks and add outcomes, evidence and comments. |
| **CTI Analyst** | View everything; import and manage intel, and promote seeds into hunts (the hunt then belongs to the hunt team). |
| **Stakeholder** | Read-only. |

Library import needs both the add and change library-task permissions; exports need only a login.

## Configuration and deployment

Settings come from environment variables (see `huntops/settings.py`):

| Variable | Default | Notes |
|---|---|---|
| `SECRET_KEY` | `dev-only-insecure-key` | **Set this** for anything beyond your own machine. |
| `DEBUG` | `1` | Set `0` in production. |
| `ALLOWED_HOSTS` | `*` | Comma-separated host names. |
| `POSTGRES_DB` / `_USER` / `_PASSWORD` | `huntops` | Change the password outside a laptop. |
| `POSTGRES_HOST` / `_PORT` | `localhost` / `5432` | The compose file sets the host to `db`. |

Uploaded evidence is stored under `media/` (the `evidence` Docker volume); the database is in the
`pgdata` volume. Back both up.

The shipped setup is a **development setup**: the Django development server, default credentials and
`DEBUG` on. It is fine for a trusted network or a single analyst. For a shared deployment, put a
real WSGI server (for example gunicorn) behind a TLS-terminating reverse proxy, set the variables
above, serve `static/` and `media/` from the proxy, and don't publish the Postgres port.
HuntOps has no built-in single sign-on; it uses Django's accounts.

## Development

```bash
docker compose exec web python manage.py test                                       # full suite
docker compose exec web python manage.py test hunts.tests.test_board                # one module
docker compose exec web python manage.py test hunts.tests.test_board.BoardMoveTests.test_blocked_move
```

Tests use Django's built-in runner and run against a real Postgres. There is no separate lint or
format step; match the surrounding code.

```
huntops/                 project shell (settings, urls, wsgi)
hunts/                   the single app
  models.py              Hunt → Objective → Task, LibraryTask, ATT&CK, Sigma, Intel*, history
  views/                 one module per area (hunts, board, library, intel, sigma, attack, …)
  library_io.py          YAML export/import for the task library
  intel_import.py        parser for the threat-intel-hunt-framework Markdown
  reporting.py           coverage classification and the Markdown exports
  management/commands/   import_attack, import_sigma, seed_library, seed_roles, import_intel,
                         export_library, import_library, seed_examples
  tests/                 test suite and real framework runs under tests/fixtures/intel/
templates/  static/      server-rendered pages; htmx and Chart.js are vendored, so there is no CDN
examples/                the example intel run and hunts loaded by seed_examples
docs/                    long-form docs (library as code)
```

A few conventions worth knowing before you change things:

- Comments starting `# ponytail:` mark a deliberately minimal implementation and say what the known
  limit is and when to revisit it. Read them before "fixing" something that looks unfinished.
- Hunt, objective, task and library numbers are assigned in `save()` (max + 1) rather than by
  database sequences; the comment in `models.py` explains the concurrent-create trade-off.
- Imports are idempotent and tolerant: the intel parser reads tables by header name and records
  unmapped sections as warnings rather than failing.
- A UTHP hypothesis-scoring gate was built and then removed because it cluttered hunt creation;
  please ask before reintroducing it.

## Screenshots

### Intial Dashboard
<img width="1275" height="532" alt="Screenshot 2026-10-20 143800" src="https://github.com/user-attachments/assets/a6cc74b6-0d6c-46be-a01f-65a232ada621" />

### Kanban Board
<img width="1242" height="849" alt="Screenshot 2026-10-20 143833" src="https://github.com/user-attachments/assets/a1bdbcb0-2f40-48a0-a70b-1843feb829b7" />

### Hunt List
<img width="1410" height="436" alt="Screenshot 2026-10-20 143906" src="https://github.com/user-attachments/assets/db044791-cc48-40ad-a530-1dfd148fdb7e" />

### Example Hunt
<img width="1343" height="1121" alt="Screenshot 2026-10-20 143929" src="https://github.com/user-attachments/assets/11acc205-d2b8-4a5a-bfd6-73e8fd38959c" />

### Task Library
<img width="1210" height="1032" alt="Screenshot 2026-10-20 143949" src="https://github.com/user-attachments/assets/dede8e8e-7c73-4d54-a9ab-6fa0a764502b" />

### MITRE TTP Coverage Map
<img width="2202" height="1095" alt="Screenshot 2026-10-20 144007" src="https://github.com/user-attachments/assets/144cc5e8-c245-444e-82ba-b0a98dcf1e43" />

### Metrics
<img width="2333" height="674" alt="Screenshot 2026-10-20 144024" src="https://github.com/user-attachments/assets/6833fd67-989e-4087-8918-3658016e7680" />


## Credits and licences

HuntOps is released under the [MIT License](LICENSE). Third-party content keeps its own terms:

- **MITRE ATT&CK®** content is imported from [attack-stix-data](https://github.com/mitre-attack/attack-stix-data)
  and is subject to [MITRE's terms of use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).
  ATT&CK® is a registered trademark of The MITRE Corporation.
- **Sigma rules** are from [SigmaHQ](https://github.com/SigmaHQ/sigma) under the Detection Rule License
  (DRL) 1.1; rule authors are kept on each rule.
- The **Unified Threat Hunting Process** and the **intel framework** are companion projects: [UnifiedThreatHunting](https://github.com/sims718718/UnifiedThreatHunting) and [agentic-threat-intel-framework](https://github.com/sims718718/agentic-threat-intel-framework).
- Vendored front-end libraries (htmx, Chart.js, CodeMirror, IBM Plex) keep their own licences in
  `static/vendor/`.
