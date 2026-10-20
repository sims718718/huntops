"""Coverage classification and Markdown exports."""

from .models import OUTCOME_TYPES, IntelTechnique, Tactic, Task, TaskSigmaRule, Technique


def data_source_status(hunt_type="", environment_profile="", start="", end=""):
    """data_source_id -> True (used by at least one executed Task), for the trend.

    Mirrors technique_status(): same filters, same "only counts if a Task
    actually executed" rule. Unlike techniques, there's no clean/gap/detection
    tier here - a data source is either referenced by an executed Task or it
    isn't.
    """
    tasks = Task.objects.filter(status=Task.EXECUTED, data_sources__isnull=False)
    if hunt_type:
        tasks = tasks.filter(objective__hunt__hunt_type=hunt_type)
    if environment_profile:
        tasks = tasks.filter(objective__hunt__environment_profile_id=environment_profile)
    if start:
        tasks = tasks.filter(objective__hunt__start_date__gte=start)
    if end:
        tasks = tasks.filter(objective__hunt__start_date__lte=end)
    return set(tasks.values_list("data_sources__id", flat=True))

NEVER, CLEAN, GAP, DETECTION, INTEL = "never", "clean", "gap", "detection", "intel"

STATUS_LABELS = {
    NEVER: "Never hunted",
    CLEAN: "Hunted, no finding",
    GAP: "Gap identified",
    DETECTION: "Detection created",
    INTEL: "In intel, not hunted",
}


def technique_status(hunt_type="", environment_profile="", start="", end=""):
    """technique_id -> coverage status, for the heatmap.

    A technique whose only Tasks are unexecuted counts as never hunted: the query
    was planned, not run.
    """
    tasks = Task.objects.filter(status=Task.EXECUTED, techniques__isnull=False)
    if hunt_type:
        tasks = tasks.filter(objective__hunt__hunt_type=hunt_type)
    if environment_profile:
        tasks = tasks.filter(objective__hunt__environment_profile_id=environment_profile)
    if start:
        tasks = tasks.filter(objective__hunt__start_date__gte=start)
    if end:
        tasks = tasks.filter(objective__hunt__start_date__lte=end)

    # A task now has zero or more Outcome rows instead of one outcome_types array, so
    # group every outcome type touching a technique - across every task - before
    # classifying, rather than ranking one status per task row.
    outcome_types_by_technique = {}
    for technique_id, outcome_type in tasks.values_list("techniques__id", "outcomes__outcome_type"):
        outcome_types_by_technique.setdefault(technique_id, set()).add(outcome_type)

    statuses = {}
    for technique_id, outcome_types in outcome_types_by_technique.items():
        if "analytics_detection" in outcome_types:
            statuses[technique_id] = DETECTION
        elif "visibility_gap" in outcome_types or "security_control_issue" in outcome_types:
            statuses[technique_id] = GAP
        else:
            statuses[technique_id] = CLEAN
    return statuses


def with_intel(statuses):
    """Overlay "in intel, not hunted" on techniques an imported report cites but no
    executed task has covered. Hunted techniques keep their real status, and
    technique_status() itself is untouched, so metrics never see INTEL.

    ponytail: the overlay ignores the heatmap's hunt-type/profile/date filters, so a
    technique hunted outside the current filter still shows "In intel, not hunted".
    Filter the overlay if analysts find that misleading.
    """
    overlaid = dict(statuses)
    for technique_id in IntelTechnique.objects.exclude(technique=None).values_list("technique_id", flat=True):
        overlaid.setdefault(technique_id, INTEL)
    return overlaid


def matrix_by_tactic(statuses):
    """[(tactic, [entry, ...]), ...] in official matrix order, sub-techniques nested.

    A parent never inherits coverage from a hunted sub-technique - hunting T1558.003 is
    not hunting all of T1558 - so parents carry their own status plus a covered count.
    """
    parents = {}
    children = {}
    for technique in Technique.objects.filter(deprecated=False).order_by("attack_id"):
        if technique.parent_id:
            children.setdefault(technique.parent_id, []).append(technique)
        else:
            parents[technique.id] = technique

    by_tactic = {}
    for technique in parents.values():
        for shortname in technique.tactics or ["unmapped"]:
            by_tactic.setdefault(shortname, []).append(technique)

    columns = []
    for tactic in Tactic.objects.all():
        entries = []
        for parent in by_tactic.get(tactic.shortname, []):
            subs = [(sub, statuses.get(sub.id, NEVER)) for sub in children.get(parent.id, [])]
            entries.append(
                {
                    "technique": parent,
                    "status": statuses.get(parent.id, NEVER),
                    "subs": subs,
                    "covered": sum(1 for _, status in subs if status not in (NEVER, INTEL)),
                }
            )
        if entries:
            columns.append((tactic, entries))
    return columns


def _attribution(rules):
    if not rules:
        return []
    lines = ["", "### Sigma attribution", ""]
    lines += [f"- {r.title} - {r.author or 'unknown author'} ({r.license})" for r in rules]
    return lines


def hunt_markdown(hunt):
    labels = dict(OUTCOME_TYPES)
    out = [
        f"# {hunt.hunt_id}: {hunt.title}",
        "",
        f"- **Status:** {hunt.get_status_display()}",
        f"- **Type:** {hunt.get_hunt_type_display() or '-'}",
        f"- **Owner:** {hunt.owner or '-'}",
        f"- **ATT&CK version:** {hunt.attack_version or '-'}",
        f"- **Environment profile:** {hunt.environment_profile or '-'}",
        *([f"- **Intel:** {hunt.intel_report.intel_id} {hunt.intel_report.title}"] if hunt.intel_report_id else []),
        "",
        "## Trigger",
        "",
        f"{hunt.get_trigger_type_display() or '-'}: {hunt.trigger_description or '-'}",
    ]
    if hunt.intel_report_id and hunt.intel_report.tlp:
        # The hunt's trigger text came from marked intel, so the export carries the marking.
        out[:0] = [f"**{hunt.intel_report.get_tlp_display()}**", ""]
    out += [f"Source: {link}" for link in hunt.trigger_source_links]
    if hunt.spun_off_from_id:
        out.append(f"Spun off from {hunt.spun_off_from.task_id}")

    out += ["", "## Hypothesis", "", hunt.hypothesis or "-"]

    if hunt.competing_hypotheses:
        out += ["", "## Competing hypotheses", "", hunt.competing_hypotheses]
    if hunt.research_notes:
        out += ["", "## Research notes", "", hunt.research_notes]

    out += [
        "",
        "## Feasibility",
        "",
        "| Criterion | Rating |",
        "| --- | --- |",
        f"| Data availability | {hunt.feasibility_data_availability or '-'} |",
        f"| Data quality | {hunt.feasibility_data_quality or '-'} |",
        f"| Skillset | {hunt.feasibility_skillset or '-'} |",
        f"| Timeline | {hunt.feasibility_timeline or '-'} |",
        f"| Tooling | {hunt.feasibility_tooling or '-'} |",
        f"| **Decision** | **{hunt.feasibility_decision or '-'}** |",
    ]
    if hunt.feasibility_override_by_id:
        out.append(
            f"| Override | {hunt.feasibility_override_by} - {hunt.feasibility_override_reason} |"
        )

    out += [
        "",
        "## Scope",
        "",
        f"- **In scope:** {hunt.scope_in or '-'}",
        f"- **Exclusions:** {hunt.scope_exclusions or '-'}",
        "",
        "## Objectives and tasks",
    ]

    rules = []
    for objective in hunt.objectives.all():
        out += [
            "",
            f"### {objective.objective_id}: {objective.title} ({objective.status})",
            "",
            f"- **Methodology:** {objective.methodology or '-'}",
            f"- **Expected (malicious):** {objective.expected_outcome_malicious or '-'}",
            f"- **Expected (benign):** {objective.expected_outcome_benign or '-'}",
        ]
        for task in objective.tasks.all():
            techniques = ", ".join(t.attack_id for t in task.techniques.all()) or "-"
            outcomes = ", ".join(labels.get(o.outcome_type, o.outcome_type) for o in task.outcomes.all()) or "-"
            rules += list(task.sigma_rules.exclude(tasksigmarule__status=TaskSigmaRule.DISCARDED))
            out += [
                "",
                f"#### {task.task_id}: {task.title}",
                "",
                f"- **Techniques:** {techniques}",
                f"- **Tool:** {task.hunting_tool or '-'}",
                f"- **Status / result:** {task.get_status_display()} / {task.get_result_display() or '-'}",
                f"- **Outcomes:** {outcomes}",
                f"- **Analyst:** {task.analyst or '-'}",
                "",
                "```",
                task.query or "(no query recorded)",
                "```",
                "",
                f"**Findings:** {task.findings or '-'}",
            ]
            evidence = [e.caption or e.file.name for e in task.evidence.all()]
            if evidence:
                out.append(f"**Evidence:** {', '.join(evidence)}")
            outcome_evidence = [
                e.caption or e.file.name
                for outcome in task.outcomes.all()
                for e in outcome.evidence.all()
            ]
            if outcome_evidence:
                out.append(f"**Outcome evidence:** {', '.join(outcome_evidence)}")

    def _outcome_line(o):
        evidence = [e.caption or e.file.name for e in o.evidence.all()]
        line = f"- {labels.get(o.outcome_type, o.outcome_type)}: {o.notes or '-'}"
        return f"{line} (Evidence: {', '.join(evidence)})" if evidence else line

    hunt_outcomes = [_outcome_line(o) for o in hunt.outcomes.all()]
    if hunt_outcomes:
        out += ["", "## Hunt-level outcomes", ""] + hunt_outcomes

    hunt_evidence = [e.caption or e.file.name for e in hunt.evidence.all()]
    if hunt_evidence:
        out += ["", "## Hunt-level evidence", ""] + [f"- {name}" for name in hunt_evidence]

    rollup = [f"- {name}: {count}" for name, count in hunt.outcome_rollup.items() if count]
    out += ["", "## Outcome rollup", ""] + (rollup or ["- No outcomes recorded"])
    out += _attribution(list(dict.fromkeys(rules)))
    return "\n".join(out) + "\n"


def task_handoff_markdown(task):
    """Detection-engineering handoff. V1 has no ticketing integration, so this is the
    artefact someone pastes into the detection backlog."""
    hunt = task.objective.hunt
    techniques = task.techniques.all()
    out = [
        f"# Detection request: {task.title}",
        "",
        f"- **Source:** {task.task_id} ({hunt.hunt_id} - {hunt.title})",
        f"- **Hunting tool:** {task.hunting_tool or '-'}",
        f"- **Result:** {task.get_result_display() or '-'}",
        f"- **ATT&CK version:** {hunt.attack_version or '-'}",
        "",
        "## ATT&CK mapping",
        "",
    ]
    out += [f"- {t.attack_id} {t.name}" for t in techniques] or ["- (none mapped)"]
    out += [
        "",
        "## Query",
        "",
        "```",
        task.query or "(no query recorded)",
        "```",
        "",
        "## Expected behaviour",
        "",
        f"- **Positive indicator:** {task.expected_positive or '-'}",
        f"- **Benign baseline:** {task.expected_benign or '-'}",
        "",
        "## Findings",
        "",
        task.findings or "-",
        "",
        "## Data sources",
        "",
        ", ".join(task.data_sources.values_list("name", flat=True)) or "-",
    ]
    out += _attribution(list(task.sigma_rules.exclude(tasksigmarule__status=TaskSigmaRule.DISCARDED)))
    return "\n".join(out) + "\n"
