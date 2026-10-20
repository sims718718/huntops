"""Trend-over-time views onto the coverage classification in reporting.py.

No new models: every function here recomputes from Task/Outcome/Hunt rows
that already exist, the same way reporting.technique_status() already does
for the (point-in-time) Coverage heatmap - a trend is just calling that same
classification once per month-end cutoff and tallying. There is no
scheduler in this deployment (docker-compose.yml runs only db and web), so
a periodic-snapshot model would be new infrastructure this doesn't need.
"""

import calendar
from datetime import date

from django.db.models import Count, Q

from . import reporting
from .models import DataSource, Hunt, Outcome, Technique

MONTHS = 12


def _month_ends(months=MONTHS, today=None):
    """[(label, date), ...] for the trailing N calendar months, oldest first."""
    today = today or date.today()
    ends = []
    y, m = today.year, today.month
    for i in range(months - 1, -1, -1):
        mm, yy = m - i, y
        while mm <= 0:
            mm += 12
            yy -= 1
        last_day = calendar.monthrange(yy, mm)[1]
        ends.append((f"{yy}-{mm:02d}", date(yy, mm, last_day)))
    return ends


def technique_coverage_trend(months=MONTHS, today=None, **filters):
    # Not filtered to deprecated=False: technique_status() below draws statuses from
    # whatever techniques executed Tasks reference, deprecated or not, so total must
    # match that same unfiltered population or a technique deprecated after being
    # hunted would undercount (or go negative) here.
    total = Technique.objects.count()
    series = []
    for label, end in _month_ends(months, today):
        statuses = reporting.technique_status(end=end.isoformat(), **filters)
        counts = {"never": total - len(statuses), "clean": 0, "gap": 0, "detection": 0}
        for status in statuses.values():
            counts[status] += 1
        series.append({"label": label, **counts})
    return series


def data_source_coverage_trend(months=MONTHS, today=None, **filters):
    total = DataSource.objects.count()
    series = []
    for label, end in _month_ends(months, today):
        used = reporting.data_source_status(end=end.isoformat(), **filters)
        series.append({"label": label, "used": len(used), "never": total - len(used)})
    return series


def hunt_throughput_trend(hunt_type="", environment_profile="", months=MONTHS, today=None):
    hunts = Hunt.objects.all()
    if hunt_type:
        hunts = hunts.filter(hunt_type=hunt_type)
    if environment_profile:
        hunts = hunts.filter(environment_profile_id=environment_profile)
    completed = hunts.filter(status__in=[Hunt.REPORTED, Hunt.ARCHIVED])

    series = []
    for label, end in _month_ends(months, today):
        series.append({
            "label": label,
            "started": hunts.filter(start_date__year=end.year, start_date__month=end.month).count(),
            "completed": completed.filter(end_date__year=end.year, end_date__month=end.month).count(),
        })
    return series


def outcome_breakdown_trend(hunt_type="", environment_profile="", months=MONTHS, today=None):
    outcomes = Outcome.objects.all()
    if hunt_type:
        outcomes = outcomes.filter(
            Q(task__objective__hunt__hunt_type=hunt_type) | Q(hunt__hunt_type=hunt_type)
        )
    if environment_profile:
        outcomes = outcomes.filter(
            Q(task__objective__hunt__environment_profile_id=environment_profile)
            | Q(hunt__environment_profile_id=environment_profile)
        )

    series = []
    for label, end in _month_ends(months, today):
        rows = (
            outcomes.filter(recorded_at__year=end.year, recorded_at__month=end.month)
            .values("outcome_type")
            .annotate(n=Count("id"))
        )
        counts = {value: 0 for value, _ in reporting.OUTCOME_TYPES}
        for row in rows:
            counts[row["outcome_type"]] = row["n"]
        series.append({"label": label, **counts})
    return series


def metrics_markdown(filters):
    labels = dict(reporting.OUTCOME_TYPES)
    out = ["# Metrics report", ""]

    out += ["## Technique coverage", "", "| Month | Never | Clean | Gap | Detection |", "| --- | --- | --- | --- | --- |"]
    out += [
        f"| {row['label']} | {row['never']} | {row['clean']} | {row['gap']} | {row['detection']} |"
        for row in technique_coverage_trend(**filters)
    ]

    out += ["", "## Data source coverage", "", "| Month | Used | Never used |", "| --- | --- | --- |"]
    out += [
        f"| {row['label']} | {row['used']} | {row['never']} |"
        for row in data_source_coverage_trend(**filters)
    ]

    out += ["", "## Hunt throughput", "", "| Month | Started | Completed |", "| --- | --- | --- |"]
    out += [
        f"| {row['label']} | {row['started']} | {row['completed']} |"
        for row in hunt_throughput_trend(**filters)
    ]

    outcome_keys = list(labels.keys())
    out += ["", "## Outcome breakdown", "", "| Month | " + " | ".join(labels[k] for k in outcome_keys) + " |",
            "| --- |" + " --- |" * len(outcome_keys)]
    out += [
        "| " + row["label"] + " | " + " | ".join(str(row[k]) for k in outcome_keys) + " |"
        for row in outcome_breakdown_trend(**filters)
    ]

    return "\n".join(out) + "\n"
