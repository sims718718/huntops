from collections import Counter

from django.contrib.auth.decorators import login_required
from django.db.models import Count, Q
from django.shortcuts import render

from .. import reporting
from ..models import Hunt, HuntSeed, Task, Technique

LIST_LIMIT = 8


@login_required
def dashboard(request):
    """The landing page: where the programme stands and what is waiting on someone.

    Everything here is derived from rows that already exist, so there is nothing
    to keep in sync - it is a set of reads, not a new record.
    """
    stage_counts = dict(Hunt.objects.values_list("status").annotate(n=Count("pk")))
    pipeline = [
        (stage, stage.replace("_", " ").capitalize(), stage_counts.get(stage, 0))
        for stage in Hunt.STATUS_ORDER
        if stage != Hunt.ARCHIVED
    ]

    # The same condition as Hunt.gate_blocked, expressed as a query.
    blocked = (
        Hunt.objects.filter(status=Hunt.FEASIBILITY_REVIEW, feasibility_override_by__isnull=True)
        .exclude(feasibility_decision__in=["GO", "CONDITIONAL"])
    )
    unrecorded = (
        Task.objects.filter(status=Task.EXECUTED, outcomes__isnull=True)
        .exclude(result="")
        .select_related("objective__hunt")
        .order_by("-pk")
    )
    active = (
        Hunt.objects.filter(status=Hunt.IN_PROGRESS)
        .select_related("owner")
        .annotate(
            task_total=Count("objectives__tasks"),
            task_done=Count("objectives__tasks", filter=Q(objectives__tasks__status=Task.EXECUTED)),
        )
    )

    statuses = reporting.technique_status()
    coverage = {
        "hunted": len(statuses),
        "total": Technique.objects.filter(deprecated=False).count(),
        **{name: count for name, count in Counter(statuses.values()).items()},
    }

    return render(request, "hunts/dashboard.html", {
        "pipeline": pipeline,
        "blocked": blocked[:LIST_LIMIT],
        "blocked_total": blocked.count(),
        "unrecorded": unrecorded[:LIST_LIMIT],
        "unrecorded_total": unrecorded.count(),
        "open_seeds": HuntSeed.objects.filter(status=HuntSeed.OPEN).count(),
        "active": active,
        "coverage": coverage,
    })
