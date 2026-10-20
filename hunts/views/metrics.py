from django.contrib.auth.decorators import login_required
from django.shortcuts import render

from .. import metrics as trend
from .common import _markdown
from ..models import EnvironmentProfile, Hunt, Technique


def _filters(request):
    # environment_profile_id is an integer FK filter downstream (reporting.py,
    # hunts/metrics.py) - a non-digit value would raise ValueError there uncaught,
    # so a malformed GET param is dropped here rather than 500ing the page.
    environment_profile = request.GET.get("environment_profile", "")
    if not environment_profile.isdigit():
        environment_profile = ""
    return {
        "hunt_type": request.GET.get("hunt_type", ""),
        "environment_profile": environment_profile,
    }


@login_required
def metrics(request):
    filters = _filters(request)
    return render(request, "hunts/metrics.html", {
        "technique_trend": trend.technique_coverage_trend(**filters),
        "data_source_trend": trend.data_source_coverage_trend(**filters),
        "throughput_trend": trend.hunt_throughput_trend(**filters),
        "outcome_trend": trend.outcome_breakdown_trend(**filters),
        "hunt_types": Hunt._meta.get_field("hunt_type").choices,
        "profiles": EnvironmentProfile.objects.all(),
        "filters": filters,
        "has_techniques": Technique.objects.filter(deprecated=False).exists(),
    })


@login_required
def metrics_report(request):
    return _markdown(trend.metrics_markdown(_filters(request)), "metrics-report.md")
