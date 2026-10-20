from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.db.models import Q
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_POST
from django.views.generic import CreateView, DetailView, ListView, UpdateView

from .. import reporting
from ..forms import HuntForm, LibraryTaskForm, ObjectiveForm, TaskForm
from ..models import (
    DataSource,
    EnvironmentProfile,
    Hunt,
    IntelReport,
    LibraryTask,
    Objective,
    SigmaRule,
    Tactic,
    Task,
    Technique,
    TechniqueMitigation,
)


from django.db.models import Count
from .common import FacetSpec, FilterableListView

def platforms():
    return [(p, p) for p in sorted({p for ps in Technique.objects.values_list('platforms', flat=True) for p in ps})]

def mapped_data_sources():
    return [(n, n) for n in DataSource.objects.exclude(techniques=None).order_by('name')
            .values_list('name', flat=True).distinct()]

class TechniqueList(FilterableListView):
    model = Technique
    template_name = 'hunts/technique_list.html'
    partial_template_name = 'hunts/partials/_technique_rows.html'
    search_fields = ['name', 'attack_id', 'description']
    facets = {
        'tactic': FacetSpec('tactics', 'Tactic', lambda: list(Tactic.objects.values_list('shortname', 'name')), 'contains', True),
        'platform': FacetSpec('platforms', 'Platform', platforms, 'contains', True),
        # "Which techniques can I hunt with Process Creation?" - the query that
        # makes the data-source model pay off during scoping.
        'data_source': FacetSpec('data_source_objects__name', 'Data source', mapped_data_sources),
    }
    def get_queryset(self):
        qs = super().get_queryset()
        if not self.request.GET.get('deprecated'):
            qs = qs.filter(deprecated=False)
        return qs.annotate(sigma_count=Count('sigma_rules', distinct=True)).order_by('attack_id')





class TechniqueDetail(LoginRequiredMixin, DetailView):
    model = Technique
    slug_field = "attack_id"
    slug_url_kwarg = "attack_id"
    template_name = "hunts/technique_detail.html"

    def get_context_data(self, **kwargs):
        technique = self.object
        hunted, total = technique.covered_subtechniques
        return super().get_context_data(
            tactics=Tactic.objects.filter(shortname__in=technique.tactics or []),
            strategies=technique.detection_strategies.prefetch_related("analytics"),
            mitigations=TechniqueMitigation.objects.filter(
                technique=technique
            ).select_related("mitigation"),
            procedures=technique.procedures.select_related("actor", "software", "campaign"),
            sigma_rules=technique.sigma_rules.all()[:50],
            sigma_count=technique.sigma_rules.count(),
            # the reason to mirror ATT&CK locally rather than link out: local hunt history
            hunts=Hunt.objects.filter(objectives__tasks__techniques=technique).distinct(),
            library=LibraryTask.objects.filter(techniques=technique),
            intel=IntelReport.objects.filter(intel_techniques__technique=technique).distinct(),
            subtechnique_coverage=(hunted, total),
            **kwargs,
        )



@login_required
def heatmap(request):
    filters = {
        "hunt_type": request.GET.get("hunt_type", ""),
        "environment_profile": request.GET.get("environment_profile", ""),
        "start": request.GET.get("start", ""),
        "end": request.GET.get("end", ""),
    }
    statuses = reporting.technique_status(**filters)
    hunted = len(statuses)
    show_intel = request.GET.get("intel") == "1"
    labels = dict(reporting.STATUS_LABELS)
    if show_intel:
        statuses = reporting.with_intel(statuses)
    else:
        labels.pop(reporting.INTEL)
    return render(
        request,
        "hunts/heatmap.html",
        {
            "columns": reporting.matrix_by_tactic(statuses),
            "labels": labels,
            "hunt_types": Hunt._meta.get_field("hunt_type").choices,
            "profiles": EnvironmentProfile.objects.all(),
            "filters": filters,
            "show_intel": show_intel,
            "hunted": hunted,
        },
    )

