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
    EnvironmentProfile,
    Hunt,
    LibraryTask,
    Objective,
    SigmaRule,
    Tactic,
    Task,
    TaskSigmaRule,
    Technique,
    TechniqueMitigation,
)


@require_POST
@permission_required("hunts.change_task")
def attach_sigma(request, pk, rule_pk):
    task = get_object_or_404(Task, pk=pk)
    rule = get_object_or_404(SigmaRule, pk=rule_pk)
    task.sigma_rules.add(rule)
    return redirect("task-detail", pk=pk)



@require_POST
@permission_required("hunts.change_task")
def set_sigma_status(request, pk, rule_pk):
    """Record whether an attached rule was run and what came of it. The rule stays
    attached either way - see TaskSigmaRule for why this replaces the old sticky
    dismissed_sigma_rules removal."""
    status = request.POST.get("status")
    if status not in dict(TaskSigmaRule.STATUS_CHOICES):
        return HttpResponse(status=400)
    link = get_object_or_404(TaskSigmaRule, task_id=pk, sigma_rule_id=rule_pk)
    link.status = status
    link.save(update_fields=["status"])
    return redirect("task-detail", pk=pk)


from .common import FacetSpec, FilterableListView, values

class SigmaList(FilterableListView):
    model = SigmaRule
    search_vector = 'search'
    template_name = 'hunts/sigma_list.html'
    partial_template_name = 'hunts/partials/_sigma_rows.html'
    facets = {
        key: FacetSpec(field, label, lambda field=field: values(SigmaRule, field))
        for key, field, label in [
            ('status', 'status', 'Status'), ('level', 'level', 'Level'),
            ('product', 'logsource_product', 'Product'), ('service', 'logsource_service', 'Service'),
            ('category', 'logsource_category', 'Category'), ('collection', 'collection', 'Collection')]
    }
    facets['technique'] = FacetSpec('techniques__attack_id', 'Technique', lambda: [(t.attack_id, str(t)) for t in Technique.objects.all()])
    def get_queryset(self):
        return super().get_queryset().prefetch_related('techniques')

class SigmaDetail(LoginRequiredMixin, DetailView):
    model = SigmaRule
    slug_field = 'rule_id'
    slug_url_kwarg = 'rule_id'
    template_name = 'hunts/sigma_detail.html'
    def get_queryset(self):
        return super().get_queryset().prefetch_related('techniques', 'tasks__objective__hunt')
