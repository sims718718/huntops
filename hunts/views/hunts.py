from django.core.paginator import Paginator
from .common import _markdown, text_search
from .library import LIBRARY_SEARCH_FIELDS
from ..search import search_sigma
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.db.models import Count, Q
from django.http import HttpResponseBadRequest
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_POST
from django.views.generic import CreateView, DetailView, ListView, UpdateView

from .. import reporting
from ..forms import (
    CommentForm,
    EvidenceForm,
    HuntForm,
    LibraryTaskForm,
    ObjectiveForm,
    OutcomeForm,
    TaskForm,
    TaskResultForm,
)
from ..models import (
    Comment,
    DetectionStrategy,
    EnvironmentProfile,
    Evidence,
    Hunt,
    LibraryTask,
    Objective,
    Outcome,
    SigmaRule,
    Tactic,
    Task,
    TaskSigmaRule,
    Technique,
    TechniqueMitigation,
)

SUGGESTION_LIMIT = 5


def _hunt_technique_ids(hunt):
    return set(
        Technique.objects.filter(Q(hunts=hunt) | Q(tasks__objective__hunt=hunt)).values_list("id", flat=True)
    )


def _suggested_tasks(hunt):
    return (
        LibraryTask.objects.filter(techniques__in=hunt.techniques.all())
        .exclude(instances__objective__hunt=hunt)
        .distinct()
        .prefetch_related("techniques")
    )


def _suggested_strategies(hunt):
    return (
        DetectionStrategy.objects.filter(technique__in=_hunt_technique_ids(hunt))
        .select_related("technique").prefetch_related("analytics")
        .order_by("technique__attack_id", "name")
    )


def _limited(name, queryset):
    """The first few rows for the detail page, plus the total so it can link to the rest."""
    return {name: list(queryset[:SUGGESTION_LIMIT]), f"{name}_total": queryset.count()}


class HuntList(LoginRequiredMixin, ListView):
    model = Hunt
    paginate_by = 50
    TECHNIQUE_CHIPS = 3

    def _filtered(self):
        """Everything but the stage, so the stage tabs can count within the other filters."""
        get = self.request.GET
        hunts = Hunt.objects.all()
        query = get.get("q", "").strip()
        if query:
            match = Q(title__icontains=query)
            number = query.lower().removeprefix("hunt-").strip()
            if number.isdigit() and len(number) <= 9:
                match |= Q(number=int(number))
            hunts = hunts.filter(match)
        if get.get("owner", "").isdigit():
            hunts = hunts.filter(owner_id=int(get["owner"]))
        if get.get("priority") in ("low", "medium", "high"):
            hunts = hunts.filter(priority=get["priority"])
        return hunts

    def get_queryset(self):
        status = self.request.GET.get("status")
        hunts = self._filtered()
        # Archived hunts only show when asked for, so the default list is live work.
        hunts = hunts.filter(status=status) if status in Hunt.STATUS_ORDER else hunts.exclude(status=Hunt.ARCHIVED)
        return hunts.select_related("owner").prefetch_related("techniques").annotate(
            task_total=Count("objectives__tasks"),
            task_done=Count("objectives__tasks", filter=Q(objectives__tasks__status=Task.EXECUTED)),
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        current = self.request.GET.get("status", "")
        counts = dict(self._filtered().order_by().values_list("status").annotate(n=Count("pk")))
        tabs = [("", "All", sum(n for s, n in counts.items() if s != Hunt.ARCHIVED))]
        tabs += [(s, s.replace("_", " ").capitalize(), counts.get(s, 0)) for s in Hunt.STATUS_ORDER]
        for hunt in context["object_list"]:
            techniques = list(hunt.techniques.all())
            hunt.technique_chips = techniques[: self.TECHNIQUE_CHIPS]
            hunt.technique_more = len(techniques) - len(hunt.technique_chips)
        context.update(
            tabs=tabs,
            current=current if current in Hunt.STATUS_ORDER else "",
            owners=get_user_model().objects.filter(owned_hunts__isnull=False).distinct().order_by("username"),
            owner=self.request.GET.get("owner", ""),
            priority=self.request.GET.get("priority", ""),
            q=self.request.GET.get("q", ""),
            priorities=Hunt._meta.get_field("priority").choices,
        )
        return context



class HuntDetail(LoginRequiredMixin, DetailView):
    model = Hunt

    def get_context_data(self, **kwargs):
        objectives = self.object.objectives.prefetch_related("tasks__techniques")
        library_page = Paginator(text_search(LibraryTask.objects.all(), self.request.GET.get("library_q", ""), LIBRARY_SEARCH_FIELDS), 25).get_page(self.request.GET.get("library_page"))
        hunt = self.object
        technique_ids = _hunt_technique_ids(hunt)
        hunt_tasks = Task.objects.filter(objective__hunt=hunt)
        rollup = {k: v for k, v in hunt.outcome_rollup.items() if v}
        prior_hunts = list(
            Hunt.objects.filter(
                Q(techniques__in=technique_ids) | Q(objectives__tasks__techniques__in=technique_ids)
            ).exclude(pk=hunt.pk).distinct().order_by("-number")[:10]
        ) if technique_ids else []
        for prior in prior_hunts:
            prior.rollup = [(label, count) for label, count in prior.outcome_rollup.items() if count]
        stories = list(hunt.intel_report.stories.all()) if hunt.intel_report_id else []
        existing_titles = set(hunt.objectives.values_list("title", flat=True))
        for story in stories:
            story.added = story.title[:300] in existing_titles
        return super().get_context_data(
            prior_hunts=prior_hunts,
            task_progress=hunt_tasks.aggregate(
                total=Count("pk"), executed=Count("pk", filter=Q(status=Task.EXECUTED))
            ),
            outcome_total=sum(rollup.values()),
            **_limited("suggested_strategies", _suggested_strategies(hunt)),
            stories=stories,
            objectives=objectives,
            rollup=rollup,
            hunt_outcomes=list(self.object.outcomes.all()),
            hunt_evidence=list(self.object.evidence.all()),
            hunt_comments=list(self.object.comments.all()),
            deprecated=self.object.deprecated_techniques,
            library=library_page.object_list, library_page=library_page,
            **_limited("suggested_tasks", _suggested_tasks(hunt)),
            **kwargs,
        )


class SuggestedTasks(LoginRequiredMixin, DetailView):
    """The full list behind the detail page's capped panel; same attach form."""

    model = Hunt
    template_name = "hunts/hunt_suggested_tasks.html"

    def get_context_data(self, **kwargs):
        hunt = self.object
        tasks = list(_suggested_tasks(hunt))
        return super().get_context_data(
            suggested_tasks=tasks, suggested_tasks_total=len(tasks),
            objectives=hunt.objectives.all(), next=self.request.path, **kwargs,
        )


class SuggestedStrategies(LoginRequiredMixin, DetailView):
    model = Hunt
    template_name = "hunts/hunt_suggested_strategies.html"

    def get_context_data(self, **kwargs):
        return super().get_context_data(
            suggested_strategies=_suggested_strategies(self.object), **kwargs
        )



class HuntCreate(PermissionRequiredMixin, CreateView):
    model = Hunt
    form_class = HuntForm
    permission_required = "hunts.add_hunt"

    def get_form_kwargs(self):
        return {**super().get_form_kwargs(), "user": self.request.user}



class HuntUpdate(PermissionRequiredMixin, UpdateView):
    model = Hunt
    form_class = HuntForm
    permission_required = "hunts.change_hunt"

    def get_form_kwargs(self):
        return {**super().get_form_kwargs(), "user": self.request.user}



class ObjectiveCreate(PermissionRequiredMixin, CreateView):
    model = Objective
    form_class = ObjectiveForm
    permission_required = "hunts.add_objective"

    def form_valid(self, form):
        form.instance.hunt = get_object_or_404(Hunt, pk=self.kwargs["hunt_pk"])
        return super().form_valid(form)

    def get_success_url(self):
        return reverse("hunt-detail", args=[self.kwargs["hunt_pk"]])



class ObjectiveUpdate(PermissionRequiredMixin, UpdateView):
    model = Objective
    form_class = ObjectiveForm
    permission_required = "hunts.change_objective"

    def get_success_url(self):
        return reverse("hunt-detail", args=[self.object.hunt_id])



class TaskDetail(LoginRequiredMixin, DetailView):
    model = Task

    def get_context_data(self, **kwargs):
        # PRD 9.2: attaching a technique surfaces matching Sigma rules as starting points,
        # filterable by status and log source so experimental noise stays out of the way.
        suggestions = (
            SigmaRule.objects.filter(techniques__in=self.object.techniques.all())
            .exclude(pk__in=self.object.sigma_rules.all())
            .distinct()
        )
        sigma_filters = {
            "status": self.request.GET.get("status", ""),
            "product": self.request.GET.get("product", ""),
        }
        if sigma_filters["status"]:
            suggestions = suggestions.filter(status=sigma_filters["status"])
        if sigma_filters["product"]:
            suggestions = suggestions.filter(logsource_product=sigma_filters["product"])

        sigma_page = Paginator(search_sigma(suggestions, self.request.GET.get("q", "")), 25).get_page(self.request.GET.get("sigma_page"))
        outcomes = list(self.object.outcomes.all())
        attached_links = list(
            TaskSigmaRule.objects.filter(task=self.object).select_related("sigma_rule")
        )
        return super().get_context_data(
            suggestions=sigma_page.object_list, sigma_page=sigma_page,
            attached_links=attached_links,
            attached_count=len(attached_links),
            result_form=TaskResultForm(instance=self.object),
            sigma_status_choices=TaskSigmaRule.STATUS_CHOICES,
            outcomes=outcomes,
            outcome_type_set={o.outcome_type for o in outcomes},
            task_comments=list(self.object.comments.all()),
            sigma_filters=sigma_filters,
            sigma_statuses=sorted(
                SigmaRule.objects.exclude(status="").values_list("status", flat=True).distinct()
            ),
            sigma_products=sorted(
                SigmaRule.objects.exclude(logsource_product="")
                .values_list("logsource_product", flat=True)
                .distinct()
            ),
            **kwargs,
        )



class TaskCreate(PermissionRequiredMixin, CreateView):
    model = Task
    form_class = TaskForm
    permission_required = "hunts.add_task"

    def form_valid(self, form):
        form.instance.objective = get_object_or_404(Objective, pk=self.kwargs["objective_pk"])
        return super().form_valid(form)



class TaskUpdate(PermissionRequiredMixin, UpdateView):
    model = Task
    form_class = TaskForm
    permission_required = "hunts.change_task"



class ParentFromURLMixin:
    """For a create view whose model belongs to exactly one of several parent
    types, chosen by which <name>_pk kwarg the URL supplies. The parent must
    be set on the form's instance before it validates - a model with an
    exactly-one-parent invariant (Outcome, Evidence) always runs clean()
    during is_valid(), so setting the parent only in form_valid() would be
    too late.

    Subclasses set `parent_kwargs` ({url kwarg: parent model}) and
    `parent_fields` ({parent model: field name on this view's model}).
    """

    parent_kwargs = {}
    parent_fields = {}

    def get_parent(self):
        if not hasattr(self, "_parent"):
            kwarg, model = next((k, m) for k, m in self.parent_kwargs.items() if k in self.kwargs)
            self._parent = get_object_or_404(model, pk=self.kwargs[kwarg])
        return self._parent

    def _parent_field_values(self):
        parent = self.get_parent()
        return {
            field: parent if isinstance(parent, model) else None
            for model, field in self.parent_fields.items()
        }

    def get_context_data(self, **kwargs):
        return super().get_context_data(**self._parent_field_values(), **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["instance"] = self.model(**self._parent_field_values())
        return kwargs


class OutcomeCreate(ParentFromURLMixin, PermissionRequiredMixin, CreateView):
    model = Outcome
    form_class = OutcomeForm
    permission_required = "hunts.add_outcome"
    parent_kwargs = {"task_pk": Task, "hunt_pk": Hunt}
    parent_fields = {Task: "task", Hunt: "hunt"}

    def form_valid(self, form):
        form.instance.recorded_by = self.request.user
        return super().form_valid(form)



class OutcomeUpdate(PermissionRequiredMixin, UpdateView):
    model = Outcome
    form_class = OutcomeForm
    permission_required = "hunts.change_outcome"

    def get_context_data(self, **kwargs):
        return super().get_context_data(task=self.object.task, hunt=self.object.hunt, **kwargs)



class EvidenceCreate(ParentFromURLMixin, PermissionRequiredMixin, CreateView):
    model = Evidence
    form_class = EvidenceForm
    permission_required = "hunts.add_evidence"
    parent_kwargs = {"task_pk": Task, "hunt_pk": Hunt, "outcome_pk": Outcome}
    parent_fields = {Task: "task", Hunt: "hunt", Outcome: "outcome"}

    def form_valid(self, form):
        form.instance.uploaded_by = self.request.user
        return super().form_valid(form)

    def get_success_url(self):
        parent = self.get_parent()
        if isinstance(parent, Outcome):
            return reverse("outcome-update", args=[parent.pk])
        return parent.get_absolute_url()



class CommentCreate(ParentFromURLMixin, PermissionRequiredMixin, CreateView):
    model = Comment
    form_class = CommentForm
    permission_required = "hunts.add_comment"
    parent_kwargs = {"task_pk": Task, "hunt_pk": Hunt, "outcome_pk": Outcome}
    parent_fields = {Task: "task", Hunt: "hunt", Outcome: "outcome"}

    def form_valid(self, form):
        form.instance.author = self.request.user
        return super().form_valid(form)

    def get_success_url(self):
        parent = self.get_parent()
        if isinstance(parent, Outcome):
            return reverse("outcome-update", args=[parent.pk])
        return parent.get_absolute_url()



@require_POST
@permission_required("hunts.change_task", raise_exception=True)
def record_task_result(request, pk):
    task = get_object_or_404(Task, pk=pk)
    form = TaskResultForm(request.POST, instance=task)
    if not form.is_valid():
        return HttpResponseBadRequest("Pick a valid status and result.")
    form.save()
    return redirect("task-detail", pk=task.pk)


@require_POST
@permission_required("hunts.add_librarytask")
def promote_task(request, pk):
    task = get_object_or_404(Task, pk=pk)
    task.promote_to_library(user=request.user)
    return redirect("library-list")



@require_POST
@permission_required("hunts.add_hunt")
def spinoff_hunt(request, pk):
    """New Hunt Idea -> its own Hunt, linked back to the Task that produced it."""
    task = get_object_or_404(Task, pk=pk)
    source = task.objective.hunt
    hunt = Hunt.objects.create(
        title=f"Follow-up: {task.title}",
        trigger_type="prior_hunt",
        trigger_description=f"Spun off from {task.task_id} ({source.hunt_id}). {task.findings}".strip(),
        spun_off_from=task,
        environment_profile=source.environment_profile,
    )
    hunt.techniques.set(task.techniques.all())
    return redirect("hunt-update", pk=hunt.pk)



@login_required
def hunt_report(request, pk):
    hunt = get_object_or_404(Hunt, pk=pk)
    return _markdown(reporting.hunt_markdown(hunt), f"{hunt.hunt_id}.md")



@login_required
def task_handoff(request, pk):
    task = get_object_or_404(Task, pk=pk)
    return _markdown(reporting.task_handoff_markdown(task), f"{task.task_id}-handoff.md")

