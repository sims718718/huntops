import io
import json
import zipfile

from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.db.models import Q
from django.http import Http404, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_GET, require_POST
from django.views.generic import CreateView, DetailView, ListView, UpdateView

from .. import reporting
from ..forms import HuntForm, LibraryTaskForm, ObjectiveForm, TaskForm
from ..library_io import apply_plan, build_plan, dump_task, export_all, over_limit, read_uploads
from ..models import (
    DataSource,
    EnvironmentProfile,
    Hunt,
    LibraryTask,
    Objective,
    SigmaRule,
    Tactic,
    Task,
    Technique,
    TechniqueMitigation,
)


from django.db.models import Count
from .common import FacetSpec, FilterableListView, values

LIBRARY_SEARCH_FIELDS = ['title', 'notes', 'query', 'expected_positive', 'expected_benign', 'techniques__attack_id', 'techniques__name', 'data_sources__name']

class LibraryList(FilterableListView):
    model = LibraryTask
    template_name = 'hunts/librarytask_list.html'
    partial_template_name = 'hunts/partials/_library_rows.html'
    search_fields = LIBRARY_SEARCH_FIELDS
    facets = {
        'provenance': FacetSpec('provenance', 'Source', lambda: LibraryTask._meta.get_field('provenance').choices),
        'tool': FacetSpec('hunting_tool', 'Tool', lambda: values(LibraryTask, 'hunting_tool')),
        'technique': FacetSpec('techniques__attack_id', 'Technique', lambda: [(t.attack_id, str(t)) for t in Technique.objects.all()]),
        'data_source': FacetSpec('data_sources__name', 'Data source', lambda: [
            (n, n) for n in DataSource.objects.exclude(library_tasks=None).order_by('name')
            .values_list('name', flat=True).distinct()]),
    }
    def get_queryset(self):
        # annotate() with an aggregate drops Meta.ordering, which makes pagination
        # non-deterministic - rows repeat or vanish between pages. Re-state it.
        return (super().get_queryset().prefetch_related('techniques')
                .annotate(instance_count=Count('instances', distinct=True))
                .order_by('-number'))





class LibraryDetail(LoginRequiredMixin, DetailView):
    """Reference entries need somewhere to be *read* - the notes are the point."""

    model = LibraryTask

    def get_context_data(self, **kwargs):
        return super().get_context_data(
            hunts=Hunt.objects.filter(objectives__tasks__source_task=self.object).distinct(),
            **kwargs,
        )



class LibraryCreate(PermissionRequiredMixin, CreateView):
    model = LibraryTask
    form_class = LibraryTaskForm
    permission_required = "hunts.add_librarytask"

    def form_valid(self, form):
        form.instance.created_by = self.request.user
        return super().form_valid(form)



class LibraryUpdate(PermissionRequiredMixin, UpdateView):
    model = LibraryTask
    form_class = LibraryTaskForm
    permission_required = "hunts.change_librarytask"

    def dispatch(self, request, *args, **kwargs):
        # Seeded entries are reference material: editing one degrades it for the next
        # reader, so the path out is "duplicate", not "edit".
        entry = self.get_object()
        if entry.is_reference:
            return redirect("library-detail", pk=entry.pk)
        return super().dispatch(request, *args, **kwargs)



@require_POST
@permission_required("hunts.add_task")
def attach_library_task(request, objective_pk):
    objective = get_object_or_404(Objective, pk=objective_pk)
    entry = get_object_or_404(LibraryTask, pk=request.POST.get("library_pk"))
    task = entry.fork_into(objective)
    return redirect("task-detail", pk=task.pk)


@require_POST
@permission_required("hunts.add_task", raise_exception=True)
def attach_suggested_tasks(request, hunt_pk):
    hunt = get_object_or_404(Hunt, pk=hunt_pk)
    # The full-list page posts here too and wants to land back on itself.
    back = request.POST.get("next", "")
    if not url_has_allowed_host_and_scheme(back, allowed_hosts={request.get_host()}):
        back = reverse("hunt-detail", args=[hunt.pk])
    entries = LibraryTask.objects.filter(pk__in=request.POST.getlist("library_pks"))
    if not entries:
        return redirect(back)

    objective_pk = request.POST.get("objective")
    if objective_pk == "new":
        title = request.POST.get("objective_title", "").strip()[:300]
        if not title:
            return redirect(back)
        objective = Objective.objects.create(hunt=hunt, title=title)
    else:
        if not (objective_pk or "").isdigit():
            raise Http404
        objective = get_object_or_404(Objective, pk=objective_pk, hunt=hunt)

    for entry in entries:
        entry.fork_into(objective)

    return redirect(back)



@require_POST
@permission_required("hunts.add_librarytask")
def duplicate_library_task(request, pk):
    """Reference entries are read-only; duplicating is how you make one yours."""
    entry = get_object_or_404(LibraryTask, pk=pk)
    copy = entry.duplicate(user=request.user)
    return redirect("library-update", pk=copy.pk)



@login_required
@require_GET
def library_export_all(request):
    """Every team-built task as one zip of YAML files. Timestamps are fixed so the same
    library always downloads as the same bytes."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, text in export_all().items():
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, text)
    response = HttpResponse(buffer.getvalue(), content_type="application/zip")
    response["Content-Disposition"] = 'attachment; filename="huntops-library.zip"'
    return response


@login_required
@require_GET
def library_export_one(request, pk):
    # Reference entries have no key and are never exported, so they are simply not found.
    task = get_object_or_404(LibraryTask.objects.exclude(key=""), pk=pk)
    response = HttpResponse(dump_task(task), content_type="text/yaml; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{task.key}.yml"'
    return response


@login_required
@permission_required(["hunts.add_librarytask", "hunts.change_librarytask"], raise_exception=True)
def library_import(request):
    """Upload -> preview -> confirm, like intel_import. Confirm re-validates what the
    preview carried rather than trusting it, since a hidden field is client-controlled.

    ponytail: the parsed files ride in one URL-encoded hidden field, so the confirm POST
    must fit DATA_UPLOAD_MAX_MEMORY_SIZE (2.5 MB); uploads are capped at 1 MB to leave
    room for the encoding. Move to a server-side store if libraries outgrow that.
    """
    context = {}
    if request.method == "POST":
        if request.POST.get("step") == "confirm":
            try:
                named = json.loads(request.POST.get("payload", ""))
            except ValueError:
                named = None
            if not isinstance(named, dict) or not all(
                isinstance(name, str) and isinstance(text, str) for name, text in named.items()
            ):
                context["errors"] = ["The preview data could not be read; upload the files again."]
            elif problem := over_limit(named):
                context["errors"] = [problem]
            else:
                plan = build_plan(named)
                if plan.ok:
                    apply_plan(plan, user=request.user)
                    context["result"] = plan
                else:
                    context["errors"] = plan.errors
        else:
            named, errors = read_uploads(request.FILES.getlist("files"))
            plan = build_plan(named) if not errors else None
            context["errors"] = errors or plan.errors
            if plan and plan.ok:
                context["plan"] = plan
                context["payload"] = json.dumps(named)
    for key in ("plan", "result"):
        if key in context:
            items = context[key].items
            context["summary"] = {a: sum(i.action == a for i in items) for a in ("created", "updated", "unchanged")}
    return render(request, "hunts/library_import.html", context)
