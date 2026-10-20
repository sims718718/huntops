from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db import transaction
from django.db.models import Count, Q
from django.http import HttpResponseBadRequest
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST
from django.views.generic import DetailView

from ..intel_import import IntelImportError, parse_files, preview, save_intel
from ..models import Actor, Hunt, HuntSeed, IntelReport, IntelStory, Technique
from .common import FacetSpec, FilterableListView

SECTION_LABELS = [
    ("executive_summary", "Executive summary"),
    ("key_judgments", "Key judgments"),
    ("actor_overview", "Actor / campaign overview"),
    ("recommended_detect", "Recommended detections"),
    ("recommended_mitigate", "Recommended mitigations"),
    ("confidence_sourcing", "Confidence and sourcing"),
    ("source_reputation", "Source reputation"),
    ("open_questions", "Open questions and gaps"),
]


class IntelList(FilterableListView):
    model = IntelReport
    template_name = "hunts/intel_list.html"
    partial_template_name = "hunts/partials/_intel_rows.html"
    search_fields = ("title", "executive_summary")
    facets = {
        "tlp": FacetSpec("tlp", "TLP", lambda: IntelReport.TLP_CHOICES),
        "gate": FacetSpec("gate_status", "Gate", lambda: IntelReport.GATE_CHOICES),
        "actor": FacetSpec("actors__attack_id", "Actor", lambda: [
            (a.attack_id, str(a)) for a in Actor.objects.exclude(intel_reports=None)]),
    }

    def get_queryset(self):
        # ponytail: three joined Count(distinct=True) annotations multiply rows per report;
        # fine at current scale. Switch to subqueries if report counts grow large.
        # annotate() drops Meta.ordering; re-state it so pagination stays stable.
        return super().get_queryset().annotate(
            technique_count=Count("intel_techniques", distinct=True),
            open_seed_count=Count("seeds", filter=Q(seeds__status=HuntSeed.OPEN), distinct=True),
            hunt_count=Count("hunts", distinct=True),
        ).order_by("-number")


class IntelDetail(LoginRequiredMixin, DetailView):
    model = IntelReport
    template_name = "hunts/intel_detail.html"
    context_object_name = "report"

    def get_context_data(self, **kwargs):
        report = self.object
        user = self.request.user
        seeds = list(report.seeds.select_related("hunt"))
        return super().get_context_data(
            sections=[(label, getattr(report, name)) for name, label in SECTION_LABELS],
            techniques=report.intel_techniques.select_related("technique"),
            indicators=report.indicators.all(),
            cves=report.cves.all(),
            seeds=seeds,
            open_seeds=any(s.status == HuntSeed.OPEN for s in seeds),
            can_promote=user.has_perms(["hunts.add_hunt", "hunts.change_huntseed"]),
            hunts=report.hunts.all(),
            files=report.evidence.all(),
            attack_version=Technique.objects.exclude(attack_version="")
            .values_list("attack_version", flat=True).first() or "",
            **kwargs,
        )


# One upload field per framework file. The framework writes them to three different
# folders (intel-reports/, intel-analysis/, hunt-plans/), and a browser file picker can
# only multi-select within one folder - so a single multi-file field yields one file.
UPLOAD_FIELDS = (
    ("report", "-report.md", "Intel report"),
    ("analysis", "-analysis.md", "Intel analysis"),
    ("plan", "-hunt-plan.md", "Hunt plan"),
)


def _read_uploads(files):
    """{filename: text} from the three upload fields, checking each holds the right file."""
    if "report" not in files:
        raise IntelImportError("Choose the run's -report.md in the Intel report field.")
    named = {}
    for field, suffix, label in UPLOAD_FIELDS:
        upload = files.get(field)
        if upload is None:
            continue
        if not upload.name.endswith(suffix):
            raise IntelImportError(f"{label}: expected a <slug>{suffix} file, got {upload.name}.")
        named[upload.name] = upload.read().decode("utf-8-sig")
    return named


@login_required
@permission_required("hunts.add_intelreport", raise_exception=True)
def intel_import(request):
    """Upload -> preview -> confirm. The confirm step re-parses the file text carried
    in hidden fields rather than trusting anything computed at preview time.

    ponytail: file text rides in hidden fields, so a run is bounded by
    DATA_UPLOAD_MAX_MEMORY_SIZE (2.5 MB). Move to a server-side temp store if runs get that large.
    """
    context = {}
    if request.method == "POST":
        try:
            if request.POST.get("step") == "confirm":
                named = dict(zip(request.POST.getlist("name"), request.POST.getlist("content")))
                report = save_intel(
                    parse_files(named),
                    files=[(name, text.encode("utf-8")) for name, text in named.items()],
                    user=request.user,
                )
                return redirect(report)
            named = _read_uploads(request.FILES)
            context = {"preview": preview(parse_files(named)), "named": named}
        except UnicodeDecodeError:
            context["error"] = "Files must be UTF-8 Markdown."
        except IntelImportError as exc:
            context["error"] = str(exc)
    context["upload_fields"] = UPLOAD_FIELDS
    return render(request, "hunts/intel_import.html", context)


@login_required
@require_POST
@permission_required(["hunts.add_hunt", "hunts.change_huntseed"], raise_exception=True)
def promote_seeds(request, pk):
    """Open seed(s) -> one TIO hunt, linked back. Mirrors spinoff_hunt: create, then
    hand the analyst the edit form to trim techniques and fix the title."""
    report = get_object_or_404(IntelReport, pk=pk)
    ids = request.POST.getlist("seed")
    if not ids or not all(i.isdecimal() for i in ids):
        return HttpResponseBadRequest("Pick one or more open seeds from this report.")
    with transaction.atomic():
        seeds = list(report.seeds.select_for_update().filter(pk__in=ids, status=HuntSeed.OPEN))
        if len(seeds) != len(set(ids)):
            return HttpResponseBadRequest("Pick one or more open seeds from this report.")
        hunt = Hunt.objects.create(
            title=(seeds[0].text if len(seeds) == 1 else f"{report.title} hunt")[:300],
            trigger_type="cti",
            hunt_type="TIO",
            trigger_description=f"From {report.intel_id} ({report.title}).\n\n" + "\n\n".join(s.text for s in seeds),
            trigger_source_links=[report.first_source_url] if report.first_source_url else [],
            hypothesis=report.hunt_plan_hypothesis,
            intel_report=report,
        )
        hunt.techniques.set(Technique.objects.filter(intel_citations__report=report).distinct())
        HuntSeed.objects.filter(pk__in=[s.pk for s in seeds]).update(status=HuntSeed.PROMOTED, hunt=hunt)
    # CTI Analyst deliberately lacks change_hunt, so the edit form would 403 for them.
    return redirect("hunt-update" if request.user.has_perm("hunts.change_hunt") else "hunt-detail", pk=hunt.pk)


@login_required
@require_POST
@permission_required("hunts.change_huntseed", raise_exception=True)
def dismiss_seed(request, pk):
    seed = get_object_or_404(HuntSeed, pk=pk, status=HuntSeed.OPEN)
    seed.status = HuntSeed.DISMISSED
    seed.dismiss_reason = request.POST.get(f"reason_{pk}", "").strip()
    seed.save(update_fields=["status", "dismiss_reason"])
    return redirect(seed.report)


@login_required
@require_POST
@permission_required("hunts.add_objective", raise_exception=True)
def attach_intel_stories(request, hunt_pk):
    """Fork chosen hunt-plan Stories into Objectives - copies, like LibraryTask.fork_into,
    so a later re-import of the intel never rewrites the hunt."""
    hunt = get_object_or_404(Hunt, pk=hunt_pk)
    ids = request.POST.getlist("story")
    if not all(i.isdecimal() for i in ids):
        return HttpResponseBadRequest("Pick stories from this hunt's intel report.")
    ids = {int(i) for i in ids}
    if any(not 1 <= i < 2**63 for i in ids):
        return HttpResponseBadRequest("Pick stories from this hunt's intel report.")
    stories = list(IntelStory.objects.filter(pk__in=ids, report_id=hunt.intel_report_id)) if hunt.intel_report_id else []
    if len(stories) != len(ids):
        return HttpResponseBadRequest("Pick stories from this hunt's intel report.")
    with transaction.atomic():
        existing = set(hunt.objectives.values_list("title", flat=True))  # same rule as the "Added" chip
        for story in stories:  # Meta.ordering keeps the plan's story order
            if story.title[:300] not in existing:
                story.fork_into(hunt)
    return redirect(hunt)
