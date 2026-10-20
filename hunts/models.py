import re

from django.conf import settings
from django.contrib.postgres.fields import ArrayField
from django.contrib.postgres.indexes import GinIndex
from django.contrib.postgres.search import SearchVectorField
from django.core.exceptions import ValidationError
from django.db import models
from django.urls import reverse
from django.utils.text import slugify
from simple_history.models import HistoricalRecords
from simple_history.signals import pre_create_historical_record

RATING = [("GO", "GO"), ("CONDITIONAL", "CONDITIONAL"), ("NO_GO", "NO-GO")]

OUTCOME_TYPES = [
    ("new_hunt_idea", "New Hunt Idea"),
    ("analytics_detection", "Analytics/Detection"),
    ("security_incident", "Security Incident"),
    ("written_report", "Written Report"),
    ("visibility_gap", "Visibility Gap"),
    ("security_control_issue", "Security Control Issue"),
]


def _check_exactly_one_parent(instance, *field_names):
    if sum(bool(getattr(instance, f"{f}_id")) for f in field_names) != 1:
        raise ValidationError(f"Must belong to exactly one of: {', '.join(field_names)}.")


def _next_number(qs):
    # ponytail: max+1 under a unique constraint. Concurrent creates collide and raise;
    # move to a DB sequence if two people ever create hunts in the same second.
    return (qs.aggregate(models.Max("number"))["number__max"] or 0) + 1


class EnvironmentProfile(models.Model):
    """Hunting context (PRD 8.1). Not a tenancy boundary - that is the Enclave,
    which is a separate deployment, not a model."""

    name = models.CharField(max_length=200, unique=True)
    siem = models.CharField(max_length=100, blank=True)
    edr = models.CharField(max_length=100, blank=True)
    env_type = models.CharField(
        max_length=20,
        blank=True,
        choices=[("on_prem", "On-prem"), ("cloud", "Cloud"), ("hybrid", "Hybrid")],
    )
    vertical = models.CharField(max_length=100, blank=True)
    retention_days = models.PositiveIntegerField(null=True, blank=True)
    maturity = models.CharField(max_length=50, blank=True)
    is_default = models.BooleanField(default=False)

    def __str__(self):
        return self.name


class Tactic(models.Model):
    """ATT&CK tactic. `order` carries the official matrix column order, which is not
    alphabetical - Reconnaissance first, Impact last."""

    attack_id = models.CharField(max_length=20, unique=True)
    shortname = models.CharField(max_length=100, unique=True)  # join key for Technique.tactics
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    url = models.URLField(blank=True)
    order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["order"]

    def __str__(self):
        return f"{self.attack_id} {self.name}"


class Technique(models.Model):
    """ATT&CK technique, imported from the STIX bundle.

    ponytail: one row per technique at the currently-imported version, not a full
    per-version snapshot. Hunts pin `attack_version` as a string and deprecated
    techniques raise a warning badge; that covers reproducibility without storing
    800+ techniques N times. Snapshot per version only if old hunts must render
    against the exact historical technique names.
    """

    attack_id = models.CharField(max_length=20, unique=True)
    name = models.CharField(max_length=300)
    description = models.TextField(blank=True)
    url = models.URLField(blank=True)
    tactics = ArrayField(models.CharField(max_length=100), default=list, blank=True)
    platforms = ArrayField(models.CharField(max_length=100), default=list, blank=True)
    data_sources = ArrayField(models.CharField(max_length=200), default=list, blank=True)
    detection = models.TextField(blank=True)  # only older bundles carry per-technique text
    is_subtechnique = models.BooleanField(default=False)
    parent = models.ForeignKey(
        "self", null=True, blank=True, on_delete=models.SET_NULL, related_name="subtechniques"
    )
    revoked_by = models.ForeignKey(
        "self", null=True, blank=True, on_delete=models.SET_NULL, related_name="revokes"
    )
    deprecated = models.BooleanField(default=False)
    technique_version = models.CharField(max_length=20, blank=True)
    modified = models.DateTimeField(null=True, blank=True)
    attack_version = models.CharField(max_length=20, blank=True)

    class Meta:
        ordering = ["attack_id"]

    def get_absolute_url(self):
        return reverse("technique-detail", args=[self.attack_id])

    @property
    def covered_subtechniques(self):
        """(hunted, total) for the child indicator. Parents never inherit coverage:
        hunting T1558.003 is not hunting all of T1558."""
        children = list(self.subtechniques.all())
        hunted = sum(
            1 for child in children if child.tasks.filter(status=Task.EXECUTED).exists()
        )
        return hunted, len(children)

    def __str__(self):
        return f"{self.attack_id} {self.name}"


class Mitigation(models.Model):
    attack_id = models.CharField(max_length=20, unique=True)
    name = models.CharField(max_length=300)
    description = models.TextField(blank=True)
    url = models.URLField(blank=True)
    techniques = models.ManyToManyField(
        Technique, through="TechniqueMitigation", related_name="mitigations"
    )

    class Meta:
        ordering = ["attack_id"]

    def __str__(self):
        return f"{self.attack_id} {self.name}"


class TechniqueMitigation(models.Model):
    """The `mitigates` relationship keeps its own prose - how this mitigation applies
    to this specific technique - which is what the website shows."""

    technique = models.ForeignKey(Technique, on_delete=models.CASCADE)
    mitigation = models.ForeignKey(Mitigation, on_delete=models.CASCADE)
    description = models.TextField(blank=True)

    class Meta:
        unique_together = [("technique", "mitigation")]


class Software(models.Model):
    attack_id = models.CharField(max_length=20, unique=True)
    name = models.CharField(max_length=300)
    software_type = models.CharField(
        max_length=10, choices=[("malware", "Malware"), ("tool", "Tool")]
    )
    aliases = ArrayField(models.CharField(max_length=200), default=list, blank=True)
    description = models.TextField(blank=True)
    url = models.URLField(blank=True)
    platforms = ArrayField(models.CharField(max_length=100), default=list, blank=True)

    class Meta:
        ordering = ["attack_id"]

    def __str__(self):
        return f"{self.attack_id} {self.name}"


class Actor(models.Model):
    """intrusion-set: an ATT&CK group."""

    attack_id = models.CharField(max_length=20, unique=True)
    name = models.CharField(max_length=300)
    aliases = ArrayField(models.CharField(max_length=200), default=list, blank=True)
    description = models.TextField(blank=True)
    url = models.URLField(blank=True)
    software = models.ManyToManyField(Software, blank=True, related_name="actors")

    class Meta:
        ordering = ["attack_id"]

    def __str__(self):
        return f"{self.attack_id} {self.name}"


class Campaign(models.Model):
    attack_id = models.CharField(max_length=20, unique=True)
    name = models.CharField(max_length=300)
    description = models.TextField(blank=True)
    url = models.URLField(blank=True)
    first_seen = models.DateTimeField(null=True, blank=True)
    last_seen = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["attack_id"]

    def __str__(self):
        return f"{self.attack_id} {self.name}"


class Procedure(models.Model):
    """A `uses` relationship pointing at a technique - the procedure examples that tell
    a hunter what the technique looks like when someone actually runs it."""

    technique = models.ForeignKey(Technique, on_delete=models.CASCADE, related_name="procedures")
    actor = models.ForeignKey(Actor, null=True, blank=True, on_delete=models.CASCADE)
    software = models.ForeignKey(Software, null=True, blank=True, on_delete=models.CASCADE)
    campaign = models.ForeignKey(Campaign, null=True, blank=True, on_delete=models.CASCADE)
    description = models.TextField(blank=True)

    class Meta:
        ordering = ["id"]

    @property
    def source(self):
        return self.actor or self.software or self.campaign


class Analytic(models.Model):
    """x-mitre-analytic: MITRE's own detection guidance. Display only - prose, not
    runnable logic, so it never attaches to a Task the way a Sigma rule does."""

    attack_id = models.CharField(max_length=20, blank=True)
    stix_id = models.CharField(max_length=100, unique=True)
    name = models.CharField(max_length=300)
    description = models.TextField(blank=True)
    platforms = ArrayField(models.CharField(max_length=100), default=list, blank=True)
    log_sources = ArrayField(models.CharField(max_length=200), default=list, blank=True)

    def __str__(self):
        return self.name


class DetectionStrategy(models.Model):
    stix_id = models.CharField(max_length=100, unique=True)
    attack_id = models.CharField(max_length=20, blank=True)
    name = models.CharField(max_length=400)
    url = models.URLField(blank=True)
    technique = models.ForeignKey(
        Technique, null=True, on_delete=models.CASCADE, related_name="detection_strategies"
    )
    analytics = models.ManyToManyField(Analytic, blank=True, related_name="strategies")

    def __str__(self):
        return self.name


class SigmaRule(models.Model):
    """SigmaHQ rule. DRL 1.1 requires author/license to survive into exports."""

    rule_id = models.UUIDField(unique=True)
    title = models.CharField(max_length=300)
    status = models.CharField(max_length=30, blank=True)
    description = models.TextField(blank=True)
    level = models.CharField(max_length=30, blank=True)
    logsource_category = models.CharField(max_length=100, blank=True)
    logsource_product = models.CharField(max_length=100, blank=True)
    logsource_service = models.CharField(max_length=100, blank=True)
    author = models.CharField(max_length=300, blank=True)
    license = models.CharField(max_length=100, blank=True)
    collection = models.CharField(
        max_length=60, blank=True, db_index=True
    )  # rules, rules-threat-hunting, rules-emerging-threats, ...
    references = ArrayField(models.CharField(max_length=500), default=list, blank=True)
    raw_yaml = models.TextField()
    techniques = models.ManyToManyField(Technique, blank=True, related_name="sigma_rules")
    search = SearchVectorField(null=True, editable=False)

    class Meta:
        indexes = [GinIndex(fields=['search'], name='sigma_search_gin')]

    def get_absolute_url(self):
        return reverse('sigma-detail', args=[self.rule_id])

    def __str__(self):
        return self.title


class DataSourceHistorySnapshot(models.Model):
    """Carries the data-source names onto historical rows as immutable text.

    The live relation is a M2M, which simple_history tracks separately, but a
    relation resolves to whatever the row is called *now*. A hunt record has to
    say what the analyst selected at the time, so the names are frozen here and
    survive both a later rename and a merge.
    """

    data_source_names_snapshot = ArrayField(
        models.CharField(max_length=200), default=list, blank=True
    )

    class Meta:
        abstract = True


class DataSource(models.Model):
    """A log source a task needs. MITRE-derived rows come from the STIX import;
    analysts add their own for whatever their SIEM actually calls things.

    `category` exists so the picker can group ~110 components under ~40 sources;
    a flat list that long is not scannable.
    """

    MITRE = "mitre"
    CUSTOM = "custom"

    name = models.CharField(max_length=200, unique=True)
    category = models.CharField(max_length=100, blank=True)
    origin = models.CharField(
        max_length=10,
        default=CUSTOM,
        choices=[(MITRE, "ATT&CK"), (CUSTOM, "Team-defined")],
    )
    techniques = models.ManyToManyField(
        Technique, blank=True, related_name="data_source_objects"
    )

    class Meta:
        ordering = ["category", "name"]

    @classmethod
    def category_of(cls, name):
        """The segment before MITRE's ": " separator, or "" for anything else.

        The space matters. "Sysmon:EventID 1" is a vendor channel name from the
        library seed, not an ATT&CK label, and must not be split.
        """
        head, separator, _ = name.partition(": ")
        return head if separator else ""

    def __str__(self):
        return self.name


KEY_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{0,99}")


def unique_key(title, taken):
    """A slug for a library task's file identity, suffixed -2, -3 ... until unused.

    Truncated to 90 characters so a suffix still fits the 100-character limit.
    """
    base = slugify(title)[:90].strip("-_") or "task"
    taken = set(taken)
    key, n = base, 1
    while key in taken:
        n += 1
        key = f"{base}-{n}"
    return key


class LibraryTask(models.Model):
    """Reusable Task definition (TASKLIB-###). Authoring fields only - no execution
    fields, because execution belongs to the forked instance."""

    number = models.PositiveIntegerField(unique=True, editable=False)
    # The identity a YAML file carries (its `id`), stable across installs where `number`
    # is not. Blank for reference entries, which are never exported.
    key = models.CharField(max_length=100, blank=True, editable=False)
    title = models.CharField(max_length=300)
    techniques = models.ManyToManyField(Technique, blank=True)
    sigma_rules = models.ManyToManyField(SigmaRule, blank=True)
    data_sources = models.ManyToManyField(DataSource, blank=True, related_name="library_tasks")
    dismissed_data_sources = models.ManyToManyField(
        DataSource, blank=True, related_name="dismissed_by_library_tasks"
    )  # sticky: auto-attach must never re-add a source the analyst cleared.
    # Task has no equivalent - see TaskSigmaRule for why sigma rules moved to a
    # status field instead, and why data sources on Task did not get the same
    # treatment (no per-attachment status concept was asked for there).
    hunting_tool = models.CharField(max_length=100, blank=True)
    query = models.TextField(blank=True)
    expected_positive = models.TextField(blank=True)
    expected_benign = models.TextField(blank=True)
    notes = models.TextField(
        blank=True, help_text="Why the query is shaped this way, what to tune locally."
    )
    provenance = models.CharField(
        max_length=10,
        default="user",
        choices=[
            ("user", "Team-built"),
            ("curated", "Reference example"),
            ("sigma", "Sigma-derived"),
        ],
    )
    seed_key = models.CharField(max_length=200, blank=True, db_index=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-number"]
        constraints = [
            models.UniqueConstraint(
                fields=["key"], condition=~models.Q(key=""), name="librarytask_key_unique_when_set"
            )
        ]

    @property
    def is_reference(self):
        """Seeded entries are read-only: editing one would degrade it for the next
        reader. Duplicating is the way to make it yours."""
        return bool(self.seed_key)

    @property
    def library_id(self):
        return f"TASKLIB-{self.number:03d}"

    def save(self, *args, **kwargs):
        if self.number is None:
            self.number = _next_number(LibraryTask.objects.all())
        if not self.key and not self.seed_key:
            # ponytail: same race as _next_number - two simultaneous creates can pick one
            # key and the constraint rejects the second. Retry on IntegrityError if it bites.
            self.key = unique_key(
                self.title, LibraryTask.objects.exclude(key="").values_list("key", flat=True)
            )
        super().save(*args, **kwargs)

    def fork_into(self, objective):
        """Attach to an Objective as a Task instance. Copies fields; no live link back,
        so later edits to this library entry never rewrite an executed hunt."""
        task = Task.objects.create(
            objective=objective,
            source_task=self,
            title=self.title,
            hunting_tool=self.hunting_tool,
            query=self.query,
            expected_positive=self.expected_positive,
            expected_benign=self.expected_benign,
        )
        # A curated entry may deliberately cite 2 rules out of 40 that match; auto-attach
        # would bury that choice, so the fork copies the entry's set verbatim.
        task.suppress_auto_sigma = True
        task.techniques.set(self.techniques.all())
        task.sigma_rules.set(self.sigma_rules.all())
        task.data_sources.set(self.data_sources.all())
        return task

    def duplicate(self, user=None):
        """Reference entries are read-only; this is how you make one yours."""
        copy = LibraryTask.objects.create(
            title=f"{self.title} (copy)",
            hunting_tool=self.hunting_tool,
            query=self.query,
            expected_positive=self.expected_positive,
            expected_benign=self.expected_benign,
            notes=self.notes,
            created_by=user,
        )
        copy.suppress_auto_sigma = True
        copy.techniques.set(self.techniques.all())
        copy.sigma_rules.set(self.sigma_rules.all())
        copy.data_sources.set(self.data_sources.all())
        return copy

    def get_absolute_url(self):
        return reverse("library-detail", args=[self.pk])

    def __str__(self):
        return f"{self.library_id} {self.title}"


class Hunt(models.Model):
    BACKLOG = "backlog"
    SCOPING = "scoping"
    FEASIBILITY_REVIEW = "feasibility_review"
    APPROVED = "approved"
    IN_PROGRESS = "in_progress"
    DOCUMENTING = "documenting"
    REPORTED = "reported"
    ARCHIVED = "archived"
    STATUS_ORDER = [
        BACKLOG,
        SCOPING,
        FEASIBILITY_REVIEW,
        APPROVED,
        IN_PROGRESS,
        DOCUMENTING,
        REPORTED,
        ARCHIVED,
    ]

    number = models.PositiveIntegerField(unique=True, editable=False)
    title = models.CharField(max_length=300)

    trigger_type = models.CharField(
        max_length=40,
        blank=True,
        choices=[
            ("cti", "CTI"),
            ("incomplete_use_case", "Incomplete use case"),
            ("past_incident", "Past incident"),
            ("red_team_finding", "Red team finding"),
            ("attack_gap", "ATT&CK TTP gap"),
            ("stakeholder_request", "Stakeholder request"),
            ("vuln_disclosure", "Vulnerability disclosure"),
            ("prior_hunt", "Prior hunt follow-up"),
        ],
    )
    spun_off_from = models.ForeignKey(
        "Task",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="spun_off_hunts",
    )
    trigger_description = models.TextField(blank=True)
    trigger_source_links = ArrayField(models.URLField(), default=list, blank=True)

    environment_profile = models.ForeignKey(
        EnvironmentProfile, null=True, blank=True, on_delete=models.SET_NULL
    )

    hypothesis = models.TextField(blank=True)
    competing_hypotheses = models.TextField(blank=True)  # plain text in V1; ACH matrix is V2
    research_notes = models.TextField(blank=True)

    feasibility_data_availability = models.CharField(max_length=12, blank=True, choices=RATING)
    feasibility_data_quality = models.CharField(max_length=12, blank=True, choices=RATING)
    feasibility_skillset = models.CharField(max_length=12, blank=True, choices=RATING)
    feasibility_timeline = models.CharField(max_length=12, blank=True, choices=RATING)
    feasibility_tooling = models.CharField(max_length=12, blank=True, choices=RATING)
    feasibility_decision = models.CharField(max_length=12, blank=True, choices=RATING)
    feasibility_override_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="feasibility_overrides",
    )
    feasibility_override_reason = models.TextField(blank=True)

    scope_in = models.TextField(blank=True)
    scope_exclusions = models.TextField(blank=True)

    techniques = models.ManyToManyField(Technique, blank=True, related_name="hunts")
    data_sources = models.ManyToManyField(DataSource, blank=True, related_name="hunts")
    hunt_type = models.CharField(
        max_length=4,
        blank=True,
        choices=[
            ("EDA", "Exploratory"),
            ("HBO", "Hypothesis-Based"),
            ("TIO", "Threat-Informed"),
            ("PIO", "Purple-Informed"),
        ],
    )
    status = models.CharField(
        max_length=20,
        default=BACKLOG,
        choices=[(s, s.replace("_", " ").title()) for s in STATUS_ORDER],
    )
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="owned_hunts",
    )
    analysts = models.ManyToManyField(
        settings.AUTH_USER_MODEL, blank=True, related_name="hunts"
    )
    priority = models.CharField(
        max_length=10,
        blank=True,
        choices=[("low", "Low"), ("medium", "Medium"), ("high", "High")],
    )
    start_date = models.DateField(null=True, blank=True)
    end_date = models.DateField(null=True, blank=True)
    attack_version = models.CharField(max_length=20, blank=True)  # pinned at creation, frozen
    intel_report = models.ForeignKey(
        "IntelReport", null=True, blank=True, on_delete=models.SET_NULL, related_name="hunts"
    )

    history = HistoricalRecords()

    class Meta:
        ordering = ["-number"]
        permissions = [
            ("override_feasibility", "Can override a NO-GO feasibility decision"),
        ]

    @property
    def hunt_id(self):
        return f"HUNT-{self.number:03d}"

    @property
    def lifecycle(self):
        """The UTHP pipeline as [(label, position)] so the UI can show where a hunt is.

        Status genuinely is a sequence, which is why it earns a stepped rail rather
        than a plain field.
        """
        current = self.STATUS_ORDER.index(self.status)
        return [
            (
                status.replace("_", " ").capitalize(),
                "done" if index < current else "current" if index == current else "ahead",
            )
            for index, status in enumerate(self.STATUS_ORDER)
        ]

    @property
    def gate_blocked(self):
        """True when the feasibility gate is what stands between this hunt and Approved."""
        return self.status == self.FEASIBILITY_REVIEW and not (
            self.feasibility_decision in ("GO", "CONDITIONAL") or self.feasibility_override_by_id
        )

    @property
    def outcome_rollup(self):
        """Counts per outcome type across every child Task, plus outcomes recorded
        directly on this Hunt."""
        counts = {label: 0 for _, label in OUTCOME_TYPES}
        labels = dict(OUTCOME_TYPES)
        rows = (
            Outcome.objects.filter(models.Q(task__objective__hunt=self) | models.Q(hunt=self))
            .values("outcome_type")
            .annotate(n=models.Count("id"))
        )
        for row in rows:
            if row["outcome_type"] in labels:
                counts[labels[row["outcome_type"]]] = row["n"]
        return counts

    @property
    def deprecated_techniques(self):
        return Technique.objects.filter(
            deprecated=True, tasks__objective__hunt=self
        ).distinct()

    def _check_feasibility_gate(self):
        past_review = self.STATUS_ORDER.index(self.status) > self.STATUS_ORDER.index(
            self.FEASIBILITY_REVIEW
        )
        # Blank blocks too: the realistic failure is nobody filling the assessment in,
        # not someone forcing a NO-GO through.
        cleared = self.feasibility_decision in ("GO", "CONDITIONAL")
        if past_review and not cleared and not self.feasibility_override_by_id:
            raise ValidationError(
                {
                    "status": "Feasibility must be GO or CONDITIONAL to advance, "
                    "or a Hunt Lead must record an override."
                }
            )

    def clean(self):
        self._check_feasibility_gate()

    def save(self, *args, **kwargs):
        # Checked here too, not only in clean(), so the gate holds for code paths
        # that never build a form.
        self._check_feasibility_gate()
        if self.number is None:
            self.number = _next_number(Hunt.objects.all())
        if not self.attack_version:
            # Every row carries the version of the last import, so any row will do.
            self.attack_version = (
                Technique.objects.exclude(attack_version="")
                .values_list("attack_version", flat=True)
                .first()
                or ""
            )
        super().save(*args, **kwargs)

    def get_absolute_url(self):
        return reverse("hunt-detail", args=[self.pk])

    def __str__(self):
        return f"{self.hunt_id} {self.title}"


class IntelReport(models.Model):
    """One threat-intel-hunt-framework run. Its analysis and report share a slug and
    are always read together, so they are one record, not two. Narrative sections
    stay text because nothing queries them yet; rows exist only for what is joined
    or filtered - techniques, indicators, CVEs, seeds."""

    TLP_CHOICES = [
        ("clear", "TLP:CLEAR"),
        ("green", "TLP:GREEN"),
        ("amber", "TLP:AMBER"),
        ("amber_strict", "TLP:AMBER+STRICT"),
        ("red", "TLP:RED"),
    ]
    GATE_CHOICES = [("ready", "READY"), ("limited", "LIMITED"), ("insufficient", "INSUFFICIENT")]

    number = models.PositiveIntegerField(unique=True, editable=False)
    slug = models.SlugField(max_length=100, unique=True)  # the re-import key
    title = models.CharField(max_length=300)
    tlp = models.CharField(max_length=12, blank=True, choices=TLP_CHOICES)
    # Blank means not assessed (runs from before the framework added its quality
    # gate), not failed.
    gate_status = models.CharField(max_length=12, blank=True, choices=GATE_CHOICES)
    actors = models.ManyToManyField(Actor, blank=True, related_name="intel_reports")

    executive_summary = models.TextField(blank=True)
    key_judgments = models.TextField(blank=True)
    actor_overview = models.TextField(blank=True)
    recommended_detect = models.TextField(blank=True)
    recommended_mitigate = models.TextField(blank=True)
    confidence_sourcing = models.TextField(blank=True)
    source_reputation = models.TextField(blank=True)
    open_questions = models.TextField(blank=True)
    hunt_plan_hypothesis = models.TextField(blank=True)  # suggested on seed promotion
    first_source_url = models.URLField(blank=True)  # becomes Hunt.trigger_source_links[0]

    parse_warnings = models.TextField(blank=True)
    imported_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL
    )
    imported_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-number"]

    @property
    def intel_id(self):
        return f"INTEL-{self.number:03d}"

    def save(self, *args, **kwargs):
        if self.number is None:
            self.number = _next_number(IntelReport.objects.all())
        super().save(*args, **kwargs)

    def get_absolute_url(self):
        return reverse("intel-detail", args=[self.pk])

    def __str__(self):
        return f"{self.intel_id} {self.title}"


class IntelTechnique(models.Model):
    report = models.ForeignKey(IntelReport, on_delete=models.CASCADE, related_name="intel_techniques")
    technique = models.ForeignKey(
        Technique, null=True, blank=True, on_delete=models.SET_NULL, related_name="intel_citations"
    )
    raw_id = models.CharField(max_length=20)  # always kept; the only value when unresolved
    tactic = models.CharField(max_length=100, blank=True)
    evidence = models.TextField(blank=True)
    visibility_note = models.TextField(blank=True)  # the report's "Do we have visibility?"


class Indicator(models.Model):
    """Reference data from the report, not a blocklist: stored verbatim (defanging
    kept), never normalized, enriched, or swept - IoC matching isn't hunting."""

    CONFIDENCE = [("confirmed", "Confirmed"), ("reported", "Reported"), ("inferred", "Inferred")]

    report = models.ForeignKey(IntelReport, on_delete=models.CASCADE, related_name="indicators")
    ioc_type = models.CharField(max_length=100)
    value = models.TextField()
    confidence = models.CharField(max_length=10, blank=True, choices=CONFIDENCE)
    source = models.TextField(blank=True)


class IntelCVE(models.Model):
    report = models.ForeignKey(IntelReport, on_delete=models.CASCADE, related_name="cves")
    identifier = models.TextField()  # verbatim cell, e.g. "CVE-2026-16812 (Arista ...) - CISA KEV"
    summary = models.TextField(blank=True)
    relevance = models.TextField(blank=True)


class HuntSeed(models.Model):
    """One recommended hunt action from a report. Promoted and dismissed seeds keep
    their status across re-imports - they record decisions already made."""

    OPEN, PROMOTED, DISMISSED, STALE = "open", "promoted", "dismissed", "stale"

    report = models.ForeignKey(IntelReport, on_delete=models.CASCADE, related_name="seeds")
    order = models.PositiveIntegerField()
    text = models.TextField()
    status = models.CharField(
        max_length=10,
        default=OPEN,
        choices=[(OPEN, "Open"), (PROMOTED, "Promoted"), (DISMISSED, "Dismissed"), (STALE, "Stale")],
    )
    dismiss_reason = models.TextField(blank=True)
    hunt = models.ForeignKey(Hunt, null=True, blank=True, on_delete=models.SET_NULL, related_name="seeds")

    class Meta:
        ordering = ["order"]


ATTACK_LINE = re.compile(r"^ATT&CK:(.*(?:\n[ \t]+\S.*)*)", re.M)
ATTACK_TOKEN = re.compile(r"\b(T\d{4})(\.\d{3})?|[/&,]\s*\.(\d{3})\b")


def attack_ids(text):
    """Technique IDs from a Story's "ATT&CK:" line, including its wrapped continuation
    lines and the framework's shorthand (T1566.001/.002, T1048.002 & .003)."""
    match = ATTACK_LINE.search(text)
    ids, parent = [], None
    for base, sub, short in ATTACK_TOKEN.findall(match.group(1) if match else ""):
        if base:
            parent = base
            ids.append(base + sub)
        elif parent:
            ids.append(f"{parent}.{short}")
    return list(dict.fromkeys(ids))


class IntelStory(models.Model):
    """One Story from a framework hunt plan: a line of investigation the analyst can
    add to a hunt. Replaced wholesale on re-import - Stories hold no analyst decisions
    (unlike HuntSeed)."""

    report = models.ForeignKey(IntelReport, on_delete=models.CASCADE, related_name="stories")
    order = models.PositiveIntegerField()
    title = models.TextField()
    objective = models.TextField(blank=True)
    hypothesis_component = models.TextField(blank=True)
    methodology = models.TextField(blank=True)
    expected_malicious = models.TextField(blank=True)
    expected_benign = models.TextField(blank=True)
    query = models.TextField(blank=True)  # the Detection Logic's primary query
    data_sources = ArrayField(models.CharField(max_length=200), default=list, blank=True)  # table "Source" names

    class Meta:
        ordering = ["order"]

    def fork_into(self, hunt):
        """Copy onto a new Objective with one Task - the shape of a hand-built hunt
        (HUNT-003): methodology steps on the Objective; the primary query and the
        Story's ATT&CK techniques on the Task, so Sigma rules auto-attach, plus the
        Story's own data-source table as team-defined DataSources (reused by name).
        The hypothesis-component block stays in the attached plan file.
        No live link back, like LibraryTask.fork_into: re-importing never rewrites a hunt."""
        # ponytail: one Task per Story (its primary query). Split into several Tasks if
        # plans start carrying more than one query per Story.
        objective = Objective.objects.create(
            hunt=hunt,
            title=self.title[:300],
            methodology=self.methodology,
            expected_outcome_malicious=self.expected_malicious,
            expected_outcome_benign=self.expected_benign,
        )
        task = Task.objects.create(
            objective=objective,
            title=self.title[:300],
            query=self.query,
            expected_positive=self.expected_malicious,
            expected_benign=self.expected_benign,
        )
        task.techniques.set(Technique.objects.filter(attack_id__in=attack_ids(self.hypothesis_component)))
        task.data_sources.add(*(
            DataSource.objects.get_or_create(name=name[:200], defaults={"origin": DataSource.CUSTOM})[0]
            for name in self.data_sources
        ))
        return objective

    def __str__(self):
        return self.title


class Objective(models.Model):
    hunt = models.ForeignKey(Hunt, on_delete=models.CASCADE, related_name="objectives")
    number = models.PositiveIntegerField(editable=False)
    title = models.CharField(max_length=300)
    methodology = models.TextField(blank=True)
    expected_outcome_malicious = models.TextField(blank=True)
    expected_outcome_benign = models.TextField(blank=True)

    class Meta:
        unique_together = [("hunt", "number")]
        ordering = ["number"]

    @property
    def objective_id(self):
        return f"{self.hunt.hunt_id}-O{self.number}"

    @property
    def status(self):
        statuses = list(self.tasks.values_list("status", flat=True))
        if not statuses:
            return "Empty"
        if all(s == Task.EXECUTED for s in statuses):
            return "Complete"
        if any(s != Task.NOT_STARTED for s in statuses):
            return "In Progress"
        return "Not Started"

    def save(self, *args, **kwargs):
        if self.number is None:
            self.number = _next_number(Objective.objects.filter(hunt=self.hunt))
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.objective_id} {self.title}"


class Task(models.Model):
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    EXECUTED = "executed"

    objective = models.ForeignKey(Objective, on_delete=models.CASCADE, related_name="tasks")
    number = models.PositiveIntegerField(editable=False)
    source_task = models.ForeignKey(
        LibraryTask, null=True, blank=True, on_delete=models.SET_NULL, related_name="instances"
    )  # provenance only - the fields above were copied, not linked

    title = models.CharField(max_length=300)
    techniques = models.ManyToManyField(Technique, blank=True, related_name="tasks")
    sigma_rules = models.ManyToManyField(
        SigmaRule, blank=True, through="TaskSigmaRule", related_name="tasks"
    )
    data_sources = models.ManyToManyField(DataSource, blank=True, related_name="tasks")
    hunting_tool = models.CharField(max_length=100, blank=True)
    query = models.TextField(blank=True)
    reference_procedure = models.TextField(blank=True)
    expected_positive = models.TextField(blank=True)
    expected_benign = models.TextField(blank=True)

    status = models.CharField(
        max_length=20,
        default=NOT_STARTED,
        choices=[
            (NOT_STARTED, "Not Started"),
            (IN_PROGRESS, "In Progress"),
            (EXECUTED, "Executed"),
        ],
    )
    result = models.CharField(
        max_length=20,
        blank=True,
        choices=[
            ("true_positive", "True Positive"),
            ("false_positive", "False Positive"),
            ("inconclusive", "Inconclusive"),
            ("no_result", "No Result"),
        ],
    )
    findings = models.TextField(blank=True)
    analyst = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL
    )
    execution_start = models.DateTimeField(null=True, blank=True)
    execution_stop = models.DateTimeField(null=True, blank=True)

    history = HistoricalRecords(
        bases=[DataSourceHistorySnapshot], m2m_fields=["data_sources"]
    )

    class Meta:
        unique_together = [("objective", "number")]
        ordering = ["number"]

    @property
    def task_id(self):
        return f"{self.objective.objective_id}-T{self.number}"

    def save(self, *args, **kwargs):
        if self.number is None:
            self.number = _next_number(Task.objects.filter(objective=self.objective))
        super().save(*args, **kwargs)

    def promote_to_library(self, user=None):
        """Save this Task's authoring fields as a reusable library entry."""
        entry = LibraryTask.objects.create(
            title=self.title,
            hunting_tool=self.hunting_tool,
            query=self.query,
            expected_positive=self.expected_positive,
            expected_benign=self.expected_benign,
            created_by=user,
        )
        entry.techniques.set(self.techniques.all())
        entry.sigma_rules.set(self.sigma_rules.all())
        entry.data_sources.set(self.data_sources.all())
        return entry

    def get_absolute_url(self):
        return reverse("task-detail", args=[self.pk])

    def __str__(self):
        return f"{self.task_id} {self.title}"


class TaskSigmaRule(models.Model):
    """Through model for Task.sigma_rules, tracking whether an attached rule was
    actually run against this task's hunt and what came of it. Replaces the old
    dismissed_sigma_rules sticky-removal field: a discarded rule stays attached and
    visible (a record of what was tried and ruled out) instead of disappearing, and
    Task.sigma_rules.add() is a no-op on an already-linked rule, so auto-attach
    re-touching techniques can't reset a status the analyst already set."""

    PENDING = "pending"
    APPLIED = "applied"
    DISCARDED = "discarded"
    STATUS_CHOICES = [
        (PENDING, "Pending"),
        (APPLIED, "Applied"),
        (DISCARDED, "Discarded"),
    ]

    task = models.ForeignKey(Task, on_delete=models.CASCADE)
    sigma_rule = models.ForeignKey(SigmaRule, on_delete=models.CASCADE)
    status = models.CharField(max_length=10, default=PENDING, choices=STATUS_CHOICES)

    class Meta:
        unique_together = [("task", "sigma_rule")]

    def __str__(self):
        return f"{self.task.task_id} {self.sigma_rule.title} ({self.status})"


class Outcome(models.Model):
    """One recorded outcome of a Task, or of a Hunt directly when it isn't
    produced by one specific task (e.g. a written report recorded once the
    hunt wraps up). A Task can produce several outcomes - e.g. both a
    detection and a visibility gap - each with its own notes, which a single
    shared outcome_types + findings pair on Task could not represent."""

    task = models.ForeignKey(
        Task, null=True, blank=True, on_delete=models.CASCADE, related_name="outcomes"
    )
    hunt = models.ForeignKey(
        Hunt, null=True, blank=True, on_delete=models.CASCADE, related_name="outcomes"
    )
    outcome_type = models.CharField(max_length=30, choices=OUTCOME_TYPES)
    notes = models.TextField(blank=True)
    recorded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL
    )
    recorded_at = models.DateTimeField(auto_now_add=True)

    def clean(self):
        _check_exactly_one_parent(self, "task", "hunt")

    def save(self, *args, **kwargs):
        # Checked here too, not only in clean(), so the invariant holds for code
        # paths that never build a form - same reasoning as Hunt._check_feasibility_gate.
        _check_exactly_one_parent(self, "task", "hunt")
        super().save(*args, **kwargs)

    def get_absolute_url(self):
        if self.task_id:
            return reverse("task-detail", args=[self.task_id])
        return reverse("hunt-detail", args=[self.hunt_id])

    def __str__(self):
        parent_id = self.task.task_id if self.task_id else self.hunt.hunt_id
        return f"{parent_id} {self.get_outcome_type_display()}"


AUTO_ATTACH_STATUSES = ["stable", "test"]


def auto_attach_sigma(sender, instance, action, pk_set, reverse, **kwargs):
    """Selecting techniques attaches the vetted Sigma rules for them.

    stable + test only: SigmaHQ marks just 104 of ~3800 rules stable, so a stable-only
    filter would leave 316 of the 382 rule-covered techniques empty. Experimental stays
    visible in the suggestions panel but never auto-attaches.

    Additive only: .add() on an already-linked rule is a no-op, so re-touching
    techniques never resets a TaskSigmaRule status the analyst already set (e.g.
    Discarded) back to Pending.
    """
    if action != "post_add" or reverse or not pk_set:
        return
    if getattr(instance, "suppress_auto_sigma", False):
        return

    rules = SigmaRule.objects.filter(
        techniques__in=pk_set, status__in=AUTO_ATTACH_STATUSES
    ).distinct()
    if rules:
        instance.sigma_rules.add(*rules)


models.signals.m2m_changed.connect(auto_attach_sigma, sender=Task.techniques.through)
models.signals.m2m_changed.connect(auto_attach_sigma, sender=LibraryTask.techniques.through)


def auto_attach_data_sources(sender, instance, action, pk_set, reverse, **kwargs):
    """Selecting techniques attaches the data sources ATT&CK maps to them.

    Same contract as auto_attach_sigma: additive only, never removes an
    analyst's own choices, and never re-adds something they dismissed.
    """
    if action != "post_add" or reverse or not pk_set:
        return
    # Reused rather than renamed: it already means "this curation is deliberate,
    # do not auto-attach", and fork_into/duplicate already set it.
    if getattr(instance, "suppress_auto_sigma", False):
        return

    sources = DataSource.objects.filter(techniques__in=pk_set).distinct()
    dismissed = getattr(instance, "dismissed_data_sources", None)
    if dismissed is not None:
        sources = sources.exclude(pk__in=dismissed.values_list("pk", flat=True))
    if sources:
        instance.data_sources.add(*sources)


models.signals.m2m_changed.connect(
    auto_attach_data_sources, sender=Task.techniques.through
)
models.signals.m2m_changed.connect(
    auto_attach_data_sources, sender=LibraryTask.techniques.through
)


def snapshot_data_source_names(sender, instance, history_instance, **kwargs):
    """Freeze the selected names onto each historical row as plain text.

    simple_history tracks the M2M itself, but a relation always resolves to
    whatever the row is called now. An executed hunt has to record what the
    analyst actually selected, so the names are copied here and survive a later
    rename or merge of the shared DataSource.
    """
    if not instance.pk:
        return
    history_instance.data_source_names_snapshot = list(
        instance.data_sources.order_by("name").values_list("name", flat=True)
    )


pre_create_historical_record.connect(
    snapshot_data_source_names, sender=Task.history.model
)


class Evidence(models.Model):
    hunt = models.ForeignKey(
        Hunt, null=True, blank=True, on_delete=models.CASCADE, related_name="evidence"
    )
    task = models.ForeignKey(
        Task, null=True, blank=True, on_delete=models.CASCADE, related_name="evidence"
    )
    outcome = models.ForeignKey(
        Outcome, null=True, blank=True, on_delete=models.CASCADE, related_name="evidence"
    )
    intel_report = models.ForeignKey(
        "IntelReport", null=True, blank=True, on_delete=models.CASCADE, related_name="evidence"
    )
    file = models.FileField(upload_to="evidence/")
    caption = models.CharField(max_length=300, blank=True)
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL
    )
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def clean(self):
        _check_exactly_one_parent(self, "hunt", "task", "outcome", "intel_report")

    def save(self, *args, **kwargs):
        _check_exactly_one_parent(self, "hunt", "task", "outcome", "intel_report")
        super().save(*args, **kwargs)

    def __str__(self):
        return self.caption or self.file.name


class Comment(models.Model):
    hunt = models.ForeignKey(
        Hunt, null=True, blank=True, on_delete=models.CASCADE, related_name="comments"
    )
    task = models.ForeignKey(
        Task, null=True, blank=True, on_delete=models.CASCADE, related_name="comments"
    )
    outcome = models.ForeignKey(
        Outcome, null=True, blank=True, on_delete=models.CASCADE, related_name="comments"
    )
    body = models.TextField()
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]

    def clean(self):
        _check_exactly_one_parent(self, "hunt", "task", "outcome")

    def save(self, *args, **kwargs):
        _check_exactly_one_parent(self, "hunt", "task", "outcome")
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.author or 'Unknown'}: {self.body[:50]}"
