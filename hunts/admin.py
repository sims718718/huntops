from django.contrib import admin
from simple_history.admin import SimpleHistoryAdmin

from .models import (
    Actor,
    Analytic,
    Campaign,
    Comment,
    DataSource,
    DetectionStrategy,
    Evidence,
    EnvironmentProfile,
    Hunt,
    LibraryTask,
    Mitigation,
    Objective,
    Outcome,
    Procedure,
    SigmaRule,
    Software,
    Tactic,
    Task,
    Technique,
)


class ObjectiveInline(admin.TabularInline):
    model = Objective
    extra = 0


class TaskInline(admin.TabularInline):
    model = Task
    extra = 0
    fields = ["title", "hunting_tool", "status", "result"]


class EvidenceInlineForTask(admin.TabularInline):
    # Evidence has three parent FKs (hunt/task/outcome); Django auto-hides
    # whichever one links to this inline's own parent, but not its siblings,
    # so the siblings must be excluded explicitly or the inline exposes
    # cross-parent dropdowns that would trip the exactly-one-parent
    # validation. A single shared class can't do this (Django's admin checks
    # forbid excluding the field that resolves as the current parent's FK),
    # hence one subclass per parent.
    model = Evidence
    fk_name = "task"
    exclude = ["hunt", "outcome"]
    extra = 0


class EvidenceInlineForHunt(admin.TabularInline):
    model = Evidence
    fk_name = "hunt"
    exclude = ["task", "outcome"]
    extra = 0


class OutcomeInlineForTask(admin.TabularInline):
    model = Outcome
    fk_name = "task"
    exclude = ["hunt"]
    extra = 0


class OutcomeInlineForHunt(admin.TabularInline):
    model = Outcome
    fk_name = "hunt"
    exclude = ["task"]
    extra = 0


class CommentInlineForTask(admin.TabularInline):
    model = Comment
    fk_name = "task"
    exclude = ["hunt", "outcome"]
    extra = 0


class CommentInlineForHunt(admin.TabularInline):
    model = Comment
    fk_name = "hunt"
    exclude = ["task", "outcome"]
    extra = 0


@admin.register(Hunt)
class HuntAdmin(SimpleHistoryAdmin):
    list_display = ["hunt_id", "title", "hunt_type", "status", "feasibility_decision", "owner"]
    list_filter = ["status", "hunt_type", "feasibility_decision"]
    search_fields = ["title", "hypothesis"]
    inlines = [OutcomeInlineForHunt, EvidenceInlineForHunt, CommentInlineForHunt, ObjectiveInline]


@admin.register(Objective)
class ObjectiveAdmin(admin.ModelAdmin):
    list_display = ["objective_id", "title", "status"]
    inlines = [TaskInline]


@admin.register(Task)
class TaskAdmin(SimpleHistoryAdmin):
    list_display = ["task_id", "title", "hunting_tool", "status", "result", "source_task"]
    list_filter = ["status", "result", "hunting_tool"]
    search_fields = ["title", "query"]
    inlines = [OutcomeInlineForTask, EvidenceInlineForTask, CommentInlineForTask]


@admin.register(LibraryTask)
class LibraryTaskAdmin(admin.ModelAdmin):
    list_display = ["library_id", "title", "provenance", "hunting_tool", "created_by", "created_at"]
    list_filter = ["provenance", "hunting_tool"]
    search_fields = ["title", "query", "notes"]


@admin.register(Technique)
class TechniqueAdmin(admin.ModelAdmin):
    list_display = ["attack_id", "name", "is_subtechnique", "deprecated", "attack_version"]
    list_filter = ["deprecated", "is_subtechnique", "attack_version"]
    search_fields = ["attack_id", "name", "description"]


@admin.register(Tactic)
class TacticAdmin(admin.ModelAdmin):
    list_display = ["order", "attack_id", "name", "shortname"]


@admin.register(Actor)
class ActorAdmin(admin.ModelAdmin):
    list_display = ["attack_id", "name"]
    search_fields = ["attack_id", "name", "aliases"]


@admin.register(Software)
class SoftwareAdmin(admin.ModelAdmin):
    list_display = ["attack_id", "name", "software_type"]
    list_filter = ["software_type"]
    search_fields = ["attack_id", "name", "aliases"]


@admin.register(Mitigation)
class MitigationAdmin(admin.ModelAdmin):
    list_display = ["attack_id", "name"]
    search_fields = ["attack_id", "name"]


@admin.register(Procedure)
class ProcedureAdmin(admin.ModelAdmin):
    list_display = ["technique", "actor", "software", "campaign"]
    search_fields = ["description"]


admin.site.register([Campaign, Analytic, DetectionStrategy])


@admin.register(SigmaRule)
class SigmaRuleAdmin(admin.ModelAdmin):
    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        from .search import refresh_sigma_search
        refresh_sigma_search(SigmaRule.objects.filter(pk=obj.pk))

    list_display = ["title", "status", "level", "logsource_product", "author"]
    list_filter = ["status", "level", "logsource_product"]
    search_fields = ["title", "description"]


@admin.register(DataSource)
class DataSourceAdmin(admin.ModelAdmin):
    """Registered so near-duplicate custom rows can be found and reconciled."""

    list_display = ["name", "category", "origin"]
    list_filter = ["origin", "category"]
    search_fields = ["name"]


admin.site.register(EnvironmentProfile)
