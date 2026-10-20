from django import forms
from django.contrib.postgres.forms import SimpleArrayField

from .models import Comment, Evidence, Hunt, LibraryTask, Objective, Outcome, Task

TEXT = forms.Textarea(attrs={"rows": 3})
QUERY = forms.Textarea(attrs={"rows": 10, "class": "query"})


class HuntForm(forms.ModelForm):
    class Meta:
        model = Hunt
        exclude = ["number", "spun_off_from", "intel_report", "attack_version"]
        widgets = {
            "hypothesis": forms.Textarea(attrs={"rows": 5}),
            "techniques": forms.SelectMultiple(attrs={"class": "technique-picker"}),
            "data_sources": forms.SelectMultiple(
                attrs={"class": "technique-picker", "data-noun": "data sources"}
            ),
            **{field: TEXT for field in [
                "trigger_description",
                "competing_hypotheses",
                "research_notes",
                "scope_in",
                "scope_exclusions",
                "feasibility_override_reason",
            ]},
        }

    # Newline, not comma: a URL can legitimately contain commas.
    trigger_source_links = SimpleArrayField(
        forms.URLField(), delimiter="\n", required=False, widget=forms.Textarea(attrs={"rows": 3}),
        help_text="One link per line.",
    )

    # ponytail: the technique field is a plain multi-select over ~860 options (~60KB of
    # HTML, browser type-ahead only). Swap in a search-backed picker if hunters complain.
    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        # Only a Hunt Lead can release the feasibility gate, so nobody else is shown the lever.
        if not (user and user.has_perm("hunts.override_feasibility")):
            self.fields.pop("feasibility_override_by", None)
            self.fields.pop("feasibility_override_reason", None)


class ObjectiveForm(forms.ModelForm):
    class Meta:
        model = Objective
        fields = ["title", "methodology", "expected_outcome_malicious", "expected_outcome_benign"]
        widgets = {
            "methodology": TEXT,
            "expected_outcome_malicious": TEXT,
            "expected_outcome_benign": TEXT,
        }


class TaskForm(forms.ModelForm):
    class Meta:
        model = Task
        # sigma_rules is attached from the suggestions panel on the detail page, not
        # picked out of a 3000-entry select.
        exclude = ["number", "objective", "source_task", "sigma_rules"]
        widgets = {
            "query": QUERY,
            "reference_procedure": TEXT,
            "expected_positive": TEXT,
            "expected_benign": TEXT,
            "findings": TEXT,
        }


class TaskResultForm(forms.ModelForm):
    """The three fields an analyst changes when a task finishes, so recording a
    result doesn't need the full Edit form."""

    class Meta:
        model = Task
        fields = ["status", "result", "findings"]
        widgets = {"findings": forms.Textarea(attrs={"rows": 4})}


class OutcomeForm(forms.ModelForm):
    class Meta:
        model = Outcome
        exclude = ["task", "hunt", "recorded_by"]
        widgets = {"notes": TEXT}


class EvidenceForm(forms.ModelForm):
    class Meta:
        model = Evidence
        exclude = ["hunt", "task", "outcome", "intel_report", "uploaded_by"]


class CommentForm(forms.ModelForm):
    class Meta:
        model = Comment
        exclude = ["hunt", "task", "outcome", "author"]
        widgets = {"body": forms.Textarea(attrs={"rows": 3})}


class LibraryTaskForm(forms.ModelForm):
    class Meta:
        model = LibraryTask
        # provenance and seed_key are set by the seeder, never by hand
        exclude = ["number", "created_by", "sigma_rules", "provenance", "seed_key"]
        widgets = {
            "query": QUERY,
            "expected_positive": TEXT,
            "expected_benign": TEXT,
            "notes": forms.Textarea(attrs={"rows": 6}),
        }
