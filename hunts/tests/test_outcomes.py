from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.test import TestCase

from .. import reporting
from ..models import Hunt, Objective, Outcome, Task


class OutcomeViewTests(TestCase):
    def setUp(self):
        call_command("seed_roles", verbosity=0)
        self.hunter = get_user_model().objects.create_user(username="hunter", password="pw")
        self.hunter.groups.add(Group.objects.get(name="Hunter"))
        self.objective = Objective.objects.create(hunt=Hunt.objects.create(title="H"), title="O")
        self.task = Task.objects.create(objective=self.objective, title="T")

    def test_hunter_can_add_an_outcome(self):
        self.client.force_login(self.hunter)
        response = self.client.post(
            f"/tasks/{self.task.pk}/outcomes/new/",
            {"outcome_type": "visibility_gap", "notes": "No EDR coverage on the jump box"},
        )
        self.assertEqual(response.status_code, 302)

        outcome = self.task.outcomes.get()
        self.assertEqual(outcome.outcome_type, "visibility_gap")
        self.assertEqual(outcome.notes, "No EDR coverage on the jump box")
        self.assertEqual(outcome.recorded_by, self.hunter)

    def test_hunter_can_edit_an_outcome(self):
        outcome = Outcome.objects.create(task=self.task, outcome_type="visibility_gap")
        self.client.force_login(self.hunter)

        response = self.client.post(
            f"/outcomes/{outcome.pk}/edit/",
            {"outcome_type": "analytics_detection", "notes": "Detection shipped"},
        )
        self.assertEqual(response.status_code, 302)
        outcome.refresh_from_db()
        self.assertEqual(outcome.outcome_type, "analytics_detection")
        self.assertEqual(outcome.notes, "Detection shipped")

    def test_stakeholder_cannot_add_an_outcome(self):
        stakeholder = get_user_model().objects.create_user(username="stakeholder", password="pw")
        stakeholder.groups.add(Group.objects.get(name="Stakeholder"))
        self.client.force_login(stakeholder)

        response = self.client.post(
            f"/tasks/{self.task.pk}/outcomes/new/",
            {"outcome_type": "visibility_gap", "notes": ""},
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.task.outcomes.count(), 0)

    def test_hunter_can_add_a_hunt_level_outcome(self):
        hunt = self.objective.hunt
        self.client.force_login(self.hunter)
        response = self.client.post(
            f"/hunts/{hunt.pk}/outcomes/new/",
            {"outcome_type": "written_report", "notes": "Final report published"},
        )
        self.assertEqual(response.status_code, 302)

        outcome = hunt.outcomes.get()
        self.assertIsNone(outcome.task)
        self.assertEqual(outcome.outcome_type, "written_report")
        self.assertEqual(outcome.recorded_by, self.hunter)


class OutcomeParentInvariantTests(TestCase):
    def test_rejects_neither_task_nor_hunt(self):
        with self.assertRaises(ValidationError):
            Outcome.objects.create(outcome_type="visibility_gap")

    def test_rejects_both_task_and_hunt(self):
        objective = Objective.objects.create(hunt=Hunt.objects.create(title="H"), title="O")
        task = Task.objects.create(objective=objective, title="T")
        with self.assertRaises(ValidationError):
            Outcome.objects.create(task=task, hunt=objective.hunt, outcome_type="visibility_gap")


class OutcomeRollupTests(TestCase):
    def test_counts_span_every_task_in_the_hunt(self):
        hunt = Hunt.objects.create(title="H")
        objective = Objective.objects.create(hunt=hunt, title="O")
        first = Task.objects.create(objective=objective, title="T1")
        second = Task.objects.create(objective=objective, title="T2")
        Outcome.objects.create(task=first, outcome_type="analytics_detection")
        Outcome.objects.create(task=second, outcome_type="analytics_detection")
        Outcome.objects.create(task=second, outcome_type="visibility_gap")

        rollup = hunt.outcome_rollup
        self.assertEqual(rollup["Analytics/Detection"], 2)
        self.assertEqual(rollup["Visibility Gap"], 1)
        self.assertEqual(rollup["Security Incident"], 0)

    def test_counts_include_hunt_level_outcomes(self):
        hunt = Hunt.objects.create(title="H")
        objective = Objective.objects.create(hunt=hunt, title="O")
        task = Task.objects.create(objective=objective, title="T1")
        Outcome.objects.create(task=task, outcome_type="analytics_detection")
        Outcome.objects.create(hunt=hunt, outcome_type="written_report")

        rollup = hunt.outcome_rollup
        self.assertEqual(rollup["Analytics/Detection"], 1)
        self.assertEqual(rollup["Written Report"], 1)


class HuntMarkdownOutcomeTests(TestCase):
    def test_hunt_level_outcomes_are_listed(self):
        hunt = Hunt.objects.create(title="H")
        Outcome.objects.create(hunt=hunt, outcome_type="written_report", notes="Shipped to leadership")

        report = reporting.hunt_markdown(hunt)
        self.assertIn("## Hunt-level outcomes", report)
        self.assertIn("Written Report: Shipped to leadership", report)


class OutcomeGatedActionTests(TestCase):
    def setUp(self):
        user = get_user_model().objects.create_superuser(username="lead", password="pw")
        self.client.force_login(user)
        objective = Objective.objects.create(hunt=Hunt.objects.create(title="H"), title="O")
        self.task = Task.objects.create(objective=objective, title="T")

    def test_spinoff_and_handoff_actions_hidden_until_outcome_recorded(self):
        page = self.client.get(f"/tasks/{self.task.pk}/")
        self.assertNotContains(page, "Spin off a new hunt")
        self.assertNotContains(page, "Export detection handoff")

        Outcome.objects.create(task=self.task, outcome_type="new_hunt_idea")
        Outcome.objects.create(task=self.task, outcome_type="analytics_detection")

        page = self.client.get(f"/tasks/{self.task.pk}/")
        self.assertContains(page, "Spin off a new hunt")
        self.assertContains(page, "Export detection handoff")
