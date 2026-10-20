from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.management import call_command
from django.test import TestCase
from django.urls import reverse

from ..models import Hunt, HuntSeed, IntelReport, Objective, Outcome, Task, Technique


class DashboardTests(TestCase):
    def setUp(self):
        call_command("seed_roles", verbosity=0)
        self.user = self._user("hunter", "Hunter")
        self.client.force_login(self.user)

    def _user(self, name, group):
        user = get_user_model().objects.create_user(username=name, password="pw")
        user.groups.add(Group.objects.get(name=group))
        return user

    def _get(self):
        return self.client.get(reverse("home"))

    def _task(self, hunt, **fields):
        objective = Objective.objects.filter(hunt=hunt).first() or Objective.objects.create(hunt=hunt, title="O")
        return Task.objects.create(objective=objective, title=fields.pop("title", "T"), **fields)

    def test_home_is_the_root_and_the_list_moved(self):
        self.assertEqual(reverse("home"), "/")
        self.assertEqual(reverse("hunt-list"), "/hunts/")
        self.assertEqual(self.client.get("/hunts/").status_code, 200)

    def test_requires_login(self):
        self.client.logout()
        response = self._get()
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("login"), response.url)

    def test_pipeline_counts_each_stage_and_skips_archived(self):
        Hunt.objects.create(title="A", status=Hunt.BACKLOG)
        Hunt.objects.create(title="B", status=Hunt.BACKLOG)
        Hunt.objects.create(title="C", status=Hunt.SCOPING)
        Hunt.objects.create(title="D", status=Hunt.ARCHIVED, feasibility_decision="GO")
        pipeline = dict((stage, count) for stage, _, count in self._get().context["pipeline"])
        self.assertEqual((pipeline[Hunt.BACKLOG], pipeline[Hunt.SCOPING]), (2, 1))
        self.assertNotIn(Hunt.ARCHIVED, pipeline)

    def test_blocked_hunts_are_listed_until_cleared(self):
        blocked = Hunt.objects.create(title="Blocked", status=Hunt.FEASIBILITY_REVIEW)
        Hunt.objects.create(title="Cleared", status=Hunt.FEASIBILITY_REVIEW, feasibility_decision="GO")
        self.assertEqual(list(self._get().context["blocked"]), [blocked])

    def test_executed_task_with_a_result_and_no_outcome_needs_follow_up(self):
        hunt = Hunt.objects.create(title="H")
        open_task = self._task(hunt, title="Open", status=Task.EXECUTED, result="true_positive")
        done = self._task(hunt, title="Done", status=Task.EXECUTED, result="clean")
        Outcome.objects.create(task=done, outcome_type="visibility_gap")
        self._task(hunt, title="No result", status=Task.EXECUTED)
        self._task(hunt, title="Not run", result="inconclusive")
        self.assertEqual(list(self._get().context["unrecorded"]), [open_task])

    def test_open_seeds_are_counted(self):
        report = IntelReport.objects.create(slug="r", title="R")
        HuntSeed.objects.create(report=report, order=1, text="a")
        HuntSeed.objects.create(report=report, order=2, text="b", status=HuntSeed.DISMISSED)
        self.assertEqual(self._get().context["open_seeds"], 1)

    def test_active_hunts_show_task_progress(self):
        hunt = Hunt.objects.create(title="Active", status=Hunt.IN_PROGRESS, feasibility_decision="GO")
        self._task(hunt, title="a", status=Task.EXECUTED)
        self._task(hunt, title="b")
        Hunt.objects.create(title="Idle", status=Hunt.BACKLOG)
        active = list(self._get().context["active"])
        self.assertEqual([(h.pk, h.task_total, h.task_done) for h in active], [(hunt.pk, 2, 1)])

    def test_coverage_snapshot_counts_hunted_techniques(self):
        hunted = Technique.objects.create(attack_id="T1055", name="Injection")
        Technique.objects.create(attack_id="T1059", name="Scripting")
        hunt = Hunt.objects.create(title="H")
        task = self._task(hunt, status=Task.EXECUTED)
        task.techniques.add(hunted)
        coverage = self._get().context["coverage"]
        self.assertEqual((coverage["hunted"], coverage["total"]), (1, 2))

    def test_start_a_hunt_button_needs_permission(self):
        self.assertContains(self._get(), reverse("hunt-create"))
        self.client.force_login(self._user("stake", "Stakeholder"))
        self.assertNotContains(self._get(), reverse("hunt-create"))
