from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.management import call_command
from django.test import TestCase

from ..models import Hunt, Objective, SigmaRule, Task, Technique


class TaskDetailTests(TestCase):
    def setUp(self):
        call_command("seed_roles", verbosity=0)
        self.client.force_login(self._user("hunter", "Hunter"))
        self.hunt = Hunt.objects.create(title="H")
        self.task = Task.objects.create(
            objective=Objective.objects.create(hunt=self.hunt, title="O"), title="T", query="index=x"
        )
        self.url = f"/tasks/{self.task.pk}/"

    def _user(self, name, group):
        user = get_user_model().objects.create_user(username=name, password="pw")
        user.groups.add(Group.objects.get(name=group))
        return user

    def _record(self, data):
        return self.client.post(f"{self.url}result/", data)

    def test_record_result_saves_status_result_and_findings(self):
        response = self._record({"status": "executed", "result": "true_positive", "findings": "Seen on host A"})
        self.assertRedirects(response, self.url)
        self.task.refresh_from_db()
        self.assertEqual(
            (self.task.status, self.task.result, self.task.findings),
            ("executed", "true_positive", "Seen on host A"),
        )

    def test_record_result_leaves_other_fields_alone(self):
        self._record({"status": "executed", "result": "inconclusive", "findings": ""})
        self.task.refresh_from_db()
        self.assertEqual(self.task.query, "index=x")

    def test_invalid_choice_is_rejected_and_changes_nothing(self):
        response = self._record({"status": "bogus", "result": "", "findings": "x"})
        self.assertEqual(response.status_code, 400)
        self.task.refresh_from_db()
        self.assertEqual((self.task.status, self.task.findings), (Task.NOT_STARTED, ""))

    def test_stakeholder_cannot_record_and_sees_no_form(self):
        self.client.force_login(self._user("stake", "Stakeholder"))
        self.assertEqual(self._record({"status": "executed", "result": "", "findings": ""}).status_code, 403)
        self.assertNotContains(self.client.get(self.url), "Record result")

    def test_record_result_rejects_get(self):
        self.assertEqual(self.client.get(f"{self.url}result/").status_code, 405)

    def test_form_is_on_the_page_for_a_hunter(self):
        self.assertContains(self.client.get(self.url), "Record result")

    def test_summary_strip_shows_the_run_details(self):
        self.task.status, self.task.result = Task.EXECUTED, "false_positive"
        self.task.save()
        html = self.client.get(self.url).content.decode()
        self.assertIn('class="summary"', html)
        self.assertIn("False Positive", html)

    def test_other_rules_section_collapsed_until_filtering(self):
        technique = Technique.objects.create(attack_id="T1055", name="Injection")
        self.task.techniques.add(technique)
        rule = SigmaRule.objects.create(
            rule_id="11111111-1111-1111-1111-111111111111", title="Other rule", raw_yaml="x", status="experimental"
        )
        rule.techniques.add(technique)
        quiet = self.client.get(self.url).content.decode()
        self.assertIn("Other rules for these techniques", quiet)
        self.assertNotIn('fold-panel" open', quiet)
        filtered = self.client.get(f"{self.url}?q=Other").content.decode()
        self.assertIn('fold-panel" open', filtered)
