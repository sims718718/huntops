import uuid

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.management import call_command
from django.test import TestCase

from ..models import Hunt, Objective, SigmaRule, Task, TaskSigmaRule


class SigmaStatusTests(TestCase):
    def setUp(self):
        call_command("seed_roles", verbosity=0)
        self.hunter = get_user_model().objects.create_user(username="hunter", password="pw")
        self.hunter.groups.add(Group.objects.get(name="Hunter"))
        self.client.force_login(self.hunter)

        objective = Objective.objects.create(hunt=Hunt.objects.create(title="H"), title="O")
        self.task = Task.objects.create(objective=objective, title="T")
        self.rule = SigmaRule.objects.create(rule_id=uuid.uuid4(), title="A rule", raw_yaml="")
        self.task.sigma_rules.add(self.rule)

    def test_new_attachment_defaults_to_pending(self):
        link = TaskSigmaRule.objects.get(task=self.task, sigma_rule=self.rule)
        self.assertEqual(link.status, TaskSigmaRule.PENDING)

    def test_set_status_to_applied(self):
        response = self.client.post(
            f"/tasks/{self.task.pk}/sigma/{self.rule.pk}/status/", {"status": "applied"}
        )
        self.assertRedirects(response, self.task.get_absolute_url())
        link = TaskSigmaRule.objects.get(task=self.task, sigma_rule=self.rule)
        self.assertEqual(link.status, TaskSigmaRule.APPLIED)
        # rule stays attached, not removed
        self.assertIn(self.rule, self.task.sigma_rules.all())

    def test_set_status_to_discarded_keeps_rule_attached(self):
        self.client.post(
            f"/tasks/{self.task.pk}/sigma/{self.rule.pk}/status/", {"status": "discarded"}
        )
        link = TaskSigmaRule.objects.get(task=self.task, sigma_rule=self.rule)
        self.assertEqual(link.status, TaskSigmaRule.DISCARDED)
        self.assertIn(self.rule, self.task.sigma_rules.all())

    def test_rejects_unknown_status(self):
        response = self.client.post(
            f"/tasks/{self.task.pk}/sigma/{self.rule.pk}/status/", {"status": "bogus"}
        )
        self.assertEqual(response.status_code, 400)
        link = TaskSigmaRule.objects.get(task=self.task, sigma_rule=self.rule)
        self.assertEqual(link.status, TaskSigmaRule.PENDING)

    def test_stakeholder_cannot_change_status(self):
        stakeholder = get_user_model().objects.create_user(username="stakeholder", password="pw")
        stakeholder.groups.add(Group.objects.get(name="Stakeholder"))
        self.client.force_login(stakeholder)

        response = self.client.post(
            f"/tasks/{self.task.pk}/sigma/{self.rule.pk}/status/", {"status": "applied"}
        )
        # attach_sigma/set_sigma_status use the plain @permission_required decorator
        # (pre-existing, unlike the class-based views elsewhere), which redirects
        # rather than raising 403 for an authenticated-but-unauthorized user.
        self.assertEqual(response.status_code, 302)
        link = TaskSigmaRule.objects.get(task=self.task, sigma_rule=self.rule)
        self.assertEqual(link.status, TaskSigmaRule.PENDING)

    def test_task_detail_links_to_sigma_detail(self):
        response = self.client.get(self.task.get_absolute_url())
        self.assertContains(response, f'href="/sigma/{self.rule.rule_id}/"')
