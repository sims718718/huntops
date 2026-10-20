from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase

from ..forms import HuntForm
from ..models import DataSource, DetectionStrategy, Hunt, Objective, Task, Technique
from ..reporting import hunt_markdown


class HuntFormTests(TestCase):
    def setUp(self):
        user = get_user_model().objects.create_user("hunter")
        user.user_permissions.add(*Permission.objects.filter(codename__in=["add_hunt", "change_hunt"]))
        self.client.force_login(user)

    def test_attack_version_is_not_on_the_form(self):
        self.assertNotIn("attack_version", HuntForm().fields)

    def test_links_are_saved_one_per_line(self):
        self.client.post("/hunts/new/", {
            "title": "H",
            "trigger_source_links": "https://example.com/a\nhttps://example.com/b?x=1,2",
            "status": Hunt.BACKLOG,
        })
        self.assertEqual(
            Hunt.objects.get().trigger_source_links,
            ["https://example.com/a", "https://example.com/b?x=1,2"],
        )

    def test_a_bad_link_is_rejected(self):
        response = self.client.post("/hunts/new/", {
            "title": "H", "trigger_source_links": "https://example.com/a\nnot a url",
            "status": Hunt.BACKLOG,
        })
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Hunt.objects.exists())

    def test_data_sources_are_saved(self):
        source = DataSource.objects.create(name="Process: Process Creation")
        self.client.post("/hunts/new/", {
            "title": "H", "data_sources": [source.pk], "status": Hunt.BACKLOG,
        })
        self.assertEqual(list(Hunt.objects.get().data_sources.all()), [source])

    def test_report_lists_every_link(self):
        hunt = Hunt.objects.create(title="H", trigger_source_links=["https://a.example", "https://b.example"])
        report = hunt_markdown(hunt)
        self.assertIn("Source: https://a.example", report)
        self.assertIn("Source: https://b.example", report)


class SuggestedStrategiesTests(TestCase):
    def setUp(self):
        self.client.force_login(get_user_model().objects.create_user("viewer"))
        self.hunt = Hunt.objects.create(title="H")
        self.on_hunt = Technique.objects.create(attack_id="T1055", name="Process Injection")
        self.on_task = Technique.objects.create(attack_id="T1059", name="Scripting")
        self.other = Technique.objects.create(attack_id="T1003", name="Credential Dumping")
        for technique in (self.on_hunt, self.on_task, self.other):
            DetectionStrategy.objects.create(
                stix_id=f"x-{technique.attack_id}", name=f"Detect {technique.attack_id}", technique=technique
            )
        self.hunt.techniques.add(self.on_hunt)

    def _names(self):
        response = self.client.get(f"/hunts/{self.hunt.pk}/")
        return {s.name for s in response.context["suggested_strategies"]}

    def test_covers_hunt_and_task_techniques_only(self):
        task = Task.objects.create(objective=Objective.objects.create(hunt=self.hunt, title="O"), title="T")
        task.techniques.add(self.on_task)
        self.assertEqual(self._names(), {"Detect T1055", "Detect T1059"})

    def test_panel_hidden_without_techniques(self):
        self.hunt.techniques.clear()
        response = self.client.get(f"/hunts/{self.hunt.pk}/")
        self.assertEqual(self._names(), set())
        self.assertNotContains(response, "Suggested detection strategies")

    def test_panel_shown_with_a_strategy(self):
        self.assertContains(self.client.get(f"/hunts/{self.hunt.pk}/"), "Detect T1055")
