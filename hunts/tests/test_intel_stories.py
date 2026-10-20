from io import StringIO

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.management import call_command
from django.test import TestCase
from django.urls import reverse

from ..models import DataSource, Hunt, IntelReport, IntelStory, Objective, Task, Technique, attack_ids


class IntelStoryForkTests(TestCase):
    HC = (
        "ID: X-S1\n"
        "ATT&CK:             T1566.001/.002 (Phishing) / T1203 (Exploit) /\n"
        "                    T1048.002 & .003 (Exfil)\n"
        "Pyramid level:      TTP\n"
    )

    def test_attack_ids_expand_shorthand_and_wrapped_lines(self):
        self.assertEqual(attack_ids(self.HC), ["T1566.001", "T1566.002", "T1203", "T1048.002", "T1048.003"])
        self.assertEqual(attack_ids("no attack line here T9999"), [])

    def test_fork_into_makes_an_objective_and_a_task_like_a_hand_built_hunt(self):
        report = IntelReport.objects.create(slug="r", title="R")
        for attack_id in ("T1566.001", "T1203"):
            Technique.objects.create(attack_id=attack_id, name=attack_id)
        story = IntelStory.objects.create(
            report=report, order=1, title="S" * 400, objective="Determine whether X",
            hypothesis_component=self.HC, methodology="Phase 1: collect\nPhase 2: analyse",
            query="SigninLogs | take 10", expected_malicious="bad", expected_benign="good",
            data_sources=["Entra ID Sign-in Logs", "M365 Unified Audit Log"],
        )
        existing = DataSource.objects.create(name="M365 Unified Audit Log")
        hunt = Hunt.objects.create(title="H")
        objective = story.fork_into(hunt)
        self.assertEqual(objective.hunt, hunt)
        self.assertEqual(len(objective.title), 300)
        self.assertEqual(objective.methodology, "Phase 1: collect\nPhase 2: analyse")
        self.assertNotIn("ATT&CK", objective.methodology)
        self.assertEqual((objective.expected_outcome_malicious, objective.expected_outcome_benign), ("bad", "good"))
        task = objective.tasks.get()
        self.assertEqual(task.title, "S" * 300)
        self.assertEqual(task.query, "SigninLogs | take 10")
        self.assertEqual((task.expected_positive, task.expected_benign), ("bad", "good"))
        self.assertEqual(sorted(task.techniques.values_list("attack_id", flat=True)), ["T1203", "T1566.001"])
        self.assertEqual(sorted(task.data_sources.values_list("name", flat=True)),
                         ["Entra ID Sign-in Logs", "M365 Unified Audit Log"])
        self.assertIn(existing, task.data_sources.all())  # reused by name, not duplicated
        self.assertEqual(DataSource.objects.get(name="Entra ID Sign-in Logs").origin, DataSource.CUSTOM)
        story.title = "changed"
        story.save()
        objective.refresh_from_db()
        self.assertEqual(objective.title, "S" * 300)

    def test_stories_order(self):
        report = IntelReport.objects.create(slug="r", title="R")
        IntelStory.objects.create(report=report, order=2, title="second")
        IntelStory.objects.create(report=report, order=1, title="first")
        self.assertEqual([s.title for s in report.stories.all()], ["first", "second"])


class IntelStoryRoleTests(TestCase):
    def test_roles(self):
        call_command("seed_roles", stdout=StringIO())
        perms = lambda name: set(Group.objects.get(name=name).permissions.values_list("codename", flat=True))
        self.assertIn("add_intelstory", perms("CTI Analyst"))
        self.assertNotIn("add_objective", perms("CTI Analyst"))
        self.assertIn("add_objective", perms("Hunter"))


class PriorHuntsTests(TestCase):
    def setUp(self):
        call_command("seed_roles", stdout=StringIO())
        user = get_user_model().objects.create_user("viewer")
        user.groups.add(Group.objects.get(name="Stakeholder"))
        self.client.force_login(user)

    def detail(self, hunt):
        return self.client.get(reverse("hunt-detail", args=[hunt.pk]))

    def test_prior_hunts_share_a_technique(self):
        technique = Technique.objects.create(attack_id="T1059", name="Cmd")
        hunt = Hunt.objects.create(title="Current")
        hunt.techniques.add(technique)
        via_hunt = Hunt.objects.create(title="Via hunt techniques")
        via_hunt.techniques.add(technique)
        via_task = Hunt.objects.create(title="Via task techniques")
        Task.objects.create(objective=Objective.objects.create(hunt=via_task, title="O"), title="T").techniques.add(technique)
        Hunt.objects.create(title="Unrelated")
        response = self.detail(hunt)
        self.assertEqual(response.context["prior_hunts"], [via_task, via_hunt])
        self.assertContains(response, "Prior hunts on these techniques")

    def test_prior_hunts_hidden_without_techniques(self):
        response = self.detail(Hunt.objects.create(title="H"))
        self.assertEqual(response.context["prior_hunts"], [])
        self.assertNotContains(response, "Prior hunts on these techniques")


class IntelStoryPanelTests(TestCase):
    def setUp(self):
        call_command("seed_roles", stdout=StringIO())
        users = get_user_model().objects
        self.hunter = users.create_user("hunter")
        self.hunter.groups.add(Group.objects.get(name="Hunter"))
        self.client.force_login(self.hunter)
        self.report = IntelReport.objects.create(slug="r", title="R")
        self.hunt = Hunt.objects.create(title="H", intel_report=self.report)
        self.s1 = IntelStory.objects.create(report=self.report, order=1, title="Story one", objective="o1")
        self.s2 = IntelStory.objects.create(report=self.report, order=2, title="Story two", objective="o2",
                                            expected_malicious="bad", expected_benign="good")
        self.s3 = IntelStory.objects.create(report=self.report, order=3, title="Story three")
        Objective.objects.create(hunt=self.hunt, title="Story one")
        self.url = reverse("attach-intel-stories", args=[self.hunt.pk])

    def test_panel_lists_stories_and_marks_added(self):
        response = self.client.get(reverse("hunt-detail", args=[self.hunt.pk]))
        self.assertContains(response, "Suggested objectives from INTEL-001")
        self.assertContains(response, "Added")
        self.assertNotContains(response, f'name="story" value="{self.s1.pk}"')
        self.assertContains(response, f'name="story" value="{self.s2.pk}"')

    def test_attach_creates_objectives_in_story_order(self):
        response = self.client.post(self.url, {"story": [self.s3.pk, self.s2.pk]})
        self.assertRedirects(response, reverse("hunt-detail", args=[self.hunt.pk]))
        titles = list(self.hunt.objectives.order_by("number").values_list("title", flat=True))
        self.assertEqual(titles, ["Story one", "Story two", "Story three"])
        objective = self.hunt.objectives.get(title="Story two")
        self.assertEqual(objective.methodology, "")
        self.assertEqual(objective.tasks.get().title, "Story two")
        self.assertEqual((objective.expected_outcome_malicious, objective.expected_outcome_benign), ("bad", "good"))

    def test_rejects_foreign_or_bad_ids(self):
        other = IntelStory.objects.create(report=IntelReport.objects.create(slug="o", title="O"), order=1, title="X")
        for data in ({"story": [other.pk]}, {"story": ["abc"]}, {"story": ["²"]}):
            with self.subTest(data=data):
                self.assertEqual(self.client.post(self.url, data).status_code, 400)
        unlinked = Hunt.objects.create(title="No intel")
        response = self.client.post(reverse("attach-intel-stories", args=[unlinked.pk]), {"story": [self.s2.pk]})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.hunt.objectives.count(), 1)

    def test_out_of_range_id_is_400(self):
        self.assertEqual(self.client.post(self.url, {"story": ["99999999999999999999"]}).status_code, 400)

    def test_resubmitting_an_added_story_creates_nothing(self):
        response = self.client.post(self.url, {"story": [self.s1.pk]})
        self.assertRedirects(response, reverse("hunt-detail", args=[self.hunt.pk]))
        self.assertEqual(self.hunt.objectives.count(), 1)

    def test_zero_padded_duplicate_id_attaches_once(self):
        response = self.client.post(self.url, {"story": [str(self.s2.pk), f"0{self.s2.pk}"]})
        self.assertRedirects(response, reverse("hunt-detail", args=[self.hunt.pk]))
        self.assertEqual(self.hunt.objectives.filter(title="Story two").count(), 1)

    def test_empty_selection_changes_nothing(self):
        self.assertRedirects(self.client.post(self.url, {}), reverse("hunt-detail", args=[self.hunt.pk]))
        self.assertEqual(self.hunt.objectives.count(), 1)

    def test_stakeholder_and_cti_cannot_attach_or_see_the_form(self):
        for group in ("Stakeholder", "CTI Analyst"):
            with self.subTest(group=group):
                user = get_user_model().objects.create_user(group.replace(" ", "").lower())
                user.groups.add(Group.objects.get(name=group))
                self.client.force_login(user)
                self.assertEqual(self.client.post(self.url, {"story": [self.s2.pk]}).status_code, 403)
                self.assertNotContains(self.client.get(reverse("hunt-detail", args=[self.hunt.pk])),
                                       "Suggested objectives from")
