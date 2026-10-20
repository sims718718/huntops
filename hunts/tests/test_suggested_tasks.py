from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.management import call_command
from django.test import TestCase

from ..models import Analytic, DetectionStrategy, Hunt, LibraryTask, Objective, Task, Technique


class SuggestedTasksContextTests(TestCase):
    def setUp(self):
        self.t1 = Technique.objects.create(attack_id="T1055", name="Process Injection")
        self.t2 = Technique.objects.create(attack_id="T1059", name="Command and Scripting Interpreter")
        self.hunt = Hunt.objects.create(title="H")
        self.hunt.techniques.add(self.t1)
        self.client.force_login(get_user_model().objects.create_user("viewer"))

    def _get(self):
        response = self.client.get(f"/hunts/{self.hunt.pk}/")
        return list(response.context["suggested_tasks"])

    def test_includes_library_task_sharing_a_technique(self):
        entry = LibraryTask.objects.create(title="Matches")
        entry.techniques.add(self.t1)
        self.assertEqual(self._get(), [entry])

    def test_excludes_library_task_with_no_shared_technique(self):
        entry = LibraryTask.objects.create(title="No overlap")
        entry.techniques.add(self.t2)
        self.assertEqual(self._get(), [])

    def test_excludes_library_task_already_forked_into_this_hunt(self):
        entry = LibraryTask.objects.create(title="Already attached")
        entry.techniques.add(self.t1)
        objective = Objective.objects.create(hunt=self.hunt, title="O")
        entry.fork_into(objective)

        self.assertEqual(self._get(), [])

    def test_exclusion_is_not_scoped_to_a_single_objective(self):
        entry = LibraryTask.objects.create(title="Already attached")
        entry.techniques.add(self.t1)
        other_objective = Objective.objects.create(hunt=self.hunt, title="Other")
        entry.fork_into(other_objective)

        self.assertEqual(self._get(), [])

    def test_empty_when_hunt_has_no_techniques(self):
        self.hunt.techniques.clear()
        entry = LibraryTask.objects.create(title="Matches")
        entry.techniques.add(self.t1)
        self.assertEqual(self._get(), [])


class AttachSuggestedTasksTests(TestCase):
    def setUp(self):
        call_command("seed_roles", verbosity=0)
        self.hunter = get_user_model().objects.create_user(username="hunter", password="pw")
        self.hunter.groups.add(Group.objects.get(name="Hunter"))
        self.client.force_login(self.hunter)

        self.technique = Technique.objects.create(attack_id="T1055", name="Process Injection")
        self.hunt = Hunt.objects.create(title="H")
        self.hunt.techniques.add(self.technique)
        self.objective = Objective.objects.create(hunt=self.hunt, title="O")

        self.entry1 = LibraryTask.objects.create(title="One")
        self.entry1.techniques.add(self.technique)
        self.entry2 = LibraryTask.objects.create(title="Two")
        self.entry2.techniques.add(self.technique)

    def _post(self, data):
        return self.client.post(f"/hunts/{self.hunt.pk}/attach-suggested/", data)

    def test_forks_selected_entries_into_existing_objective(self):
        response = self._post({
            "objective": str(self.objective.pk),
            "library_pks": [str(self.entry1.pk), str(self.entry2.pk)],
        })
        self.assertRedirects(response, self.hunt.get_absolute_url())
        titles = set(self.objective.tasks.values_list("title", flat=True))
        self.assertEqual(titles, {"One", "Two"})

    def test_creates_new_objective_when_requested(self):
        response = self._post({
            "objective": "new",
            "objective_title": "Fresh objective",
            "library_pks": [str(self.entry1.pk)],
        })
        self.assertRedirects(response, self.hunt.get_absolute_url())
        objective = self.hunt.objectives.get(title="Fresh objective")
        self.assertEqual(list(objective.tasks.values_list("title", flat=True)), ["One"])

    def test_rejects_objective_belonging_to_a_different_hunt(self):
        other_hunt = Hunt.objects.create(title="Other")
        other_objective = Objective.objects.create(hunt=other_hunt, title="O")

        response = self._post({
            "objective": str(other_objective.pk),
            "library_pks": [str(self.entry1.pk)],
        })
        self.assertEqual(response.status_code, 404)

    def test_rejects_get(self):
        response = self.client.get(f"/hunts/{self.hunt.pk}/attach-suggested/")
        self.assertEqual(response.status_code, 405)

    def test_non_integer_objective_is_a_404_not_a_500(self):
        response = self._post({"objective": "not-a-number", "library_pks": [str(self.entry1.pk)]})
        self.assertEqual(response.status_code, 404)

    def test_no_checked_entries_does_not_create_an_empty_objective(self):
        before = self.hunt.objectives.count()
        response = self._post({"objective": "new", "objective_title": "Should not be created"})
        self.assertRedirects(response, self.hunt.get_absolute_url())
        self.assertEqual(self.hunt.objectives.count(), before)

    def test_overlong_objective_title_is_truncated_not_a_server_error(self):
        response = self._post({
            "objective": "new",
            "objective_title": "x" * 400,
            "library_pks": [str(self.entry1.pk)],
        })
        self.assertRedirects(response, self.hunt.get_absolute_url())
        objective = self.hunt.objectives.get(title="x" * 300)
        self.assertEqual(list(objective.tasks.values_list("title", flat=True)), ["One"])

    def test_requires_add_task_permission(self):
        stakeholder = get_user_model().objects.create_user(username="stakeholder", password="pw")
        stakeholder.groups.add(Group.objects.get(name="Stakeholder"))
        self.client.force_login(stakeholder)

        response = self._post({
            "objective": str(self.objective.pk),
            "library_pks": [str(self.entry1.pk)],
        })
        self.assertEqual(response.status_code, 403)


class SuggestionLimitTests(TestCase):
    """The detail page caps each suggestion panel; a separate page lists them all."""

    def setUp(self):
        call_command("seed_roles", verbosity=0)
        hunter = get_user_model().objects.create_user(username="hunter", password="pw")
        hunter.groups.add(Group.objects.get(name="Hunter"))
        self.client.force_login(hunter)
        self.technique = Technique.objects.create(attack_id="T1055", name="Process Injection")
        self.hunt = Hunt.objects.create(title="H")
        self.hunt.techniques.add(self.technique)
        self.objective = Objective.objects.create(hunt=self.hunt, title="O")

    def _tasks(self, count):
        for n in range(count):
            LibraryTask.objects.create(title=f"Entry {n}").techniques.add(self.technique)

    def _strategies(self, count):
        for n in range(count):
            DetectionStrategy.objects.create(
                stix_id=f"x-{n}", name=f"Strategy {n}", technique=self.technique
            )

    def test_detail_caps_tasks_at_five_and_links_to_the_rest(self):
        self._tasks(7)
        response = self.client.get(self.hunt.get_absolute_url())
        self.assertEqual(len(response.context["suggested_tasks"]), 5)
        self.assertContains(response, "See all 7 suggested tasks")
        self.assertContains(response, f"/hunts/{self.hunt.pk}/suggested-tasks/")

    def test_no_see_all_link_at_five_or_fewer(self):
        self._tasks(5)
        self.assertNotContains(self.client.get(self.hunt.get_absolute_url()), "See all")

    def test_full_task_page_lists_everything_and_returns_to_itself(self):
        self._tasks(7)
        url = f"/hunts/{self.hunt.pk}/suggested-tasks/"
        response = self.client.get(url)
        self.assertEqual(len(response.context["suggested_tasks"]), 7)
        self.assertContains(response, f'name="next" value="{url}"')

    def test_attach_returns_to_the_next_page(self):
        self._tasks(1)
        entry = LibraryTask.objects.get()
        url = f"/hunts/{self.hunt.pk}/suggested-tasks/"
        response = self.client.post(f"/hunts/{self.hunt.pk}/attach-suggested/", {
            "objective": str(self.objective.pk), "library_pks": [str(entry.pk)], "next": url,
        })
        self.assertRedirects(response, url)
        self.assertEqual(self.objective.tasks.count(), 1)

    def test_attach_ignores_an_off_site_next(self):
        self._tasks(1)
        entry = LibraryTask.objects.get()
        response = self.client.post(f"/hunts/{self.hunt.pk}/attach-suggested/", {
            "objective": str(self.objective.pk), "library_pks": [str(entry.pk)],
            "next": "https://evil.example/",
        })
        self.assertRedirects(response, self.hunt.get_absolute_url())

    def test_detail_caps_strategies_at_five_and_links_to_the_rest(self):
        self._strategies(6)
        response = self.client.get(self.hunt.get_absolute_url())
        self.assertEqual(len(response.context["suggested_strategies"]), 5)
        self.assertContains(response, "See all 6 suggested strategies")

    def test_full_strategy_page_lists_everything(self):
        self._strategies(6)
        response = self.client.get(f"/hunts/{self.hunt.pk}/suggested-strategies/")
        self.assertEqual(len(response.context["suggested_strategies"]), 6)
        self.assertNotContains(response, "type=\"checkbox\"")

    def test_full_pages_require_login(self):
        self.client.logout()
        for name in ("suggested-tasks", "suggested-strategies"):
            self.assertEqual(self.client.get(f"/hunts/{self.hunt.pk}/{name}/").status_code, 302)

    def test_strategies_link_nowhere_external_and_full_page_shows_analytics(self):
        strategy = DetectionStrategy.objects.create(
            stix_id="x-1", name="Strategy", technique=self.technique, url="https://attack.mitre.org/detectionstrategies/DET0001"
        )
        analytic = Analytic.objects.create(
            stix_id="a-1", name="Analytic 1", description="Look for odd parents.", log_sources=["Sysmon:EventID 1"]
        )
        strategy.analytics.add(analytic)
        detail = self.client.get(self.hunt.get_absolute_url())
        self.assertNotContains(detail, "attack.mitre.org/detectionstrategies")
        full = self.client.get(f"/hunts/{self.hunt.pk}/suggested-strategies/")
        self.assertNotContains(full, "attack.mitre.org/detectionstrategies")
        self.assertContains(full, "Look for odd parents.")
        self.assertContains(full, "Sysmon:EventID 1")


class HuntSummaryTests(TestCase):
    def setUp(self):
        call_command("seed_roles", verbosity=0)
        hunter = get_user_model().objects.create_user(username="hunter", password="pw")
        hunter.groups.add(Group.objects.get(name="Hunter"))
        self.client.force_login(hunter)
        self.hunt = Hunt.objects.create(title="H")
        objective = Objective.objects.create(hunt=self.hunt, title="O")
        Task.objects.create(objective=objective, title="Done", status=Task.EXECUTED)
        Task.objects.create(objective=objective, title="Open")

    def test_summary_counts_tasks_executed(self):
        response = self.client.get(self.hunt.get_absolute_url())
        self.assertEqual(response.context["task_progress"], {"total": 2, "executed": 1})
        self.assertContains(response, "<b>1</b> of 2 executed")

    def test_library_section_is_collapsed_once_objectives_exist(self):
        html = self.client.get(self.hunt.get_absolute_url()).content.decode()
        self.assertIn("Add tasks from the library", html)
        self.assertNotIn('fold-panel" open', html)

    def test_library_section_opens_on_an_empty_hunt(self):
        empty = Hunt.objects.create(title="Empty")
        html = self.client.get(empty.get_absolute_url()).content.decode()
        self.assertIn('fold-panel" open', html)
