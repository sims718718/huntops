from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.management import call_command
from django.test import TestCase
from django.urls import reverse

from ..models import Hunt, Objective, Task, Technique


class HuntListTests(TestCase):
    def setUp(self):
        call_command("seed_roles", verbosity=0)
        self.user = get_user_model().objects.create_user(username="hunter", password="pw")
        self.user.groups.add(Group.objects.get(name="Hunter"))
        self.client.force_login(self.user)

    def _list(self, **params):
        return self.client.get(reverse("hunt-list"), params)

    def _titles(self, **params):
        return [h.title for h in self._list(**params).context["object_list"]]

    def test_default_list_hides_archived(self):
        Hunt.objects.create(title="Live")
        Hunt.objects.create(title="Old", status=Hunt.ARCHIVED, feasibility_decision="GO")
        self.assertEqual(self._titles(), ["Live"])
        self.assertEqual(self._titles(status="archived"), ["Old"])

    def test_stage_tabs_count_within_the_other_filters(self):
        Hunt.objects.create(title="Alpha", status=Hunt.BACKLOG)
        Hunt.objects.create(title="Alpha two", status=Hunt.SCOPING)
        Hunt.objects.create(title="Beta", status=Hunt.SCOPING)
        tabs = {value: count for value, _, count in self._list(q="alpha").context["tabs"]}
        self.assertEqual((tabs[""], tabs[Hunt.BACKLOG], tabs[Hunt.SCOPING]), (2, 1, 1))

    def test_search_matches_title_or_hunt_id(self):
        wanted = Hunt.objects.create(title="Lateral movement")
        Hunt.objects.create(title="Phishing")
        self.assertEqual(self._titles(q="lateral"), ["Lateral movement"])
        self.assertEqual(self._titles(q=wanted.hunt_id), ["Lateral movement"])
        self.assertEqual(self._titles(q=str(wanted.number)), ["Lateral movement"])

    def test_owner_and_priority_filters_combine(self):
        Hunt.objects.create(title="Mine high", owner=self.user, priority="high")
        Hunt.objects.create(title="Mine low", owner=self.user, priority="low")
        Hunt.objects.create(title="Theirs high", priority="high")
        self.assertEqual(self._titles(owner=self.user.pk, priority="high"), ["Mine high"])

    def test_junk_filter_values_are_ignored(self):
        Hunt.objects.create(title="One")
        self.assertEqual(self._titles(owner="x", priority="urgent", status="nonsense"), ["One"])
        self.assertEqual(self._titles(q="HUNT-" + "9" * 30), [])

    def test_rows_carry_task_progress_and_technique_chips(self):
        hunt = Hunt.objects.create(title="H")
        objective = Objective.objects.create(hunt=hunt, title="O")
        Task.objects.create(objective=objective, title="a", status=Task.EXECUTED)
        Task.objects.create(objective=objective, title="b")
        for n in range(5):
            hunt.techniques.add(Technique.objects.create(attack_id=f"T10{n}", name=f"T{n}"))
        row = self._list().context["object_list"][0]
        self.assertEqual((row.task_total, row.task_done), (2, 1))
        self.assertEqual((len(row.technique_chips), row.technique_more), (3, 2))

    def test_owner_choices_are_only_people_who_own_hunts(self):
        Hunt.objects.create(title="H", owner=self.user)
        get_user_model().objects.create_user(username="idle", password="pw")
        self.assertEqual(list(self._list().context["owners"]), [self.user])
