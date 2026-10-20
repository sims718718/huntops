from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from ..forms import LibraryTaskForm
from ..models import KEY_PATTERN, LibraryTask, Objective, Hunt, Task


class LibraryKeyTests(TestCase):
    def test_new_entry_gets_a_slug_key(self):
        entry = LibraryTask.objects.create(title="Rare Service Installs!")
        self.assertEqual(entry.key, "rare-service-installs")

    def test_colliding_titles_get_numeric_suffixes(self):
        keys = [LibraryTask.objects.create(title="Same").key for _ in range(3)]
        self.assertEqual(keys, ["same", "same-2", "same-3"])

    def test_symbol_only_title_falls_back_to_task(self):
        self.assertEqual(LibraryTask.objects.create(title="!!!").key, "task")

    def test_key_is_stable_when_the_title_changes(self):
        entry = LibraryTask.objects.create(title="Original")
        entry.title = "Renamed"
        entry.save()
        entry.refresh_from_db()
        self.assertEqual(entry.key, "original")

    def test_reference_entries_have_no_key(self):
        first = LibraryTask.objects.create(title="R1", seed_key="r1", provenance="curated")
        second = LibraryTask.objects.create(title="R2", seed_key="r2", provenance="curated")
        self.assertEqual((first.key, second.key), ("", ""))

    def test_duplicate_and_promote_get_their_own_keys(self):
        entry = LibraryTask.objects.create(title="Original")
        copy = entry.duplicate()
        hunt = Hunt.objects.create(title="H")
        task = Task.objects.create(objective=Objective.objects.create(hunt=hunt, title="O"), title="Promoted")
        promoted = task.promote_to_library()
        keys = {entry.key, copy.key, promoted.key}
        self.assertEqual(len(keys), 3)
        self.assertNotIn("", keys)

    def test_every_generated_key_matches_the_pattern(self):
        entry = LibraryTask.objects.create(title="A long title " * 23)
        self.assertLessEqual(len(entry.key), 100)
        self.assertTrue(KEY_PATTERN.fullmatch(entry.key))

    def test_key_is_not_on_the_edit_form(self):
        self.assertNotIn("key", LibraryTaskForm().fields)

    def test_detail_page_shows_the_key(self):
        entry = LibraryTask.objects.create(title="Shown")
        self.client.force_login(get_user_model().objects.create_user("reader"))
        self.assertContains(self.client.get(reverse("library-detail", args=[entry.pk])), "shown")
