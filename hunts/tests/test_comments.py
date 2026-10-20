from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.test import TestCase

from ..models import Comment, Hunt, Objective, Outcome, Task


class CommentViewTests(TestCase):
    def setUp(self):
        call_command("seed_roles", verbosity=0)
        self.hunter = get_user_model().objects.create_user(username="hunter", password="pw")
        self.hunter.groups.add(Group.objects.get(name="Hunter"))
        self.client.force_login(self.hunter)

        self.hunt = Hunt.objects.create(title="H")
        self.objective = Objective.objects.create(hunt=self.hunt, title="O")
        self.task = Task.objects.create(objective=self.objective, title="T")
        self.outcome = Outcome.objects.create(task=self.task, outcome_type="visibility_gap")

    def test_post_comment_on_hunt(self):
        response = self.client.post(f"/hunts/{self.hunt.pk}/comments/new/", {"body": "Kicking this off"})
        self.assertRedirects(response, self.hunt.get_absolute_url())
        comment = self.hunt.comments.get()
        self.assertEqual(comment.body, "Kicking this off")
        self.assertEqual(comment.author, self.hunter)

    def test_post_comment_on_task(self):
        response = self.client.post(f"/tasks/{self.task.pk}/comments/new/", {"body": "Query needs a filter"})
        self.assertRedirects(response, self.task.get_absolute_url())
        self.assertEqual(self.task.comments.count(), 1)

    def test_post_comment_on_outcome_redirects_to_outcome_edit_page(self):
        response = self.client.post(
            f"/outcomes/{self.outcome.pk}/comments/new/", {"body": "Confirmed with the SOC"}
        )
        self.assertRedirects(response, f"/outcomes/{self.outcome.pk}/edit/")
        self.assertEqual(self.outcome.comments.count(), 1)

    def test_comments_display_oldest_first(self):
        Comment.objects.create(hunt=self.hunt, body="first")
        Comment.objects.create(hunt=self.hunt, body="second")
        self.assertEqual([c.body for c in self.hunt.comments.all()], ["first", "second"])

    def test_stakeholder_cannot_post(self):
        stakeholder = get_user_model().objects.create_user(username="stakeholder", password="pw")
        stakeholder.groups.add(Group.objects.get(name="Stakeholder"))
        self.client.force_login(stakeholder)

        response = self.client.post(f"/hunts/{self.hunt.pk}/comments/new/", {"body": "Hi"})
        self.assertEqual(response.status_code, 403)

    def test_detection_engineer_can_post(self):
        engineer = get_user_model().objects.create_user(username="engineer", password="pw")
        engineer.groups.add(Group.objects.get(name="Detection Engineer"))
        self.client.force_login(engineer)

        response = self.client.post(f"/tasks/{self.task.pk}/comments/new/", {"body": "Handoff ready"})
        self.assertEqual(response.status_code, 302)


class CommentParentInvariantTests(TestCase):
    def test_rejects_neither_parent(self):
        with self.assertRaises(ValidationError):
            Comment.objects.create(body="orphaned")

    def test_rejects_more_than_one_parent(self):
        objective = Objective.objects.create(hunt=Hunt.objects.create(title="H"), title="O")
        task = Task.objects.create(objective=objective, title="T")
        with self.assertRaises(ValidationError):
            Comment.objects.create(task=task, hunt=objective.hunt, body="ambiguous")


class CommentFeedLayoutTests(TestCase):
    """Comments render as one full-width feed at the bottom of the page, not in the rail."""

    def setUp(self):
        call_command("seed_roles", verbosity=0)
        users = get_user_model().objects
        self.hunter = users.create_user(username="hunter", password="pw")
        self.hunter.groups.add(Group.objects.get(name="Hunter"))
        self.stakeholder = users.create_user(username="stakeholder", password="pw")
        self.stakeholder.groups.add(Group.objects.get(name="Stakeholder"))
        self.hunt = Hunt.objects.create(title="H")
        self.task = Task.objects.create(objective=Objective.objects.create(hunt=self.hunt, title="O"), title="T")
        for parent in ({"hunt": self.hunt}, {"task": self.task}):
            Comment.objects.create(body="first note", **parent)
            Comment.objects.create(body="second note", **parent)

    def pages(self):
        return (f"/hunts/{self.hunt.pk}/", f"/tasks/{self.task.pk}/")

    def test_feed_is_after_the_rail_in_posting_order(self):
        self.client.force_login(self.hunter)
        for url in self.pages():
            with self.subTest(url=url):
                html = self.client.get(url).content.decode()
                feed = html.index('class="comment-feed"')
                self.assertGreater(feed, html.index("</aside>"))
                self.assertLess(html.index("first note"), html.index("second note"))
                self.assertGreater(html.index("first note"), feed)

    def test_add_form_only_for_users_who_can_comment(self):
        for user, shown in ((self.hunter, True), (self.stakeholder, False)):
            self.client.force_login(user)
            for url in self.pages():
                with self.subTest(user=user.username, url=url):
                    html = self.client.get(url).content.decode()
                    self.assertEqual('placeholder="Add a comment"' in html, shown)
