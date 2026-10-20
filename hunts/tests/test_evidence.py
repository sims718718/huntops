import shutil
import tempfile

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.test import TestCase, override_settings

from .. import reporting
from ..models import Evidence, Hunt, Objective, Outcome, Task

MEDIA_ROOT = tempfile.mkdtemp()


def teardown_module(module):
    shutil.rmtree(MEDIA_ROOT, ignore_errors=True)


@override_settings(MEDIA_ROOT=MEDIA_ROOT)
class EvidenceUploadTests(TestCase):
    def setUp(self):
        call_command("seed_roles", verbosity=0)
        self.hunter = get_user_model().objects.create_user(username="hunter", password="pw")
        self.hunter.groups.add(Group.objects.get(name="Hunter"))
        self.client.force_login(self.hunter)

        self.hunt = Hunt.objects.create(title="H")
        self.objective = Objective.objects.create(hunt=self.hunt, title="O")
        self.task = Task.objects.create(objective=self.objective, title="T")
        self.outcome = Outcome.objects.create(task=self.task, outcome_type="visibility_gap")

    def _file(self, name="proof.txt"):
        return SimpleUploadedFile(name, b"contents", content_type="text/plain")

    def test_upload_to_task(self):
        response = self.client.post(
            f"/tasks/{self.task.pk}/evidence/new/",
            {"caption": "screenshot", "file": self._file()},
        )
        self.assertRedirects(response, self.task.get_absolute_url())
        evidence = self.task.evidence.get()
        self.assertEqual(evidence.uploaded_by, self.hunter)
        self.assertIsNone(evidence.hunt)
        self.assertIsNone(evidence.outcome)

    def test_upload_to_hunt(self):
        response = self.client.post(
            f"/hunts/{self.hunt.pk}/evidence/new/",
            {"caption": "screenshot", "file": self._file()},
        )
        self.assertRedirects(response, self.hunt.get_absolute_url())
        self.assertEqual(self.hunt.evidence.count(), 1)

    def test_upload_to_outcome_redirects_to_outcome_edit_page(self):
        response = self.client.post(
            f"/outcomes/{self.outcome.pk}/evidence/new/",
            {"caption": "screenshot", "file": self._file()},
        )
        self.assertRedirects(response, f"/outcomes/{self.outcome.pk}/edit/")
        self.assertEqual(self.outcome.evidence.count(), 1)

    def test_stakeholder_cannot_upload(self):
        stakeholder = get_user_model().objects.create_user(username="stakeholder", password="pw")
        stakeholder.groups.add(Group.objects.get(name="Stakeholder"))
        self.client.force_login(stakeholder)

        response = self.client.post(
            f"/tasks/{self.task.pk}/evidence/new/",
            {"caption": "screenshot", "file": self._file()},
        )
        self.assertEqual(response.status_code, 403)

    def test_detection_engineer_can_upload(self):
        engineer = get_user_model().objects.create_user(username="engineer", password="pw")
        engineer.groups.add(Group.objects.get(name="Detection Engineer"))
        self.client.force_login(engineer)

        response = self.client.post(
            f"/tasks/{self.task.pk}/evidence/new/",
            {"caption": "screenshot", "file": self._file()},
        )
        self.assertEqual(response.status_code, 302)


class ExactlyOneParentTests(TestCase):
    def setUp(self):
        self.objective = Objective.objects.create(hunt=Hunt.objects.create(title="H"), title="O")
        self.task = Task.objects.create(objective=self.objective, title="T")

    def test_evidence_rejects_neither_parent(self):
        with self.assertRaises(ValidationError):
            Evidence.objects.create(file=SimpleUploadedFile("f.txt", b"x"))

    def test_evidence_rejects_more_than_one_parent(self):
        with self.assertRaises(ValidationError):
            Evidence.objects.create(
                task=self.task, hunt=self.objective.hunt, file=SimpleUploadedFile("f.txt", b"x")
            )


@override_settings(MEDIA_ROOT=MEDIA_ROOT)
class HuntMarkdownEvidenceTests(TestCase):
    def test_hunt_and_outcome_level_evidence_are_listed(self):
        hunt = Hunt.objects.create(title="H")
        objective = Objective.objects.create(hunt=hunt, title="O")
        task = Task.objects.create(objective=objective, title="T")
        outcome = Outcome.objects.create(task=task, outcome_type="analytics_detection")

        Evidence.objects.create(
            hunt=hunt, caption="Executive summary", file=SimpleUploadedFile("s.txt", b"x")
        )
        Evidence.objects.create(
            outcome=outcome, caption="Detection rule export", file=SimpleUploadedFile("d.txt", b"x")
        )

        report = reporting.hunt_markdown(hunt)
        self.assertIn("## Hunt-level evidence", report)
        self.assertIn("Executive summary", report)
        self.assertIn("Outcome evidence:", report)
        self.assertIn("Detection rule export", report)
