import io
import json
import zipfile

import yaml
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.urls import reverse

from ..library_io import SCHEMA
from ..models import LibraryTask, Technique


def doc(**fields):
    data = {"schema": SCHEMA, "id": "a-task", "title": "A task", **fields}
    return yaml.safe_dump({k: v for k, v in data.items() if v is not None}, sort_keys=False)


def upload(name, content):
    return SimpleUploadedFile(name, content if isinstance(content, bytes) else content.encode())


def zip_bytes(members):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in members.items():
            archive.writestr(name, content)
    return buffer.getvalue()


class LibraryImportViewTests(TestCase):
    url = "/library/import/"

    def login(self, *codenames):
        user = get_user_model().objects.create_user(f"user{get_user_model().objects.count()}")
        user.user_permissions.set(Permission.objects.filter(content_type__app_label="hunts", codename__in=codenames))
        self.client.force_login(user)
        return user

    def importer(self):
        return self.login("add_librarytask", "change_librarytask")

    def post_files(self, *files):
        return self.client.post(reverse("library-import"), {"files": list(files)})

    def test_url_is_library_import(self):
        self.assertEqual(reverse("library-import"), self.url)

    def test_get_shows_the_upload_form(self):
        self.importer()
        response = self.client.get(reverse("library-import"))
        self.assertContains(response, 'type="file"')
        self.assertContains(response, "multiple")

    def test_upload_shows_a_preview_and_writes_nothing(self):
        self.importer()
        Technique.objects.create(attack_id="T1003", name="Dumping")
        LibraryTask.objects.create(title="Existing", query="old")
        response = self.post_files(
            upload("a.yml", doc(techniques=["T1003", "T9999"])),
            upload("b.yml", doc(id="existing", title="Existing", query="new")),
        )
        self.assertContains(response, "created")
        self.assertContains(response, "updated")
        self.assertContains(response, "T9999")  # the warning
        self.assertContains(response, "old")  # the diff
        self.assertEqual(LibraryTask.objects.count(), 1)
        self.assertEqual(LibraryTask.objects.get(key="existing").query, "old")

    def test_confirm_applies_and_shows_a_result(self):
        self.importer()
        preview = self.post_files(upload("a.yml", doc()))
        confirm = self.client.post(reverse("library-import"), {"step": "confirm", "payload": preview.context["payload"]})
        self.assertContains(confirm, "1 created")
        self.assertTrue(LibraryTask.objects.filter(key="a-task").exists())

    def test_confirm_revalidates_a_tampered_payload(self):
        self.importer()
        payload = json.dumps({"a.yml": doc(id=None)})
        response = self.client.post(reverse("library-import"), {"step": "confirm", "payload": payload})
        self.assertContains(response, "a.yml")
        self.assertEqual(LibraryTask.objects.count(), 0)

    def test_confirm_with_a_malformed_payload_shows_an_error(self):
        self.importer()
        for payload in ("not json", json.dumps(["a"]), json.dumps({"a.yml": 3}), ""):
            with self.subTest(payload=payload):
                response = self.client.post(reverse("library-import"), {"step": "confirm", "payload": payload})
                self.assertEqual(response.status_code, 200)
                self.assertContains(response, "upload the files again")

    def test_confirm_enforces_the_same_limits_as_upload(self):
        self.importer()
        too_many = {f"{n}.yml": doc(id=f"task-{n}") for n in range(501)}
        too_big = {"a.yml": doc(notes="x" * 1_100_000)}
        for named in (too_many, too_big):
            with self.subTest(files=len(named)):
                response = self.client.post(
                    reverse("library-import"), {"step": "confirm", "payload": json.dumps(named)}
                )
                self.assertContains(response, "Nothing was imported")
        self.assertEqual(LibraryTask.objects.count(), 0)

    def test_errors_are_listed_and_there_is_no_confirm_button(self):
        self.importer()
        response = self.post_files(upload("bad.yml", doc(id=None)), upload("worse.yml", "- x"))
        self.assertContains(response, "bad.yml")
        self.assertContains(response, "worse.yml")
        self.assertNotContains(response, 'value="confirm"')

    def test_zip_upload_works(self):
        self.importer()
        response = self.post_files(upload("lib.zip", zip_bytes({"lib/a.yml": doc(), "README.md": "hi"})))
        self.assertContains(response, 'value="confirm"')
        self.assertEqual(len(response.context["plan"].items), 1)

    def test_corrupt_zip_shows_an_error_not_a_500(self):
        self.importer()
        response = self.post_files(upload("lib.zip", b"not a zip"))
        self.assertContains(response, "not a valid zip")

    def test_non_utf8_file_shows_an_error(self):
        self.importer()
        self.assertContains(self.post_files(upload("a.yml", b"\xff\xfe\x00bad")), "UTF-8")

    def test_oversize_upload_shows_an_error(self):
        self.importer()
        self.assertContains(self.post_files(upload("a.yml", "x" * 1_100_000)), "larger than")

    def test_no_files_shows_an_error(self):
        self.importer()
        self.assertContains(self.client.post(reverse("library-import"), {}), "No YAML files")

    def test_import_requires_both_permissions(self):
        for codenames in (("add_librarytask",), ("change_librarytask",), ()):
            with self.subTest(codenames=codenames):
                self.login(*codenames)
                self.assertEqual(self.client.get(reverse("library-import")).status_code, 403)
                self.assertEqual(self.post_files(upload("a.yml", doc())).status_code, 403)
        self.assertEqual(LibraryTask.objects.count(), 0)
        self.client.logout()
        self.assertEqual(self.client.get(reverse("library-import")).status_code, 302)

    def test_list_page_shows_the_import_button_only_with_both_permissions(self):
        self.login("add_librarytask")
        self.assertNotContains(self.client.get(reverse("library-list")), reverse("library-import"))
        self.importer()
        self.assertContains(self.client.get(reverse("library-list")), reverse("library-import"))
