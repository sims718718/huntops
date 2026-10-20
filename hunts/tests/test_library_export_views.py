import io
import zipfile

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from ..library_io import dump_task
from ..models import LibraryTask


class LibraryExportViewTests(TestCase):
    def setUp(self):
        self.client.force_login(get_user_model().objects.create_user("reader"))
        self.alpha = LibraryTask.objects.create(title="Alpha", query="a\nb\n")
        self.beta = LibraryTask.objects.create(title="Beta")
        self.reference = LibraryTask.objects.create(title="Ref", seed_key="ref", provenance="curated")

    def test_export_all_downloads_a_zip_of_team_built_tasks(self):
        response = self.client.get(reverse("library-export"))
        self.assertEqual(response["Content-Type"], "application/zip")
        self.assertIn('filename="huntops-library.zip"', response["Content-Disposition"])
        archive = zipfile.ZipFile(io.BytesIO(response.content))
        self.assertEqual(sorted(archive.namelist()), ["alpha.yml", "beta.yml"])
        self.assertEqual(archive.read("alpha.yml").decode(), dump_task(self.alpha))

    def test_export_all_is_byte_identical_between_requests(self):
        url = reverse("library-export")
        self.assertEqual(self.client.get(url).content, self.client.get(url).content)

    def test_export_all_with_no_team_tasks_returns_an_empty_zip(self):
        LibraryTask.objects.filter(provenance="user").delete()
        response = self.client.get(reverse("library-export"))
        self.assertEqual(zipfile.ZipFile(io.BytesIO(response.content)).namelist(), [])

    def test_export_one_downloads_yaml(self):
        response = self.client.get(reverse("library-export-one", args=[self.alpha.pk]))
        self.assertIn('filename="alpha.yml"', response["Content-Disposition"])
        self.assertEqual(response.content.decode(), dump_task(self.alpha))

    def test_export_one_for_a_reference_entry_is_404(self):
        self.assertEqual(self.client.get(reverse("library-export-one", args=[self.reference.pk])).status_code, 404)

    def test_export_requires_login(self):
        self.client.logout()
        for url in (reverse("library-export"), reverse("library-export-one", args=[self.alpha.pk])):
            response = self.client.get(url)
            self.assertEqual(response.status_code, 302)
            self.assertIn(reverse("login"), response.url)

    def test_list_links_export_all_and_detail_links_export_one_for_team_tasks_only(self):
        self.assertContains(self.client.get(reverse("library-list")), reverse("library-export"))
        one = reverse("library-export-one", args=[self.alpha.pk])
        self.assertContains(self.client.get(reverse("library-detail", args=[self.alpha.pk])), one)
        reference_one = reverse("library-export-one", args=[self.reference.pk])
        self.assertNotContains(self.client.get(reverse("library-detail", args=[self.reference.pk])), reference_one)
