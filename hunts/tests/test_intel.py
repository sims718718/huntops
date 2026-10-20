import shutil
import tempfile
from io import StringIO
from pathlib import Path

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.exceptions import ValidationError
from django.core.files.base import ContentFile
from django.core.management import CommandError, call_command
from django.test import TestCase, override_settings

from .. import reporting
from ..forms import HuntForm
from ..intel_import import ParsedIntel, ParsedTechnique, ParsedIndicator, ParsedStory, preview, save_intel
from ..models import Actor, Evidence, Hunt, HuntSeed, IntelReport, IntelStory, Objective, Task, Technique

# Evidence writes real files; keep them out of the media volume (as test_evidence.py does).
MEDIA_ROOT = tempfile.mkdtemp()


def teardown_module(module):
    shutil.rmtree(MEDIA_ROOT, ignore_errors=True)


@override_settings(MEDIA_ROOT=MEDIA_ROOT)
class IntelModelTests(TestCase):
    def test_numbering_and_intel_id(self):
        first = IntelReport.objects.create(slug="a", title="A")
        second = IntelReport.objects.create(slug="b", title="B")
        self.assertEqual((first.intel_id, second.intel_id), ("INTEL-001", "INTEL-002"))
        self.assertEqual(first.get_absolute_url(), f"/intel/{first.pk}/")

    def test_evidence_accepts_intel_report_as_its_only_parent(self):
        report = IntelReport.objects.create(slug="a", title="A")
        Evidence.objects.create(intel_report=report, file=ContentFile(b"x", name="a-report.md"))
        with self.assertRaises(ValidationError):
            Evidence.objects.create(
                intel_report=report, hunt=Hunt.objects.create(title="H"), file=ContentFile(b"x", name="y.md")
            )

    def test_seed_defaults_open_and_orders(self):
        report = IntelReport.objects.create(slug="a", title="A")
        HuntSeed.objects.create(report=report, order=2, text="second")
        HuntSeed.objects.create(report=report, order=1, text="first")
        self.assertEqual([s.text for s in report.seeds.all()], ["first", "second"])
        self.assertEqual(report.seeds.first().status, HuntSeed.OPEN)

    def test_hunt_form_cannot_repoint_intel(self):
        self.assertNotIn("intel_report", HuntForm().fields)


def make_parsed(**overrides):
    values = dict(
        slug="apt",
        title="APT29 activity",
        tlp="amber",
        sections={"executive_summary": "summary", "actor_overview": "Midnight Blizzard did things"},
        techniques=[ParsedTechnique("T1059"), ParsedTechnique("T0001"), ParsedTechnique("T9999")],
        indicators=[ParsedIndicator("Domain", "evil[.]com", "confirmed", "CISA")],
        seeds=["Hunt one", "Hunt two"],
        hunt_plan_hypothesis="We hypothesize",
        first_source_url="https://example.com/a",
        warnings=["report: unmapped section 'X'"],
    )
    values.update(overrides)
    return ParsedIntel(**values)


@override_settings(MEDIA_ROOT=MEDIA_ROOT)
class SaveIntelTests(TestCase):
    def setUp(self):
        self.t1059 = Technique.objects.create(attack_id="T1059", name="Command and Scripting Interpreter")
        self.new = Technique.objects.create(attack_id="T1000", name="Replacement")
        Technique.objects.create(attack_id="T0001", name="Old", revoked_by=self.new)
        Actor.objects.create(attack_id="G0016", name="APT29", aliases=["Midnight Blizzard"])
        Actor.objects.create(attack_id="G0007", name="APT28", aliases=["Fancy Bear"])

    def test_create(self):
        report = save_intel(make_parsed(), files=[("apt-report.md", b"# r")])
        self.assertEqual(report.title, "APT29 activity")
        self.assertEqual(report.tlp, "amber")
        self.assertEqual(report.executive_summary, "summary")
        self.assertEqual(report.key_judgments, "")
        rows = {r.raw_id: r.technique for r in report.intel_techniques.all()}
        self.assertEqual(rows, {"T1059": self.t1059, "T0001": self.new, "T9999": None})
        self.assertIn("T9999 is not in the imported ATT&CK bundle", report.parse_warnings)
        self.assertIn("unmapped section 'X'", report.parse_warnings)
        self.assertEqual(report.indicators.get().confidence, "confirmed")
        self.assertEqual([s.text for s in report.seeds.all()], ["Hunt one", "Hunt two"])
        self.assertEqual([a.attack_id for a in report.actors.all()], ["G0016"])
        self.assertEqual(report.evidence.get().caption, "apt-report.md")

    def test_reimport_replaces_rows_and_preserves_seed_decisions(self):
        report = save_intel(make_parsed(seeds=["Hunt one", "Hunt two", "Hunt three", "Hunt four"]))
        hunt = Hunt.objects.create(title="H")
        seeds = {s.text: s for s in report.seeds.all()}
        seeds["Hunt one"].status, seeds["Hunt one"].hunt = HuntSeed.PROMOTED, hunt
        seeds["Hunt one"].save()
        seeds["Hunt two"].status = HuntSeed.DISMISSED
        seeds["Hunt two"].save()
        seeds["Hunt four"].status = HuntSeed.STALE
        seeds["Hunt four"].save()

        again = save_intel(make_parsed(
            title="Renamed", techniques=[ParsedTechnique("T1059")], indicators=[],
            seeds=["hunt   FOUR", "Hunt five"],  # one, two, three vanish; four reappears
        ))

        self.assertEqual(again.pk, report.pk)
        self.assertEqual(again.title, "Renamed")
        self.assertEqual(again.intel_techniques.count(), 1)
        self.assertEqual(again.indicators.count(), 0)
        status = {s.text: s.status for s in again.seeds.all()}
        self.assertEqual(status, {
            "Hunt one": HuntSeed.PROMOTED, "Hunt two": HuntSeed.DISMISSED, "Hunt three": HuntSeed.STALE,
            "Hunt four": HuntSeed.OPEN, "Hunt five": HuntSeed.OPEN,
        })
        self.assertEqual(again.seeds.get(text="Hunt one").hunt, hunt)
        hunt.refresh_from_db()
        self.assertEqual(hunt.title, "H")

    def test_reimport_accumulates_source_files(self):
        save_intel(make_parsed(), files=[("apt-report.md", b"1")])
        report = save_intel(make_parsed(), files=[("apt-report.md", b"2")])
        self.assertEqual(report.evidence.count(), 2)

    def test_preview_reports_counts_unresolved_and_seed_changes(self):
        self.assertIsNone(preview(make_parsed())["report"])
        save_intel(make_parsed())
        result = preview(make_parsed(seeds=["Hunt two", "Hunt new"]))
        self.assertIsNotNone(result["report"])
        self.assertEqual(result["techniques"], 3)
        self.assertEqual(result["unresolved"], ["T9999"])
        self.assertEqual(result["new_seeds"], ["Hunt new"])
        self.assertEqual(result["stale_seeds"], ["Hunt one"])


FIXTURE_DIR = str(Path(__file__).parent / "fixtures" / "intel")


@override_settings(MEDIA_ROOT=MEDIA_ROOT)
class ImportIntelCommandTests(TestCase):
    def test_imports_every_fixture_run(self):
        out = StringIO()
        call_command("import_intel", dir=FIXTURE_DIR, stdout=out)
        self.assertEqual(IntelReport.objects.count(), 3)
        report = IntelReport.objects.get(slug="apt29-past-year")
        self.assertEqual(report.seeds.count(), 3)
        self.assertEqual(report.evidence.count(), 3)  # report + analysis + plan
        self.assertIn("created", out.getvalue())

    def test_dry_run_writes_nothing(self):
        out = StringIO()
        call_command("import_intel", dir=FIXTURE_DIR, slug="apt29-past-year", dry_run=True, stdout=out)
        self.assertEqual(IntelReport.objects.count(), 0)
        self.assertIn("dry run", out.getvalue())

    def test_second_run_updates(self):
        call_command("import_intel", dir=FIXTURE_DIR, slug="apt29-past-year", stdout=StringIO())
        out = StringIO()
        call_command("import_intel", dir=FIXTURE_DIR, slug="apt29-past-year", stdout=out)
        self.assertEqual(IntelReport.objects.count(), 1)
        self.assertIn("updated", out.getvalue())

    def test_unknown_slug_is_an_error(self):
        with self.assertRaises(CommandError):
            call_command("import_intel", dir=FIXTURE_DIR, slug="nope", stdout=StringIO())


class IntelRoleTests(TestCase):
    def test_cti_analyst_and_hunt_lead_permissions(self):
        call_command("seed_roles", stdout=StringIO())
        cti = set(Group.objects.get(name="CTI Analyst").permissions.values_list("codename", flat=True))
        self.assertTrue({"add_intelreport", "change_huntseed", "add_hunt", "view_hunt"} <= cti)
        self.assertNotIn("change_hunt", cti)
        lead = set(Group.objects.get(name="Hunt Lead").permissions.values_list("codename", flat=True))
        self.assertTrue({"add_intelreport", "change_huntseed", "delete_intelreport"} <= lead)
        hunter = set(Group.objects.get(name="Hunter").permissions.values_list("codename", flat=True))
        self.assertIn("view_intelreport", hunter)
        self.assertNotIn("change_huntseed", hunter)


from django.contrib.auth import get_user_model

from ..models import IntelTechnique


class IntelPageTests(TestCase):
    def setUp(self):
        call_command("seed_roles", stdout=StringIO())
        self.user = get_user_model().objects.create_user(username="s", password="pw")
        self.user.groups.add(Group.objects.get(name="Stakeholder"))
        self.client.force_login(self.user)
        self.report = IntelReport.objects.create(
            slug="apt", title="APT29 activity", tlp="red", executive_summary="<script>x</script>"
        )
        technique = Technique.objects.create(attack_id="T1059", name="Cmd")
        IntelTechnique.objects.create(report=self.report, technique=technique, raw_id="T1059")
        IntelTechnique.objects.create(report=self.report, raw_id="T9999")
        HuntSeed.objects.create(report=self.report, order=1, text="Hunt for it")

    def test_list_shows_report_and_filters_by_tlp(self):
        response = self.client.get("/intel/")
        self.assertContains(response, "INTEL-001")
        self.assertContains(response, "TLP:RED")
        self.assertNotContains(self.client.get("/intel/?tlp=green"), "INTEL-001")

    def test_list_htmx_returns_partial(self):
        response = self.client.get("/intel/", HTTP_HX_REQUEST="true")
        self.assertTemplateUsed(response, "hunts/partials/_intel_rows.html")
        self.assertTemplateNotUsed(response, "hunts/intel_list.html")

    def test_detail_escapes_imported_text_and_shows_unresolved(self):
        response = self.client.get(f"/intel/{self.report.pk}/")
        self.assertContains(response, "&lt;script&gt;x&lt;/script&gt;")
        self.assertContains(response, 'href="/attack/T1059/"')
        self.assertContains(response, "T9999")
        self.assertContains(response, "Hunt for it")
        self.assertNotContains(response, "Create hunt from selected")  # stakeholder can't promote

    def test_nav_links_intel(self):
        self.assertContains(self.client.get("/intel/"), 'href="/intel/" aria-current="page"')


from django.core.files.uploadedfile import SimpleUploadedFile


def fixture_upload(slug, suffix, folder):
    path = Path(FIXTURE_DIR) / folder / f"{slug}-{suffix}.md"
    return SimpleUploadedFile(path.name, path.read_bytes(), content_type="text/markdown")


@override_settings(MEDIA_ROOT=MEDIA_ROOT)
class IntelUploadTests(TestCase):
    def setUp(self):
        call_command("seed_roles", stdout=StringIO())
        users = get_user_model().objects
        self.cti = users.create_user(username="cti", password="pw")
        self.cti.groups.add(Group.objects.get(name="CTI Analyst"))
        self.stakeholder = users.create_user(username="sh", password="pw")
        self.stakeholder.groups.add(Group.objects.get(name="Stakeholder"))

    def upload(self, **files):
        return self.client.post("/intel/import/", files)

    def all_three(self, slug="apt29-past-year"):
        return dict(
            report=fixture_upload(slug, "report", "intel-reports"),
            analysis=fixture_upload(slug, "analysis", "intel-analysis"),
            plan=fixture_upload(slug, "hunt-plan", "hunt-plans"),
        )

    def test_form_has_one_field_per_file(self):
        self.client.force_login(self.cti)
        response = self.client.get("/intel/import/")
        for name in ("report", "analysis", "plan"):
            self.assertContains(response, f'name="{name}"')
        self.assertNotContains(response, "multiple")

    def test_all_three_files_preview_then_confirm(self):
        self.client.force_login(self.cti)
        response = self.upload(**self.all_three())
        self.assertContains(response, "Confirm import")
        self.assertEqual(response.context["preview"]["stories"], 3)
        self.assertEqual(response.context["preview"]["seeds"], 3)
        self.assertEqual(IntelReport.objects.count(), 0)  # preview writes nothing

        names = response.context["named"]
        response = self.client.post("/intel/import/", {
            "step": "confirm", "name": list(names.keys()), "content": list(names.values()),
        })
        report = IntelReport.objects.get(slug="apt29-past-year")
        self.assertRedirects(response, report.get_absolute_url())
        self.assertEqual(report.imported_by, self.cti)
        self.assertEqual(report.evidence.count(), 3)
        self.assertEqual(report.stories.count(), 3)
        self.assertTrue(report.hunt_plan_hypothesis.startswith("We hypothesize"))

    def test_report_alone_is_enough(self):
        self.client.force_login(self.cti)
        response = self.upload(report=fixture_upload("apt29-past-year", "report", "intel-reports"))
        self.assertContains(response, "Confirm import")

    def test_missing_report_is_an_error(self):
        self.client.force_login(self.cti)
        response = self.upload(analysis=fixture_upload("apt29-past-year", "analysis", "intel-analysis"))
        self.assertContains(response, "Intel report")
        self.assertNotContains(response, "Confirm import")

    def test_wrong_file_in_a_field_names_it(self):
        self.client.force_login(self.cti)
        files = self.all_three()
        files["report"], files["plan"] = files["plan"], files["report"]
        response = self.upload(**files)
        self.assertContains(response, "apt29-past-year-hunt-plan.md")
        self.assertContains(response, "-report.md")
        self.assertNotContains(response, "Confirm import")

    def test_mismatched_slugs_show_an_error(self):
        self.client.force_login(self.cti)
        response = self.upload(
            report=fixture_upload("apt29-past-year", "report", "intel-reports"),
            analysis=fixture_upload("russian-webmail-espionage", "analysis", "intel-analysis"),
        )
        self.assertContains(response, "must share one slug")

    def test_stakeholder_cannot_import(self):
        self.client.force_login(self.stakeholder)
        self.assertEqual(self.client.get("/intel/import/").status_code, 403)


class SeedPromotionTests(TestCase):
    def setUp(self):
        call_command("seed_roles", stdout=StringIO())
        users = get_user_model().objects
        self.cti = users.create_user(username="cti", password="pw")
        self.cti.groups.add(Group.objects.get(name="CTI Analyst"))
        self.client.force_login(self.cti)
        self.report = IntelReport.objects.create(
            slug="apt", title="APT29 activity", hunt_plan_hypothesis="We hypothesize X",
            first_source_url="https://example.com/a",
        )
        self.t1059 = Technique.objects.create(attack_id="T1059", name="Cmd")
        IntelTechnique.objects.create(report=self.report, technique=self.t1059, raw_id="T1059")
        IntelTechnique.objects.create(report=self.report, raw_id="T9999")
        self.one = HuntSeed.objects.create(report=self.report, order=1, text="Hunt one")
        self.two = HuntSeed.objects.create(report=self.report, order=2, text="Hunt two")

    def test_promote_single_seed(self):
        response = self.client.post(f"/intel/{self.report.pk}/promote/", {"seed": [self.one.pk]})
        hunt = Hunt.objects.get()
        self.assertRedirects(response, f"/hunts/{hunt.pk}/")
        self.assertEqual(hunt.title, "Hunt one")
        self.assertEqual((hunt.trigger_type, hunt.hunt_type), ("cti", "TIO"))
        self.assertEqual(hunt.intel_report, self.report)
        self.assertEqual(hunt.hypothesis, "We hypothesize X")
        self.assertEqual(hunt.trigger_source_links, ["https://example.com/a"])
        self.assertIn("INTEL-001", hunt.trigger_description)
        self.assertEqual(list(hunt.techniques.all()), [self.t1059])
        self.one.refresh_from_db()
        self.assertEqual((self.one.status, self.one.hunt), (HuntSeed.PROMOTED, hunt))

    def test_hunt_lead_lands_on_edit_form(self):
        lead = get_user_model().objects.create_user(username="lead", password="pw")
        lead.groups.add(Group.objects.get(name="Hunt Lead"))
        self.client.force_login(lead)
        response = self.client.post(f"/intel/{self.report.pk}/promote/", {"seed": [self.one.pk]})
        self.assertRedirects(response, f"/hunts/{Hunt.objects.get().pk}/edit/", fetch_redirect_response=False)

    def test_promote_several_seeds_into_one_hunt(self):
        self.client.post(f"/intel/{self.report.pk}/promote/", {"seed": [self.one.pk, self.two.pk]})
        hunt = Hunt.objects.get()
        self.assertEqual(hunt.title, "APT29 activity hunt")
        self.assertEqual(set(hunt.seeds.values_list("text", flat=True)), {"Hunt one", "Hunt two"})
        self.assertIn("Hunt two", hunt.trigger_description)

    def test_rejects_non_open_foreign_or_missing_seeds(self):
        other = IntelReport.objects.create(slug="b", title="B")
        foreign = HuntSeed.objects.create(report=other, order=1, text="x")
        self.two.status = HuntSeed.DISMISSED
        self.two.save()
        url = f"/intel/{self.report.pk}/promote/"
        for data in ({"seed": [foreign.pk]}, {"seed": [self.two.pk]}, {}, {"seed": ["abc"]}, {"seed": ["²"]}):
            with self.subTest(data=data):
                self.assertEqual(self.client.post(url, data).status_code, 400)
        self.assertFalse(Hunt.objects.exists())

    def test_dismiss_with_reason(self):
        response = self.client.post(f"/seeds/{self.one.pk}/dismiss/", {f"reason_{self.one.pk}": "Not our stack"})
        self.assertRedirects(response, self.report.get_absolute_url())
        self.one.refresh_from_db()
        self.assertEqual((self.one.status, self.one.dismiss_reason), (HuntSeed.DISMISSED, "Not our stack"))

    def test_detail_shows_promote_controls_for_cti(self):
        response = self.client.get(f"/intel/{self.report.pk}/")
        self.assertContains(response, "Create hunt from selected")
        self.assertContains(response, f'formaction="/seeds/{self.one.pk}/dismiss/"')

    def test_stakeholder_cannot_promote_or_dismiss(self):
        stakeholder = get_user_model().objects.create_user(username="sh", password="pw")
        stakeholder.groups.add(Group.objects.get(name="Stakeholder"))
        self.client.force_login(stakeholder)
        self.assertEqual(self.client.post(f"/intel/{self.report.pk}/promote/", {"seed": [self.one.pk]}).status_code, 403)
        self.assertEqual(self.client.post(f"/seeds/{self.one.pk}/dismiss/").status_code, 403)

    def test_promoting_same_seed_twice_is_rejected(self):
        url = f"/intel/{self.report.pk}/promote/"
        self.client.post(url, {"seed": [self.one.pk]})
        self.assertEqual(self.client.post(url, {"seed": [self.one.pk]}).status_code, 400)
        self.assertEqual(Hunt.objects.count(), 1)

    def test_enter_key_default_button_is_disabled(self):
        html = self.client.get(f"/intel/{self.report.pk}/").content.decode()
        default = html.index('<button type="submit" disabled hidden')
        self.assertLess(default, html.index("formaction="))


class IntelCrossLinkTests(TestCase):
    def setUp(self):
        call_command("seed_roles", stdout=StringIO())
        user = get_user_model().objects.create_user(username="s", password="pw")
        user.groups.add(Group.objects.get(name="Stakeholder"))
        self.client.force_login(user)
        self.report = IntelReport.objects.create(slug="apt", title="APT29 activity", tlp="amber")
        self.cited = Technique.objects.create(attack_id="T1059", name="Cmd", tactics=["execution"])
        self.hunted = Technique.objects.create(attack_id="T1003", name="Dump", tactics=["credential-access"])
        for technique in (self.cited, self.hunted):
            IntelTechnique.objects.create(report=self.report, technique=technique, raw_id=technique.attack_id)
        self.hunt = Hunt.objects.create(title="H", intel_report=self.report)
        task = Task.objects.create(objective=Objective.objects.create(hunt=self.hunt, title="O"), title="T",
                                   status=Task.EXECUTED)
        task.techniques.add(self.hunted)

    def test_with_intel_overlays_only_unhunted(self):
        statuses = reporting.with_intel(reporting.technique_status())
        self.assertEqual(statuses[self.cited.id], reporting.INTEL)
        self.assertEqual(statuses[self.hunted.id], reporting.CLEAN)

    def test_heatmap_toggle(self):
        self.assertNotContains(self.client.get("/heatmap/"), "In intel, not hunted")
        self.assertContains(self.client.get("/heatmap/?intel=1"), "In intel, not hunted")

    def test_hunt_detail_intel_panel(self):
        response = self.client.get(f"/hunts/{self.hunt.pk}/")
        self.assertContains(response, "INTEL-001")
        self.assertContains(response, "TLP:AMBER")

    def test_technique_detail_cited_in_intel(self):
        self.assertContains(self.client.get("/attack/T1059/"), "INTEL-001")

    def test_hunt_report_carries_tlp_and_intel(self):
        markdown = reporting.hunt_markdown(self.hunt)
        self.assertTrue(markdown.startswith("**TLP:AMBER**"))
        self.assertIn("- **Intel:** INTEL-001 APT29 activity", markdown)


class EvidenceFormIntelTests(TestCase):
    def test_upload_form_does_not_expose_intel_report(self):
        from ..forms import EvidenceForm
        self.assertNotIn("intel_report", EvidenceForm().fields)

    def test_save_intel_strips_path_from_filenames(self):
        report = save_intel(ParsedIntel(slug="apt", title="T"), files=[("a/b/apt-report.md", b"x")])
        evidence = report.evidence.get()
        self.assertEqual(evidence.caption, "apt-report.md")
        self.assertTrue(evidence.file.name.startswith("evidence/"))
        self.assertNotIn("a/b", evidence.file.name)


@override_settings(MEDIA_ROOT=MEDIA_ROOT)
class SaveStoriesTests(TestCase):
    def test_reimport_replaces_stories(self):
        report = save_intel(make_parsed(stories=[ParsedStory("One", objective="o1"), ParsedStory("Two")]))
        self.assertEqual([(s.order, s.title, s.objective) for s in report.stories.all()],
                         [(1, "One", "o1"), (2, "Two", "")])
        report = save_intel(make_parsed(stories=[ParsedStory("Three")]))
        self.assertEqual([s.title for s in report.stories.all()], ["Three"])

    def test_preview_counts_stories(self):
        self.assertEqual(preview(make_parsed(stories=[ParsedStory("One")]))["stories"], 1)

    def test_command_imports_fixture_stories(self):
        out = StringIO()
        call_command("import_intel", dir=FIXTURE_DIR, slug="apt29-past-year", stdout=out)
        self.assertEqual(IntelReport.objects.get(slug="apt29-past-year").stories.count(), 3)
        self.assertIn("3 stories", out.getvalue())
