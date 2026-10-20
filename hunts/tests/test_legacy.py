import json
import os
import tempfile
import uuid

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.test import TestCase

from .. import reporting
from ..forms import HuntForm
from ..models import (
    Actor,
    Hunt,
    LibraryTask,
    Objective,
    Outcome,
    SigmaRule,
    Tactic,
    Task,
    TaskSigmaRule,
    Technique,
    TechniqueMitigation,
)


class FeasibilityGateTests(TestCase):
    def test_no_go_blocks_advance_and_override_releases_it(self):
        hunt = Hunt.objects.create(title="Kerberoasting", feasibility_decision="NO_GO")

        hunt.status = Hunt.APPROVED
        with self.assertRaises(ValidationError):
            hunt.save()

        hunt.feasibility_override_by = get_user_model().objects.create(username="lead")
        hunt.feasibility_override_reason = "CTI too hot to wait on log coverage"
        hunt.save()
        self.assertEqual(Hunt.objects.get(pk=hunt.pk).status, Hunt.APPROVED)

    def test_go_advances_freely(self):
        hunt = Hunt.objects.create(title="Golden ticket", feasibility_decision="GO")
        hunt.status = Hunt.IN_PROGRESS
        hunt.save()
        self.assertEqual(Hunt.objects.get(pk=hunt.pk).status, Hunt.IN_PROGRESS)


class IdentifierTests(TestCase):
    def test_ids_and_auto_numbering(self):
        hunt = Hunt.objects.create(title="H")
        first = Objective.objects.create(hunt=hunt, title="O1")
        second = Objective.objects.create(hunt=hunt, title="O2")
        task = Task.objects.create(objective=first, title="T")

        self.assertEqual(hunt.hunt_id, "HUNT-001")
        self.assertEqual(first.objective_id, "HUNT-001-O1")
        self.assertEqual(second.objective_id, "HUNT-001-O2")
        self.assertEqual(task.task_id, "HUNT-001-O1-T1")


class ObjectiveRollupTests(TestCase):
    def setUp(self):
        self.objective = Objective.objects.create(
            hunt=Hunt.objects.create(title="H"), title="O"
        )

    def test_status_rolls_up_from_tasks(self):
        self.assertEqual(self.objective.status, "Empty")

        task = Task.objects.create(objective=self.objective, title="T")
        self.assertEqual(self.objective.status, "Not Started")

        task.status = Task.EXECUTED
        task.save()
        self.assertEqual(self.objective.status, "Complete")


class LibraryForkTests(TestCase):
    def test_fork_copies_fields_and_does_not_live_link(self):
        entry = LibraryTask.objects.create(title="Baseline 4768", query="index=wineventlog 4768")
        objective = Objective.objects.create(hunt=Hunt.objects.create(title="H"), title="O")

        task = entry.fork_into(objective)
        self.assertEqual(task.query, "index=wineventlog 4768")
        self.assertEqual(task.source_task, entry)

        entry.query = "REWRITTEN"
        entry.save()

        task.refresh_from_db()
        self.assertEqual(task.query, "index=wineventlog 4768")

    def test_promote_copies_authoring_fields_only(self):
        objective = Objective.objects.create(hunt=Hunt.objects.create(title="H"), title="O")
        task = Task.objects.create(
            objective=objective, title="T", query="q", findings="secret finding"
        )

        entry = task.promote_to_library()
        self.assertEqual(entry.query, "q")
        self.assertFalse(hasattr(entry, "findings"))


def _ref(external_id, url="https://attack.mitre.org/x"):
    return [{"source_name": "mitre-attack", "external_id": external_id, "url": url}]


# Shaped like ATT&CK v17+, where detection guidance and data sources hang off
# detection-strategy -> analytic -> log source refs rather than the technique itself.
# The v15-shaped fixture this replaces is why the empty-data_sources defect shipped.
BUNDLE = {
    "objects": [
        {"type": "x-mitre-collection", "id": "collection--1", "x_mitre_version": "19.2"},
        {
            "type": "x-mitre-matrix",
            "id": "matrix--1",
            "tactic_refs": ["tactic--exec", "tactic--cred"],
        },
        {
            "type": "x-mitre-tactic", "id": "tactic--cred", "name": "Credential Access",
            "x_mitre_shortname": "credential-access", "external_references": _ref("TA0006"),
        },
        {
            "type": "x-mitre-tactic", "id": "tactic--exec", "name": "Execution",
            "x_mitre_shortname": "execution", "external_references": _ref("TA0002"),
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--parent",
            "name": "Steal or Forge Kerberos Tickets",
            "description": "Adversaries may abuse Kerberos tickets.",
            "external_references": _ref("T1558"),
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}
            ],
            "x_mitre_platforms": ["Windows"],
            "x_mitre_version": "1.5",
            "modified": "2025-04-15T00:00:00.000Z",
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--1",
            "name": "Kerberoasting",
            "description": "Adversaries may abuse a valid Kerberos ticket-granting ticket.",
            "external_references": _ref("T1558.003"),
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}
            ],
            "x_mitre_platforms": ["Windows"],
            "x_mitre_is_subtechnique": True,
        },
        {
            "type": "relationship", "relationship_type": "subtechnique-of",
            "source_ref": "attack-pattern--1", "target_ref": "attack-pattern--parent",
        },
        {"type": "x-mitre-data-source", "id": "ds--1", "name": "Active Directory"},
        {
            "type": "x-mitre-data-component", "id": "dc--1",
            "name": "Active Directory Credential Request", "x_mitre_data_source_ref": "ds--1",
        },
        {
            "type": "x-mitre-analytic",
            "id": "analytic--1",
            "name": "Analytic 0110",
            "description": "Monitor 4769 for RC4 service ticket requests.",
            "x_mitre_platforms": ["Windows"],
            "x_mitre_log_source_references": [
                {"x_mitre_data_component_ref": "dc--1", "name": "WinEventLog:Security"}
            ],
            "external_references": _ref("AN0110"),
        },
        {
            "type": "x-mitre-detection-strategy",
            "id": "detection-strategy--1",
            "name": "Behavioral detection of Kerberoasting",
            "x_mitre_analytic_refs": ["analytic--1"],
            "external_references": _ref("DET0110"),
        },
        {
            "type": "relationship", "relationship_type": "detects",
            "source_ref": "detection-strategy--1", "target_ref": "attack-pattern--1",
        },
        {
            "type": "course-of-action", "id": "course-of-action--1", "name": "Password Policies",
            "description": "Use strong passwords.", "external_references": _ref("M1027"),
        },
        {
            "type": "relationship", "relationship_type": "mitigates",
            "source_ref": "course-of-action--1", "target_ref": "attack-pattern--1",
            "description": "Long service account passwords resist cracking.",
        },
        {
            "type": "intrusion-set", "id": "intrusion-set--1", "name": "APT Example",
            "aliases": ["Example Bear"], "external_references": _ref("G0016"),
        },
        {
            "type": "tool", "id": "tool--1", "name": "Rubeus",
            "external_references": _ref("S0005"),
        },
        {
            "type": "relationship", "relationship_type": "uses",
            "source_ref": "intrusion-set--1", "target_ref": "attack-pattern--1",
            "description": "APT Example has used Rubeus to kerberoast.",
        },
        {
            "type": "relationship", "relationship_type": "uses",
            "source_ref": "intrusion-set--1", "target_ref": "tool--1",
        },
    ]
}

SIGMA_RULE = """
title: Suspicious Kerberos RC4 Ticket
id: 3b4b232a-1d94-4d78-9f5c-9c9a1e7ef2a1
status: test
description: Detects Kerberoasting
author: Test Author
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769
    condition: selection
level: high
tags:
    - attack.credential_access
    - attack.t1558.003
"""


class ImportAttackTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        Technique.objects.create(attack_id="T9999", name="Removed upstream")
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bundle.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(BUNDLE, handle)
            call_command("import_attack", file=path, verbosity=0)

    def test_technique_metadata_and_hierarchy(self):
        technique = Technique.objects.get(attack_id="T1558.003")
        self.assertEqual(technique.name, "Kerberoasting")
        self.assertEqual(technique.attack_version, "19.2")
        self.assertEqual(technique.tactics, ["credential-access"])
        self.assertIn("ticket-granting", technique.description)
        self.assertTrue(technique.is_subtechnique)
        self.assertEqual(technique.parent.attack_id, "T1558")
        self.assertEqual(technique.parent.technique_version, "1.5")
        self.assertFalse(technique.deprecated)

    def test_data_sources_resolve_through_the_v17_detection_chain(self):
        """The defect this guards: v17+ moved data sources behind
        detection-strategy -> analytic -> log source refs, leaving them empty."""
        technique = Technique.objects.get(attack_id="T1558.003")
        self.assertEqual(
            technique.data_sources, ["Active Directory: Active Directory Credential Request"]
        )

        strategy = technique.detection_strategies.get()
        analytic = strategy.analytics.get()
        self.assertIn("4769", analytic.description)
        self.assertEqual(analytic.log_sources, ["WinEventLog:Security"])

    def test_threat_context_imports(self):
        technique = Technique.objects.get(attack_id="T1558.003")

        link = TechniqueMitigation.objects.get(technique=technique)
        self.assertEqual(link.mitigation.attack_id, "M1027")
        self.assertIn("service account passwords", link.description)

        procedure = technique.procedures.get()
        self.assertEqual(procedure.source.attack_id, "G0016")
        self.assertIn("kerberoast", procedure.description)

        actor = Actor.objects.get(attack_id="G0016")
        self.assertEqual([s.name for s in actor.software.all()], ["Rubeus"])

    def test_tactics_use_matrix_order_not_alphabetical(self):
        self.assertEqual(
            [t.shortname for t in Tactic.objects.all()], ["execution", "credential-access"]
        )

    def test_dropped_techniques_are_flagged(self):
        self.assertTrue(Technique.objects.get(attack_id="T9999").deprecated)


class ImportSigmaTests(TestCase):
    def test_rules_link_to_techniques_by_attack_tag(self):
        technique = Technique.objects.create(attack_id="T1558.003", name="Kerberoasting")

        with tempfile.TemporaryDirectory() as tmp:
            rules_dir = os.path.join(tmp, "rules", "windows")
            os.makedirs(rules_dir)
            with open(os.path.join(rules_dir, "rule.yml"), "w", encoding="utf-8") as handle:
                handle.write(SIGMA_RULE)
            call_command("import_sigma", path=tmp, verbosity=0)

        rule = SigmaRule.objects.get()
        self.assertEqual(rule.title, "Suspicious Kerberos RC4 Ticket")
        self.assertEqual(rule.logsource_product, "windows")
        self.assertEqual(rule.license, "DRL-1.1")  # attribution must survive to export
        self.assertEqual(list(rule.techniques.all()), [technique])


class CoverageTests(TestCase):
    def setUp(self):
        self.technique = Technique.objects.create(attack_id="T1558.003", name="Kerberoasting")
        self.objective = Objective.objects.create(
            hunt=Hunt.objects.create(title="H", hunt_type="HBO"), title="O"
        )

    def _task(self, outcome_types=(), **kwargs):
        task = Task.objects.create(objective=self.objective, title="T", **kwargs)
        task.techniques.add(self.technique)
        for outcome_type in outcome_types:
            Outcome.objects.create(task=task, outcome_type=outcome_type)
        return task

    def test_unexecuted_task_is_not_coverage(self):
        self._task()
        self.assertEqual(reporting.technique_status(), {})

    def test_outcome_drives_colour_and_detection_wins(self):
        self._task(status=Task.EXECUTED, outcome_types=["visibility_gap"])
        self.assertEqual(reporting.technique_status()[self.technique.id], reporting.GAP)

        self._task(status=Task.EXECUTED, outcome_types=["analytics_detection"])
        self.assertEqual(reporting.technique_status()[self.technique.id], reporting.DETECTION)

    def test_filters_narrow_the_matrix(self):
        self._task(status=Task.EXECUTED, outcome_types=["analytics_detection"])
        self.assertEqual(reporting.technique_status(hunt_type="HBO"), {self.technique.id: "detection"})
        self.assertEqual(reporting.technique_status(hunt_type="EDA"), {})


class ExportTests(TestCase):
    def test_hunt_report_carries_sigma_attribution(self):
        hunt = Hunt.objects.create(title="Kerberoasting sweep", feasibility_decision="GO")
        objective = Objective.objects.create(hunt=hunt, title="Baseline 4769")
        task = Task.objects.create(
            objective=objective,
            title="RC4 tickets",
            query="index=wineventlog EventCode=4769",
            status=Task.EXECUTED,
        )
        Outcome.objects.create(task=task, outcome_type="analytics_detection")
        task.sigma_rules.add(
            SigmaRule.objects.create(
                rule_id="3b4b232a-1d94-4d78-9f5c-9c9a1e7ef2a1",
                title="Suspicious Kerberos RC4 Ticket",
                author="Test Author",
                license="DRL-1.1",
                raw_yaml="",
            )
        )

        report = reporting.hunt_markdown(hunt)
        self.assertIn("# HUNT-001: Kerberoasting sweep", report)
        self.assertIn("index=wineventlog EventCode=4769", report)
        self.assertIn("Test Author (DRL-1.1)", report)
        self.assertIn("Analytics/Detection: 1", report)

        handoff = reporting.task_handoff_markdown(task)
        self.assertIn("# Detection request: RC4 tickets", handoff)
        self.assertIn("Test Author (DRL-1.1)", handoff)

    def test_discarded_sigma_rules_are_excluded_from_attribution(self):
        hunt = Hunt.objects.create(title="Kerberoasting sweep")
        objective = Objective.objects.create(hunt=hunt, title="Baseline 4769")
        task = Task.objects.create(objective=objective, title="RC4 tickets")
        task.sigma_rules.add(
            SigmaRule.objects.create(
                rule_id="4c4b232a-1d94-4d78-9f5c-9c9a1e7ef2a1",
                title="Ruled Out Rule",
                author="Test Author",
                license="DRL-1.1",
                raw_yaml="",
            )
        )
        TaskSigmaRule.objects.filter(task=task).update(status=TaskSigmaRule.DISCARDED)

        self.assertNotIn("Ruled Out Rule", reporting.hunt_markdown(hunt))
        self.assertNotIn("Ruled Out Rule", reporting.task_handoff_markdown(task))


class RoleTests(TestCase):
    def test_seed_roles_grants_override_only_to_hunt_lead(self):
        call_command("seed_roles", verbosity=0)

        lead = Group.objects.get(name="Hunt Lead")
        hunter = Group.objects.get(name="Hunter")
        self.assertTrue(lead.permissions.filter(codename="override_feasibility").exists())
        self.assertFalse(hunter.permissions.filter(codename="override_feasibility").exists())
        self.assertFalse(
            Group.objects.get(name="Stakeholder").permissions.exclude(codename__startswith="view_").exists()
        )

    def test_override_fields_hidden_from_non_leads(self):
        call_command("seed_roles", verbosity=0)
        users = get_user_model().objects
        hunter = users.create(username="hunter")
        hunter.groups.add(Group.objects.get(name="Hunter"))
        lead = users.create(username="lead")
        lead.groups.add(Group.objects.get(name="Hunt Lead"))

        self.assertNotIn("feasibility_override_by", HuntForm(user=hunter).fields)
        self.assertIn("feasibility_override_by", HuntForm(user=lead).fields)


class SpinoffTests(TestCase):
    def test_spinoff_creates_linked_hunt(self):
        call_command("seed_roles", verbosity=0)
        user = get_user_model().objects.create_user(username="hunter", password="pw")
        user.groups.add(Group.objects.get(name="Hunter"))
        self.client.force_login(user)

        technique = Technique.objects.create(attack_id="T1558.003", name="Kerberoasting")
        objective = Objective.objects.create(hunt=Hunt.objects.create(title="Source"), title="O")
        task = Task.objects.create(objective=objective, title="Odd service tickets")
        Outcome.objects.create(task=task, outcome_type="new_hunt_idea")
        task.techniques.add(technique)

        response = self.client.post(f"/tasks/{task.pk}/spinoff/")
        self.assertEqual(response.status_code, 302)

        spun = Hunt.objects.get(spun_off_from=task)
        self.assertEqual(spun.trigger_type, "prior_hunt")
        self.assertIn(task.task_id, spun.trigger_description)
        self.assertEqual(list(spun.techniques.all()), [technique])


class SigmaAutoAttachTests(TestCase):
    def setUp(self):
        self.technique = Technique.objects.create(attack_id="T1558.003", name="Kerberoasting")
        self.objective = Objective.objects.create(hunt=Hunt.objects.create(title="H"), title="O")
        self.rules = {}
        for status in ("stable", "test", "experimental"):
            rule = SigmaRule.objects.create(
                rule_id=uuid.uuid4(), title=f"{status} rule", status=status, raw_yaml=""
            )
            rule.techniques.add(self.technique)
            self.rules[status] = rule

    def test_selecting_a_technique_attaches_vetted_rules_only(self):
        task = Task.objects.create(objective=self.objective, title="T")
        task.techniques.add(self.technique)

        attached = {rule.status for rule in task.sigma_rules.all()}
        self.assertEqual(attached, {"stable", "test"})

    def test_discarded_rules_keep_their_status_and_stay_attached(self):
        task = Task.objects.create(objective=self.objective, title="T")
        task.techniques.add(self.technique)

        TaskSigmaRule.objects.filter(task=task, sigma_rule=self.rules["stable"]).update(
            status=TaskSigmaRule.DISCARDED
        )

        task.techniques.clear()
        task.techniques.add(self.technique)  # re-running auto-attach

        link = TaskSigmaRule.objects.get(task=task, sigma_rule=self.rules["stable"])
        self.assertEqual(link.status, TaskSigmaRule.DISCARDED)
        self.assertIn(self.rules["stable"], task.sigma_rules.all())

    def test_forking_copies_the_entrys_curation_instead_of_auto_attaching(self):
        entry = LibraryTask.objects.create(title="Curated")
        entry.suppress_auto_sigma = True
        entry.techniques.set([self.technique])
        entry.sigma_rules.set([self.rules["stable"]])  # deliberately 1 of 2 vetted rules

        task = entry.fork_into(self.objective)
        self.assertEqual([r.status for r in task.sigma_rules.all()], ["stable"])


class LibraryReferenceTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_superuser(username="lead", password="pw")
        self.client.force_login(self.user)

    def test_seeding_is_idempotent_and_marks_entries_read_only(self):
        call_command("seed_library", skip_sigma=True, verbosity=0)
        first = LibraryTask.objects.count()
        self.assertEqual(first, 12)

        entry = LibraryTask.objects.get(seed_key="kerberoasting-rc4")
        self.assertEqual(entry.provenance, "curated")
        self.assertTrue(entry.is_reference)
        self.assertIn("baselining", entry.notes)
        self.assertIn("EventCode=4769", entry.query)

        call_command("seed_library", skip_sigma=True, verbosity=0)
        self.assertEqual(LibraryTask.objects.count(), first)  # skipped, not duplicated

    def test_force_refreshes_seeded_entries_in_place(self):
        call_command("seed_library", skip_sigma=True, verbosity=0)
        entry = LibraryTask.objects.get(seed_key="dcsync")
        entry.query = "edited by a hunter"
        entry.save()

        call_command("seed_library", skip_sigma=True, verbosity=0)
        entry.refresh_from_db()
        self.assertEqual(entry.query, "edited by a hunter")  # never clobbered by default

        call_command("seed_library", skip_sigma=True, force=True, verbosity=0)
        entry.refresh_from_db()
        self.assertIn("EventCode=4662", entry.query)
        self.assertEqual(LibraryTask.objects.filter(seed_key="dcsync").count(), 1)

    def test_reference_entries_redirect_edit_to_read_only_view(self):
        call_command("seed_library", skip_sigma=True, verbosity=0)
        entry = LibraryTask.objects.get(seed_key="kerberoasting-rc4")

        response = self.client.get(f"/library/{entry.pk}/edit/")
        self.assertRedirects(response, f"/library/{entry.pk}/")

    def test_duplicate_produces_an_editable_copy(self):
        call_command("seed_library", skip_sigma=True, verbosity=0)
        entry = LibraryTask.objects.get(seed_key="kerberoasting-rc4")

        response = self.client.post(f"/library/{entry.pk}/duplicate/")
        copy = LibraryTask.objects.get(title__endswith="(copy)")
        self.assertRedirects(response, f"/library/{copy.pk}/edit/")
        self.assertFalse(copy.is_reference)
        self.assertEqual(copy.provenance, "user")
        self.assertEqual(copy.query, entry.query)
        self.assertEqual(copy.notes, entry.notes)


class MatrixTests(TestCase):
    def test_parents_do_not_inherit_subtechnique_coverage(self):
        Tactic.objects.create(
            attack_id="TA0006", shortname="credential-access", name="Credential Access", order=0
        )
        parent = Technique.objects.create(
            attack_id="T1558", name="Kerberos Tickets", tactics=["credential-access"]
        )
        child = Technique.objects.create(
            attack_id="T1558.003", name="Kerberoasting", tactics=["credential-access"],
            is_subtechnique=True, parent=parent,
        )
        objective = Objective.objects.create(hunt=Hunt.objects.create(title="H"), title="O")
        task = Task.objects.create(objective=objective, title="T", status=Task.EXECUTED)
        Outcome.objects.create(task=task, outcome_type="visibility_gap")
        task.techniques.add(child)

        columns = reporting.matrix_by_tactic(reporting.technique_status())
        (tactic, entries), = columns
        self.assertEqual(tactic.shortname, "credential-access")

        entry, = entries
        self.assertEqual(entry["technique"], parent)
        self.assertEqual(entry["status"], reporting.NEVER)  # parent is NOT hunted
        self.assertEqual(entry["covered"], 1)
        self.assertEqual(entry["subs"], [(child, reporting.GAP)])


class PageRenderTests(TestCase):
    """Every page renders. Catches template errors the logic tests never touch."""

    def setUp(self):
        user = get_user_model().objects.create_superuser(username="lead", password="pw")
        self.client.force_login(user)

        Tactic.objects.create(
            attack_id="TA0006", shortname="credential-access", name="Credential Access"
        )
        technique = Technique.objects.create(
            attack_id="T1558.003", name="Kerberoasting", tactics=["credential-access"]
        )
        self.technique = technique
        self.hunt = Hunt.objects.create(title="H", feasibility_decision="GO")
        self.objective = Objective.objects.create(hunt=self.hunt, title="O")
        self.task = Task.objects.create(
            objective=self.objective, title="T", status=Task.EXECUTED,
        )
        Outcome.objects.create(task=self.task, outcome_type="new_hunt_idea")
        Outcome.objects.create(task=self.task, outcome_type="analytics_detection")
        self.task.techniques.add(technique)
        self.entry = LibraryTask.objects.create(title="Library entry")

    def test_all_pages_render(self):
        urls = [
            "/",
            "/hunts/new/",
            f"/hunts/{self.hunt.pk}/",
            f"/hunts/{self.hunt.pk}/edit/",
            f"/hunts/{self.hunt.pk}/report.md",
            f"/hunts/{self.hunt.pk}/objectives/new/",
            f"/objectives/{self.objective.pk}/edit/",
            f"/objectives/{self.objective.pk}/tasks/new/",
            f"/tasks/{self.task.pk}/",
            f"/tasks/{self.task.pk}/edit/",
            f"/tasks/{self.task.pk}/handoff.md",
            f"/tasks/{self.task.pk}/outcomes/new/",
            f"/hunts/{self.hunt.pk}/outcomes/new/",
            f"/outcomes/{self.task.outcomes.first().pk}/edit/",
            f"/tasks/{self.task.pk}/evidence/new/",
            f"/hunts/{self.hunt.pk}/evidence/new/",
            f"/outcomes/{self.task.outcomes.first().pk}/evidence/new/",
            f"/tasks/{self.task.pk}/comments/new/",
            f"/hunts/{self.hunt.pk}/comments/new/",
            f"/outcomes/{self.task.outcomes.first().pk}/comments/new/",
            "/library/",
            "/library/new/",
            f"/library/{self.entry.pk}/",
            f"/library/{self.entry.pk}/edit/",
            "/attack/",
            "/attack/?q=kerberoast&tactic=credential-access",
            f"/attack/{self.technique.attack_id}/",
            "/heatmap/",
            "/accounts/login/",
        ]
        for url in urls:
            with self.subTest(url=url):
                self.assertEqual(self.client.get(url).status_code, 200)

    def test_attack_prose_strips_stix_markup(self):
        """MITRE descriptions carry markdown links and (Citation: ...) markers that
        wreck the primary reading content on a technique page."""
        from ..templatetags.attack import attack_prose

        rendered = attack_prose(
            "Vulnerable to [Brute Force](https://attack.mitre.org/techniques/T1110)."
            "(Citation: AdSecurity Cracking Kerberos Dec 2015) Also <script>x</script>"
        )
        self.assertIn('<a href="https://attack.mitre.org/techniques/T1110">Brute Force</a>', rendered)
        self.assertNotIn("Citation:", rendered)
        self.assertNotIn("<script>", rendered)

    def test_sigma_suggestions_filter_by_status_and_log_source(self):
        technique = self.task.techniques.get()
        stable = SigmaRule.objects.create(
            rule_id="11111111-1111-1111-1111-111111111111", title="Stable rule",
            status="stable", logsource_product="windows", raw_yaml="",
        )
        experimental = SigmaRule.objects.create(
            rule_id="22222222-2222-2222-2222-222222222222", title="Experimental rule",
            status="experimental", logsource_product="linux", raw_yaml="",
        )
        stable.techniques.add(technique)
        experimental.techniques.add(technique)

        url = f"/tasks/{self.task.pk}/"
        self.assertEqual(len(self.client.get(url).context["suggestions"]), 2)
        self.assertEqual(
            [r.title for r in self.client.get(url, {"status": "stable"}).context["suggestions"]],
            ["Stable rule"],
        )
        self.assertEqual(
            [r.title for r in self.client.get(url, {"product": "linux"}).context["suggestions"]],
            ["Experimental rule"],
        )

    def test_attach_from_library_forks_into_the_objective(self):
        response = self.client.post(
            f"/objectives/{self.objective.pk}/attach/", {"library_pk": self.entry.pk}
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.objective.tasks.filter(source_task=self.entry).count(), 1)

