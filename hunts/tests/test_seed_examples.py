from io import StringIO

from django.core.management import call_command
from django.test import TestCase

from ..models import Hunt, HuntSeed, IntelReport, Task, Technique


def run():
    out = StringIO()
    call_command("seed_examples", stdout=out)
    return out.getvalue()


class SeedExamplesTests(TestCase):
    def test_loads_the_intel_run_and_both_hunts(self):
        run()
        report = IntelReport.objects.get(slug="apt29-past-year")
        hunts = Hunt.objects.order_by("number")
        self.assertEqual(hunts.count(), 2)
        self.assertEqual({h.intel_report_id for h in hunts}, {report.pk})
        approved, backlog = hunts
        self.assertEqual((approved.status, backlog.status), ("approved", "backlog"))
        self.assertEqual(approved.objectives.count(), 3)
        self.assertEqual(Task.objects.filter(objective__hunt=approved).count(), 3)
        self.assertTrue(Task.objects.filter(objective__hunt=backlog).get().query)

    def test_promoted_seed_points_at_its_hunt(self):
        run()
        seed = HuntSeed.objects.get(report__slug="apt29-past-year", order=1)
        self.assertEqual(seed.status, HuntSeed.PROMOTED)
        self.assertEqual(seed.hunt.status, "backlog")

    def test_rerun_adds_nothing(self):
        run()
        self.assertIn("already present", run())
        self.assertEqual(Hunt.objects.count(), 2)
        self.assertEqual(Task.objects.count(), 4)

    def test_techniques_link_when_attack_is_imported_and_warn_when_it_is_not(self):
        self.assertIn("run import_attack first", run())
        Hunt.objects.all().delete()
        Technique.objects.create(attack_id="T1621", name="MFA Request Generation")
        run()
        approved = Hunt.objects.get(status="approved")
        self.assertEqual(list(approved.techniques.values_list("attack_id", flat=True)), ["T1621"])
