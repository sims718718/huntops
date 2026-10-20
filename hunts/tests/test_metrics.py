from datetime import date

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from .. import metrics, reporting
from ..models import DataSource, Hunt, Objective, Outcome, Task, Technique


class MonthEndsTests(TestCase):
    def test_trailing_months_oldest_first(self):
        ends = metrics._month_ends(months=3, today=date(2026, 3, 15))
        self.assertEqual(
            ends,
            [
                ("2026-01", date(2026, 1, 31)),
                ("2026-02", date(2026, 2, 28)),
                ("2026-03", date(2026, 3, 31)),
            ],
        )

    def test_wraps_across_year_boundary(self):
        ends = metrics._month_ends(months=3, today=date(2026, 1, 20))
        self.assertEqual([label for label, _ in ends], ["2025-11", "2025-12", "2026-01"])


class DataSourceStatusTests(TestCase):
    def setUp(self):
        self.source = DataSource.objects.create(name="WinEventLog:Security")
        self.hunt = Hunt.objects.create(title="H", start_date=date(2026, 2, 10))
        self.objective = Objective.objects.create(hunt=self.hunt, title="O")

    def _task(self, **kwargs):
        task = Task.objects.create(objective=self.objective, title="T", **kwargs)
        task.suppress_auto_sigma = True
        return task

    def test_unused_source_is_absent(self):
        self.assertEqual(reporting.data_source_status(), set())

    def test_used_by_executed_task(self):
        task = self._task(status=Task.EXECUTED)
        task.data_sources.add(self.source)
        self.assertEqual(reporting.data_source_status(), {self.source.pk})

    def test_not_executed_does_not_count(self):
        task = self._task(status=Task.NOT_STARTED)
        task.data_sources.add(self.source)
        self.assertEqual(reporting.data_source_status(), set())

    def test_end_cutoff_excludes_later_hunts(self):
        task = self._task(status=Task.EXECUTED)
        task.data_sources.add(self.source)
        self.assertEqual(reporting.data_source_status(end="2026-01-31"), set())
        self.assertEqual(reporting.data_source_status(end="2026-02-28"), {self.source.pk})

    def test_hunt_type_filter(self):
        task = self._task(status=Task.EXECUTED)
        task.data_sources.add(self.source)
        self.hunt.hunt_type = "TIO"
        self.hunt.save()
        self.assertEqual(reporting.data_source_status(hunt_type="EDA"), set())
        self.assertEqual(reporting.data_source_status(hunt_type="TIO"), {self.source.pk})


class TechniqueCoverageTrendTests(TestCase):
    def test_technique_moves_from_never_to_detection_at_its_hunt_month(self):
        technique = Technique.objects.create(attack_id="T1055", name="Process Injection")
        hunt = Hunt.objects.create(title="H", start_date=date(2026, 2, 15))
        objective = Objective.objects.create(hunt=hunt, title="O")
        task = Task.objects.create(objective=objective, title="T", status=Task.EXECUTED)
        task.techniques.add(technique)
        Outcome.objects.create(task=task, outcome_type="analytics_detection")

        series = {
            row["label"]: row
            for row in metrics.technique_coverage_trend(months=3, today=date(2026, 3, 31))
        }
        self.assertEqual(series["2026-01"]["detection"], 0)
        self.assertEqual(series["2026-01"]["never"], 1)
        self.assertEqual(series["2026-02"]["detection"], 1)
        self.assertEqual(series["2026-03"]["detection"], 1)

    def test_hunt_type_filter_narrows_the_trend(self):
        technique = Technique.objects.create(attack_id="T1055", name="Process Injection")
        hunt = Hunt.objects.create(title="H", start_date=date(2026, 2, 15), hunt_type="TIO")
        objective = Objective.objects.create(hunt=hunt, title="O")
        task = Task.objects.create(objective=objective, title="T", status=Task.EXECUTED)
        task.techniques.add(technique)
        Outcome.objects.create(task=task, outcome_type="analytics_detection")

        other = metrics.technique_coverage_trend(months=1, today=date(2026, 2, 28), hunt_type="EDA")
        mine = metrics.technique_coverage_trend(months=1, today=date(2026, 2, 28), hunt_type="TIO")
        self.assertEqual(other[0]["detection"], 0)
        self.assertEqual(mine[0]["detection"], 1)

    def test_never_count_is_never_negative_for_a_technique_deprecated_after_being_hunted(self):
        technique = Technique.objects.create(attack_id="T1055", name="Process Injection", deprecated=True)
        hunt = Hunt.objects.create(title="H", start_date=date(2026, 2, 15))
        objective = Objective.objects.create(hunt=hunt, title="O")
        task = Task.objects.create(objective=objective, title="T", status=Task.EXECUTED)
        task.techniques.add(technique)
        Outcome.objects.create(task=task, outcome_type="analytics_detection")

        row = metrics.technique_coverage_trend(months=1, today=date(2026, 2, 28))[0]
        self.assertEqual(row["detection"], 1)
        self.assertGreaterEqual(row["never"], 0)


class DataSourceCoverageTrendTests(TestCase):
    def test_source_moves_from_never_to_used_at_its_hunt_month(self):
        source = DataSource.objects.create(name="WinEventLog:Security")
        hunt = Hunt.objects.create(title="H", start_date=date(2026, 2, 15))
        objective = Objective.objects.create(hunt=hunt, title="O")
        task = Task.objects.create(objective=objective, title="T", status=Task.EXECUTED)
        task.suppress_auto_sigma = True
        task.data_sources.add(source)

        series = {
            row["label"]: row
            for row in metrics.data_source_coverage_trend(months=3, today=date(2026, 3, 31))
        }
        self.assertEqual(series["2026-01"]["used"], 0)
        self.assertEqual(series["2026-02"]["used"], 1)
        self.assertEqual(series["2026-03"]["used"], 1)


class HuntThroughputTrendTests(TestCase):
    def test_started_and_completed_land_in_their_own_months(self):
        Hunt.objects.create(title="Started", start_date=date(2026, 2, 5))
        Hunt.objects.create(
            title="Completed", start_date=date(2026, 1, 1), end_date=date(2026, 4, 20),
            status=Hunt.REPORTED, feasibility_decision="GO",
        )

        series = {
            row["label"]: row
            for row in metrics.hunt_throughput_trend(months=6, today=date(2026, 4, 30))
        }
        self.assertEqual(series["2026-02"]["started"], 1)
        self.assertEqual(series["2026-02"]["completed"], 0)
        self.assertEqual(series["2026-04"]["completed"], 1)
        self.assertEqual(series["2026-04"]["started"], 0)

    def test_incomplete_hunt_never_counts_as_completed(self):
        Hunt.objects.create(
            title="Open", start_date=date(2026, 1, 1), end_date=date(2026, 2, 1),
            status=Hunt.IN_PROGRESS, feasibility_decision="GO",
        )

        series = {
            row["label"]: row
            for row in metrics.hunt_throughput_trend(months=2, today=date(2026, 2, 28))
        }
        self.assertEqual(series["2026-02"]["completed"], 0)

    def test_hunt_type_filter_narrows_started_count(self):
        Hunt.objects.create(title="A", start_date=date(2026, 2, 5), hunt_type="TIO")
        Hunt.objects.create(title="B", start_date=date(2026, 2, 6), hunt_type="EDA")

        series = {
            row["label"]: row
            for row in metrics.hunt_throughput_trend(hunt_type="TIO", months=3, today=date(2026, 2, 28))
        }
        self.assertEqual(series["2026-02"]["started"], 1)


class OutcomeBreakdownTrendTests(TestCase):
    def setUp(self):
        self.hunt = Hunt.objects.create(title="H")
        self.objective = Objective.objects.create(hunt=self.hunt, title="O")
        self.task = Task.objects.create(objective=self.objective, title="T")

    def _recorded(self, when, **kwargs):
        outcome = Outcome.objects.create(**kwargs)
        Outcome.objects.filter(pk=outcome.pk).update(recorded_at=when)
        return outcome

    def test_buckets_by_recorded_month(self):
        self._recorded(
            timezone.make_aware(timezone.datetime(2026, 3, 10)),
            task=self.task, outcome_type="analytics_detection",
        )

        series = {
            row["label"]: row
            for row in metrics.outcome_breakdown_trend(months=3, today=date(2026, 3, 31))
        }
        self.assertEqual(series["2026-03"]["analytics_detection"], 1)
        self.assertEqual(series["2026-02"]["analytics_detection"], 0)

    def test_hunt_level_outcome_counts_too(self):
        self._recorded(
            timezone.make_aware(timezone.datetime(2026, 3, 10)),
            hunt=self.hunt, outcome_type="visibility_gap",
        )

        series = {
            row["label"]: row
            for row in metrics.outcome_breakdown_trend(months=1, today=date(2026, 3, 31))
        }
        self.assertEqual(series["2026-03"]["visibility_gap"], 1)

    def test_environment_profile_filter_narrows_the_trend(self):
        from ..models import EnvironmentProfile

        profile = EnvironmentProfile.objects.create(name="Prod")
        self.hunt.environment_profile = profile
        self.hunt.save()
        self._recorded(
            timezone.make_aware(timezone.datetime(2026, 3, 10)),
            task=self.task, outcome_type="analytics_detection",
        )

        other = EnvironmentProfile.objects.create(name="Test")
        matching = metrics.outcome_breakdown_trend(
            environment_profile=str(profile.pk), months=1, today=date(2026, 3, 31)
        )
        non_matching = metrics.outcome_breakdown_trend(
            environment_profile=str(other.pk), months=1, today=date(2026, 3, 31)
        )
        self.assertEqual(matching[0]["analytics_detection"], 1)
        self.assertEqual(non_matching[0]["analytics_detection"], 0)


class MetricsMarkdownTests(TestCase):
    def test_report_contains_all_four_sections(self):
        report = metrics.metrics_markdown({"hunt_type": "", "environment_profile": ""})
        for heading in ["Technique coverage", "Data source coverage", "Hunt throughput", "Outcome breakdown"]:
            self.assertIn(heading, report)


class MetricsViewTests(TestCase):
    def setUp(self):
        call_command("seed_roles", verbosity=0)
        self.stakeholder = get_user_model().objects.create_user(username="s", password="pw")
        self.stakeholder.groups.add(Group.objects.get(name="Stakeholder"))
        self.client.force_login(self.stakeholder)

    def test_stakeholder_can_view_metrics_page(self):
        response = self.client.get("/metrics/")
        self.assertEqual(response.status_code, 200)

    def test_stakeholder_can_export_metrics_report(self):
        response = self.client.get("/metrics/report.md")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/markdown; charset=utf-8")
        self.assertIn('filename="metrics-report.md"', response["Content-Disposition"])

    def test_malformed_environment_profile_is_ignored_not_a_500(self):
        response = self.client.get("/metrics/", {"environment_profile": "not-a-number"})
        self.assertEqual(response.status_code, 200)

    def test_malformed_environment_profile_does_not_break_the_export_either(self):
        response = self.client.get("/metrics/report.md", {"environment_profile": "not-a-number"})
        self.assertEqual(response.status_code, 200)

    def test_export_link_carries_the_current_filters_encoded(self):
        from ..models import EnvironmentProfile

        profile = EnvironmentProfile.objects.create(name="Prod & Test")
        response = self.client.get("/metrics/", {"environment_profile": str(profile.pk)})
        self.assertContains(response, f"environment_profile={profile.pk}")

    def test_anonymous_is_redirected(self):
        self.client.logout()
        response = self.client.get("/metrics/")
        self.assertEqual(response.status_code, 302)
