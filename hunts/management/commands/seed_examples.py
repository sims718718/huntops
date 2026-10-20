"""Load the worked examples: one threat-intel-hunt-framework run (APT29, past year) and two
hunts built from it - a hand-built, approved hunt and a seed-promoted backlog hunt.

Idempotent: the intel run is re-imported (see save_intel), and a hunt whose title already
exists is left alone, so re-running never duplicates or overwrites an analyst's edits.
Run import_attack and import_sigma first for the best result - without them the hunts load
but carry no techniques or Sigma rules. Works air-gapped: everything is read from examples/.
"""
from pathlib import Path

import yaml
from django.conf import settings
from django.core.management import call_command
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from hunts.models import DataSource, Hunt, HuntSeed, IntelReport, Objective, Task, Technique

EXAMPLES = Path(settings.BASE_DIR) / "examples"
NESTED = {"hunt": ("techniques", "objectives", "promoted_from_seed"), "objective": ("tasks",),
          "task": ("techniques", "data_sources")}


def _plain(spec, kind):
    return {key: value for key, value in spec.items() if key not in NESTED[kind]}


class Command(BaseCommand):
    help = "Load the example intel run and the two example hunts built from it."

    def handle(self, *args, **options):
        path = EXAMPLES / "hunts.yml"
        if not path.exists():
            raise CommandError(f"{path} not found")
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        call_command("import_intel", dir=str(EXAMPLES / "threat-hunting"), slug=data["intel"], stdout=self.stdout)
        report = IntelReport.objects.get(slug=data["intel"])
        missing = set()
        for spec in data["hunts"]:
            if Hunt.objects.filter(title=spec["title"]).exists():
                self.stdout.write(f"already present: {spec['title']}")
                continue
            with transaction.atomic():
                hunt = self.create_hunt(spec, report, missing)
            self.stdout.write(self.style.SUCCESS(f"created {hunt.hunt_id}: {hunt.title}"))
        if missing:
            self.stdout.write(self.style.WARNING(
                f"{len(missing)} technique(s) not in the database were skipped "
                f"(run import_attack first): {', '.join(sorted(missing))}"
            ))

    def techniques(self, attack_ids, missing):
        found = Technique.objects.filter(attack_id__in=attack_ids)
        missing.update(set(attack_ids) - {t.attack_id for t in found})
        return found

    def create_hunt(self, spec, report, missing):
        hunt = Hunt.objects.create(intel_report=report, **_plain(spec, "hunt"))
        hunt.techniques.set(self.techniques(spec.get("techniques", []), missing))
        for objective_spec in spec.get("objectives", []):
            objective = Objective.objects.create(hunt=hunt, **_plain(objective_spec, "objective"))
            for task_spec in objective_spec.get("tasks", []):
                task = Task.objects.create(objective=objective, **_plain(task_spec, "task"))
                # Setting techniques also auto-attaches matching Sigma rules and ATT&CK data
                # sources (see the m2m_changed handlers), as it would for an analyst.
                task.techniques.set(self.techniques(task_spec.get("techniques", []), missing))
                for name in task_spec.get("data_sources", []):
                    source, _ = DataSource.objects.get_or_create(name=name, defaults={"origin": DataSource.CUSTOM})
                    task.data_sources.add(source)
        if "promoted_from_seed" in spec:
            HuntSeed.objects.filter(
                report=report, order=spec["promoted_from_seed"], status=HuntSeed.OPEN
            ).update(status=HuntSeed.PROMOTED, hunt=hunt)
        return hunt
