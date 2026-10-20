"""Import library tasks from YAML files (see docs/library-as-code.md).

The files win: a task whose id already exists is overwritten from the file. Any error
in any file stops the whole run with nothing written and a non-zero exit, so a CI job
can gate on it. Use --dry-run to see the plan first.
"""
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from hunts.library_io import apply_plan, build_plan, read_directory


def _short(value):
    text = repr(value)
    return text if len(text) <= 70 else text[:67] + "..."


class Command(BaseCommand):
    help = "Import library tasks from a directory of YAML files, or from one file."

    def add_arguments(self, parser):
        source = parser.add_mutually_exclusive_group(required=True)
        source.add_argument("--dir", help="Directory to read; hidden folders such as .github are skipped")
        source.add_argument("--file", help="A single YAML file")
        parser.add_argument("--dry-run", action="store_true", help="Show the plan, write nothing")

    def handle(self, *args, **options):
        if options["file"]:
            path = Path(options["file"])
            try:
                named, errors = {path.name: path.read_text(encoding="utf-8")}, []
            except (OSError, UnicodeDecodeError) as exc:
                raise CommandError(f"Cannot read {path}: {exc}")
        else:
            named, errors = read_directory(options["dir"])
        if errors:
            raise CommandError("\n".join(errors))

        plan = build_plan(named)
        if not plan.ok:
            raise CommandError("\n".join(plan.errors))

        for item in plan.items:
            self.stdout.write(f"{item.action:<9} {item.entry.id}  ({item.entry.source})")
            for field, (old, new) in item.changes.items():
                self.stdout.write(f"            {field}: {_short(old)} -> {_short(new)}")
            for warning in item.warnings:
                self.stdout.write(self.style.WARNING(f"WARNING {warning}"))
        counts = {action: sum(i.action == action for i in plan.items) for action in ("created", "updated", "unchanged")}
        summary = f"{counts['created']} created, {counts['updated']} updated, {counts['unchanged']} unchanged"

        if options["dry_run"]:
            self.stdout.write(self.style.SUCCESS(f"{summary} (dry run, nothing written)"))
            return
        apply_plan(plan)
        self.stdout.write(self.style.SUCCESS(summary))
