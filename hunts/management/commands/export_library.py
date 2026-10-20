"""Write the team-built task library to a directory as one YAML file per task.

Meant for a git checkout: output is deterministic, so a re-export changes only the
files whose tasks changed. Never deletes anything - a task removed from the platform
leaves its file behind for you to remove in the repo.
"""
from pathlib import Path

from django.core.management.base import BaseCommand

from hunts.library_io import export_all


class Command(BaseCommand):
    help = "Export team-built library tasks as YAML files, one per task."

    def add_arguments(self, parser):
        parser.add_argument("--dir", required=True, help="Directory to write into (created if missing)")

    def handle(self, *args, **options):
        target = Path(options["dir"])
        target.mkdir(parents=True, exist_ok=True)
        files = export_all()
        for name, text in files.items():
            (target / name).write_text(text, encoding="utf-8", newline="\n")
        self.stdout.write(self.style.SUCCESS(f"Wrote {len(files)} file{'s' if len(files) != 1 else ''} to {target}"))
