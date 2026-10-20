"""Import threat-intel-hunt-framework runs from a ./threat-hunting directory.

Idempotent: re-running updates the IntelReport for each slug (see save_intel for
what is replaced vs. preserved). Works air-gapped - only local files are read.
"""
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from hunts.intel_import import IntelImportError, parse_files, preview, save_intel

LAYOUT = (("intel-reports", "report"), ("intel-analysis", "analysis"), ("hunt-plans", "hunt-plan"))


class Command(BaseCommand):
    help = "Import intel-analysis / intel-report / hunt-plan Markdown from a threat-hunting directory."

    def add_arguments(self, parser):
        parser.add_argument("--dir", required=True, help="The framework's threat-hunting directory")
        parser.add_argument("--slug", help="Import one run; default is every run with a report")
        parser.add_argument("--dry-run", action="store_true", help="Parse and report, write nothing")

    def handle(self, *args, **options):
        root = Path(options["dir"])
        reports = root / "intel-reports"
        slugs = [options["slug"]] if options["slug"] else sorted(
            p.name[: -len("-report.md")] for p in reports.glob("*-report.md")
        )
        if not slugs:
            raise CommandError(f"No *-report.md files under {reports}")
        for slug in slugs:
            paths = [root / folder / f"{slug}-{suffix}.md" for folder, suffix in LAYOUT]
            named = {p.name: p.read_text(encoding="utf-8-sig") for p in paths if p.exists()}
            try:
                parsed = parse_files(named) if named else None
                if parsed is None:
                    raise IntelImportError(f"{slug}-report.md not found under {reports}")
            except IntelImportError as exc:
                raise CommandError(str(exc))
            summary = preview(parsed)
            action = "updated" if summary["report"] else "created"
            if options["dry_run"]:
                action = f"dry run ({'update' if summary['report'] else 'create'})"
            else:
                save_intel(parsed, files=[(name, text.encode("utf-8")) for name, text in named.items()])
            self.stdout.write(self.style.SUCCESS(
                f"{slug}: {action} - {summary['techniques']} techniques, {summary['indicators']} indicators, "
                f"{summary['cves']} CVEs, {summary['seeds']} seeds, {summary['stories']} stories"
            ))
            if summary["unresolved"]:
                self.stdout.write(self.style.WARNING(f"  unresolved techniques: {', '.join(summary['unresolved'])}"))
            for warning in summary["warnings"]:
                self.stdout.write(self.style.WARNING(f"  {warning}"))
