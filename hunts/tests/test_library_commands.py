import tempfile
from io import StringIO
from pathlib import Path

import yaml
from django.core.management import CommandError, call_command
from django.test import TestCase

from ..library_io import SCHEMA
from ..models import LibraryTask, Technique


def doc(**fields):
    data = {"schema": SCHEMA, "id": "a-task", "title": "A task", **fields}
    return yaml.safe_dump({k: v for k, v in data.items() if v is not None}, sort_keys=False)


class LibraryCommandTests(TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        Technique.objects.create(attack_id="T1003", name="Dumping")

    def write(self, rel, text):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def run_command(self, name, *args):
        out = StringIO()
        call_command(name, *args, stdout=out)
        return out.getvalue()

    def test_export_writes_one_file_per_team_built_task_and_creates_the_directory(self):
        LibraryTask.objects.create(title="Alpha")
        LibraryTask.objects.create(title="Ref", seed_key="ref", provenance="curated")
        target = self.root / "new" / "library"
        output = self.run_command("export_library", "--dir", str(target))
        self.assertEqual([p.name for p in target.iterdir()], ["alpha.yml"])
        self.assertIn("1 file", output)

    def test_export_never_deletes_existing_files(self):
        stray = self.write("old.yml", "x: 1\n")
        LibraryTask.objects.create(title="Alpha")
        self.run_command("export_library", "--dir", str(self.root))
        self.assertTrue(stray.exists())

    def test_import_dry_run_prints_the_plan_and_writes_nothing(self):
        LibraryTask.objects.create(title="Existing", query="old")
        self.write("a.yml", doc(id="existing", title="Existing", query="new"))
        self.write("b.yml", doc(id="brand-new", title="Brand new"))
        before = LibraryTask.objects.count()
        output = self.run_command("import_library", "--dir", str(self.root), "--dry-run")
        self.assertIn("1 created, 1 updated, 0 unchanged", output)
        self.assertIn("query", output)
        self.assertIn("dry run", output)
        self.assertEqual(LibraryTask.objects.count(), before)
        self.assertEqual(LibraryTask.objects.get(key="existing").query, "old")

    def test_import_applies_and_reports_counts(self):
        self.write("a.yml", doc(techniques=["T1003", "T9999"]))
        output = self.run_command("import_library", "--dir", str(self.root))
        self.assertIn("1 created, 0 updated, 0 unchanged", output)
        self.assertIn("T9999", output)  # the warning is shown
        self.assertEqual(LibraryTask.objects.get(key="a-task").techniques.count(), 1)

    def test_import_with_errors_raises_commanderror_and_writes_nothing(self):
        self.write("a.yml", doc(id=None))
        self.write("b.yml", "- not a mapping\n")
        self.write("c.yml", doc(id="fine"))
        with self.assertRaises(CommandError) as raised:
            self.run_command("import_library", "--dir", str(self.root))
        self.assertIn("a.yml", str(raised.exception))
        self.assertIn("b.yml", str(raised.exception))
        self.assertEqual(LibraryTask.objects.count(), 0)

    def test_import_empty_directory_raises_commanderror(self):
        with self.assertRaises(CommandError) as raised:
            self.run_command("import_library", "--dir", str(self.root))
        self.assertIn("No YAML files", str(raised.exception))

    def test_import_missing_directory_raises_commanderror(self):
        with self.assertRaises(CommandError):
            self.run_command("import_library", "--dir", str(self.root / "nope"))

    def test_import_dir_ignores_dot_directories(self):
        self.write(".github/workflows/ci.yml", "name: ci\non: push\n")
        self.write(".gitlab-ci.yml", "stages: [test]\n")
        self.write("lib/a.yml", doc())
        output = self.run_command("import_library", "--dir", str(self.root))
        self.assertIn("1 created", output)

    def test_import_single_file(self):
        path = self.write("anywhere.yml", doc())
        self.run_command("import_library", "--file", str(path))
        self.assertTrue(LibraryTask.objects.filter(key="a-task").exists())

    def test_import_needs_exactly_one_source(self):
        with self.assertRaises(CommandError):
            self.run_command("import_library")

    def test_export_then_import_into_an_empty_database_recreates_the_library(self):
        for title in ("Alpha", "Beta"):
            task = LibraryTask.objects.create(title=title, query=f"{title}\nsecond line\n")
            task.techniques.set(Technique.objects.all())
        self.run_command("export_library", "--dir", str(self.root))
        before = {t.key: (t.title, t.query, sorted(t.techniques.values_list("attack_id", flat=True)))
                  for t in LibraryTask.objects.all()}
        LibraryTask.objects.all().delete()
        self.run_command("import_library", "--dir", str(self.root))
        after = {t.key: (t.title, t.query, sorted(t.techniques.values_list("attack_id", flat=True)))
                 for t in LibraryTask.objects.all()}
        self.assertEqual(after, before)
