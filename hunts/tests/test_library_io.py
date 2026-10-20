import uuid

import yaml
from django.test import SimpleTestCase, TestCase

from ..library_io import SCHEMA, Entry, dump_task, parse_documents
from ..models import LibraryTask, SigmaRule, Technique


def doc(**fields):
    """A minimal valid file as text; pass None to drop a field, anything else to set it."""
    data = {"schema": SCHEMA, "id": "a-task", "title": "A task", **fields}
    return yaml.safe_dump({k: v for k, v in data.items() if v is not None}, sort_keys=False)


class DumpTests(TestCase):
    def setUp(self):
        for attack_id in ("T1543.003", "T1569.002"):
            Technique.objects.create(attack_id=attack_id, name=attack_id)
        self.rule = SigmaRule.objects.create(rule_id=uuid.uuid4(), title="Rule", raw_yaml="x")

    def _task(self, **fields):
        task = LibraryTask.objects.create(title=fields.pop("title", "Rare service installs"), **fields)
        task.suppress_auto_sigma = True
        task.techniques.set(Technique.objects.filter(attack_id__in=["T1569.002", "T1543.003"]))
        task.sigma_rules.add(self.rule)
        return task

    def test_dump_matches_the_spec_example(self):
        task = self._task(hunting_tool="Splunk", query="index=x\n| stats count\n")
        lines = dump_task(task).splitlines()
        self.assertEqual(lines[0], f"schema: {SCHEMA}")
        self.assertEqual(lines[1], f"id: {task.key}")
        self.assertIn("query: |", lines)

    def test_dump_is_deterministic_and_sorted(self):
        task = self._task()
        self.assertEqual(dump_task(task), dump_task(task))
        self.assertIn("techniques:\n- T1543.003\n- T1569.002", dump_task(task))

    def test_dump_omits_empty_optional_fields(self):
        text = dump_task(LibraryTask.objects.create(title="Bare"))
        self.assertEqual(yaml.safe_load(text), {"schema": SCHEMA, "id": "bare", "title": "Bare"})

    def test_reference_entries_cannot_be_dumped(self):
        entry = LibraryTask.objects.create(title="Ref", seed_key="ref", provenance="curated")
        with self.assertRaises(ValueError):
            dump_task(entry)

    def test_dump_then_parse_round_trips(self):
        queries = ["a: b\n# not a comment to yaml\n  indented\n", "line1\nline2", " lead: x #y"]
        for query in queries:
            with self.subTest(query=query):
                task = self._task(
                    title=f"Round trip: {query[:5]!r}", query=query, notes="n", hunting_tool="Splunk",
                    expected_positive="p\nq", expected_benign="b",
                )
                entries, errors = parse_documents({"f.yml": dump_task(task)})
                self.assertEqual(errors, [])
                self.assertEqual(entries, [Entry(
                    source="f.yml", id=task.key, title=task.title, hunting_tool="Splunk",
                    techniques=("T1543.003", "T1569.002"), data_sources=(),
                    sigma_rules=(str(self.rule.rule_id),), query=query,
                    expected_positive="p\nq", expected_benign="b", notes="n",
                )])


class ParseTests(SimpleTestCase):
    def one(self, text, name="f.yml"):
        return parse_documents({name: text})

    def assertRejected(self, text, *needles, name="f.yml"):
        entries, errors = self.one(text, name)
        self.assertEqual(entries, [], errors)
        self.assertTrue(errors)
        for message in errors:
            self.assertTrue(message.startswith(f"{name}: "), message)
        for needle in needles:
            self.assertIn(needle, " ".join(errors))

    def test_omitted_optional_fields_default_to_empty(self):
        entries, errors = self.one(doc())
        self.assertEqual(errors, [])
        self.assertEqual(entries, [Entry(source="f.yml", id="a-task", title="A task")])

    def test_empty_optional_value_is_treated_as_empty(self):
        entries, errors = self.one("schema: %s\nid: a\ntitle: T\nnotes:\ntechniques:\n" % SCHEMA)
        self.assertEqual((errors, entries[0].notes, entries[0].techniques), ([], "", ()))

    def test_invalid_yaml(self):
        self.assertRejected("schema: [unclosed")

    def test_top_level_is_a_list(self):
        self.assertRejected("- a\n- b\n")

    def test_schema_missing(self):
        self.assertRejected(doc(schema=None), "schema")

    def test_schema_unsupported(self):
        self.assertRejected(doc(schema="huntops/library-task/v2"), "schema")

    def test_id_missing(self):
        self.assertRejected(doc(id=None), "id")

    def test_title_missing(self):
        self.assertRejected(doc(title=None), "title")

    def test_id_malformed(self):
        self.assertRejected(doc(id="Bad Id"), "id")

    def test_id_too_long(self):
        self.assertRejected(doc(id="a" * 101), "id")

    def test_id_must_be_a_string(self):
        self.assertRejected(doc(id=1), "id")

    def test_title_must_be_a_string(self):
        self.assertRejected(doc(title=123), "title")

    def test_title_over_300_characters(self):
        self.assertRejected(doc(title="t" * 301), "title")

    def test_hunting_tool_over_100_characters(self):
        self.assertRejected(doc(hunting_tool="t" * 101), "hunting_tool")

    def test_techniques_must_be_a_list(self):
        self.assertRejected(doc(techniques="T1003"), "techniques")

    def test_list_elements_must_be_strings(self):
        self.assertRejected(doc(data_sources=[None]), "data_sources")

    def test_scalar_fields_must_be_strings(self):
        self.assertRejected(doc(hunting_tool=True), "hunting_tool")

    def test_data_source_name_over_200_characters(self):
        self.assertRejected(doc(data_sources=["d" * 201]), "data_sources")

    def test_unknown_top_level_key(self):
        self.assertRejected(doc(colour="red"), "colour")

    def test_duplicate_id_across_files_names_both(self):
        entries, errors = parse_documents({"a.yml": doc(), "b.yml": doc()})
        self.assertEqual(len(errors), 1)
        self.assertIn("a.yml", errors[0])
        self.assertIn("b.yml", errors[0])

    def test_collects_every_error_not_just_the_first(self):
        entries, errors = parse_documents({"a.yml": doc(id=None), "b.yml": "- x", "c.yml": doc(id="ok")})
        self.assertEqual([e.id for e in entries], ["ok"])
        self.assertEqual(len(errors), 2)


import io
import tempfile
import zipfile
from pathlib import Path
from unittest import mock

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile

from ..library_io import apply_plan, build_plan, export_all, over_limit, read_directory, read_uploads
from ..models import DataSource


class PlanApplyTests(TestCase):
    def setUp(self):
        self.t1 = Technique.objects.create(attack_id="T1003", name="Dumping")
        self.t2 = Technique.objects.create(attack_id="T1059", name="Scripting")
        self.rules = [
            SigmaRule.objects.create(rule_id=uuid.uuid4(), title=f"R{n}", status="stable", raw_yaml="x")
            for n in range(3)
        ]
        for rule in self.rules:
            rule.techniques.add(self.t1)

    def plan(self, **docs):
        return build_plan(dict(docs))

    def counts(self):
        return (LibraryTask.objects.count(), DataSource.objects.count())

    def test_new_id_is_created(self):
        plan = self.plan(**{"a.yml": doc(techniques=["T1003"])})
        self.assertTrue(plan.ok)
        self.assertEqual([(i.entry.id, i.action) for i in plan.items], [("a-task", "created")])

    def test_existing_key_with_same_content_is_unchanged(self):
        apply_plan(self.plan(**{"a.yml": doc(query="q")}))
        self.assertEqual(self.plan(**{"a.yml": doc(query="q")}).items[0].action, "unchanged")

    def test_existing_key_with_edited_query_is_updated_with_a_diff(self):
        apply_plan(self.plan(**{"a.yml": doc(query="old")}))
        item = self.plan(**{"a.yml": doc(query="new")}).items[0]
        self.assertEqual(item.action, "updated")
        self.assertEqual(item.changes["query"], ("old", "new"))

    def test_missing_technique_is_a_warning_and_stays_unchanged_on_reimport(self):
        text = doc(techniques=["T1003", "T9999"])
        first = self.plan(**{"a.yml": text})
        self.assertTrue(first.ok)
        self.assertIn("T9999", " ".join(first.items[0].warnings))
        apply_plan(first)
        self.assertEqual(self.plan(**{"a.yml": text}).items[0].action, "unchanged")

    def test_missing_or_malformed_sigma_rule_is_a_warning(self):
        plan = self.plan(**{"a.yml": doc(sigma_rules=[str(uuid.uuid4()), "not-a-uuid"])})
        self.assertTrue(plan.ok)
        self.assertEqual(len(plan.items[0].warnings), 2)

    def test_missing_data_source_is_created_team_defined_on_apply(self):
        apply_plan(self.plan(**{"a.yml": doc(data_sources=["Brand New Log"])}))
        self.assertEqual(DataSource.objects.get(name="Brand New Log").origin, DataSource.CUSTOM)

    def test_id_equal_to_a_seed_key_is_an_error(self):
        LibraryTask.objects.create(title="Ref", seed_key="a-task", provenance="curated")
        plan = self.plan(**{"a.yml": doc()})
        self.assertFalse(plan.ok)
        self.assertIn("reference", " ".join(plan.errors))

    def test_parse_errors_reach_the_plan(self):
        plan = self.plan(**{"a.yml": doc(id=None)})
        self.assertFalse(plan.ok)
        self.assertTrue(plan.errors[0].startswith("a.yml: "))

    def test_build_plan_writes_nothing(self):
        before = self.counts()
        self.plan(**{"a.yml": doc(data_sources=["Brand New Log"], techniques=["T1003"])})
        self.assertEqual(self.counts(), before)

    def test_apply_overwrites_and_clears_omitted_fields(self):
        apply_plan(self.plan(**{"a.yml": doc(notes="old", techniques=["T1003", "T1059"])}))
        apply_plan(self.plan(**{"a.yml": doc(techniques=["T1003"])}))
        task = LibraryTask.objects.get(key="a-task")
        self.assertEqual(task.notes, "")
        self.assertEqual(set(task.techniques.values_list("attack_id", flat=True)), {"T1003"})

    def test_apply_respects_sigma_rules_exactly(self):
        chosen = str(self.rules[0].rule_id)
        apply_plan(self.plan(**{"a.yml": doc(techniques=["T1003"], sigma_rules=[chosen])}))
        task = LibraryTask.objects.get(key="a-task")
        self.assertEqual([str(r) for r in task.sigma_rules.values_list("rule_id", flat=True)], [chosen])

    def test_apply_sets_provenance_user_and_created_by(self):
        user = get_user_model().objects.create_user("importer")
        apply_plan(self.plan(**{"a.yml": doc()}), user=user)
        task = LibraryTask.objects.get(key="a-task")
        self.assertEqual((task.provenance, task.created_by), ("user", user))

    def test_apply_with_errors_raises_and_writes_nothing(self):
        plan = self.plan(**{"a.yml": doc(id=None)})
        before = self.counts()
        with self.assertRaises(ValueError):
            apply_plan(plan)
        self.assertEqual(self.counts(), before)

    def test_apply_is_atomic(self):
        plan = self.plan(**{"a.yml": doc(id="one"), "b.yml": doc(id="two")})
        real, calls = LibraryTask.save, []

        def flaky(task, *args, **kwargs):
            calls.append(1)
            if len(calls) == 2:
                raise RuntimeError("boom")
            return real(task, *args, **kwargs)

        with mock.patch.object(LibraryTask, "save", flaky), self.assertRaises(RuntimeError):
            apply_plan(plan)
        self.assertEqual(LibraryTask.objects.count(), 0)

    def _library(self):
        for n, title in enumerate(["Alpha", "Beta", "Gamma: with colon"]):
            task = LibraryTask.objects.create(title=title, query=f"line {n}\nline two\n", notes="n")
            task.suppress_auto_sigma = True
            task.techniques.set([self.t1, self.t2][: n % 2 + 1])
            task.sigma_rules.add(self.rules[n])
            task.data_sources.set([DataSource.objects.get_or_create(name=f"Log {n}")[0]])

    def test_export_then_build_plan_is_all_unchanged(self):
        self._library()
        plan = build_plan(export_all())
        self.assertTrue(plan.ok, plan.errors)
        self.assertEqual([i.action for i in plan.items], ["unchanged"] * 3)

    def test_export_excludes_reference_entries(self):
        self._library()
        LibraryTask.objects.create(title="Ref", seed_key="ref", provenance="curated")
        self.assertEqual(sorted(export_all()), ["alpha.yml", "beta.yml", "gamma-with-colon.yml"])

    def test_two_exports_are_byte_identical(self):
        self._library()
        self.assertEqual(export_all(), export_all())


def upload(name, content):
    return SimpleUploadedFile(name, content if isinstance(content, bytes) else content.encode())


def zip_of(members):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in members.items():
            archive.writestr(name, content)
    return buffer.getvalue()


class ReaderTests(SimpleTestCase):
    def test_read_directory_skips_dot_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel in (".github/workflows/ci.yml", ".gitlab-ci.yml", "lib/a.yml", "b.yaml", "notes.txt"):
                path = root / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("x: 1\n", encoding="utf-8")
            named, errors = read_directory(root)
        self.assertEqual((sorted(named), errors), (["b.yaml", "lib/a.yml"], []))

    def test_read_directory_with_no_yaml_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            named, errors = read_directory(tmp)
        self.assertEqual(named, {})
        self.assertIn("No YAML files", errors[0])

    def test_read_directory_reports_non_utf8(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "bad.yml").write_bytes(b"\xff\xfe\x00bad")
            named, errors = read_directory(tmp)
        self.assertIn("bad.yml", errors[0])

    def test_read_uploads_unpacks_a_zip_and_ignores_non_yaml_members(self):
        data = zip_of({"lib/a.yml": "a: 1", "README.md": "hi", ".github/ci.yml": "x: 1"})
        named, errors = read_uploads([upload("lib.zip", data)])
        self.assertEqual((list(named.values()), errors), (["a: 1"], []))

    def test_plain_yaml_uploads_are_read_and_other_names_rejected(self):
        named, errors = read_uploads([upload("a.yml", "a: 1"), upload("notes.txt", "x")])
        self.assertEqual(list(named.values()), ["a: 1"])
        self.assertIn("notes.txt", errors[0])

    def test_zip_member_with_path_traversal_is_an_error(self):
        for evil in ("../evil.yml", "/etc/x.yml", "..\\x.yml"):
            with self.subTest(evil=evil):
                named, errors = read_uploads([upload("lib.zip", zip_of({evil: "a: 1"}))])
                self.assertEqual(named, {})
                self.assertIn("unsafe", errors[0])

    def test_corrupt_zip_is_an_error(self):
        named, errors = read_uploads([upload("lib.zip", b"not a zip")])
        self.assertIn("lib.zip", errors[0])

    def test_non_utf8_file_is_an_error(self):
        named, errors = read_uploads([upload("a.yml", b"\xff\xfe\x00bad")])
        self.assertIn("UTF-8", errors[0])

    def test_oversize_total_is_an_error(self):
        named, errors = read_uploads([upload("a.yml", "x" * 600)], max_bytes=500)
        self.assertIn("larger than", errors[0])
        data = zip_of({"a.yml": "x" * 600})
        self.assertIn("larger than", read_uploads([upload("a.zip", data)], max_bytes=500)[1][0])

    def test_oversized_zip_is_rejected_before_its_directory_is_parsed(self):
        data = zip_of({"a.yml": "x" * 1000})  # stored size is well over 2 * max_bytes
        with mock.patch("hunts.library_io.zipfile.ZipFile") as parse:
            named, errors = read_uploads([upload("a.zip", data)], max_bytes=100)
        parse.assert_not_called()
        self.assertIn("larger than", errors[0])

    def test_over_limit_checks_a_payload_the_way_uploads_are_checked(self):
        self.assertIsNone(over_limit({"a.yml": "x"}, max_bytes=10, max_files=2))
        self.assertIn("larger than", over_limit({"a.yml": "x" * 11}, max_bytes=10, max_files=2))
        self.assertIn("more than 2", over_limit({f"{n}.yml": "x" for n in range(3)}, max_bytes=10, max_files=2))
        self.assertIn("larger than", over_limit({"a.yml": "é" * 6}, max_bytes=10, max_files=2))  # bytes, not characters

    def test_too_many_files_is_an_error(self):
        files = [upload(f"{n}.yml", "a: 1") for n in range(3)]
        self.assertIn("more than 2", read_uploads(files, max_files=2)[1][0])

    def test_no_yaml_found_is_an_error(self):
        self.assertIn("No YAML files", read_uploads([])[1][0])
        self.assertIn("No YAML files", read_uploads([upload("e.zip", zip_of({"README.md": "x"}))])[1][0])
