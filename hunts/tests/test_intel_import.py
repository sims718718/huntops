import re
from pathlib import Path

from django.test import SimpleTestCase

from ..intel_import import IntelImportError, normalize, parse, parse_files, parse_tables, split_sections, split_technique_ids

FIXTURES = Path(__file__).parent / "fixtures" / "intel"


class PrimitiveTests(SimpleTestCase):
    def test_normalize_ignores_case_punctuation_and_trailing_parenthetical(self):
        self.assertEqual(normalize("Indicators of Compromise (IOCs)"), "indicators of compromise")
        self.assertEqual(normalize("ATT&CK / TTP Mapping"), "att ck ttp mapping")
        self.assertEqual(normalize("  Appendix: Full Source List "), "appendix full source list")

    def test_split_sections_nests_h3_inside_h2_and_skips_code_fences(self):
        text = (
            "# Title\n"
            "## Recommended Actions\nintro\n"
            "### Hunt\n1. seed\n"
            "### Detect\nrule\n"
            "```\n## not a heading\n```\n"
            "## Next\nbody\n"
        )
        sections = split_sections(text)
        self.assertIn("### Hunt", sections["recommended actions"])
        self.assertEqual(sections["hunt"], "1. seed")
        self.assertIn("## not a heading", sections["detect"])
        self.assertNotIn("not a heading", sections)
        self.assertEqual(sections["next"], "body")

    def test_split_sections_keeps_first_duplicate(self):
        self.assertEqual(split_sections("## A\none\n## A\ntwo\n")["a"], "one")

    def test_parse_tables_reads_every_table_by_header_name(self):
        body = (
            "| Value | Type |\n|---|---|\n| evil.com | Domain |\n\ntext\n\n"
            "| Type | Value | Extra |\n|:--|--:|---|\n| IP | 1.2.3.4 | x |\n| Hash |\n"
        )
        rows = parse_tables(body)
        self.assertEqual([r["value"] for r in rows], ["evil.com", "1.2.3.4", ""])
        self.assertEqual(rows[0]["type"], "Domain")
        self.assertEqual(rows[2]["type"], "Hash")

    def test_split_technique_ids(self):
        self.assertEqual(split_technique_ids("T1566.001 / T1566.002"), ["T1566.001", "T1566.002"])
        self.assertEqual(split_technique_ids("T1203, T1059"), ["T1203", "T1059"])
        self.assertEqual(split_technique_ids("none"), [])


SLUGS = ["apt29-past-year", "communication-channel-identity-risks", "russian-webmail-espionage"]


def read(kind, slug, suffix):
    return (FIXTURES / kind / f"{slug}-{suffix}.md").read_text(encoding="utf-8")


def table_rows(text, heading):
    """Data rows of every pipe table under the '## <heading>' section.

    Deliberately independent of the parser: plain line scanning, so a parser bug
    can't make the expected and actual counts agree.
    """
    rows, inside, lines = [], False, text.splitlines()
    is_separator = lambda s: bool(s.strip()) and set(s.strip()) <= set("|-: ")
    for i, line in enumerate(lines):
        if line.startswith("## "):
            inside = line[3:].strip().lower().startswith(heading.lower())
            continue
        header = i + 1 < len(lines) and is_separator(lines[i + 1])
        if inside and line.startswith("|") and not is_separator(line) and not header:
            rows.append(line)
    return rows


def parse_run(slug):
    return parse(
        slug,
        read("intel-reports", slug, "report"),
        read("intel-analysis", slug, "analysis"),
        read("hunt-plans", slug, "hunt-plan"),
    )


class FixtureParseTests(SimpleTestCase):
    def test_row_counts_match_source_tables(self):
        for slug in SLUGS:
            with self.subTest(slug=slug):
                analysis = read("intel-analysis", slug, "analysis")
                parsed = parse_run(slug)
                ttp_rows = table_rows(analysis, "ATT&CK / TTP Mapping")
                expected_ids = sum(len(re.findall(r"T\d{4}(?:\.\d{3})?", r.split("|")[1])) for r in ttp_rows)
                self.assertEqual(len(parsed.techniques), expected_ids)
                self.assertEqual(len(parsed.indicators), len(table_rows(analysis, "Indicators of Compromise")))
                self.assertEqual(len(parsed.cves), len(table_rows(analysis, "Related CVEs")))
                self.assertEqual(len(parsed.seeds), 3)

    def test_no_unmapped_sections_in_real_runs(self):
        for slug in SLUGS:
            with self.subTest(slug=slug):
                parsed = parse_run(slug)
                self.assertEqual([w for w in parsed.warnings if "unmapped section" in w], [])
                # Real fixture runs produce zero warnings overall
                self.assertEqual(parsed.warnings, [])

    def test_title_sections_and_source_url(self):
        parsed = parse_run("apt29-past-year")
        self.assertTrue(parsed.title.startswith("APT29 / Midnight Blizzard Activity"))
        self.assertTrue(parsed.sections["executive_summary"])
        self.assertTrue(parsed.sections["recommended_detect"])
        self.assertTrue(parsed.first_source_url.startswith("https://"))

    def test_combined_technique_cell_splits(self):
        ids = [t.raw_id for t in parse_run("russian-webmail-espionage").techniques]
        self.assertIn("T1566.001", ids)
        self.assertIn("T1566.002", ids)

    def test_visibility_note_merged_from_report_table(self):
        technique = next(t for t in parse_run("apt29-past-year").techniques if t.raw_id == "T1189")
        self.assertTrue(technique.visibility_note.startswith("Unknown"))
        self.assertTrue(technique.evidence)

    def test_indicator_confidence_labels(self):
        confidences = {i.confidence for i in parse_run("apt29-past-year").indicators}
        self.assertTrue(confidences <= {"confirmed", "reported", "inferred", ""})
        self.assertIn("reported", confidences)

    def test_hunt_plan_hypothesis_both_dialects(self):
        for slug in SLUGS:
            with self.subTest(slug=slug):
                self.assertTrue(parse_run(slug).hunt_plan_hypothesis.startswith("We hypothesize"))

    def test_tlp_falls_back_to_plan_and_gate_blank_for_pre_gate_runs(self):
        parsed = parse_run("apt29-past-year")
        self.assertEqual(parsed.tlp, "clear")  # only the hunt plan carries a marking
        self.assertEqual(parsed.gate_status, "")
        self.assertEqual(parse("t", "# Actionable Intel Report: t\n").tlp, "")


class SyntheticParseTests(SimpleTestCase):
    REPORT = (
        "# Actionable Intel Report: Test\n"
        "## Executive Summary\nsummary\n"
        "## Recommended Actions\n### Hunt\n1. First seed\n   continues here\n2. Second seed\n"
        "## Brand New Section\nx\n"
    )

    def test_continuation_lines_join_seed_and_unknown_section_warns(self):
        parsed = parse("t", self.REPORT)
        self.assertEqual(parsed.seeds, ["First seed continues here", "Second seed"])
        self.assertIn("report: unmapped section 'Brand New Section'", parsed.warnings)

    def test_heading_and_column_drift(self):
        analysis = (
            "## indicators of compromise\n"
            "| Source | Confidence | Value | Type | Added |\n|---|---|---|---|---|\n"
            "| CISA | **Confirmed** | evil[.]com | Domain | y |\n"
            "| CISA | maybe | 1.2.3.4 | IP | y |\n"
            "| CISA | Reported |  | IP | y |\n"
            "## Quality Gate\nStatus: LIMITED\n"
        )
        parsed = parse("t", self.REPORT, analysis)
        self.assertEqual([(i.value, i.confidence) for i in parsed.indicators], [("evil[.]com", "confirmed"), ("1.2.3.4", "")])
        self.assertTrue(any("maybe" in w for w in parsed.warnings))
        self.assertTrue(any("without a value" in w for w in parsed.warnings))
        self.assertEqual(parsed.gate_status, "limited")

    def test_report_tables_used_when_no_analysis(self):
        report = self.REPORT + (
            "## MITRE ATT&CK Coverage\n| Technique ID | Technique Name | Tactic | Do we have visibility? |\n"
            "|---|---|---|---|\n| T1059 | Cmd | Execution | Yes |\n"
        )
        parsed = parse("t", report)
        self.assertEqual([(t.raw_id, t.visibility_note) for t in parsed.techniques], [("T1059", "Yes")])

    def test_missing_report_is_the_only_hard_error(self):
        with self.assertRaises(IntelImportError):
            parse("t", "  ")

    def test_parse_files_classifies_by_suffix_and_requires_one_slug(self):
        parsed = parse_files({"x-report.md": self.REPORT, "x-hunt-plan.md": "### Hypothesis\nWe hypothesize y"})
        self.assertEqual((parsed.slug, parsed.hunt_plan_hypothesis), ("x", "We hypothesize y"))
        with self.assertRaises(IntelImportError):
            parse_files({"x-report.md": self.REPORT, "y-analysis.md": ""})
        with self.assertRaises(IntelImportError):
            parse_files({"x-analysis.md": ""})
        with self.assertRaises(IntelImportError):
            parse_files({"x-report.html": ""})

    def test_parse_files_rejects_bad_slugs(self):
        for slug in ("a" * 101, "has space"):
            with self.subTest(slug=slug), self.assertRaises(IntelImportError):
                parse_files({f"{slug}-report.md": self.REPORT})

    def test_no_hunt_seeds_warns(self):
        report = "# Actionable Intel Report: Test\n## Executive Summary\nsummary\n"
        parsed = parse("t", report)
        self.assertIn("report: no hunt seeds found under '### Hunt'", parsed.warnings)

    def test_empty_table_sections_warn(self):
        report = "# Actionable Intel Report: Test\n## Executive Summary\nsummary\n"
        analysis = (
            "## ATT&CK / TTP Mapping\n"
            "| Technique ID | Evidence |\n|---|---|\n\n"
            "## Indicators of Compromise\n"
            "| Type | Value |\n|---|---|\n\n"
            "## Related CVEs Advisories\n"
            "| CVE Advisory | Summary |\n|---|---|\n\n"
        )
        parsed = parse("t", report, analysis)
        self.assertIn("analysis: section 'att ck ttp mapping' has no table rows", parsed.warnings)
        self.assertIn("analysis: section 'indicators of compromise' has no table rows", parsed.warnings)
        self.assertIn("analysis: section 'related cves advisories' has no table rows", parsed.warnings)

    def test_empty_report_technique_table_warns(self):
        report = (
            "# Actionable Intel Report: Test\n"
            "## Executive Summary\nsummary\n"
            "## MITRE ATT&CK Coverage\n"
            "| Technique ID | Technique Name |\n|---|---|\n\n"
        )
        parsed = parse("t", report)
        self.assertIn("report: section 'mitre att ck coverage' has no table rows", parsed.warnings)

    def test_empty_report_ioc_table_warns_when_used(self):
        report = (
            "# Actionable Intel Report: Test\n"
            "## Executive Summary\nsummary\n"
            "## Indicators of Compromise\n"
            "| Type | Value |\n|---|---|\n\n"
        )
        parsed = parse("t", report)
        self.assertIn("report: section 'indicators of compromise' has no table rows", parsed.warnings)

    def test_no_hypothesis_in_plan_warns(self):
        report = "# Actionable Intel Report: Test\n## Executive Summary\nsummary\n"
        plan = "## Some Section\nNo hypothesis here\n"
        parsed = parse("t", report, "", plan)
        self.assertIn("hunt-plan: no hypothesis found", parsed.warnings)

    def test_crlf_hunt_plan_hypothesis_normalizes(self):
        report = "# Actionable Intel Report: Test\n## Executive Summary\nsummary\n"
        # Simulate CRLF line endings in the hunt plan
        plan = "### Hypothesis\r\nWe hypothesize the attacker used lateral movement\r\n"
        parsed = parse("t", report, "", plan)
        self.assertEqual(parsed.hunt_plan_hypothesis, "We hypothesize the attacker used lateral movement")
        # Should not warn about missing hypothesis
        self.assertFalse(any("no hypothesis found" in w for w in parsed.warnings))


STORY_FIELDS = ("title", "objective", "hypothesis_component", "methodology", "expected_malicious", "expected_benign")


class StoryParseTests(SimpleTestCase):
    def test_data_source_names_from_story_table(self):
        for slug in SLUGS:
            for story in parse_run(slug).stories:
                with self.subTest(slug=slug, story=story.title):
                    self.assertTrue(story.data_sources)
        self.assertEqual(parse_run("apt29-past-year").stories[0].data_sources,
                         ["Entra ID Sign-in Logs", "Entra ID Audit Logs", "M365 Unified Audit Log"])

    def test_primary_query_from_detection_logic(self):
        for slug in SLUGS:
            for story in parse_run(slug).stories:
                with self.subTest(slug=slug, story=story.title):
                    self.assertTrue(story.query.strip())
                    self.assertNotIn("```", story.query)
                    self.assertFalse(story.query.lstrip().startswith("title:"))  # not the Sigma YAML
        self.assertTrue(parse_run("apt29-past-year").stories[0].query.startswith("SigninLogs"))

    def test_fixture_stories_in_both_dialects(self):
        for slug in SLUGS:
            with self.subTest(slug=slug):
                parsed = parse_run(slug)
                self.assertEqual(len(parsed.stories), 3)
                for story in parsed.stories:
                    for name in STORY_FIELDS:
                        self.assertTrue(getattr(story, name).strip(), f"{story.title!r} has empty {name}")
                self.assertEqual(parsed.warnings, [])

    def test_titles_drop_the_jira_id(self):
        self.assertEqual(parse_run("apt29-past-year").stories[0].title, "Device-Code / ASP Authentication Anomaly Hunt")

    def test_jira_dialect_sections_are_clean(self):
        story = parse_run("apt29-past-year").stories[0]
        self.assertNotIn("-----", story.objective)
        self.assertNotIn("OBJECTIVE", story.objective)
        self.assertIn("Device-code sign-in", story.expected_malicious)
        self.assertNotIn("previously-seen", story.expected_malicious)
        self.assertIn("previously-seen", story.expected_benign)

    def test_markdown_dialect_outcomes_split(self):
        story = parse_run("communication-channel-identity-risks").stories[0]
        self.assertIn("Escalate to IR", story.expected_malicious)
        self.assertIn("negative finding", story.expected_benign)

    def test_story_warnings(self):
        plan = (
            "### Hypothesis\nWe hypothesize x\n"
            "## Story: [X-S1] One\n### Objective\nobj\n### Expected Outcomes\nsome text\n"
            "## Story: Two\nnothing here\n"
        )
        parsed = parse("t", SyntheticParseTests.REPORT, "", plan)
        self.assertEqual([s.title for s in parsed.stories], ["One", "Two"])
        self.assertEqual(parsed.stories[0].expected_malicious, "some text")
        self.assertIn("hunt-plan: story 'One' expected outcomes have no malicious/benign markers", parsed.warnings)
        self.assertIn("hunt-plan: story 'Two' has no recognizable sections", parsed.warnings)

    def test_plan_without_stories_warns(self):
        parsed = parse("t", SyntheticParseTests.REPORT, "", "### Hypothesis\nWe hypothesize x\n")
        self.assertEqual(parsed.stories, [])
        self.assertIn("hunt-plan: no '## Story:' sections found", parsed.warnings)

    def test_no_plan_no_story_warning(self):
        self.assertNotIn("hunt-plan: no '## Story:' sections found", parse("t", SyntheticParseTests.REPORT).warnings)

    def test_jira_inner_code_blocks_preserved(self):
        # Regression: _story_sections must preserve inner ``` in non-last sections
        # while stripping only the Story's outer closing fence.
        plan = (
            "### Hypothesis\nWe hypothesize x\n"
            "## Story: Test\n"
            "```\n"
            "---\n"
            "OBJECTIVE\n"
            "---\n"
            "Initial scan\n"
            "---\n"
            "METHODOLOGY\n"
            "---\n"
            "Run:\n"
            "```spl\n"
            "index=x\n"
            "```\n"
            "---\n"
            "EXPECTED OUTCOMES\n"
            "---\n"
            "If malicious activity present\n"
            "Found malware\n"
            "If hypothesis invalid\n"
            "No findings\n"
            "---\n"
            "ACCEPTANCE CRITERIA\n"
            "---\n"
            "All systems scanned\n"
            "```\n"
        )
        # Use a minimal report without unmapped sections to avoid warnings from the report parsing
        report = (
            "# Actionable Intel Report: Test\n"
            "## Executive Summary\nsummary\n"
            "## Recommended Actions\n### Hunt\n1. Seed\n"
        )
        parsed = parse("t", report, "", plan)
        self.assertEqual(len(parsed.stories), 1)
        story = parsed.stories[0]
        # Methodology should preserve its inner closing fence
        self.assertTrue(story.methodology.endswith("```"), f"methodology lost inner fence: {story.methodology!r}")
        # No field should end with dangling outer fence
        for field_name in ("objective", "hypothesis_component", "methodology", "expected_malicious", "expected_benign"):
            field_value = getattr(story, field_name)
            if field_value:
                # Check for unbalanced outer fence (shouldn't end with lone ```)
                self.assertFalse(field_value.endswith("```") and not field_value.count("```spl"),
                               f"{field_name} has dangling outer fence: {field_value!r}")
        self.assertEqual(parsed.warnings, [])
