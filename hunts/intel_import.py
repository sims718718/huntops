"""Import threat-intel-hunt-framework Markdown runs as IntelReport records.

The framework's output drifts between runs (see the intel intake spec), so the
parse half of this module never touches the database and is tested directly
against real runs in tests/fixtures/intel. Rule: structured where the format is
stable (tables, known headings), verbatim where it isn't. Anything unmapped
becomes a warning, never an exception - except a missing report, without which
there is nothing to import.
"""
import os
import re
from dataclasses import dataclass, field

from django.core.files.base import ContentFile
from django.db import transaction

from .models import Actor, Evidence, HuntSeed, Indicator, IntelCVE, IntelReport, IntelStory, IntelTechnique, Technique

HEADING = re.compile(r"^(#{1,3})\s+(.*?)\s*#*\s*$")
SEPARATOR_ROW = re.compile(r"^\|(\s*:?-+:?\s*\|)+\s*$")
TECHNIQUE_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


class IntelImportError(Exception):
    pass


def normalize(heading):
    heading = re.sub(r"\([^)]*\)\s*$", "", heading.strip())
    return re.sub(r"[^a-z0-9]+", " ", heading.lower()).strip()


def _headings(text):
    """(lines, [(level, title, line_index)]) for #/##/### headings outside code fences."""
    lines, found, fenced = text.splitlines(), [], False
    for index, line in enumerate(lines):
        if line.lstrip().startswith("```"):
            fenced = not fenced
            continue
        match = None if fenced else HEADING.match(line)
        if match:
            found.append((len(match.group(1)), match.group(2), index))
    return lines, found


def split_sections(text):
    """normalized heading -> body. A body runs to the next heading of the same or
    higher level, so a ## body includes its ### subsections."""
    lines, heads = _headings(text)
    sections = {}
    for n, (level, title, start) in enumerate(heads):
        end = next((i for lv, _, i in heads[n + 1:] if lv <= level), len(lines))
        sections.setdefault(normalize(title), "\n".join(lines[start + 1:end]).strip())
    return sections


def _cells(line):
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def parse_tables(body):
    """Rows of every pipe table in body, as {normalized header: cell}.

    Keyed by header name, never position, so a reordered or added column still
    parses. Short rows are padded with "".
    """
    rows, lines = [], body.splitlines()
    for index, line in enumerate(lines):
        if index and SEPARATOR_ROW.match(line.strip()) and lines[index - 1].strip().startswith("|"):
            headers = [normalize(h) for h in _cells(lines[index - 1])]
            for row in lines[index + 1:]:
                if not row.strip().startswith("|"):
                    break
                cells = _cells(row)
                rows.append(dict(zip(headers, cells + [""] * (len(headers) - len(cells)))))
    return rows


def split_technique_ids(cell):
    return TECHNIQUE_ID.findall(cell)


TEXT_FIELDS = (
    "executive_summary", "key_judgments", "actor_overview", "recommended_detect",
    "recommended_mitigate", "confidence_sourcing", "source_reputation", "open_questions",
)
REPORT_SECTIONS = {  # IntelReport field -> normalized report heading
    "executive_summary": "executive summary",
    "key_judgments": "key judgments",
    "actor_overview": "actor campaign overview",
    "confidence_sourcing": "confidence and sourcing",
    "recommended_detect": "detect",
    "recommended_mitigate": "mitigate",
}
ANALYSIS_SECTIONS = {
    "source_reputation": "source reputation notes",
    "open_questions": "open questions and gaps",
}
REPORT_KNOWN = {
    "executive summary", "key judgments", "actor campaign overview", "mitre att ck coverage",
    "indicators of compromise", "recommended actions", "confidence and sourcing",
    "appendix full source list",
}
# "source material" and "actor profile" are recognized but not stored as fields:
# they stay in the attached analysis file (Evidence) and shouldn't warn on every import.
ANALYSIS_KNOWN = {
    "source material", "actor profile", "att ck ttp mapping", "indicators of compromise",
    "related cves advisories", "source reputation notes", "open questions and gaps", "quality gate",
}
SUFFIXES = {"-report.md": "report", "-analysis.md": "analysis", "-hunt-plan.md": "plan"}
CONFIDENCE = re.compile(r"^\W*(confirmed|reported|inferred)\b", re.I)
TLP = re.compile(r"TLP:\s*(CLEAR|GREEN|AMBER\+STRICT|AMBER|RED)\b", re.I)
GATE = re.compile(r"\b(READY|LIMITED|INSUFFICIENT)\b")
URL = re.compile(r"https?://[^\s)>\]|]+")
LIST_ITEM = re.compile(r"^(\d+[.)]|[-*])\s+")
JIRA_HYPOTHESIS = re.compile(r"^HYPOTHESIS[ \t]*\n-{3,}[ \t]*\n(.*?)\n\s*-{3,}", re.S | re.M)
STORY_HEADING = re.compile(r"^Story:\s*(?:\[[^\]]*\]\s*)?(.+)$")
# The Jira dialect fences each Story and marks sections as a dashed rule, an UPPERCASE
# name, another dashed rule. Deliberately matched inside the fence.
JIRA_SECTION = re.compile(r"^-{3,}[ \t]*\n([A-Z][^\n]*)\n-{3,}[ \t]*$", re.M)
OUTCOME_MARKER = re.compile(r"^\W*if\s+(malicious activity present|hypothesis invalid)\W*$", re.I | re.M)
# normalized section-name prefix -> ParsedStory field ("expected" is split further)
STORY_SECTIONS = (
    ("objective", "objective"),
    ("hypothesis component", "hypothesis_component"),
    ("methodology", "methodology"),
    ("expected outcomes", "expected"),
    ("detection logic", "detection"),
    ("data sources", "data_sources"),
)
FENCE = re.compile(r"```(\w*)[ \t]*\n(.*?)\n[ \t]*```", re.S)


@dataclass
class ParsedTechnique:
    raw_id: str
    tactic: str = ""
    evidence: str = ""
    visibility_note: str = ""


@dataclass
class ParsedIndicator:
    ioc_type: str
    value: str
    confidence: str = ""
    source: str = ""


@dataclass
class ParsedCVE:
    identifier: str
    summary: str = ""
    relevance: str = ""


@dataclass
class ParsedStory:
    title: str
    objective: str = ""
    hypothesis_component: str = ""
    methodology: str = ""
    expected_malicious: str = ""
    expected_benign: str = ""
    query: str = ""
    data_sources: list = field(default_factory=list)  # the Story table's "Source" column


@dataclass
class ParsedIntel:
    slug: str
    title: str = ""
    tlp: str = ""
    gate_status: str = ""
    sections: dict = field(default_factory=dict)
    techniques: list = field(default_factory=list)
    indicators: list = field(default_factory=list)
    cves: list = field(default_factory=list)
    seeds: list = field(default_factory=list)
    hunt_plan_hypothesis: str = ""
    stories: list = field(default_factory=list)
    first_source_url: str = ""
    warnings: list = field(default_factory=list)


def _list_items(body):
    """Top-level numbered/bulleted items; indented lines continue the current item."""
    items = []
    for line in body.splitlines():
        if LIST_ITEM.match(line):
            items.append(LIST_ITEM.sub("", line).strip())
        elif items and line.strip() and line[:1] in (" ", "\t"):
            items[-1] += " " + line.strip()
    return items


def _unmapped(label, text, known):
    _, heads = _headings(text)
    return [f"{label}: unmapped section '{title}'" for level, title, _ in heads
            if level == 2 and normalize(title) not in known]


def _story_section(key, body, found):
    for prefix, name in STORY_SECTIONS:
        if key.startswith(prefix) and name not in found:
            found[name] = body.strip()
            return


def _story_sections(block):
    """Pass 1: the ### dialect. Pass 2, only if pass 1 found nothing: Jira markers."""
    found = {}
    for key, body in split_sections(block).items():
        _story_section(key, body, found)
    if not found:
        markers = list(JIRA_SECTION.finditer(block))
        for n, (marker, following) in enumerate(zip(markers, markers[1:] + [None])):
            body = block[marker.end(): following.start() if following else len(block)]
            body = body.strip()
            # Only strip trailing ``` from the LAST marker's body (which carries the Story's outer fence)
            is_last = n == len(markers) - 1
            if is_last and body.endswith("```"):
                body = body[:-3].rstrip()
            _story_section(normalize(marker.group(1)), body, found)
    return found


def _primary_query(text):
    """The Story's primary query: the first fenced block in Detection Logic that isn't
    the draft Sigma YAML (every framework plan puts the query first, then the Sigma)."""
    return next((body.strip() for lang, body in FENCE.findall(text) if lang.lower() not in ("yaml", "yml")), "")


def _split_outcomes(text):
    """(malicious, benign), or None when the framework's markers are absent."""
    parts = OUTCOME_MARKER.split(text)
    if len(parts) == 1:
        return None
    found = {}
    for marker, body in zip(parts[1::2], parts[2::2]):
        found["malicious" if marker.lower().startswith("malicious") else "benign"] = body.strip()
    return found.get("malicious", ""), found.get("benign", "")


def _parse_stories(plan_text, warnings):
    lines, heads = _headings(plan_text)
    level2 = [(title, index) for level, title, index in heads if level == 2]
    stories = []
    for n, (heading, start) in enumerate(level2):
        match = STORY_HEADING.match(heading)
        if not match:
            continue
        end = level2[n + 1][1] if n + 1 < len(level2) else len(lines)
        title = match.group(1).strip()[:300]
        found = _story_sections("\n".join(lines[start + 1:end]))
        if not found:
            warnings.append(f"hunt-plan: story '{title}' has no recognizable sections")
        story = ParsedStory(
            title=title,
            objective=found.get("objective", ""),
            hypothesis_component=found.get("hypothesis_component", ""),
            methodology=found.get("methodology", ""),
            query=_primary_query(found.get("detection", "")),
            data_sources=[row["source"] for row in parse_tables(found.get("data_sources", "")) if row.get("source")],
        )
        expected = found.get("expected", "")
        if expected:
            outcomes = _split_outcomes(expected)
            if outcomes is None:
                story.expected_malicious = expected
                warnings.append(f"hunt-plan: story '{title}' expected outcomes have no malicious/benign markers")
            else:
                story.expected_malicious, story.expected_benign = outcomes
        stories.append(story)
    if plan_text.strip() and not stories:
        warnings.append("hunt-plan: no '## Story:' sections found")
    return stories


def _plan_hypothesis(plan_text):
    section = split_sections(plan_text).get("hypothesis")
    if section:
        return section
    match = JIRA_HYPOTHESIS.search(plan_text)
    return match.group(1).strip() if match else ""


def parse(slug, report_text, analysis_text="", plan_text=""):
    # Normalize line endings for consistent parsing
    report_text = report_text.replace("\r\n", "\n")
    analysis_text = analysis_text.replace("\r\n", "\n")
    plan_text = plan_text.replace("\r\n", "\n")

    if not report_text.strip():
        raise IntelImportError(f"{slug}-report.md is missing or empty")
    parsed = ParsedIntel(slug=slug)
    report, analysis = split_sections(report_text), split_sections(analysis_text)

    title = re.search(r"^#\s+Actionable Intel Report:\s*(.+)$", report_text, re.M)
    parsed.title = (title.group(1).strip() if title else slug)[:300]
    parsed.sections = {name: report.get(key, "") for name, key in REPORT_SECTIONS.items()}
    parsed.sections.update({name: analysis.get(key, "") for name, key in ANALYSIS_SECTIONS.items()})
    parsed.seeds = _list_items(report.get("hunt", ""))
    if not parsed.seeds:
        parsed.warnings.append("report: no hunt seeds found under '### Hunt'")

    report_ttp = parse_tables(report.get("mitre att ck coverage", ""))
    visibility = {}
    for row in report_ttp:
        for raw_id in split_technique_ids(row.get("technique id", "")):
            visibility.setdefault(raw_id, row.get("do we have visibility", ""))

    analysis_ttp = parse_tables(analysis.get("att ck ttp mapping", ""))
    if analysis.get("att ck ttp mapping", "").strip() and not analysis_ttp:
        parsed.warnings.append("analysis: section 'att ck ttp mapping' has no table rows")
    ttp_rows = analysis_ttp or report_ttp
    if report.get("mitre att ck coverage", "").strip() and not report_ttp and not analysis_ttp:
        parsed.warnings.append("report: section 'mitre att ck coverage' has no table rows")

    for row in ttp_rows:
        ids = split_technique_ids(row.get("technique id", ""))
        if not ids:
            parsed.warnings.append(f"technique row without an ATT&CK ID: {row.get('technique id', '')[:80]!r}")
        for raw_id in ids:
            parsed.techniques.append(ParsedTechnique(
                raw_id=raw_id, tactic=row.get("tactic", ""), evidence=row.get("evidence", ""),
                visibility_note=visibility.get(raw_id, ""),
            ))

    analysis_ioc = parse_tables(analysis.get("indicators of compromise", ""))
    report_ioc = parse_tables(report.get("indicators of compromise", ""))
    if analysis.get("indicators of compromise", "").strip() and not analysis_ioc:
        parsed.warnings.append("analysis: section 'indicators of compromise' has no table rows")
    if report.get("indicators of compromise", "").strip() and not report_ioc and not analysis_ioc:
        parsed.warnings.append("report: section 'indicators of compromise' has no table rows")

    ioc_rows = analysis_ioc or report_ioc
    for row in ioc_rows:
        value = row.get("value", "")
        if not value:
            parsed.warnings.append(f"indicator row without a value: {row.get('type', '')[:80]!r}")
            continue
        cell = row.get("confidence", "")
        match = CONFIDENCE.match(cell)
        if cell and not match:
            parsed.warnings.append(f"unrecognized indicator confidence {cell[:40]!r} for {value[:60]!r}")
        parsed.indicators.append(ParsedIndicator(
            ioc_type=row.get("type", ""), value=value,
            confidence=match.group(1).lower() if match else "", source=row.get("source", ""),
        ))

    cve_rows = parse_tables(analysis.get("related cves advisories", ""))
    if analysis.get("related cves advisories", "").strip() and not cve_rows:
        parsed.warnings.append("analysis: section 'related cves advisories' has no table rows")

    for row in cve_rows:
        if not row.get("cve advisory"):
            parsed.warnings.append("CVE row without an identifier")
            continue
        parsed.cves.append(ParsedCVE(row["cve advisory"], row.get("summary", ""), row.get("relevance", "")))

    tlp = next((m for m in (TLP.search(t) for t in (report_text, analysis_text, plan_text)) if m), None)
    parsed.tlp = tlp.group(1).lower().replace("+strict", "_strict") if tlp else ""
    gate = GATE.search(analysis.get("quality gate", ""))
    parsed.gate_status = gate.group(1).lower() if gate else ""
    url = URL.search(report.get("appendix full source list", ""))
    parsed.first_source_url = url.group(0)[:200] if url else ""
    parsed.hunt_plan_hypothesis = _plan_hypothesis(plan_text)
    if plan_text.strip() and not parsed.hunt_plan_hypothesis:
        parsed.warnings.append("hunt-plan: no hypothesis found")

    parsed.stories = _parse_stories(plan_text, parsed.warnings)

    parsed.warnings += _unmapped("report", report_text, REPORT_KNOWN)
    parsed.warnings += _unmapped("analysis", analysis_text, ANALYSIS_KNOWN)
    return parsed


def parse_files(named_texts):
    """{filename: text} for one run -> ParsedIntel. All files must share one slug."""
    kinds, slugs = {}, set()
    for name, text in named_texts.items():
        base = os.path.basename(name)
        for suffix, kind in SUFFIXES.items():
            if base.endswith(suffix):
                slugs.add(base[: -len(suffix)])
                kinds[kind] = text
                break
        else:
            raise IntelImportError(f"{base}: expected <slug>-report.md, <slug>-analysis.md or <slug>-hunt-plan.md")
    if len(slugs) != 1:
        raise IntelImportError("All files must share one slug; got: " + ", ".join(sorted(slugs)))
    slug = slugs.pop()
    if not re.fullmatch(r"[\w-]{1,100}", slug):
        raise IntelImportError(f"Invalid slug {slug[:50]!r}: use 1-100 letters, digits, underscores or hyphens")
    if "report" not in kinds:
        raise IntelImportError(f"{slug}-report.md is required")
    return parse(slug, kinds["report"], kinds.get("analysis", ""), kinds.get("plan", ""))


def _seed_key(text):
    return " ".join(text.lower().split())


def preview(parsed):
    """What save_intel would do, without writing. Shared by the CLI's --dry-run and
    the upload preview so the two can't disagree."""
    report = IntelReport.objects.filter(slug=parsed.slug).first()
    ids = {t.raw_id for t in parsed.techniques}
    known = set(Technique.objects.filter(attack_id__in=ids).values_list("attack_id", flat=True))
    old = {_seed_key(s.text): s for s in report.seeds.all()} if report else {}
    incoming = {_seed_key(text) for text in parsed.seeds}
    return {
        "report": report,
        "techniques": len(parsed.techniques),
        "indicators": len(parsed.indicators),
        "cves": len(parsed.cves),
        "seeds": len(parsed.seeds),
        "stories": len(parsed.stories),
        "unresolved": sorted(ids - known),
        "new_seeds": [text for text in parsed.seeds if _seed_key(text) not in old],
        "stale_seeds": [s.text for key, s in old.items() if key not in incoming and s.status == HuntSeed.OPEN],
        "warnings": parsed.warnings,
    }


def _matching_actors(text):
    # Case-sensitive whole-word match on names and aliases: these are proper nouns,
    # and case-insensitive matching turns short aliases into false positives.
    return [
        actor for actor in Actor.objects.all()
        if any(re.search(rf"\b{re.escape(name)}\b", text) for name in [actor.name, *actor.aliases] if name)
    ]


@transaction.atomic
def save_intel(parsed, files=(), user=None):
    """Create or update the IntelReport for parsed.slug. Replaces techniques,
    indicators and CVEs; reconciles seeds without undoing decisions; never touches
    a Hunt (hunts are forked from intel, like LibraryTask.fork_into).

    ponytail: Evidence files are written to storage inside the atomic block, so a
    rollback leaves orphan files. Revisit if imports start failing mid-transaction.
    """
    report, _ = IntelReport.objects.get_or_create(slug=parsed.slug, defaults={"title": parsed.title})
    warnings = list(parsed.warnings)

    report.intel_techniques.all().delete()
    report.indicators.all().delete()
    report.cves.all().delete()
    report.stories.all().delete()
    by_id = {
        t.attack_id: t
        for t in Technique.objects.filter(attack_id__in={p.raw_id for p in parsed.techniques}).select_related("revoked_by")
    }
    rows = []
    for item in parsed.techniques:
        technique = by_id.get(item.raw_id)
        if technique and technique.revoked_by_id:
            technique = technique.revoked_by
        if technique is None:
            warnings.append(f"{item.raw_id} is not in the imported ATT&CK bundle")
        rows.append(IntelTechnique(
            report=report, technique=technique, raw_id=item.raw_id, tactic=item.tactic[:100],
            evidence=item.evidence, visibility_note=item.visibility_note,
        ))
    IntelTechnique.objects.bulk_create(rows)
    Indicator.objects.bulk_create([
        Indicator(report=report, ioc_type=i.ioc_type[:100], value=i.value, confidence=i.confidence, source=i.source)
        for i in parsed.indicators
    ])
    IntelCVE.objects.bulk_create([
        IntelCVE(report=report, identifier=c.identifier, summary=c.summary, relevance=c.relevance)
        for c in parsed.cves
    ])
    IntelStory.objects.bulk_create([
        IntelStory(
            report=report, order=order, title=s.title, objective=s.objective,
            hypothesis_component=s.hypothesis_component, methodology=s.methodology,
            expected_malicious=s.expected_malicious, expected_benign=s.expected_benign, query=s.query,
            data_sources=s.data_sources,
        )
        for order, s in enumerate(parsed.stories, start=1)
    ])

    existing = {_seed_key(s.text): s for s in report.seeds.all()}
    seen = set()
    for order, text in enumerate(parsed.seeds, start=1):
        key = _seed_key(text)
        if key in seen:
            continue
        seen.add(key)
        seed = existing.get(key)
        if seed is None:
            HuntSeed.objects.create(report=report, order=order, text=text)
            continue
        seed.order = order
        if seed.status == HuntSeed.STALE:
            seed.status = HuntSeed.OPEN
        seed.save(update_fields=["order", "status"])
    for key, seed in existing.items():
        if key not in seen and seed.status == HuntSeed.OPEN:
            seed.status = HuntSeed.STALE
            seed.save(update_fields=["status"])

    report.title = parsed.title or parsed.slug
    report.tlp = parsed.tlp
    report.gate_status = parsed.gate_status
    for name in TEXT_FIELDS:
        setattr(report, name, parsed.sections.get(name, ""))
    report.hunt_plan_hypothesis = parsed.hunt_plan_hypothesis
    report.first_source_url = parsed.first_source_url
    report.parse_warnings = "\n".join(dict.fromkeys(warnings))
    report.imported_by = user
    report.save()
    report.actors.set(_matching_actors(f"{report.title}\n{report.actor_overview}"))

    for filename, content in files:
        filename = os.path.basename(filename)
        Evidence.objects.create(
            intel_report=report, file=ContentFile(content, name=filename), caption=filename, uploaded_by=user
        )
    return report
