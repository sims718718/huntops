"""Task library as code: one YAML file per team-built library task.

The file format, its validation and the dump live here, apart from any view or
command, the way hunts/intel_import.py separates parsing from saving. Files carry
stable names (an `id`, ATT&CK ids, Sigma rule ids, data source names) rather than
database keys, so a library moves between installs and through a git repo.
"""

import os
import re
import uuid
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from django.db import transaction

from .models import KEY_PATTERN, DataSource, LibraryTask, SigmaRule, Technique

SCHEMA = "huntops/library-task/v1"

# YAML key -> (maximum length, or None for unbounded). The limits are the model's, checked
# here so an over-long value is a validation error rather than a database error at apply.
TEXT_FIELDS = {"hunting_tool": 100, "query": None, "expected_positive": None, "expected_benign": None, "notes": None}
LIST_FIELDS = ("techniques", "data_sources", "sigma_rules")
LIST_ITEM_LIMITS = {"data_sources": 200}  # DataSource.name
SCALARS = ("title", "hunting_tool", "query", "expected_positive", "expected_benign", "notes")
KNOWN_KEYS = {"schema", "id", "title", *TEXT_FIELDS, *LIST_FIELDS}


@dataclass(frozen=True)
class Entry:
    """One parsed, validated file."""

    source: str
    id: str
    title: str
    hunting_tool: str = ""
    techniques: tuple = ()
    data_sources: tuple = ()
    sigma_rules: tuple = ()
    query: str = ""
    expected_positive: str = ""
    expected_benign: str = ""
    notes: str = ""


class _BlockDumper(yaml.SafeDumper):
    """Multi-line strings as `|` blocks so queries read as queries in a pull request.
    PyYAML falls back to a quoted style when a block would not round-trip."""


_BlockDumper.add_representer(
    str,
    lambda dumper, value: dumper.represent_scalar(
        "tag:yaml.org,2002:str", value, style="|" if "\n" in value else None
    ),
)


def dump_task(task):
    """The task as YAML text. Deterministic: fixed key order, sorted lists, no timestamps."""
    if not task.key:
        raise ValueError(f"{task.library_id} is a reference entry and is not exported")
    data = {"schema": SCHEMA, "id": task.key, "title": task.title}
    if task.hunting_tool:
        data["hunting_tool"] = task.hunting_tool
    relations = {
        "techniques": sorted(task.techniques.values_list("attack_id", flat=True)),
        "data_sources": sorted(task.data_sources.values_list("name", flat=True)),
        "sigma_rules": sorted(str(rule_id) for rule_id in task.sigma_rules.values_list("rule_id", flat=True)),
    }
    data.update({name: values for name, values in relations.items() if values})
    for name in ("query", "expected_positive", "expected_benign", "notes"):
        if getattr(task, name):
            data[name] = getattr(task, name)
    return yaml.dump(data, Dumper=_BlockDumper, sort_keys=False, allow_unicode=True, width=10**6)


def _parse_one(name, text):
    """Returns (Entry, []) or (None, [errors]); every error is prefixed with the file name."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        problem = str(exc).splitlines()[0] if str(exc) else "invalid YAML"
        return None, [f"{name}: not valid YAML ({problem})"]
    if not isinstance(data, dict):
        return None, [f"{name}: the file must be a mapping of keys to values"]

    errors = []
    if unknown := sorted(str(key) for key in data.keys() - KNOWN_KEYS):
        errors.append(f"{name}: unknown key{'s' if len(unknown) > 1 else ''} {', '.join(unknown)}")
    if "schema" not in data:
        errors.append(f"{name}: schema is required (expected {SCHEMA})")
    elif data["schema"] != SCHEMA:
        errors.append(f"{name}: unsupported schema {data['schema']!r} (expected {SCHEMA})")

    def text_value(key, limit, required=False):
        value = data.get(key)
        if value is None:
            if required:
                errors.append(f"{name}: {key} is required")
            return ""
        if not isinstance(value, str):
            errors.append(f"{name}: {key} must be text, not {type(value).__name__}")
            return ""
        if limit and len(value) > limit:
            errors.append(f"{name}: {key} is {len(value)} characters; the limit is {limit}")
        return value

    id_ = text_value("id", None, required=True)
    if id_ and not KEY_PATTERN.fullmatch(id_):
        errors.append(f"{name}: id {id_!r} must be lower-case letters, digits, '.', '_' or '-' (at most 100 characters)")
    fields = {"title": text_value("title", 300, required=True)}
    for key, limit in TEXT_FIELDS.items():
        fields[key] = text_value(key, limit)
    for key in LIST_FIELDS:
        value = data.get(key)
        if value is None:
            fields[key] = ()
        elif isinstance(value, list) and all(isinstance(item, str) for item in value):
            limit = LIST_ITEM_LIMITS.get(key)
            if limit and any(len(item) > limit for item in value):
                errors.append(f"{name}: a {key} value is longer than {limit} characters")
            fields[key] = tuple(value)
        else:
            errors.append(f"{name}: {key} must be a list of text values")
            fields[key] = ()
    if errors:
        return None, errors
    return Entry(source=name, id=id_, **fields), []


def parse_documents(named):
    """Parse {file name: text}. Returns (entries, errors): every file is checked, so a
    run reports all of its problems at once instead of one per attempt."""
    entries, errors, first_seen = [], [], {}
    for name in sorted(named):
        entry, problems = _parse_one(name, named[name])
        errors.extend(problems)
        if entry is None:
            continue
        if entry.id in first_seen:
            errors.append(f"{name}: id {entry.id!r} is also used by {first_seen[entry.id]}")
        else:
            first_seen[entry.id] = name
        entries.append(entry)
    return entries, errors


@dataclass
class PlanItem:
    entry: Entry
    action: str  # "created", "updated" or "unchanged"
    changes: dict = field(default_factory=dict)  # field -> (old, new); empty unless updated
    warnings: list = field(default_factory=list)


@dataclass
class Plan:
    items: list = field(default_factory=list)
    errors: list = field(default_factory=list)

    @property
    def ok(self):
        return not self.errors


def _uuid(text):
    try:
        return uuid.UUID(text)
    except ValueError:
        return None


def build_plan(named):
    """What importing these files would do, without doing it.

    Existing tasks are compared on what the database actually knows: a technique that
    is not installed is a warning and is left out of the comparison, so a file that
    names one reads as unchanged on every re-import instead of updated forever.
    """
    entries, errors = parse_documents(named)
    ids = [entry.id for entry in entries]
    reference = set(LibraryTask.objects.filter(seed_key__in=ids).values_list("seed_key", flat=True))
    known_techniques = set(
        Technique.objects.filter(attack_id__in={t for e in entries for t in e.techniques})
        .values_list("attack_id", flat=True)
    )
    uuids = {r: _uuid(r) for e in entries for r in e.sigma_rules}
    known_rules = set(
        SigmaRule.objects.filter(rule_id__in=[u for u in uuids.values() if u]).values_list("rule_id", flat=True)
    )
    existing = {
        task.key: task
        for task in LibraryTask.objects.filter(key__in=ids).prefetch_related("techniques", "data_sources", "sigma_rules")
    }

    items = []
    for entry in entries:
        if entry.id in reference:
            errors.append(f"{entry.source}: id {entry.id!r} belongs to a reference entry, which import never changes")
            continue
        warnings = [
            f"{entry.source}: technique {t} is not installed; link skipped"
            for t in entry.techniques if t not in known_techniques
        ]
        warnings += [
            f"{entry.source}: Sigma rule {r} is not installed or not a valid rule id; link skipped"
            for r in entry.sigma_rules if uuids[r] not in known_rules
        ]
        task = existing.get(entry.id)
        if task is None:
            items.append(PlanItem(entry, "created", {}, warnings))
            continue
        new = {
            "techniques": sorted({t for t in entry.techniques if t in known_techniques}),
            "data_sources": sorted(set(entry.data_sources)),
            "sigma_rules": sorted({str(uuids[r]) for r in entry.sigma_rules if uuids[r] in known_rules}),
        }
        old = {
            "techniques": sorted(t.attack_id for t in task.techniques.all()),
            "data_sources": sorted(d.name for d in task.data_sources.all()),
            "sigma_rules": sorted(str(r.rule_id) for r in task.sigma_rules.all()),
        }
        changes = {f: (getattr(task, f), getattr(entry, f)) for f in SCALARS if getattr(task, f) != getattr(entry, f)}
        changes.update({f: (old[f], new[f]) for f in new if old[f] != new[f]})
        items.append(PlanItem(entry, "updated" if changes else "unchanged", changes, warnings))
    return Plan(items, errors)


def apply_plan(plan, user=None):
    """Write a plan that has no errors, all or nothing. The repo wins: an update
    overwrites every field from the file."""
    if not plan.ok:
        raise ValueError("The plan has errors; nothing was written")
    applied = []
    with transaction.atomic():
        for item in plan.items:
            if item.action == "unchanged":
                continue
            entry = item.entry
            task = LibraryTask.objects.filter(key=entry.id).first() or LibraryTask(key=entry.id, created_by=user)
            for name in SCALARS:
                setattr(task, name, getattr(entry, name))
            task.save()
            # The file's Sigma list is the repo's deliberate choice; without this flag the
            # technique assignment below would auto-attach every matching stable rule.
            task.suppress_auto_sigma = True
            task.techniques.set(Technique.objects.filter(attack_id__in=entry.techniques))
            task.sigma_rules.set(
                SigmaRule.objects.filter(rule_id__in=[u for u in map(_uuid, entry.sigma_rules) if u])
            )
            task.data_sources.set([DataSource.objects.get_or_create(name=n)[0] for n in entry.data_sources])
            applied.append(task)
    return applied


def export_all():
    """{file name: YAML text} for every team-built task, ordered by key."""
    tasks = LibraryTask.objects.filter(provenance="user").exclude(key="").order_by("key")
    return {f"{task.key}.yml": dump_task(task) for task in tasks}


def _is_yaml(name):
    return name.lower().endswith((".yml", ".yaml"))


def _hidden(parts):
    return any(part.startswith(".") for part in parts)


def read_directory(path):
    """Every YAML file under a directory as ({relative path: text}, errors). Hidden
    directories and files (.git, .github, .gitlab-ci.yml) are skipped, so a repo
    checkout can be passed as is."""
    root = Path(path)
    if not root.is_dir():
        return {}, [f"{root} is not a directory"]
    named, errors = {}, []
    for directory, subdirs, files in os.walk(root):
        subdirs[:] = sorted(d for d in subdirs if not d.startswith("."))
        for filename in sorted(files):
            if filename.startswith(".") or not _is_yaml(filename):
                continue
            file = Path(directory) / filename
            name = file.relative_to(root).as_posix()
            try:
                named[name] = file.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                errors.append(f"{name}: not valid UTF-8 text")
    if not named and not errors:
        errors.append(f"No YAML files found under {root}")
    return named, errors


class _LimitExceeded(Exception):
    pass


MAX_UPLOAD_BYTES = 1_000_000
MAX_UPLOAD_FILES = 500


def over_limit(named, max_bytes=MAX_UPLOAD_BYTES, max_files=MAX_UPLOAD_FILES):
    """The upload limits applied to an already-read {name: text}: the import page's confirm
    step takes its files from a client-controlled field, so it must re-check them."""
    if len(named) > max_files:
        return f"The upload has more than {max_files} files"
    if sum(len(text.encode("utf-8")) for text in named.values()) > max_bytes:
        return f"The upload is larger than {max_bytes:,} bytes"
    return None


def read_uploads(files, max_bytes=MAX_UPLOAD_BYTES, max_files=MAX_UPLOAD_FILES):
    """Uploaded .yml/.yaml files and .zip archives as ({name: text}, errors).

    Zips are read in memory and never extracted, so a member's path is only ever a label.
    The byte budget counts decompressed bytes, so a small zip cannot hide a large payload.
    """
    named, errors, budget, count = {}, [], max_bytes, 0

    def take(stream):
        nonlocal budget, count
        count += 1
        if count > max_files:
            raise _LimitExceeded(f"The upload has more than {max_files} files")
        data = stream.read(budget + 1)
        if len(data) > budget:
            raise _LimitExceeded(f"The upload is larger than {max_bytes:,} bytes")
        budget -= len(data)
        return data

    def keep(label, data):
        if label in named:
            errors.append(f"{label}: more than one file has this name")
            return
        try:
            named[label] = data.decode("utf-8")
        except UnicodeDecodeError:
            errors.append(f"{label}: not valid UTF-8 text")

    try:
        for upload in files:
            name = os.path.basename(upload.name)
            if name.lower().endswith(".zip"):
                # Parsing a zip's directory costs memory per entry before any byte budget
                # applies, so refuse an archive that is too big to be a legitimate library
                # (YAML compresses, so its stored size never exceeds its content by much).
                if getattr(upload, "size", 0) > 2 * max_bytes:
                    raise _LimitExceeded(f"The upload is larger than {max_bytes:,} bytes")
                try:
                    archive = zipfile.ZipFile(upload)
                    members = archive.infolist()
                except zipfile.BadZipFile:
                    errors.append(f"{name}: not a valid zip file")
                    continue
                for info in members:
                    parts = info.filename.replace("\\", "/").split("/")
                    if info.is_dir():
                        continue
                    if info.filename.startswith(("/", "\\")) or ".." in parts or re.match(r"[A-Za-z]:", info.filename):
                        errors.append(f"{name}: unsafe path {info.filename!r} in the zip")
                        continue
                    if _hidden(parts) or not _is_yaml(parts[-1]):
                        continue
                    try:
                        with archive.open(info) as member:
                            keep(f"{name}:{info.filename}", take(member))
                    except (RuntimeError, NotImplementedError, zipfile.BadZipFile):
                        errors.append(f"{name}: cannot read {info.filename!r} (encrypted or damaged)")
            elif _is_yaml(name):
                keep(name, take(upload))
            else:
                errors.append(f"{name}: not a .yml, .yaml or .zip file")
    except _LimitExceeded as exc:
        errors.append(str(exc))
    if not named and not errors:
        errors.append("No YAML files found")
    return named, errors
