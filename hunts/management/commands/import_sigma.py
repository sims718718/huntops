"""Import the SigmaHQ rule set.

Same shape as import_attack: --path takes a checked-out repo or a downloaded zip
(air-gapped), --url pulls the zip. Rules are linked to techniques through their
`attack.tXXXX` tags, which is the join that powers the coverage overlay.
"""

import io
import os
import re
import urllib.request
import uuid
import zipfile

import yaml
from django.core.management.base import BaseCommand, CommandError

from hunts.models import SigmaRule, Technique
from hunts.search import refresh_sigma_search

DEFAULT_URL = "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip"
ATTACK_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
RULE_DIR = re.compile(r"(^|/)rules[^/]*/")
# regression_data/ mirrors the rules tree with test fixtures, not rules.
NOT_RULES = re.compile(r"(^|/)regression_data/")


class Command(BaseCommand):
    help = "Import SigmaHQ rules from a repo directory, a zip, or the SigmaHQ zip URL."

    def add_arguments(self, parser):
        parser.add_argument("--path", help="Sigma repo directory or zip file (air-gapped import)")
        parser.add_argument("--url", default=DEFAULT_URL, help="Zip URL to pull")

    def handle(self, *args, **options):
        techniques = {t.attack_id.upper(): t for t in Technique.objects.all()}
        imported = skipped = 0

        for name, text in self._iter_rules(options):
            collection = collection_of(name)
            rule = parse_rule(text)
            if not rule:
                skipped += 1
                continue
            try:
                rule_id = uuid.UUID(str(rule["id"]))
            except (ValueError, TypeError):
                skipped += 1
                continue

            logsource = rule.get("logsource") or {}
            obj, _ = SigmaRule.objects.update_or_create(
                rule_id=rule_id,
                defaults={
                    "title": str(rule.get("title", ""))[:300],
                    "status": str(rule.get("status", "")),
                    "description": str(rule.get("description", "")),
                    "level": str(rule.get("level", "")),
                    "logsource_category": str(logsource.get("category", "")),
                    "logsource_product": str(logsource.get("product", "")),
                    "logsource_service": str(logsource.get("service", "")),
                    "author": str(rule.get("author", ""))[:300],
                    # DRL 1.1 unless a rule states otherwise; attribution has to survive export.
                    "license": str(rule.get("license", "DRL-1.1")),
                    "collection": collection,
                    "references": [str(r)[:500] for r in rule.get("references", []) or []],
                    "raw_yaml": text,
                },
            )
            obj.techniques.set(
                [techniques[tid] for tid in attack_ids(rule.get("tags") or []) if tid in techniques]
            )
            imported += 1

        refresh_sigma_search()
        self.stdout.write(
            self.style.SUCCESS(f"Sigma: {imported} rules imported, {skipped} skipped")
        )
        if not techniques:
            self.stdout.write(
                self.style.WARNING("No techniques in the database - run import_attack first to link rules.")
            )

    def _iter_rules(self, options):
        path = options["path"]
        if path and os.path.isdir(path):
            yield from self._iter_dir(path)
        elif path:
            yield from self._iter_zip(zipfile.ZipFile(path))
        else:
            try:
                with urllib.request.urlopen(options["url"], timeout=300) as response:
                    payload = response.read()
            except OSError as exc:
                raise CommandError(f"Could not fetch {options['url']}: {exc}. Use --path when air-gapped.")
            yield from self._iter_zip(zipfile.ZipFile(io.BytesIO(payload)))

    @staticmethod
    def _iter_dir(root):
        for dirpath, _, filenames in os.walk(root):
            normalised = dirpath.replace(os.sep, "/") + "/"
            if not RULE_DIR.search(normalised) or NOT_RULES.search(normalised):
                continue
            for filename in filenames:
                if filename.endswith((".yml", ".yaml")):
                    full = os.path.join(dirpath, filename)
                    with open(full, encoding="utf-8") as handle:
                        yield full, handle.read()

    @staticmethod
    def _iter_zip(archive):
        with archive:
            for name in archive.namelist():
                if (
                    name.endswith((".yml", ".yaml"))
                    and RULE_DIR.search(name)
                    and not NOT_RULES.search(name)
                ):
                    yield name, archive.read(name).decode("utf-8", errors="replace")


def collection_of(path):
    """Top-level rules directory a rule came from, e.g. rules-threat-hunting."""
    match = re.search(r"(^|/)(rules[^/]*)/", path.replace("\\", "/"))
    return match.group(2) if match else ""


def parse_rule(text):
    """First document carrying an `id`.

    ponytail: Sigma collection rules (action: global/repeat) span several documents;
    taking the first identified one imports the parent and drops its variants. Expand
    to full collection expansion if hunters start missing rules because of it.
    """
    try:
        documents = list(yaml.safe_load_all(text))
    except yaml.YAMLError:
        return None
    for document in documents:
        if isinstance(document, dict) and document.get("id") and document.get("title"):
            return document
    return None


def attack_ids(tags):
    ids = []
    for tag in tags:
        match = ATTACK_TAG.match(str(tag))
        if match:
            ids.append(match.group(1).upper())
    return ids
