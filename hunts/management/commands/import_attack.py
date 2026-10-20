"""Import MITRE ATT&CK Enterprise from a STIX 2.1 bundle.

One code path for both connected and air-gapped installs: --url pulls, --file reads
a bundle someone carried in. Nothing here is scheduled; an admin runs it.

This mirrors enough of the ATT&CK site that a hunter does not have to leave the app:
techniques with descriptions and hierarchy, tactics in matrix order, mitigations,
groups, software, campaigns, procedure examples, and the detection-strategy/analytic
chain that carries detection guidance and log sources in ATT&CK v17+.
"""

import json
import urllib.request

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils.dateparse import parse_datetime

from hunts.models import (
    Actor,
    Analytic,
    Campaign,
    DetectionStrategy,
    Mitigation,
    Procedure,
    Software,
    Tactic,
    Technique,
    TechniqueMitigation,
)

# attack-stix-data, not the older mitre/cti: only this bundle ships the
# x-mitre-collection object, and without it a Hunt has no ATT&CK version to pin.
DEFAULT_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)


def external_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") in ("mitre-attack", "mitre-attack-detection"):
            return ref.get("external_id") or ""
    return ""


def attack_url(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") in ("mitre-attack", "mitre-attack-detection"):
            return ref.get("url") or ""
    return ""


class Command(BaseCommand):
    help = "Import ATT&CK Enterprise from a STIX 2.1 bundle (URL or local file)."

    def add_arguments(self, parser):
        parser.add_argument("--file", help="Path to enterprise-attack.json (air-gapped import)")
        parser.add_argument("--url", default=DEFAULT_URL, help="Bundle URL to pull")
        # not --version: argparse reserves that for Django's own version flag
        parser.add_argument("--attack-version", help="Override the ATT&CK version label to record")

    @transaction.atomic
    def handle(self, *args, **options):
        objects = self._load(options)["objects"]
        self.index = {obj["id"]: obj for obj in objects if "id" in obj}
        self.relationships = [obj for obj in objects if obj.get("type") == "relationship"]
        version = options["attack_version"] or self._bundle_version(objects) or "unknown"

        counts = {
            "tactics": self._tactics(objects),
            "techniques": self._techniques(objects, version),
            "mitigations": self._mitigations(objects),
            "software": self._software(objects),
            "groups": self._actors(objects),
            "campaigns": self._campaigns(objects),
            "analytics": self._analytics(objects),
        }
        self._hierarchy()
        counts["mitigates"] = self._mitigates()
        counts["procedures"] = self._procedures()
        counts["strategies"] = self._detection_strategies(objects)
        counts["data sources"] = self._resolve_data_sources()
        # Order matters: _resolve_data_sources writes the arrays this reads.
        counts["data source rows"] = self._sync_data_sources()

        summary = ", ".join(f"{value} {key}" for key, value in counts.items())
        self.stdout.write(self.style.SUCCESS(f"ATT&CK {version}: {summary}"))

    # ------------------------------------------------------------------ loading

    def _load(self, options):
        if options["file"]:
            with open(options["file"], encoding="utf-8") as handle:
                return json.load(handle)
        try:
            with urllib.request.urlopen(options["url"], timeout=300) as response:
                return json.loads(response.read().decode("utf-8"))
        except OSError as exc:
            raise CommandError(f"Could not fetch {options['url']}: {exc}. Use --file when air-gapped.")

    @staticmethod
    def _bundle_version(objects):
        for obj in objects:
            if obj.get("type") == "x-mitre-collection":
                return obj.get("x_mitre_version")
        return None

    def _of_type(self, objects, *types):
        return [obj for obj in objects if obj.get("type") in types]

    def _rels(self, kind):
        return [r for r in self.relationships if r.get("relationship_type") == kind]

    # ------------------------------------------------------------------ passes

    def _tactics(self, objects):
        # The matrix object carries the official column order; alphabetical is wrong.
        order = {}
        for matrix in self._of_type(objects, "x-mitre-matrix"):
            for position, ref in enumerate(matrix.get("tactic_refs", [])):
                order[ref] = position

        for obj in self._of_type(objects, "x-mitre-tactic"):
            Tactic.objects.update_or_create(
                attack_id=external_id(obj),
                defaults={
                    "shortname": obj.get("x_mitre_shortname", ""),
                    "name": obj.get("name", ""),
                    "description": obj.get("description", "") or "",
                    "url": attack_url(obj),
                    "order": order.get(obj["id"], 99),
                },
            )
        return Tactic.objects.count()

    def _techniques(self, objects, version):
        self.techniques = {}
        seen = set()
        for obj in self._of_type(objects, "attack-pattern"):
            attack_id = external_id(obj)
            if not attack_id:
                continue
            seen.add(attack_id)
            technique, _ = Technique.objects.update_or_create(
                attack_id=attack_id,
                defaults={
                    "name": obj.get("name", ""),
                    "description": obj.get("description", "") or "",
                    "url": attack_url(obj),
                    "tactics": [
                        phase["phase_name"]
                        for phase in obj.get("kill_chain_phases", [])
                        if phase.get("kill_chain_name") == "mitre-attack"
                    ],
                    "platforms": obj.get("x_mitre_platforms", []),
                    # older bundles carry per-technique detection text; v17+ moved it
                    # into detection strategies, handled in _detection_strategies
                    "detection": obj.get("x_mitre_detection", "") or "",
                    "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
                    "deprecated": bool(obj.get("x_mitre_deprecated") or obj.get("revoked")),
                    "technique_version": obj.get("x_mitre_version", "") or "",
                    "modified": parse_datetime(obj.get("modified") or "") or None,
                    "attack_version": version,
                },
            )
            self.techniques[obj["id"]] = technique

        # A technique the new bundle no longer carries was removed upstream; flag it so
        # hunts referencing it show the deprecation badge instead of silently drifting.
        Technique.objects.exclude(attack_id__in=seen).update(deprecated=True)
        return len(seen)

    def _hierarchy(self):
        for rel in self._rels("subtechnique-of"):
            child = self.techniques.get(rel["source_ref"])
            parent = self.techniques.get(rel["target_ref"])
            if child and parent:
                Technique.objects.filter(pk=child.pk).update(parent=parent)

        for rel in self._rels("revoked-by"):
            old = self.techniques.get(rel["source_ref"])
            new = self.techniques.get(rel["target_ref"])
            if old and new:
                Technique.objects.filter(pk=old.pk).update(revoked_by=new, deprecated=True)

    def _mitigations(self, objects):
        self.mitigations = {}
        for obj in self._of_type(objects, "course-of-action"):
            attack_id = external_id(obj)
            if not attack_id:
                continue
            mitigation, _ = Mitigation.objects.update_or_create(
                attack_id=attack_id,
                defaults={
                    "name": obj.get("name", ""),
                    "description": obj.get("description", "") or "",
                    "url": attack_url(obj),
                },
            )
            self.mitigations[obj["id"]] = mitigation
        return len(self.mitigations)

    def _mitigates(self):
        # Pure reference data - rebuild rather than diff.
        TechniqueMitigation.objects.all().delete()
        rows = [
            TechniqueMitigation(
                technique=self.techniques[rel["target_ref"]],
                mitigation=self.mitigations[rel["source_ref"]],
                description=rel.get("description", "") or "",
            )
            for rel in self._rels("mitigates")
            if rel["target_ref"] in self.techniques and rel["source_ref"] in self.mitigations
        ]
        TechniqueMitigation.objects.bulk_create(rows, ignore_conflicts=True)
        return len(rows)

    def _software(self, objects):
        self.software = {}
        for obj in self._of_type(objects, "malware", "tool"):
            attack_id = external_id(obj)
            if not attack_id:
                continue
            software, _ = Software.objects.update_or_create(
                attack_id=attack_id,
                defaults={
                    "name": obj.get("name", ""),
                    "software_type": "malware" if obj["type"] == "malware" else "tool",
                    "aliases": obj.get("x_mitre_aliases", []) or [],
                    "description": obj.get("description", "") or "",
                    "url": attack_url(obj),
                    "platforms": obj.get("x_mitre_platforms", []) or [],
                },
            )
            self.software[obj["id"]] = software
        return len(self.software)

    def _actors(self, objects):
        self.actors = {}
        for obj in self._of_type(objects, "intrusion-set"):
            attack_id = external_id(obj)
            if not attack_id:
                continue
            actor, _ = Actor.objects.update_or_create(
                attack_id=attack_id,
                defaults={
                    "name": obj.get("name", ""),
                    "aliases": obj.get("aliases", []) or [],
                    "description": obj.get("description", "") or "",
                    "url": attack_url(obj),
                },
            )
            self.actors[obj["id"]] = actor

        for rel in self._rels("uses"):
            actor = self.actors.get(rel["source_ref"])
            software = self.software.get(rel["target_ref"])
            if actor and software:
                actor.software.add(software)
        return len(self.actors)

    def _campaigns(self, objects):
        self.campaigns = {}
        for obj in self._of_type(objects, "campaign"):
            attack_id = external_id(obj)
            if not attack_id:
                continue
            campaign, _ = Campaign.objects.update_or_create(
                attack_id=attack_id,
                defaults={
                    "name": obj.get("name", ""),
                    "description": obj.get("description", "") or "",
                    "url": attack_url(obj),
                    "first_seen": parse_datetime(obj.get("first_seen") or "") or None,
                    "last_seen": parse_datetime(obj.get("last_seen") or "") or None,
                },
            )
            self.campaigns[obj["id"]] = campaign
        return len(self.campaigns)

    def _procedures(self):
        """`uses` relationships that point at a technique - what the technique looks
        like when a real actor, tool or campaign performs it."""
        Procedure.objects.all().delete()
        rows = []
        for rel in self._rels("uses"):
            technique = self.techniques.get(rel["target_ref"])
            if not technique:
                continue
            source = rel["source_ref"]
            rows.append(
                Procedure(
                    technique=technique,
                    actor=self.actors.get(source),
                    software=self.software.get(source),
                    campaign=self.campaigns.get(source),
                    description=rel.get("description", "") or "",
                )
            )
        Procedure.objects.bulk_create(rows, batch_size=2000)
        return len(rows)

    def _analytics(self, objects):
        self.analytics = {}
        for obj in self._of_type(objects, "x-mitre-analytic"):
            # the reference `name` (e.g. "WinEventLog:Security") is the log channel a
            # hunter actually searches, so that is what gets stored
            channels = [
                ref.get("name", "")
                for ref in obj.get("x_mitre_log_source_references", [])
                if ref.get("name")
            ]
            analytic, _ = Analytic.objects.update_or_create(
                stix_id=obj["id"],
                defaults={
                    "attack_id": external_id(obj),
                    "name": obj.get("name", ""),
                    "description": obj.get("description", "") or "",
                    "platforms": obj.get("x_mitre_platforms", []) or [],
                    "log_sources": channels,
                },
            )
            self.analytics[obj["id"]] = analytic
        return len(self.analytics)

    def _detection_strategies(self, objects):
        detects = {rel["source_ref"]: rel["target_ref"] for rel in self._rels("detects")}
        count = 0
        for obj in self._of_type(objects, "x-mitre-detection-strategy"):
            technique = self.techniques.get(detects.get(obj["id"]))
            strategy, _ = DetectionStrategy.objects.update_or_create(
                stix_id=obj["id"],
                defaults={
                    "attack_id": external_id(obj),
                    "name": obj.get("name", ""),
                    "url": attack_url(obj),
                    "technique": technique,
                },
            )
            strategy.analytics.set(
                [
                    self.analytics[ref]
                    for ref in obj.get("x_mitre_analytic_refs", [])
                    if ref in self.analytics
                ]
            )
            count += 1
        return count

    def _sync_data_sources(self):
        """Mirror Technique.data_sources into DataSource rows and their M2M.

        The ArrayField is the import's record; this M2M is the app's queryable
        relation. Rebuilding the links from the ArrayField on every run is what
        stops the two representations drifting apart - which only holds because
        _resolve_data_sources now replaces that array instead of unioning into it.

        Every label in the bundle gets a row, whether or not a task uses it, so
        suggestions work without waiting for a second import.
        """
        from hunts.models import DataSource

        by_name = {}
        for technique_pk, labels in Technique.objects.exclude(data_sources=[]).values_list(
            "pk", "data_sources"
        ):
            for label in labels or []:
                by_name.setdefault(label, set()).add(technique_pk)

        for label, technique_pks in by_name.items():
            row, _ = DataSource.objects.update_or_create(
                name=label,
                defaults={
                    "origin": DataSource.MITRE,
                    "category": DataSource.category_of(label),
                },
            )
            row.techniques.set(technique_pks)

        # Rows the bundle no longer maps keep their row - a task may still select
        # one - but lose their links, so a stale row cannot pose as current
        # guidance. A loop because update() cannot write an M2M.
        for row in DataSource.objects.filter(origin=DataSource.MITRE).exclude(name__in=by_name):
            row.techniques.clear()

        return DataSource.objects.count()

    def _resolve_data_sources(self):
        """"Data Source: Data Component" per technique, walked back through the
        analytics' log-source references. In v17+ this is the only place the
        data-source model is still expressed for a technique."""
        components = {
            obj["id"]: (obj.get("name", ""), obj.get("x_mitre_data_source_ref"))
            for obj in self.index.values()
            if obj.get("type") == "x-mitre-data-component"
        }
        sources = {
            obj["id"]: obj.get("name", "")
            for obj in self.index.values()
            if obj.get("type") == "x-mitre-data-source"
        }
        # A pre-v17 bundle expresses no data-source model at all. Recomputing from
        # it would clear every label rather than leave them untouched, so bail out.
        if not components:
            return 0

        by_analytic = {}
        for obj in self.index.values():
            if obj.get("type") != "x-mitre-analytic":
                continue
            labels = []
            for ref in obj.get("x_mitre_log_source_references", []):
                component = components.get(ref.get("x_mitre_data_component_ref"))
                if not component:
                    continue
                name, source_ref = component
                source = sources.get(source_ref, "")
                labels.append(f"{source}: {name}" if source else name)
            by_analytic[obj["id"]] = labels

        # Accumulate per technique first: several strategies can target the same
        # technique, so a per-strategy write would clobber its siblings.
        by_technique = {}
        for strategy in DetectionStrategy.objects.filter(technique__isnull=False).prefetch_related(
            "analytics"
        ):
            labels = set()
            for analytic in strategy.analytics.all():
                labels.update(by_analytic.get(analytic.stix_id, []))
            by_technique.setdefault(strategy.technique_id, set()).update(labels)

        # Replace rather than union. Unioning meant a technique never lost a label
        # the current bundle had dropped, so the derived DataSource links could
        # never be cleared either. Techniques that resolve to nothing are emptied.
        stale = Technique.objects.exclude(data_sources=[]).exclude(pk__in=by_technique)
        targets = {t.pk: t for t in Technique.objects.filter(pk__in=by_technique)}
        targets.update({t.pk: t for t in stale})

        updated = 0
        for pk, technique in targets.items():
            labels = sorted(by_technique.get(pk, set()))
            if technique.data_sources != labels:
                technique.data_sources = labels
                technique.save(update_fields=["data_sources"])
            updated += 1
        return updated
