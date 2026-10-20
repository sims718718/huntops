"""Create the five RBAC groups (PRD 13 + the v0.2 CTI Analyst). Idempotent - safe to re-run after upgrades."""

from django.contrib.auth.models import Group, Permission
from django.core.management.base import BaseCommand

AUTHORING = ["hunt", "objective", "task", "librarytask", "evidence", "outcome", "comment"]
INTEL = ["intelreport", "inteltechnique", "indicator", "intelcve", "huntseed", "intelstory"]

ROLES = {
    "Hunter": {"view": "all", "add": AUTHORING, "change": AUTHORING},
    "Hunt Lead": {
        "view": "all",
        "add": AUTHORING + INTEL,
        "change": AUTHORING + INTEL,
        "delete": AUTHORING + INTEL,
        "extra": ["override_feasibility"],
    },
    "Detection Engineer": {
        "view": "all",
        "add": ["outcome", "evidence", "comment"],
        "change": ["task", "outcome", "evidence", "comment"],
    },
    # add_hunt so a seed can be promoted; no change_hunt - once promoted, the hunt
    # belongs to the hunt team.
    "CTI Analyst": {"view": "all", "add": INTEL + ["hunt", "evidence"], "change": INTEL},
    "Stakeholder": {"view": "all"},
}


class Command(BaseCommand):
    help = "Create/refresh the Hunter, Hunt Lead, Detection Engineer, CTI Analyst and Stakeholder groups."

    def handle(self, *args, **options):
        app_perms = Permission.objects.filter(content_type__app_label="hunts")
        by_codename = {perm.codename: perm for perm in app_perms}

        for name, spec in ROLES.items():
            group, _ = Group.objects.get_or_create(name=name)
            codenames = set(spec.get("extra", []))
            for action in ("view", "add", "change", "delete"):
                models = spec.get(action)
                if models == "all":
                    codenames.update(c for c in by_codename if c.startswith(f"{action}_"))
                elif models:
                    codenames.update(f"{action}_{model}" for model in models)

            missing = codenames - by_codename.keys()
            if missing:
                self.stdout.write(self.style.WARNING(f"{name}: unknown permissions {sorted(missing)}"))
            group.permissions.set([by_codename[c] for c in codenames if c in by_codename])
            self.stdout.write(self.style.SUCCESS(f"{name}: {group.permissions.count()} permissions"))
