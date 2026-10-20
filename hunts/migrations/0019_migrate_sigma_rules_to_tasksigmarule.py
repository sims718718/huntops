"""Copy every existing Task<->SigmaRule link into TaskSigmaRule before 0020
switches Task.sigma_rules over to the through model and drops the plain
auto-generated link table this reads from. A rule the analyst had already
dismissed becomes status=discarded, not a dropped row - losing that distinction
here would let the next technique edit silently revive it via auto-attach's
.add(), exactly what dismissed_sigma_rules existed to prevent. One-way:
reversing is a no-op rather than deleting TaskSigmaRule rows, because by the
time anyone rolls back this far the table may hold Applied/Discarded statuses
set live through the app, not just rows this migration backfilled - deleting
those would be data loss, not a clean rollback (same reasoning as the
Outcome/outcome_types split).
"""

from django.db import migrations


def forward(apps, schema_editor):
    alias = schema_editor.connection.alias
    Task = apps.get_model('hunts', 'Task')
    TaskSigmaRule = apps.get_model('hunts', 'TaskSigmaRule')
    ActiveLink = Task.sigma_rules.through
    DismissedLink = Task.dismissed_sigma_rules.through

    statuses = {}
    for row in ActiveLink.objects.using(alias).all():
        statuses[(row.task_id, row.sigmarule_id)] = 'pending'
    for row in DismissedLink.objects.using(alias).all():
        statuses[(row.task_id, row.sigmarule_id)] = 'discarded'

    TaskSigmaRule.objects.using(alias).bulk_create(
        [
            TaskSigmaRule(task_id=task_id, sigma_rule_id=rule_id, status=status)
            for (task_id, rule_id), status in statuses.items()
        ]
    )


class Migration(migrations.Migration):

    dependencies = [
        ('hunts', '0018_tasksigmarule'),
    ]

    operations = [
        migrations.RunPython(forward, migrations.RunPython.noop),
    ]
