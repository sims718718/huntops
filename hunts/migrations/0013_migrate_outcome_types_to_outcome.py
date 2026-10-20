"""One Outcome row per value in the old Task.outcome_types array.

Notes are left blank and recorded_by is null - the array never carried either,
so there's nothing to backfill them from. One-way: reversing this migration is
a no-op rather than deleting Outcome rows, because by the time anyone rolls
back this far the table may already hold outcomes recorded live through the
app, not just ones this migration backfilled - deleting those would be data
loss, not a clean rollback.
"""

from django.db import migrations


def forward(apps, schema_editor):
    alias = schema_editor.connection.alias
    Task = apps.get_model('hunts', 'Task')
    Outcome = apps.get_model('hunts', 'Outcome')

    for task in Task.objects.using(alias).exclude(outcome_types=[]):
        Outcome.objects.using(alias).bulk_create(
            [Outcome(task=task, outcome_type=t) for t in task.outcome_types]
        )


class Migration(migrations.Migration):

    dependencies = [
        ('hunts', '0012_outcome'),
    ]

    operations = [
        migrations.RunPython(forward, migrations.RunPython.noop),
    ]
