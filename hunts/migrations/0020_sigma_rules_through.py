"""Switch Task.sigma_rules from a plain M2M to one backed by TaskSigmaRule.

Hand-written: Django's schema editor refuses to AlterField an M2M into a
through-based one directly ("you cannot ... add or remove through= on M2M
fields"), so this drops the old field (its auto-generated link table, already
copied into TaskSigmaRule by 0019) and re-adds it pointing at the through
model that already exists - same RemoveField+re-add shape as 0009's
data_sources conversion.
"""

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('hunts', '0019_migrate_sigma_rules_to_tasksigmarule'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='task',
            name='sigma_rules',
        ),
        migrations.AddField(
            model_name='task',
            name='sigma_rules',
            field=models.ManyToManyField(blank=True, related_name='tasks', through='hunts.TaskSigmaRule', to='hunts.sigmarule'),
        ),
    ]
