"""Drop the live ArrayFields and promote the M2Ms into their place.

Hand-written rather than generated: `makemigrations --noinput` cannot tell a
rename from a remove-plus-add, and guessing wrong here would drop the relations
0008 has just populated.

`historicaltask.data_sources` goes too, because a M2M is not copied onto the
historical model. Its contents were already copied to
`data_source_names_snapshot` in 0008, so nothing is lost - which is why that
copy and this removal must ship as one sequence and never as two deployments.
"""

import django.contrib.postgres.fields
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('hunts', '0008_add_data_source_m2m'),
    ]

    operations = [
        migrations.RemoveField(model_name='task', name='data_sources'),
        migrations.RemoveField(model_name='librarytask', name='data_sources'),
        migrations.RemoveField(model_name='historicaltask', name='data_sources'),
        migrations.RenameField(
            model_name='task', old_name='data_sources_new', new_name='data_sources'
        ),
        migrations.RenameField(
            model_name='librarytask', old_name='data_sources_new', new_name='data_sources'
        ),
    ]
