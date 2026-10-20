from django.contrib.postgres.indexes import GinIndex
from django.contrib.postgres.search import SearchVector, SearchVectorField
from django.db import migrations


def backfill(apps, schema_editor):
    vector = (SearchVector('title', weight='A', config='english')
        + SearchVector('description', weight='B', config='english')
        + SearchVector('logsource_product', 'logsource_service', 'logsource_category', 'author', weight='C', config='english')
        + SearchVector('raw_yaml', weight='D', config='english'))
    apps.get_model('hunts', 'SigmaRule').objects.using(schema_editor.connection.alias).update(search=vector)


class Migration(migrations.Migration):
    dependencies = [('hunts', '0005_sigmarule_collection')]
    operations = [
        migrations.AddField('sigmarule', 'search', SearchVectorField(null=True, editable=False)),
        migrations.RunPython(backfill, migrations.RunPython.noop),
        migrations.AddIndex('sigmarule', GinIndex(fields=['search'], name='sigma_search_gin')),
    ]
