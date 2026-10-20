import django.contrib.postgres.fields
from django.db import migrations, models


def single_to_list(apps, schema_editor):
    for name in ('Hunt', 'HistoricalHunt'):
        model = apps.get_model('hunts', name)
        for row in model.objects.exclude(trigger_source_link=''):
            row.trigger_source_links = [row.trigger_source_link]
            row.save(update_fields=['trigger_source_links'])


def list_to_single(apps, schema_editor):
    # Lossy by nature: only the first link survives a rollback.
    for name in ('Hunt', 'HistoricalHunt'):
        model = apps.get_model('hunts', name)
        for row in model.objects.exclude(trigger_source_links=[]):
            row.trigger_source_link = row.trigger_source_links[0]
            row.save(update_fields=['trigger_source_link'])


links = django.contrib.postgres.fields.ArrayField(
    base_field=models.URLField(), blank=True, default=list, size=None
)


class Migration(migrations.Migration):

    dependencies = [
        ('hunts', '0025_intelstory_query_data_sources'),
    ]

    operations = [
        migrations.AddField(model_name='hunt', name='trigger_source_links', field=links),
        migrations.AddField(model_name='historicalhunt', name='trigger_source_links', field=links),
        migrations.RunPython(single_to_list, list_to_single),
        migrations.RemoveField(model_name='historicalhunt', name='trigger_source_link'),
        migrations.RemoveField(model_name='hunt', name='trigger_source_link'),
        migrations.AddField(
            model_name='hunt',
            name='data_sources',
            field=models.ManyToManyField(blank=True, related_name='hunts', to='hunts.datasource'),
        ),
    ]
