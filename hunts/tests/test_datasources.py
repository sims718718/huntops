import copy
import json
import os
import tempfile

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.db import IntegrityError
from django.test import TestCase

from ..models import DataSource, Hunt, LibraryTask, Objective, Task, Technique
from .test_legacy import BUNDLE


def import_bundle(bundle):
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, 'bundle.json')
        with open(path, 'w', encoding='utf-8') as handle:
            json.dump(bundle, handle)
        call_command('import_attack', file=path, verbosity=0)


class DataSourceModelTests(TestCase):
    def test_mitre_labels_split_into_a_category(self):
        self.assertEqual(DataSource.category_of('Process: Process Creation'), 'Process')

    def test_near_miss_strings_have_no_category(self):
        # MITRE uses ": " with a space. These are vendor channel names from the
        # library seed, not ATT&CK labels, and must not be split.
        for name in ['Sysmon:EventID 1', 'Network Traffic:Network Connection Creation', 'Proxy logs']:
            with self.subTest(name=name):
                self.assertEqual(DataSource.category_of(name), '')

    def test_names_are_unique(self):
        DataSource.objects.create(name='Process: Process Creation')
        with self.assertRaises(IntegrityError):
            DataSource.objects.create(name='Process: Process Creation')

    def test_custom_is_the_default_origin(self):
        self.assertEqual(DataSource.objects.create(name='Zeek conn.log').origin, DataSource.CUSTOM)


LABEL = 'Active Directory: Active Directory Credential Request'


class DataSourceSyncTests(TestCase):
    """import_attack derives DataSource rows from Technique.data_sources, which
    stays the ArrayField the STIX resolver writes."""

    def test_rows_are_created_with_mitre_origin_and_category(self):
        import_bundle(BUNDLE)
        row = DataSource.objects.get(name=LABEL)
        self.assertEqual(row.origin, DataSource.MITRE)
        self.assertEqual(row.category, 'Active Directory')
        self.assertEqual([t.attack_id for t in row.techniques.all()], ['T1558.003'])

    def test_rows_exist_even_when_no_task_uses_them(self):
        # Suggestions must work on a fresh install without a second import.
        import_bundle(BUNDLE)
        self.assertTrue(DataSource.objects.filter(origin=DataSource.MITRE).exists())

    def test_running_twice_does_not_duplicate(self):
        import_bundle(BUNDLE)
        first = DataSource.objects.count()
        import_bundle(BUNDLE)
        self.assertEqual(DataSource.objects.count(), first)

    def test_a_bundle_that_drops_a_mapping_clears_it(self):
        # The resolver used to union labels into the stored array, so a mapping
        # removed upstream could never be cleared and the derived links went stale.
        import_bundle(BUNDLE)
        self.assertEqual(Technique.objects.get(attack_id='T1558.003').data_sources, [LABEL])

        trimmed = copy.deepcopy(BUNDLE)
        for obj in trimmed['objects']:
            if obj.get('type') == 'x-mitre-analytic':
                obj['x_mitre_log_source_references'] = []
        import_bundle(trimmed)

        self.assertEqual(Technique.objects.get(attack_id='T1558.003').data_sources, [])
        self.assertEqual(list(DataSource.objects.get(name=LABEL).techniques.all()), [])

    def test_custom_rows_are_never_reclassified_or_unlinked(self):
        DataSource.objects.create(name='Zeek conn.log', origin=DataSource.CUSTOM)
        import_bundle(BUNDLE)
        self.assertEqual(DataSource.objects.get(name='Zeek conn.log').origin, DataSource.CUSTOM)


class DataSourceConversionTests(TestCase):
    def setUp(self):
        self.hunt = Hunt.objects.create(title='Kerberoasting')
        self.objective = Objective.objects.create(hunt=self.hunt, title='Find SPN abuse')

    def _task(self, **kwargs):
        task = Task.objects.create(objective=self.objective, title='Ticket volume', **kwargs)
        task.suppress_auto_sigma = True
        return task

    def test_data_sources_are_related_objects(self):
        task = self._task()
        task.data_sources.add(DataSource.objects.create(name='WinEventLog:Security'))
        self.assertEqual(list(task.data_sources.values_list('name', flat=True)), ['WinEventLog:Security'])

    def test_fork_copies_selections_without_live_linking(self):
        entry = LibraryTask.objects.create(title='Ticket volume')
        entry.suppress_auto_sigma = True
        entry.data_sources.add(DataSource.objects.create(name='WinEventLog:Security'))

        task = entry.fork_into(self.objective)
        entry.data_sources.clear()
        self.assertEqual(list(task.data_sources.values_list('name', flat=True)), ['WinEventLog:Security'])

    def test_duplicate_copies_selections_without_sharing(self):
        entry = LibraryTask.objects.create(title='Ticket volume')
        entry.suppress_auto_sigma = True
        entry.data_sources.add(DataSource.objects.create(name='WinEventLog:Security'))

        copied = entry.duplicate()
        copied.data_sources.clear()
        self.assertEqual(entry.data_sources.count(), 1)

    def test_promote_carries_selections_into_the_library(self):
        task = self._task()
        task.data_sources.add(DataSource.objects.create(name='Sysmon:EventID 1'))
        promoted = task.promote_to_library()
        self.assertEqual(list(promoted.data_sources.values_list('name', flat=True)), ['Sysmon:EventID 1'])

    def test_seed_library_creates_rows_and_keeps_near_misses_custom(self):
        call_command('seed_library', verbosity=0)
        self.assertTrue(DataSource.objects.filter(name='WinEventLog:Security').exists())
        near_miss = DataSource.objects.get(name='Network Traffic:Network Connection Creation')
        self.assertEqual(near_miss.origin, DataSource.CUSTOM)
        self.assertEqual(near_miss.category, '')

    def test_handoff_still_lists_data_sources(self):
        from .. import reporting

        task = self._task()
        task.data_sources.add(DataSource.objects.create(name='WinEventLog:Security'))
        self.assertIn('WinEventLog:Security', reporting.task_handoff_markdown(task))


class DataSourceAutoAttachTests(TestCase):
    """Same contract as the Sigma auto-attach this mirrors."""

    def setUp(self):
        import_bundle(BUNDLE)
        self.technique = Technique.objects.get(attack_id='T1558.003')
        hunt = Hunt.objects.create(title='Credential access')
        self.objective = Objective.objects.create(hunt=hunt, title='Kerberoasting')

    def test_selecting_a_technique_attaches_its_data_sources(self):
        task = Task.objects.create(objective=self.objective, title='Ticket volume')
        task.techniques.add(self.technique)
        self.assertEqual(list(task.data_sources.values_list('name', flat=True)), [LABEL])

    def test_curated_entries_keep_their_own_selection(self):
        entry = LibraryTask.objects.create(title='Curated')
        entry.suppress_auto_sigma = True
        entry.techniques.add(self.technique)
        self.assertEqual(entry.data_sources.count(), 0)

    def test_library_entry_dismissed_sources_do_not_come_back(self):
        # LibraryTask keeps dismissed_data_sources (only Task's copy was removed -
        # library entries have no per-attachment status to fall back on instead).
        entry = LibraryTask.objects.create(title='Curated')
        entry.techniques.add(self.technique)
        source = entry.data_sources.get()
        entry.data_sources.remove(source)
        entry.dismissed_data_sources.add(source)

        entry.techniques.clear()
        entry.techniques.add(self.technique)
        self.assertEqual(entry.data_sources.count(), 0)

    def test_library_entries_auto_attach_too(self):
        entry = LibraryTask.objects.create(title='Uncurated')
        entry.techniques.add(self.technique)
        self.assertEqual(entry.data_sources.count(), 1)

    def test_existing_selections_are_never_removed(self):
        task = Task.objects.create(objective=self.objective, title='Ticket volume')
        own = DataSource.objects.create(name='Zeek conn.log')
        task.data_sources.add(own)
        task.techniques.add(self.technique)
        self.assertIn('Zeek conn.log', task.data_sources.values_list('name', flat=True))


class DataSourceFacetTests(TestCase):
    def setUp(self):
        self.client.force_login(get_user_model().objects.create_user('facets'))
        import_bundle(BUNDLE)

    def test_attack_list_filters_by_data_source(self):
        response = self.client.get('/attack/', {'data_source': LABEL})
        self.assertEqual(
            [t.attack_id for t in response.context['object_list']], ['T1558.003']
        )

    def test_library_list_filters_by_data_source(self):
        wanted = LibraryTask.objects.create(title='Wanted')
        wanted.suppress_auto_sigma = True
        wanted.data_sources.add(DataSource.objects.get(name=LABEL))
        LibraryTask.objects.create(title='Other')

        response = self.client.get('/library/', {'data_source': LABEL})
        self.assertEqual([e.title for e in response.context['object_list']], ['Wanted'])

    def test_library_search_reaches_data_source_names(self):
        entry = LibraryTask.objects.create(title='Wanted')
        entry.suppress_auto_sigma = True
        entry.data_sources.add(DataSource.objects.create(name='Zeek conn.log'))
        response = self.client.get('/library/', {'q': 'Zeek'})
        self.assertEqual([e.title for e in response.context['object_list']], ['Wanted'])


class DataSourceHistoryTests(TestCase):
    """Converting away from an ArrayField must not silently drop the audit trail."""

    def setUp(self):
        hunt = Hunt.objects.create(title='Kerberoasting')
        self.objective = Objective.objects.create(hunt=hunt, title='Find SPN abuse')

    def test_history_records_the_names_a_task_had(self):
        task = Task.objects.create(objective=self.objective, title='Ticket volume')
        task.suppress_auto_sigma = True
        task.data_sources.add(DataSource.objects.create(name='WinEventLog:Security'))

        task.title = 'Ticket volume v2'
        task.save()
        self.assertEqual(task.history.first().data_source_names_snapshot, ['WinEventLog:Security'])

    def test_snapshot_keeps_the_old_name_after_a_rename(self):
        # The snapshot is immutable text on purpose: renaming a shared DataSource
        # must not rewrite what an executed hunt recorded at the time.
        task = Task.objects.create(objective=self.objective, title='Ticket volume')
        task.suppress_auto_sigma = True
        source = DataSource.objects.create(name='WinEventLog:Security')
        task.data_sources.add(source)
        task.save()

        source.name = 'Renamed'
        source.save()
        self.assertEqual(task.history.first().data_source_names_snapshot, ['WinEventLog:Security'])
