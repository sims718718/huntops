"""Migration round-trip for the data-source conversion.

TransactionTestCase because MigrationExecutor runs its own transactions, and the
schema is restored in tearDown so later tests see the current models. This runs
against the disposable test database only - never a populated one.
"""

from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase

BEFORE = ('hunts', '0007_datasource')
AFTER = ('hunts', '0010_historical_data_source_m2m')


def migrate_to(target):
    executor = MigrationExecutor(connection)
    executor.loader.build_graph()
    executor.migrate([target])
    executor.loader.build_graph()
    return executor.loader.project_state([target]).apps


class DataSourceMigrationTests(TransactionTestCase):
    available_apps = ['hunts', 'django.contrib.auth', 'django.contrib.contenttypes']

    def tearDown(self):
        migrate_to(AFTER)

    def test_arrays_convert_to_relations_and_back(self):
        apps = migrate_to(BEFORE)
        Technique = apps.get_model('hunts', 'Technique')
        Hunt = apps.get_model('hunts', 'Hunt')
        Objective = apps.get_model('hunts', 'Objective')
        Task = apps.get_model('hunts', 'Task')
        LibraryTask = apps.get_model('hunts', 'LibraryTask')

        Technique.objects.create(
            attack_id='T1003', name='OS Credential Dumping',
            data_sources=['Process: OS API Execution'],
        )
        hunt = Hunt.objects.create(number=1, title='Hunt')
        objective = Objective.objects.create(hunt=hunt, number=1, title='Objective')
        # An exact MITRE label, a near-miss vendor string, and an empty task.
        keeper = Task.objects.create(
            objective=objective, number=1, title='Keeper',
            data_sources=['Process: OS API Execution', 'Sysmon:EventID 1'],
        )
        empty = Task.objects.create(objective=objective, number=2, title='Empty', data_sources=[])
        entry = LibraryTask.objects.create(number=1, title='Entry', data_sources=['Proxy logs'])

        apps = migrate_to(AFTER)
        DataSource = apps.get_model('hunts', 'DataSource')
        Task = apps.get_model('hunts', 'Task')
        LibraryTask = apps.get_model('hunts', 'LibraryTask')

        self.assertEqual(
            set(Task.objects.get(pk=keeper.pk).data_sources.values_list('name', flat=True)),
            {'Process: OS API Execution', 'Sysmon:EventID 1'},
        )
        self.assertEqual(Task.objects.get(pk=empty.pk).data_sources.count(), 0)
        self.assertEqual(
            list(LibraryTask.objects.get(pk=entry.pk).data_sources.values_list('name', flat=True)),
            ['Proxy logs'],
        )
        # Exact match against a technique label is mitre; everything else custom.
        self.assertEqual(DataSource.objects.get(name='Process: OS API Execution').origin, 'mitre')
        self.assertEqual(DataSource.objects.get(name='Sysmon:EventID 1').origin, 'custom')
        self.assertEqual(DataSource.objects.get(name='Sysmon:EventID 1').category, '')

        # Clearing a relation must come back as an empty array, not a stale value.
        Task.objects.get(pk=keeper.pk).data_sources.clear()

        apps = migrate_to(BEFORE)
        Task = apps.get_model('hunts', 'Task')
        LibraryTask = apps.get_model('hunts', 'LibraryTask')
        self.assertEqual(Task.objects.get(pk=keeper.pk).data_sources, [])
        self.assertEqual(Task.objects.get(pk=empty.pk).data_sources, [])
        self.assertEqual(LibraryTask.objects.get(pk=entry.pk).data_sources, ['Proxy logs'])

    def test_historical_rows_keep_their_names_verbatim(self):
        apps = migrate_to(BEFORE)
        HistoricalTask = apps.get_model('hunts', 'HistoricalTask')
        Hunt = apps.get_model('hunts', 'Hunt')
        Objective = apps.get_model('hunts', 'Objective')
        Task = apps.get_model('hunts', 'Task')

        hunt = Hunt.objects.create(number=1, title='Hunt')
        objective = Objective.objects.create(hunt=hunt, number=1, title='Objective')
        task = Task.objects.create(objective=objective, number=1, title='T', data_sources=[])
        # Two revisions, with duplicates and a deliberate non-alphabetical order
        # that the relation could not represent.
        messy = ['Sysmon:EventID 1', 'Process: OS API Execution', 'Sysmon:EventID 1']
        for revision, names in enumerate([messy, ['Proxy logs']]):
            HistoricalTask.objects.create(
                id=task.pk, objective_id=objective.pk, number=1, title='T',
                data_sources=names, history_date=f'2026-01-0{revision + 1}T00:00:00Z',
                history_type='~', status='not_started',
            )

        apps = migrate_to(AFTER)
        HistoricalTask = apps.get_model('hunts', 'HistoricalTask')
        snapshots = list(
            HistoricalTask.objects.order_by('history_date')
            .values_list('data_source_names_snapshot', flat=True)
        )
        self.assertEqual(snapshots, [messy, ['Proxy logs']])


class TriggerLinkMigrationTests(TransactionTestCase):
    available_apps = ['hunts', 'django.contrib.auth', 'django.contrib.contenttypes']
    BEFORE = ('hunts', '0025_intelstory_query_data_sources')
    AFTER = ('hunts', '0026_hunt_links_and_data_sources')

    def tearDown(self):
        migrate_to(self.AFTER)

    def test_single_link_becomes_a_list_and_back(self):
        apps = migrate_to(self.BEFORE)
        Hunt = apps.get_model('hunts', 'Hunt')
        linked = Hunt.objects.create(number=1, title='Linked', trigger_source_link='https://example.com/a')
        bare = Hunt.objects.create(number=2, title='Bare')

        apps = migrate_to(self.AFTER)
        Hunt = apps.get_model('hunts', 'Hunt')
        self.assertEqual(Hunt.objects.get(pk=linked.pk).trigger_source_links, ['https://example.com/a'])
        self.assertEqual(Hunt.objects.get(pk=bare.pk).trigger_source_links, [])

        Hunt.objects.filter(pk=linked.pk).update(trigger_source_links=['https://example.com/a', 'https://b.example'])
        apps = migrate_to(self.BEFORE)
        Hunt = apps.get_model('hunts', 'Hunt')
        self.assertEqual(Hunt.objects.get(pk=linked.pk).trigger_source_link, 'https://example.com/a')
        self.assertEqual(Hunt.objects.get(pk=bare.pk).trigger_source_link, '')


class LibraryKeyMigrationTests(TransactionTestCase):
    available_apps = ['hunts', 'django.contrib.auth', 'django.contrib.contenttypes']
    BEFORE = ('hunts', '0026_hunt_links_and_data_sources')
    AFTER = ('hunts', '0027_librarytask_key')

    def tearDown(self):
        migrate_to(self.AFTER)

    def test_team_built_entries_get_keys_and_reference_entries_stay_blank(self):
        apps = migrate_to(self.BEFORE)
        LibraryTask = apps.get_model('hunts', 'LibraryTask')
        first = LibraryTask.objects.create(number=1, title='Same title')
        second = LibraryTask.objects.create(number=2, title='Same title')
        reference = LibraryTask.objects.create(number=3, title='Ref', seed_key='s', provenance='curated')

        apps = migrate_to(self.AFTER)
        LibraryTask = apps.get_model('hunts', 'LibraryTask')
        keys = {pk: LibraryTask.objects.get(pk=pk).key for pk in (first.pk, second.pk, reference.pk)}
        self.assertEqual(keys, {first.pk: 'same-title', second.pk: 'same-title-2', reference.pk: ''})

        migrate_to(self.BEFORE)  # reversible
