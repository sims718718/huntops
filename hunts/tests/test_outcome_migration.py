"""Migration round-trip for the outcome_types -> Outcome conversion."""

from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase

BEFORE = ('hunts', '0011_dismissed_data_sources')
AFTER = ('hunts', '0014_drop_task_outcome_types')


def migrate_to(target):
    executor = MigrationExecutor(connection)
    executor.loader.build_graph()
    executor.migrate([target])
    executor.loader.build_graph()
    return executor.loader.project_state([target]).apps


class OutcomeMigrationTests(TransactionTestCase):
    available_apps = ['hunts', 'django.contrib.auth', 'django.contrib.contenttypes']

    def tearDown(self):
        migrate_to(AFTER)

    def test_array_values_become_one_row_each(self):
        apps = migrate_to(BEFORE)
        Hunt = apps.get_model('hunts', 'Hunt')
        Objective = apps.get_model('hunts', 'Objective')
        Task = apps.get_model('hunts', 'Task')

        hunt = Hunt.objects.create(number=1, title='Hunt')
        objective = Objective.objects.create(hunt=hunt, number=1, title='Objective')
        multi = Task.objects.create(
            objective=objective, number=1, title='Multi',
            outcome_types=['new_hunt_idea', 'analytics_detection'],
        )
        empty = Task.objects.create(objective=objective, number=2, title='Empty', outcome_types=[])

        apps = migrate_to(AFTER)
        Outcome = apps.get_model('hunts', 'Outcome')

        self.assertEqual(
            set(Outcome.objects.filter(task_id=multi.pk).values_list('outcome_type', flat=True)),
            {'new_hunt_idea', 'analytics_detection'},
        )
        self.assertEqual(Outcome.objects.filter(task_id=empty.pk).count(), 0)
