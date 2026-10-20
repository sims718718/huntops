"""Migration round-trip for the sigma_rules -> TaskSigmaRule conversion."""

from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase

BEFORE = ('hunts', '0017_comment')
AFTER = ('hunts', '0021_drop_task_dismissed_fields')


def migrate_to(target):
    executor = MigrationExecutor(connection)
    executor.loader.build_graph()
    executor.migrate([target])
    executor.loader.build_graph()
    return executor.loader.project_state([target]).apps


class SigmaStatusMigrationTests(TransactionTestCase):
    available_apps = ['hunts', 'django.contrib.auth', 'django.contrib.contenttypes']

    def tearDown(self):
        migrate_to(AFTER)

    def test_active_rules_become_pending_and_dismissed_rules_become_discarded(self):
        apps = migrate_to(BEFORE)
        Hunt = apps.get_model('hunts', 'Hunt')
        Objective = apps.get_model('hunts', 'Objective')
        Task = apps.get_model('hunts', 'Task')
        SigmaRule = apps.get_model('hunts', 'SigmaRule')

        hunt = Hunt.objects.create(number=1, title='Hunt')
        objective = Objective.objects.create(hunt=hunt, number=1, title='Objective')
        task = Task.objects.create(objective=objective, number=1, title='T')
        active_rule = SigmaRule.objects.create(
            rule_id='11111111-1111-1111-1111-111111111111', title='Active', raw_yaml=''
        )
        dismissed_rule = SigmaRule.objects.create(
            rule_id='22222222-2222-2222-2222-222222222222', title='Dismissed', raw_yaml=''
        )
        task.sigma_rules.add(active_rule)
        task.dismissed_sigma_rules.add(dismissed_rule)

        apps = migrate_to(AFTER)
        TaskSigmaRule = apps.get_model('hunts', 'TaskSigmaRule')

        statuses = dict(
            TaskSigmaRule.objects.filter(task_id=task.pk).values_list('sigma_rule__title', 'status')
        )
        self.assertEqual(statuses, {'Active': 'pending', 'Dismissed': 'discarded'})
