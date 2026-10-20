import uuid

from django.contrib.auth import get_user_model
from django.test import TestCase

from ..models import Hunt, LibraryTask, Objective, SigmaRule, Task, Technique


class SearchTests(TestCase):
    def setUp(self):
        self.client.force_login(get_user_model().objects.create_user('searcher'))
        self.technique = Technique.objects.create(attack_id='T1059', name='Interpreter', tactics=['execution'])

    def test_sigma_browse_literal_search_and_detail(self):
        rule = SigmaRule.objects.create(rule_id=uuid.uuid4(), title='PowerShell',
            raw_yaml='Image|endswith: powershell.exe', author='Example', license='DRL-1.1')
        response = self.client.get('/sigma/', {'q': 'Image|endswith'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context['object_list']), [rule])
        self.assertContains(self.client.get(f'/sigma/{rule.rule_id}/'), 'Example')

    def test_library_searches_notes_and_facets_without_duplicate_rows(self):
        entry = LibraryTask.objects.create(title='Library entry', notes='needle', hunting_tool='Splunk')
        entry.techniques.add(self.technique)
        response = self.client.get('/library/', {'q': 'needle', 'tool': 'Splunk'})
        self.assertEqual(list(response.context['object_list']), [entry])

    def test_attack_live_results_and_history_restore(self):
        response = self.client.get('/attack/', HTTP_HX_REQUEST='true')
        self.assertContains(response, 'id="results"')
        self.assertNotContains(response, '<!doctype html>')
        restored = self.client.get('/attack/', HTTP_HX_REQUEST='true', HTTP_HX_HISTORY_RESTORE_REQUEST='true')
        self.assertContains(restored, '<!doctype html>')
        self.assertIn('HX-Request', response.headers['Vary'])

    def test_invalid_facet_is_an_explained_empty_result(self):
        response = self.client.get('/attack/', {'platform': 'not-a-platform'})
        self.assertEqual(len(response.context['object_list']), 0)
        self.assertContains(response, 'Choose a valid filter value')

    def test_library_pages_do_not_repeat_or_drop_rows(self):
        # annotate() clears Meta.ordering; without an explicit order_by the
        # paginator hands back an arbitrary slice per page.
        for n in range(60):
            LibraryTask.objects.create(title=f'Entry {n}')
        first = self.client.get('/library/')
        second = self.client.get('/library/', {'page': 2})
        self.assertTrue(first.context['object_list'].ordered)
        seen = [e.pk for e in first.context['object_list']] + [e.pk for e in second.context['object_list']]
        self.assertEqual(len(seen), len(set(seen)))
        self.assertEqual(len(seen), 60)

    def test_library_picker_searches_beyond_old_cap(self):
        hunt = Hunt.objects.create(title='Hunt')
        Objective.objects.create(hunt=hunt, title='Objective')
        wanted = LibraryTask.objects.create(title='Oldest needle')
        for n in range(201):
            LibraryTask.objects.create(title=f'New {n}')
        response = self.client.get(f'/hunts/{hunt.pk}/', {'library_q': 'needle'})
        self.assertEqual(list(response.context['library']), [wanted])

    def test_task_rule_picker_searches_literal_body(self):
        hunt = Hunt.objects.create(title='Hunt')
        obj = Objective.objects.create(hunt=hunt, title='Objective')
        task = Task.objects.create(objective=obj, title='Task')
        task.techniques.add(self.technique)
        for title, body in [('Wanted', 'Image|endswith: abc'), ('Unwanted', 'nothing')]:
            rule = SigmaRule.objects.create(rule_id=uuid.uuid4(), title=title, raw_yaml=body, status='experimental')
            rule.techniques.add(self.technique)
        response = self.client.get(f'/tasks/{task.pk}/', {'q': 'Image|endswith'})
        self.assertEqual([r.title for r in response.context['suggestions']], ['Wanted'])
