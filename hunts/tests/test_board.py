from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.db import connection
from django.test import Client, TestCase
from django.test.utils import CaptureQueriesContext
from django.urls import reverse

from ..models import EnvironmentProfile, Hunt, Objective, Task


class BoardTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user('board-reader')
        self.client.force_login(self.user)

    def test_seven_columns_exclude_archived_hunts(self):
        Hunt.objects.create(title='Hidden archive', status=Hunt.ARCHIVED,
                            feasibility_decision='GO')
        response = self.client.get(reverse('hunt-board'))
        self.assertEqual([c['status'] for c in response.context['columns']],
                         Hunt.STATUS_ORDER[:-1])
        self.assertNotContains(response, 'Hidden archive')

    def test_progress_counts_tasks_across_objectives(self):
        hunt = Hunt.objects.create(title='Progress fixture')
        obj = Objective.objects.create(hunt=hunt, title='Work')
        Objective.objects.create(hunt=hunt, title='Empty objective')
        Task.objects.create(objective=obj, title='Done', status=Task.EXECUTED)
        Task.objects.create(objective=obj, title='Pending')
        response = self.client.get(reverse('hunt-board'))
        card = response.context['columns'][0]['hunts'][0]
        self.assertEqual((card.task_done, card.task_total), (1, 2))
        self.assertContains(response, '1/2 tasks')

    def test_filters_compose(self):
        Hunt.objects.create(title='Needle', owner=self.user, priority='high')
        Hunt.objects.create(title='Needle low', owner=self.user, priority='low')
        response = self.client.get(reverse('hunt-board'),
                                   {'q': 'Needle', 'priority': 'high', 'owner': self.user.pk})
        cards = [h for c in response.context['columns'] for h in c['hunts']]
        self.assertEqual([h.title for h in cards], ['Needle'])

    def test_partial_and_full_page(self):
        url = reverse('hunt-board')
        self.assertContains(self.client.get(url), '<!doctype html>', html=False)
        partial = self.client.get(url, HTTP_HX_REQUEST='true')
        self.assertContains(partial, 'id="board"')
        self.assertNotContains(partial, '<!doctype html>')

    def test_hunt_with_no_tasks_shows_placeholder_not_zero_of_zero(self):
        Hunt.objects.create(title='No tasks yet hunt')
        response = self.client.get(reverse('hunt-board'))
        card = response.context['columns'][0]['hunts'][0]
        self.assertEqual((card.task_done, card.task_total), (0, 0))
        self.assertContains(response, 'No tasks yet')
        self.assertNotContains(response, '0/0 tasks')

    def test_blocked_hunt_is_flagged_on_its_card_and_lane(self):
        Hunt.objects.create(title='Stuck', status=Hunt.FEASIBILITY_REVIEW)
        Hunt.objects.create(title='Cleared', status=Hunt.FEASIBILITY_REVIEW, feasibility_decision='GO')
        response = self.client.get(reverse('hunt-board'))
        self.assertContains(response, '1 blocked')
        self.assertContains(response, 'Blocked at the feasibility gate', count=1)

    def test_start_a_hunt_button_needs_add_permission(self):
        self.assertNotContains(self.client.get(reverse('hunt-board')), reverse('hunt-create'))
        self.user.user_permissions.add(Permission.objects.get(codename='add_hunt'))
        self.assertContains(self.client.get(reverse('hunt-board')), reverse('hunt-create'))

    def test_owner_facet_filters_board(self):
        other = get_user_model().objects.create_user('someone-else')
        Hunt.objects.create(title='Mine', owner=self.user)
        Hunt.objects.create(title='Theirs', owner=other)
        response = self.client.get(reverse('hunt-board'), {'owner': self.user.pk})
        cards = [h for c in response.context['columns'] for h in c['hunts']]
        self.assertEqual([h.title for h in cards], ['Mine'])

    def test_priority_facet_filters_board(self):
        Hunt.objects.create(title='Urgent', priority='high')
        Hunt.objects.create(title='Someday', priority='low')
        response = self.client.get(reverse('hunt-board'), {'priority': 'high'})
        cards = [h for c in response.context['columns'] for h in c['hunts']]
        self.assertEqual([h.title for h in cards], ['Urgent'])

    def test_hunt_type_facet_filters_board(self):
        Hunt.objects.create(title='Exploratory', hunt_type='EDA')
        Hunt.objects.create(title='Hypothesis-based', hunt_type='HBO')
        response = self.client.get(reverse('hunt-board'), {'hunt_type': 'EDA'})
        cards = [h for c in response.context['columns'] for h in c['hunts']]
        self.assertEqual([h.title for h in cards], ['Exploratory'])

    def test_environment_facet_filters_board(self):
        env = EnvironmentProfile.objects.create(name='Prod')
        Hunt.objects.create(title='In prod', environment_profile=env)
        Hunt.objects.create(title='No env set')
        response = self.client.get(reverse('hunt-board'), {'environment': env.pk})
        cards = [h for c in response.context['columns'] for h in c['hunts']]
        self.assertEqual([h.title for h in cards], ['In prod'])

    def test_empty_filtered_board_shows_no_hunts(self):
        Hunt.objects.create(title='Something', priority='low')
        response = self.client.get(reverse('hunt-board'), {'priority': 'high'})
        cards = [h for c in response.context['columns'] for h in c['hunts']]
        self.assertEqual(cards, [])
        self.assertContains(response, 'No hunts in this stage.')

    def test_invalid_facet_value_shows_filter_error(self):
        response = self.client.get(reverse('hunt-board'), {'owner': '999999'})
        self.assertContains(response, 'Choose a valid filter value.')

    def test_clear_link_targets_the_board_url(self):
        response = self.client.get(reverse('hunt-board'), {'priority': 'high'})
        self.assertContains(response, f'href="{reverse("hunt-board")}">Clear</a>')

    def test_anonymous_users_are_redirected_to_login(self):
        self.client.logout()
        response = self.client.get(reverse('hunt-board'))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse('login'), response.url)

    def test_query_count_stays_constant_as_hunts_grow(self):
        # Guards against N+1 queries from per-card lookups (e.g. hunt.owner,
        # task counts) that annotate()/select_related() are meant to avoid.
        # One hunt exists before either snapshot so both renders exercise the
        # per-request (not per-card) permission check the move-hunt form uses.
        Hunt.objects.create(title='Baseline hunt')
        url = reverse('hunt-board')
        with CaptureQueriesContext(connection) as before:
            self.client.get(url)
        for i in range(10):
            owner = get_user_model().objects.create_user(f'owner-{i}')
            hunt = Hunt.objects.create(title=f'Hunt {i}', owner=owner)
            obj = Objective.objects.create(hunt=hunt, title='Work')
            Task.objects.create(objective=obj, title='Done', status=Task.EXECUTED)
        with CaptureQueriesContext(connection) as after:
            self.client.get(url)
        self.assertEqual(len(before.captured_queries), len(after.captured_queries))


class MoveHuntTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user('board-mover')
        self.user.user_permissions.add(
            Permission.objects.get(codename='change_hunt', content_type__app_label='hunts'))
        self.client.force_login(self.user)
        self.hunt = Hunt.objects.create(title='Reviewed hunt', status=Hunt.FEASIBILITY_REVIEW)

    def test_rejected_move_keeps_database_and_history_unchanged(self):
        before = self.hunt.history.count()
        response = self.client.post(reverse('move-hunt', args=[self.hunt.pk]),
                                    {'status': Hunt.APPROVED}, HTTP_HX_REQUEST='true')
        self.hunt.refresh_from_db()
        self.assertEqual(self.hunt.status, Hunt.FEASIBILITY_REVIEW)
        self.assertEqual(self.hunt.history.count(), before)
        self.assertContains(response, 'Feasibility must be GO or CONDITIONAL')
        self.assertContains(response, reverse('hunt-update', args=[self.hunt.pk]))

    def test_go_decision_allows_the_move_past_the_gate(self):
        self.hunt.feasibility_decision = 'GO'
        self.hunt.save(update_fields=['feasibility_decision'])
        response = self.client.post(reverse('move-hunt', args=[self.hunt.pk]),
                                    {'status': Hunt.APPROVED})
        self.hunt.refresh_from_db()
        self.assertEqual(self.hunt.status, Hunt.APPROVED)
        self.assertRedirects(response, reverse('hunt-board'))

    def test_conditional_decision_allows_the_move_past_the_gate(self):
        self.hunt.feasibility_decision = 'CONDITIONAL'
        self.hunt.save(update_fields=['feasibility_decision'])
        response = self.client.post(reverse('move-hunt', args=[self.hunt.pk]),
                                    {'status': Hunt.APPROVED})
        self.hunt.refresh_from_db()
        self.assertEqual(self.hunt.status, Hunt.APPROVED)
        self.assertRedirects(response, reverse('hunt-board'))

    def test_hunt_lead_override_allows_the_move_past_the_gate(self):
        lead = get_user_model().objects.create_user('hunt-lead')
        self.hunt.feasibility_override_by = lead
        self.hunt.feasibility_override_reason = 'Time-boxed exception approved.'
        self.hunt.save(update_fields=['feasibility_override_by', 'feasibility_override_reason'])
        response = self.client.post(reverse('move-hunt', args=[self.hunt.pk]),
                                    {'status': Hunt.APPROVED})
        self.hunt.refresh_from_db()
        self.assertEqual(self.hunt.status, Hunt.APPROVED)
        self.assertRedirects(response, reverse('hunt-board'))

    def test_no_go_decision_rejects_the_move_even_with_every_field_filled(self):
        for field in ('feasibility_data_availability', 'feasibility_data_quality',
                      'feasibility_skillset', 'feasibility_timeline', 'feasibility_tooling'):
            setattr(self.hunt, field, 'GO')
        self.hunt.feasibility_decision = 'NO_GO'
        self.hunt.save()
        before = self.hunt.history.count()
        response = self.client.post(reverse('move-hunt', args=[self.hunt.pk]),
                                    {'status': Hunt.APPROVED})
        self.hunt.refresh_from_db()
        self.assertEqual(self.hunt.status, Hunt.FEASIBILITY_REVIEW)
        self.assertEqual(self.hunt.history.count(), before)
        self.assertContains(response, 'Feasibility must be GO or CONDITIONAL')
        self.assertNotContains(response, 'Unfilled assessment fields')

    def test_missing_assessment_fields_are_named_in_the_error(self):
        response = self.client.post(reverse('move-hunt', args=[self.hunt.pk]),
                                    {'status': Hunt.APPROVED})
        self.assertContains(response, 'Unfilled assessment fields')
        self.assertContains(response, 'feasibility decision')

    def test_backward_move_before_the_gate_does_not_require_clearance(self):
        response = self.client.post(reverse('move-hunt', args=[self.hunt.pk]),
                                    {'status': Hunt.SCOPING})
        self.hunt.refresh_from_db()
        self.assertEqual(self.hunt.status, Hunt.SCOPING)
        self.assertRedirects(response, reverse('hunt-board'))

    def test_missing_status_is_rejected(self):
        response = self.client.post(reverse('move-hunt', args=[self.hunt.pk]), {})
        self.hunt.refresh_from_db()
        self.assertEqual(self.hunt.status, Hunt.FEASIBILITY_REVIEW)
        self.assertContains(response, 'Choose a valid hunt stage.')

    def test_unknown_status_is_rejected(self):
        response = self.client.post(reverse('move-hunt', args=[self.hunt.pk]),
                                    {'status': 'not-a-real-status'})
        self.hunt.refresh_from_db()
        self.assertEqual(self.hunt.status, Hunt.FEASIBILITY_REVIEW)
        self.assertContains(response, 'Choose a valid hunt stage.')

    def test_no_op_status_is_a_successful_no_write(self):
        before = self.hunt.history.count()
        response = self.client.post(reverse('move-hunt', args=[self.hunt.pk]),
                                    {'status': Hunt.FEASIBILITY_REVIEW})
        self.hunt.refresh_from_db()
        self.assertEqual(self.hunt.status, Hunt.FEASIBILITY_REVIEW)
        self.assertEqual(self.hunt.history.count(), before)
        self.assertRedirects(response, reverse('hunt-board'))

    def test_archived_status_is_rejected(self):
        response = self.client.post(reverse('move-hunt', args=[self.hunt.pk]),
                                    {'status': Hunt.ARCHIVED})
        self.hunt.refresh_from_db()
        self.assertEqual(self.hunt.status, Hunt.FEASIBILITY_REVIEW)
        self.assertContains(response, 'Choose a valid hunt stage.')

    def test_missing_hunt_returns_404(self):
        response = self.client.post(reverse('move-hunt', args=[999999]),
                                    {'status': Hunt.SCOPING})
        self.assertEqual(response.status_code, 404)

    def test_get_is_not_allowed(self):
        response = self.client.get(reverse('move-hunt', args=[self.hunt.pk]))
        self.assertEqual(response.status_code, 405)

    def test_user_without_permission_is_forbidden(self):
        other = get_user_model().objects.create_user('no-perm')
        self.client.force_login(other)
        response = self.client.post(reverse('move-hunt', args=[self.hunt.pk]),
                                    {'status': Hunt.SCOPING})
        self.assertEqual(response.status_code, 403)

    def test_csrf_is_enforced(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        response = client.post(reverse('move-hunt', args=[self.hunt.pk]),
                               {'status': Hunt.SCOPING})
        self.assertEqual(response.status_code, 403)

    def test_successful_move_creates_exactly_one_historical_record_for_the_requester(self):
        self.hunt.feasibility_decision = 'GO'
        self.hunt.save(update_fields=['feasibility_decision'])
        before = self.hunt.history.count()
        self.client.post(reverse('move-hunt', args=[self.hunt.pk]), {'status': Hunt.APPROVED})
        self.hunt.refresh_from_db()
        self.assertEqual(self.hunt.history.count(), before + 1)
        self.assertEqual(self.hunt.history.first().history_user_id, self.user.pk)

    def test_normal_post_redirects_preserving_only_board_filter_params(self):
        self.hunt.feasibility_decision = 'GO'
        self.hunt.save(update_fields=['feasibility_decision'])
        url = reverse('move-hunt', args=[self.hunt.pk]) + f'?owner={self.user.pk}&bogus=x'
        response = self.client.post(url, {'status': Hunt.APPROVED})
        self.assertRedirects(response, reverse('hunt-board') + f'?owner={self.user.pk}')
