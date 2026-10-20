from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required, permission_required
from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Count, Q
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.views.decorators.http import require_POST

from ..models import EnvironmentProfile, Hunt, Task
from .common import FacetSpec, FilterableListView


def model_choices(model, field):
    return model._meta.get_field(field).choices


class BoardView(FilterableListView):
    model = Hunt
    paginate_by = None
    template_name = 'hunts/hunt_board.html'
    partial_template_name = 'hunts/partials/_board.html'
    search_fields = ['title']
    facets = {
        'owner': FacetSpec('owner_id', 'Owner', lambda: [
            (str(u.pk), u.get_username()) for u in get_user_model().objects.all()]),
        'priority': FacetSpec('priority', 'Priority', lambda: model_choices(Hunt, 'priority')),
        'hunt_type': FacetSpec('hunt_type', 'Hunt type', lambda: model_choices(Hunt, 'hunt_type')),
        'environment': FacetSpec('environment_profile_id', 'Environment', lambda: [
            (str(e.pk), e.name) for e in EnvironmentProfile.objects.order_by('name')]),
    }

    def get_queryset(self):
        return (super().get_queryset().exclude(status=Hunt.ARCHIVED)
                .select_related('owner').annotate(
                    task_total=Count('objectives__tasks', distinct=True),
                    task_done=Count('objectives__tasks', distinct=True,
                                    filter=Q(objectives__tasks__status=Task.EXECUTED))))

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        labels = dict(model_choices(Hunt, 'status'))
        columns = {s: {'status': s, 'label': labels[s], 'hunts': [], 'blocked': 0}
                   for s in Hunt.STATUS_ORDER if s != Hunt.ARCHIVED}
        for hunt in context['object_list']:
            columns[hunt.status]['hunts'].append(hunt)
            columns[hunt.status]['blocked'] += int(hunt.gate_blocked)
        params = self.request.GET.copy()
        for key in list(params):
            if key not in ('q', *self.facets):
                del params[key]
        context.update(columns=list(columns.values()),
                       stage_choices=[(s, labels[s]) for s in columns],
                       board_query=params.urlencode(),
                       clear_url=reverse('hunt-board'))
        return context


hunt_board = BoardView.as_view()


@login_required
@permission_required('hunts.change_hunt', raise_exception=True)
@require_POST
def move_hunt(request, pk):
    error = ''
    with transaction.atomic():
        hunt = get_object_or_404(Hunt.objects.select_for_update(), pk=pk)
        target = request.POST.get('status', '')
        if target not in Hunt.STATUS_ORDER or target == Hunt.ARCHIVED:
            error = 'Choose a valid hunt stage.'
        elif target != hunt.status:
            previous = hunt.status
            hunt.status = target
            try:
                hunt.save(update_fields=['status'])
            except ValidationError as exc:
                hunt.status = previous
                error = ' '.join(exc.messages)
                # Only a feasibility-gate rejection is about unfilled feasibility fields.
                if error.startswith('Feasibility'):
                    missing = [f.verbose_name for f in Hunt._meta.fields
                               if f.name.startswith('feasibility_')
                               and 'override' not in f.name and not getattr(hunt, f.name)]
                    if missing:
                        error += ' Unfilled assessment fields: ' + ', '.join(missing) + '.'
    view = BoardView()
    view.setup(request)
    view.object_list = view.get_queryset()
    context = view.get_context_data(move_error=error, rejected_hunt=hunt if error else None)
    if not error and request.headers.get('HX-Request') != 'true':
        query = context['board_query']
        return HttpResponseRedirect(reverse('hunt-board') + ('?' + query if query else ''))
    return view.render_to_response(context)
