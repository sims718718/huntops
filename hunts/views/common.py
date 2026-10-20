"""Server-rendered search/facets shared by lists and selection panels."""
from dataclasses import dataclass
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Q
from django.http import HttpResponse
from django.utils.cache import patch_vary_headers
from django.views.generic import ListView


def _markdown(content, filename):
    response = HttpResponse(content, content_type="text/markdown; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


@dataclass(frozen=True)
class FacetSpec:
    field: str
    label: str
    choices: object
    lookup: str = 'exact'
    wrap_in_list: bool = False


def text_search(queryset, query, fields):
    if not query.strip():
        return queryset
    condition = Q()
    for field in fields:
        condition |= Q(**{field + '__icontains': query.strip()})
    return queryset.filter(condition).distinct()


def values(model, field):
    return [(v, v) for v in model.objects.exclude(**{field: ''}).order_by(field).values_list(field, flat=True).distinct()]


class FilterableListView(LoginRequiredMixin, ListView):
    search_fields = ()
    search_vector = ''
    facets = {}
    partial_template_name = ''
    paginate_by = 50

    def facet_options(self):
        if not hasattr(self, '_facet_options'):
            self._facet_options = {key: list(spec.choices()) for key, spec in self.facets.items()}
        return self._facet_options

    def apply_facets(self, queryset):
        self.filter_error = ''
        for key, spec in self.facets.items():
            value = self.request.GET.get(key, '').strip()
            if not value:
                continue
            if value not in {str(k) for k, label in self.facet_options()[key]}:
                self.filter_error = 'Choose a valid filter value.'
                return queryset.none()
            queryset = queryset.filter(**{spec.field + '__' + spec.lookup: [value] if spec.wrap_in_list else value})
        return queryset.distinct()

    def apply_search(self, queryset):
        query = self.request.GET.get('q', '')
        if self.search_vector:
            from ..search import search_sigma
            return search_sigma(queryset, query)
        return text_search(queryset, query, self.search_fields)

    def get_queryset(self):
        return self.apply_search(self.apply_facets(super().get_queryset())).distinct()

    def get_template_names(self):
        if (self.partial_template_name and self.request.headers.get('HX-Request') == 'true'
                and self.request.headers.get('HX-History-Restore-Request') != 'true'):
            return [self.partial_template_name]
        return super().get_template_names()

    def render_to_response(self, context, **kwargs):
        response = super().render_to_response(context, **kwargs)
        patch_vary_headers(response, ['HX-Request', 'HX-History-Restore-Request'])
        return response

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update(q=self.request.GET.get('q', ''), filter_error=getattr(self, 'filter_error', ''),
            facet_controls=[{'param': key, 'label': spec.label, 'choices': self.facet_options()[key],
                             'selected': self.request.GET.get(key, '')} for key, spec in self.facets.items()])
        return context
