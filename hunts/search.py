"""Shared Sigma search used by browsing, attachment and imports."""
from django.contrib.postgres.search import SearchQuery, SearchRank, SearchVector
from django.db.models import Case, IntegerField, Q, Value, When

SIGMA_VECTOR = (
    SearchVector('title', weight='A', config='english')
    + SearchVector('description', weight='B', config='english')
    + SearchVector('logsource_product', 'logsource_service', 'logsource_category', 'author', weight='C', config='english')
    + SearchVector('raw_yaml', weight='D', config='english')
)


def refresh_sigma_search(queryset=None):
    from .models import SigmaRule
    return (SigmaRule.objects.all() if queryset is None else queryset).update(search=SIGMA_VECTOR)


def search_sigma(queryset, query):
    query = query.strip()
    if not query:
        return queryset.order_by('title', 'pk')
    search = SearchQuery(query, config='english', search_type='websearch')
    match = Q(search=search)
    if any(char in query for char in '|\\/'):
        match |= Q(raw_yaml__icontains=query)
    return queryset.filter(match).annotate(
        title_match=Case(When(title__icontains=query, then=Value(1)), default=Value(0), output_field=IntegerField()),
        rank=SearchRank('search', search),
    ).order_by('-title_match', '-rank', 'pk').distinct()
