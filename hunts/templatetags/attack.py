"""Render ATT&CK prose.

MITRE's descriptions carry markdown links and "(Citation: ...)" markers straight from
STIX. Left raw they wreck the primary reading content on a technique page. Cleaning
happens here rather than at import so the stored text stays faithful to the source.
"""

import re

from django import template
from django.utils.html import escape
from django.utils.safestring import mark_safe

register = template.Library()

CITATION = re.compile(r"\s*\(Citation:[^)]*\)")
LINK = re.compile(r"\[([^\]]+)\]\((https?://[^)\s]+)\)")


@register.filter
def attack_prose(value):
    if not value:
        return ""
    text = CITATION.sub("", str(value))
    text = escape(text)
    # escape() has already neutralised the source, so building anchors here is safe
    text = LINK.sub(r'<a href="\2">\1</a>', text)
    return mark_safe(text.strip())
