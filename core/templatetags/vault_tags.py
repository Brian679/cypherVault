"""
CipherVault Template Tags
==========================
Custom template filters and tags.
"""

from django import template

register = template.Library()


@register.filter
def status_badge(status):
    """Return Bootstrap badge class for transfer status."""
    badges = {
        'pending': 'bg-secondary',
        'encrypting': 'bg-info',
        'sent': 'bg-primary',
        'received': 'bg-info',
        'decrypting': 'bg-info',
        'verified': 'bg-success',
        'failed': 'bg-danger',
        'rejected': 'bg-danger',
    }
    return badges.get(status, 'bg-secondary')


@register.filter
def action_badge(action):
    """Return Bootstrap badge class for audit log actions."""
    if 'fail' in action or 'reject' in action or 'attack' in action:
        return 'bg-danger'
    elif 'pass' in action or 'complete' in action or 'login' in action:
        return 'bg-success'
    elif 'generate' in action or 'rotate' in action:
        return 'bg-info'
    else:
        return 'bg-secondary'


@register.filter
def filesizeformat_custom(bytes_value):
    """Format file size as human-readable."""
    try:
        bytes_value = int(bytes_value)
    except (TypeError, ValueError):
        return '0 B'

    if bytes_value < 1024:
        return f'{bytes_value} B'
    elif bytes_value < 1024 ** 2:
        return f'{bytes_value / 1024:.1f} KB'
    elif bytes_value < 1024 ** 3:
        return f'{bytes_value / (1024 ** 2):.1f} MB'
    else:
        return f'{bytes_value / (1024 ** 3):.1f} GB'
