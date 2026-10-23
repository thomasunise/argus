"""Microsoft Entra ID executors. Same Graph calls as azure.ad.*, but credentials come from the
'entra' namespace (ACTIONS_ENTRA_*), falling back to the Azure app registration."""
from __future__ import annotations

from ..catalog import register
from .azure import DisableUser


@register
class EntraDisableUser(DisableUser):
    name = 'entra.user.disable'
    description = 'Block sign-in for an Entra ID user by setting accountEnabled=false (Graph PATCH /users/{id}). Rollback re-enables the account.'
    platforms = ['entra']
    platform = 'entra'
