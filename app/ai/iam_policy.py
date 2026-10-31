"""Conservative offline AWS IAM identity-policy evaluator.

Matches a single action/resource against *supplied* identity-policy documents.
A matching Allow is not effective access: SCPs, session policies, boundaries,
resource policies, AWS conditions, and service-specific evaluation still matter.
Unknown fields cause indeterminate rather than an invented permission grant.
"""
from __future__ import annotations

import fnmatch
from typing import Any

MAX_DOCUMENTS = 20
MAX_STATEMENTS = 500


def _values(obj: Any) -> list[str] | None:
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, list) and all(isinstance(v, str) for v in obj):
        return obj
    return None


def _matches(patterns: list[str], value: str, *, casefold: bool = False) -> bool:
    text = value.lower() if casefold else value
    return any(fnmatch.fnmatchcase(text, pattern.lower() if casefold else pattern) for pattern in patterns)


def evaluate_identity_policies(policies: list[dict], action: str, resource: str) -> dict:
    if not isinstance(policies, list) or not 0 < len(policies) <= MAX_DOCUMENTS or any(not isinstance(x, dict) for x in policies):
        raise ValueError(f'Provide 1-{MAX_DOCUMENTS} IAM policy objects')
    if not isinstance(action, str) or not (1 <= len(action) <= 200):
        raise ValueError('action must be a nonempty string of at most 200 characters')
    if not isinstance(resource, str) or not (1 <= len(resource) <= 1024):
        raise ValueError('resource must be a nonempty string of at most 1024 characters')

    allows: list[dict] = []
    denies: list[dict] = []
    uncertain: list[dict] = []
    count = 0
    for index, document in enumerate(policies):
        statement = document.get('Statement')
        statements = statement if isinstance(statement, list) else [statement]
        if not statements or any(not isinstance(s, dict) for s in statements):
            uncertain.append({'document': index, 'reason': 'malformed_statement'})
            continue
        for offset, stmt in enumerate(statements):
            count += 1
            if count > MAX_STATEMENTS:
                raise ValueError('too many IAM statements')
            sid = str(stmt.get('Sid') or '')[:128]
            evidence = {'document': index, 'statement_index': offset, 'sid': sid}
            effect = stmt.get('Effect')
            actions = _values(stmt.get('Action'))
            resources = _values(stmt.get('Resource'))
            if actions is None or resources is None or effect not in {'Allow', 'Deny'}:
                uncertain.append({**evidence, 'reason': 'unsupported_statement'})
                continue
            if not _matches(actions, action, casefold=True) or not _matches(resources, resource):
                continue
            if any(key in stmt for key in ('NotAction', 'NotResource', 'Principal', 'NotPrincipal')):
                uncertain.append({**evidence, 'reason': 'unsupported_selector'})
                continue
            if stmt.get('Condition') is not None:
                # Conditions must be evaluated using real authenticated context.
                uncertain.append({**evidence, 'reason': 'condition_not_evaluated'})
                continue
            if effect == 'Deny':
                denies.append(evidence)
            else:
                allows.append(evidence)
    if denies:
        result = 'explicit_deny_in_supplied_documents'
    elif uncertain:
        result = 'indeterminate'
    elif allows:
        result = 'potentially_allowed_in_supplied_documents'
    else:
        result = 'not_allowed_by_supplied_documents'
    return {'action': action, 'resource': resource, 'result': result,
            'effective_access_confirmed': False, 'documents_checked': len(policies),
            'statements_checked': count, 'matching_allows': allows[:40],
            'matching_denies': denies[:40], 'uncertainties': uncertain[:40],
            'limitations': 'Identity policy documents alone cannot establish effective AWS access. '
                           'SCPs, permissions boundaries, session policies, resource policies and conditions are not evaluated.'}
