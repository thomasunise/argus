"""Bounded IAM simulation must not report authorization as proven."""
import pytest

from app.ai.iam_policy import evaluate_identity_policies


def test_allow_is_potential_and_explicit_deny_wins():
    policy = {'Version': '2012-10-17', 'Statement': [
        {'Sid': 'AllowedReads', 'Effect': 'Allow', 'Action': ['s3:GetObject'], 'Resource': 'arn:aws:s3:::docs/*'},
        {'Sid': 'DeniedSecret', 'Effect': 'Deny', 'Action': 's3:getobject', 'Resource': 'arn:aws:s3:::docs/secret/*'},
    ]}
    allowed = evaluate_identity_policies([policy], 's3:GetObject', 'arn:aws:s3:::docs/manual.pdf')
    assert allowed['result'] == 'potentially_allowed_in_supplied_documents'
    assert allowed['effective_access_confirmed'] is False
    denied = evaluate_identity_policies([policy], 's3:GetObject', 'arn:aws:s3:::docs/secret/key.txt')
    assert denied['result'] == 'explicit_deny_in_supplied_documents'
    missing = evaluate_identity_policies([policy], 'ec2:TerminateInstances', '*')
    assert missing['result'] == 'not_allowed_by_supplied_documents'


def test_condition_is_indeterminate_not_allow():
    p = {'Statement': {'Effect': 'Allow', 'Action': '*', 'Resource': '*',
                      'Condition': {'Bool': {'aws:MultiFactorAuthPresent': 'true'}}}}
    out = evaluate_identity_policies([p], 'iam:CreateAccessKey', '*')
    assert out['result'] == 'indeterminate'
    assert out['uncertainties'][0]['reason'] == 'condition_not_evaluated'


def test_malformed_statements_are_indeterminate():
    assert evaluate_identity_policies([{'Statement': 'garbled'}], 's3:GetObject', '*')['result'] == 'indeterminate'
    with pytest.raises(ValueError):
        evaluate_identity_policies([], 's3:GetObject', '*')


def test_permission_api_requires_auth(owner, client):
    c, headers = owner
    body = {'policies': [{'Statement': {'Effect': 'Allow', 'Action': '*', 'Resource': '*'}}],
            'action': 's3:GetObject', 'resource': '*'}
    # The shared client already has the owner's session; mutating without CSRF is forbidden.
    assert client.post('/api/v1/cloud-permissions/aws/identity-policy/evaluate', json=body).status_code == 403
    r = c.post('/api/v1/cloud-permissions/aws/identity-policy/evaluate', json=body, headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()['effective_access_confirmed'] is False
