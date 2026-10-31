"""No false 'remediated' claim from scan-result comparison."""
from app.api.verification import compare_rules


def test_compare_rules_reports_changes_not_fixes():
    d = compare_rules(['old_issue', 'persistent'], ['persistent', 'new_issue'])
    assert d['no_longer_reproduced'] == ['old_issue']
    assert d['still_detected'] == ['persistent']
    assert d['newly_detected'] == ['new_issue']
