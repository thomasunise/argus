"""Attack-path evidence status should never imply exploit proof."""
from sqlalchemy import select

from app.graph import service
from app.graph.validation import validate_path
from app.models.graph import AttackPath
from tests.test_graph import estate


def test_paths_without_proof_are_unverified(db, default_tenant_id):
    service.apply(db, default_tenant_id, estate(), 'aws')
    paths = service.attack_paths(db, default_tenant_id)
    assert paths
    report = validate_path(db, default_tenant_id, paths[0])
    assert report['validation_status'] == 'unverified'
    assert report['score_is_proof'] is False
    assert report['exploitability_verified'] is False
    assert all(edge['status'] == 'unverified' for edge in report['edges'])
