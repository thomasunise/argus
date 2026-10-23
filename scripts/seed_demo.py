"""Explicitly opt-in demo fixtures; never call these real alerts or scans."""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.config import get_settings
from app.database import make_db, init_db, session_scope
from app.models import Asset
from app.findings import add_finding, add_event, correlate_event
from app.audit import record_audit

settings=get_settings()
engine,factory=make_db(settings.database_url)
init_db(engine)
with session_scope(factory) as db:
    asset=Asset(name='DEMO · Staging web service',kind='web',target='https://example.org',environment='staging',approved=False)
    db.add(asset)
    db.flush()
    add_finding(db,asset_id=asset.id,source='demo-fixture',rule='demo-tls',title='[DEMO] TLS certificate nearing expiry',
                description='Illustrative finding only. This is not an actual scan of example.org.',
                remediation='Verify actual certificate expiration and review renewal automation.',severity_name='high')
    add_finding(db,asset_id=asset.id,source='demo-fixture',rule='demo-config',title='[DEMO] Cloud storage access misconfiguration',
                description='Illustrative finding only. No cloud environment has been checked.',
                remediation='Audit the storage access policy in the cloud provider.',severity_name='medium')
    e,_=add_event(db,source='demo-fixture',external_id=f'demo-event-{asset.id}',title='[DEMO] Unexpected process activity',
                severity_name='critical',asset_id=asset.id)
    correlate_event(db,e)
    record_audit(db,'demo','demo.seeded',asset.id,'Synthetic test records; not live telemetry')
print('Inserted synthetic demo data. These records are NOT security scan results.')
