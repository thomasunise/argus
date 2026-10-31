from datetime import datetime, timedelta, timezone

from app.core.findings import upsert_event
from app.detections.engine import run
from app.models.detections import Detection
from app.integrations.inbound import ParseContext, registry


def test_modbus_write_is_passively_detected(db, default_tenant_id):
    p = registry.get('suricata')
    now = datetime.now(timezone.utc)
    for i, code in enumerate((3, 6)):
        payload = {'event_type': 'modbus', 'timestamp': (now-timedelta(minutes=5)).isoformat(),
                   'flow_id': 100, 'src_ip': '10.0.1.4', 'dest_ip': '10.0.1.5',
                   'app_proto': 'modbus', 'modbus': {'function_code': code, 'unit': 1}}
        draft = p.parse_item(payload, ParseContext(tenant_id=default_tenant_id, source='suricata'))[0]
        draft.external_id = str(i)
        upsert_event(db, default_tenant_id, draft)
    outcome = run(db, default_tenant_id, rule_ids=['industrial.modbus_write_observed'], now=now)
    assert outcome['detections_created'] == 1 and not outcome['errors']
    detection = db.query(Detection).filter(Detection.rule_id == 'industrial.modbus_write_observed',
                                          Detection.tenant_id == default_tenant_id).one()
    assert detection.entity == '10.0.1.5'
