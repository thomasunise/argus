"""New network inputs preserve scoped bounded metadata."""
from app.integrations.inbound import registry, ParseContext


def test_suricata_eve_alert():
    parser = registry.get('suricata')
    events = parser.parse({'event_type': 'alert', 'flow_id': 22, 'src_ip': '10.0.0.1',
                           'dest_ip': '203.0.113.2', 'proto': 'TCP',
                           'alert': {'severity': 1, 'signature': 'Suspicious traffic'}},
                          ParseContext(tenant_id='test', source='suricata'))
    assert len(events) == 1
    assert events[0].category == 'network'
    assert events[0].severity == 'critical'
    assert events[0].metadata['src_ip'] == '10.0.0.1'


def test_zeek_connection():
    parser = registry.get('zeek')
    events = parser.parse([{'ts': 1770000000, 'uid': 'uid-1',
                           'id.orig_h': '10.0.0.1', 'id.resp_h': '10.0.0.2',
                           'id.resp_p': 443, '_path': 'conn'}],
                          ParseContext(tenant_id='test', source='zeek'))
    assert len(events) == 1
    assert events[0].action == 'network.conn'
    assert events[0].metadata['dst_ip'] == '10.0.0.2'
