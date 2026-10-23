import hashlib
import json

from sqlalchemy import select

from .models import AuditEntry, utcnow


def record_audit(db, actor: str, action: str, subject: str = '', detail: str = ''):
    prev = db.execute(select(AuditEntry).order_by(AuditEntry.id.desc()).limit(1)).scalar_one_or_none()
    previous = prev.entry_hash if prev else '0' * 64
    time = utcnow()
    raw = json.dumps([previous, actor, action, subject, detail[:400], time.replace(tzinfo=None).isoformat()], separators=(',', ':'))
    entry = AuditEntry(actor=actor, action=action, subject=subject[:128], detail=detail[:400],
                       previous_hash=previous, entry_hash=hashlib.sha256(raw.encode()).hexdigest(), created_at=time)
    db.add(entry)
    db.flush()
    return entry


def verify_audit_chain(db):
    previous = '0'*64
    for entry in db.execute(select(AuditEntry).order_by(AuditEntry.id.asc())).scalars():
        raw = json.dumps([previous, entry.actor, entry.action, entry.subject, entry.detail, entry.created_at.replace(tzinfo=None).isoformat()], separators=(',', ':'))
        expected = hashlib.sha256(raw.encode()).hexdigest()
        if entry.previous_hash != previous or entry.entry_hash != expected:
            return False
        previous = entry.entry_hash
    return True
