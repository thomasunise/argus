"""A software WebAuthn authenticator for tests: it produces the same attestation and assertion structures a browser
hands back from navigator.credentials.create() / .get(), so the server-side verification is exercised for real."""
from __future__ import annotations

import hashlib
import json
import os

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from webauthn.helpers import bytes_to_base64url


class SoftKey:
    def __init__(self, rp_id: str = '127.0.0.1', origin: str = 'http://127.0.0.1:8080'):
        self.rp_id, self.origin = rp_id, origin
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = os.urandom(32)
        self.sign_count = 0

    def _client_data(self, kind: str, challenge: str, origin: str | None = None) -> bytes:
        return json.dumps({'type': kind, 'challenge': challenge, 'origin': origin or self.origin, 'crossOrigin': False}).encode()

    def _auth_data(self, *, attested: bool, user_verified: bool = True, rp_id: str | None = None) -> bytes:
        flags = 0x01 | (0x04 if user_verified else 0) | (0x40 if attested else 0)
        data = hashlib.sha256((rp_id or self.rp_id).encode()).digest() + bytes([flags]) + self.sign_count.to_bytes(4, 'big')
        if attested:
            numbers = self.private_key.public_key().public_numbers()
            cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: numbers.x.to_bytes(32, 'big'), -3: numbers.y.to_bytes(32, 'big')})
            data += bytes(16) + len(self.credential_id).to_bytes(2, 'big') + self.credential_id + cose
        return data

    def attestation(self, options: dict, **overrides) -> dict:
        client_data = self._client_data('webauthn.create', options['challenge'], overrides.get('origin'))
        auth_data = self._auth_data(attested=True, user_verified=overrides.get('user_verified', True))
        attestation_object = cbor2.dumps({'fmt': 'none', 'attStmt': {}, 'authData': auth_data})
        cid = bytes_to_base64url(self.credential_id)
        return {'id': cid, 'rawId': cid, 'type': 'public-key', 'authenticatorAttachment': 'cross-platform',
                'response': {'clientDataJSON': bytes_to_base64url(client_data),
                             'attestationObject': bytes_to_base64url(attestation_object), 'transports': ['usb']},
                'clientExtensionResults': {}}

    def assertion(self, options: dict, **overrides) -> dict:
        self.sign_count += 1
        client_data = self._client_data('webauthn.get', options['challenge'], overrides.get('origin'))
        auth_data = self._auth_data(attested=False, user_verified=overrides.get('user_verified', True), rp_id=overrides.get('rp_id'))
        key = overrides.get('signing_key') or self.private_key
        signature = key.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        cid = bytes_to_base64url(self.credential_id)
        return {'id': cid, 'rawId': cid, 'type': 'public-key',
                'response': {'clientDataJSON': bytes_to_base64url(client_data), 'authenticatorData': bytes_to_base64url(auth_data),
                             'signature': bytes_to_base64url(signature), 'userHandle': None},
                'clientExtensionResults': {}}
