"""A minimal SAML identity provider for tests: builds a Response whose Assertion carries a real enveloped XML
signature, the way Okta, Entra ID or ADFS post one to the assertion consumer service."""
from __future__ import annotations

import base64
import uuid
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from onelogin.saml2.constants import OneLogin_Saml2_Constants as C
from onelogin.saml2.utils import OneLogin_Saml2_Utils


def _ts(dt: datetime) -> str:
    return dt.strftime('%Y-%m-%dT%H:%M:%SZ')


class TestIdP:
    __test__ = False

    def __init__(self, entity_id: str = 'https://idp.corp.example/saml'):
        self.entity_id = entity_id
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'test-idp')])
        now = datetime.now(UTC)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=30)).sign(key, hashes.SHA256()))
        self.key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                         serialization.NoEncryption()).decode()
        self.cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()

    def response(self, *, base_url: str, in_response_to: str, email: str, groups: list[str] | None = None,
                 sign: bool = True, valid_for: int = 300, audience: str | None = None, recipient: str | None = None,
                 extra_attributes: dict[str, list[str]] | None = None) -> str:
        base = base_url.rstrip('/')
        acs = recipient or f'{base}/api/v1/auth/saml/acs'
        aud = audience or f'{base}/api/v1/auth/saml/metadata'
        now = datetime.now(UTC)
        nb, noa = _ts(now - timedelta(seconds=30)), _ts(now + timedelta(seconds=valid_for))
        attrs = {'groups': groups or [], **(extra_attributes or {})}
        attr_xml = ''.join(
            f'<saml:Attribute Name="{name}">' + ''.join(f'<saml:AttributeValue>{v}</saml:AttributeValue>' for v in values) + '</saml:Attribute>'
            for name, values in attrs.items() if values)
        assertion = (
            f'<saml:Assertion xmlns:saml="{C.NS_SAML}" xmlns:samlp="{C.NS_SAMLP}" ID="_a{uuid.uuid4().hex}" Version="2.0" IssueInstant="{_ts(now)}">'
            f'<saml:Issuer>{self.entity_id}</saml:Issuer>'
            f'<saml:Subject><saml:NameID Format="{C.NAMEID_EMAIL_ADDRESS}">{email}</saml:NameID>'
            f'<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
            f'<saml:SubjectConfirmationData NotOnOrAfter="{noa}" Recipient="{acs}" InResponseTo="{in_response_to}"/>'
            f'</saml:SubjectConfirmation></saml:Subject>'
            f'<saml:Conditions NotBefore="{nb}" NotOnOrAfter="{noa}"><saml:AudienceRestriction><saml:Audience>{aud}</saml:Audience></saml:AudienceRestriction></saml:Conditions>'
            f'<saml:AuthnStatement AuthnInstant="{_ts(now)}" SessionIndex="_s{uuid.uuid4().hex}"><saml:AuthnContext>'
            f'<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>'
            f'</saml:AuthnContext></saml:AuthnStatement>'
            + (f'<saml:AttributeStatement>{attr_xml}</saml:AttributeStatement>' if attr_xml else '')
            + '</saml:Assertion>')
        if sign:
            signed = OneLogin_Saml2_Utils.add_sign(assertion, self.key_pem, self.cert_pem,
                                                   sign_algorithm=C.RSA_SHA256, digest_algorithm=C.SHA256)
            assertion = signed.decode() if isinstance(signed, bytes) else signed
            assertion = assertion.split('?>', 1)[-1] if assertion.lstrip().startswith('<?xml') else assertion
        response = (
            f'<samlp:Response xmlns:samlp="{C.NS_SAMLP}" xmlns:saml="{C.NS_SAML}" ID="_r{uuid.uuid4().hex}" Version="2.0" '
            f'IssueInstant="{_ts(now)}" Destination="{acs}" InResponseTo="{in_response_to}">'
            f'<saml:Issuer>{self.entity_id}</saml:Issuer>'
            f'<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
            f'{assertion}</samlp:Response>')
        return base64.b64encode(response.encode()).decode()
