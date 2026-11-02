"""Sign a production rules-of-engagement grant with the independent engagement key.

Example:
  EXPLOIT_ROE_SIGNING_KEY=... python scripts/sign_production_roe.py \
    --tenant-id TENANT --asset-id ASSET --target https://host.example \
    --document ./signed-roe.pdf --expires-epoch 1835568000

The signing key should live on the independent approver's machine, not in the
ARGUS API operator's environment. The document SHA-256 is bound to the token;
ARGUS verifies the signature and asset binding, but cannot independently prove
a document's legal authority or the signer's identity.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.testing.authorization import sign_roe


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--tenant-id', required=True)
    parser.add_argument('--asset-id', required=True)
    parser.add_argument('--target', required=True)
    parser.add_argument('--document', type=Path, required=True)
    parser.add_argument('--expires-epoch', type=int, required=True)
    args = parser.parse_args()
    key = os.environ.get('EXPLOIT_ROE_SIGNING_KEY', '')
    if not key:
        parser.error('EXPLOIT_ROE_SIGNING_KEY is required')
    digest = hashlib.sha256(args.document.read_bytes()).hexdigest()
    print(sign_roe(key=key, tenant_id=args.tenant_id, asset_id=args.asset_id,
                   target=args.target, document_sha256=digest, expires_epoch=args.expires_epoch))


if __name__ == '__main__':
    main()
