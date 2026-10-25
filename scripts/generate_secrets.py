"""Print fresh random values for the secrets Argus requires.

    python scripts/generate_secrets.py            # print KEY=value lines
    python scripts/generate_secrets.py --write    # fill the REPLACE_ placeholders (and empty AUDIT_SIGNING_KEY / DATA_ENCRYPTION_KEY / BACKUP_ENCRYPTION_KEY) in .env in place

Never commit the output. Rotation procedures are in docs/RUNBOOKS.md.
"""
from __future__ import annotations

import re
import secrets
import sys
from pathlib import Path

SECRETS = {
    'ADMIN_PASSWORD': lambda: secrets.token_urlsafe(24),      # >= 14 chars required by assert_safe_config
    'SESSION_SECRET': lambda: secrets.token_urlsafe(48),      # >= 32 chars required
    'INGEST_API_KEY': lambda: f'argus_{secrets.token_hex(4)}_{secrets.token_urlsafe(32)}',  # same shape as keys minted by the API
    'AUDIT_SIGNING_KEY': lambda: secrets.token_hex(32),       # HMAC key for the audit chain
    'DATA_ENCRYPTION_KEY': lambda: secrets.token_urlsafe(32),  # encryption at rest (required in production)
    'BACKUP_ENCRYPTION_KEY': lambda: secrets.token_urlsafe(32),  # encrypts backup files; keep a copy off the server
}


def main(argv: list[str]) -> int:
    values = {name: make() for name, make in SECRETS.items()}
    if '--write' in argv:
        env_path = Path(argv[argv.index('--write') + 1]) if len(argv) > argv.index('--write') + 1 else Path('.env')
        if not env_path.is_file():
            sys.stderr.write(f'{env_path} does not exist; copy .env.example first\n')
            return 1
        text = env_path.read_text(encoding='utf-8')
        replaced = []
        for name, value in values.items():
            # Replace REPLACE_ placeholders; the key variables are also filled when empty.
            optional = '?' if name in {'AUDIT_SIGNING_KEY', 'DATA_ENCRYPTION_KEY', 'BACKUP_ENCRYPTION_KEY'} else ''
            pattern = re.compile(rf'^{name}=(REPLACE_[^\n]*){optional}$', re.MULTILINE)
            if pattern.search(text):
                text = pattern.sub(f'{name}={value}', text, count=1)
                replaced.append(name)
        env_path.write_text(text, encoding='utf-8')
        sys.stdout.write('replaced placeholders: ' + (', '.join(replaced) or 'none') + '\n')
        return 0
    for name, value in values.items():
        sys.stdout.write(f'{name}={value}\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
