"""Fail if the mypy error count grows past the recorded baseline.

The codebase predates type checking (654 errors in 119 files when the gate was
introduced). Rather than weakening mypy config, CI ratchets: the count in
docs/mypy-baseline.txt may only go down. Lower it whenever you fix errors.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

BASELINE = Path(__file__).resolve().parents[1] / 'docs' / 'mypy-baseline.txt'


def main() -> int:
    allowed = int(BASELINE.read_text(encoding='utf-8').strip())
    proc = subprocess.run([sys.executable, '-m', 'mypy', 'app'], capture_output=True, text=True, check=False)
    match = re.search(r'Found (\d+) error', proc.stdout + proc.stderr)
    if match is None:
        if proc.returncode == 0:
            print('mypy: 0 errors (clean). Lower docs/mypy-baseline.txt to 0.')
            return 0
        print(proc.stdout[-2000:], proc.stderr[-2000:])
        print('mypy ratchet: could not parse mypy output')
        return 1
    count = int(match.group(1))
    print(f'mypy: {count} errors (baseline allows {allowed})')
    if count > allowed:
        print('mypy ratchet: error count grew. Fix the new errors; do not raise the baseline.')
        return 1
    if count < allowed:
        print(f'mypy ratchet: improved. Lower docs/mypy-baseline.txt to {count} in this change.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
