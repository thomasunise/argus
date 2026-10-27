#!/usr/bin/env python3
"""One PoC, inside the sandbox container.

The runner does three things: read the script the executor mounted, execute it with a wall-clock
limit and bounded output, and print a single machine-readable trailer the executor parses out of
the pod log. It never talks to the network itself and holds no credentials.

Expected mount: /poc/script.py (read-only ConfigMap). Writable /tmp is provided by the Job.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

CODE_PATH = os.environ.get('ARGUS_CODE_PATH', '/poc/script.py')
MARKER = 'ARGUS_EXEC '


def _limit(name: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(name, default)))
    except (TypeError, ValueError):
        return default


def main(argv: list[str]) -> int:
    language = 'python'
    for index, value in enumerate(argv):
        if value == '--language' and index + 1 < len(argv):
            language = argv[index + 1]
    wall = _limit('ARGUS_WALL_SECONDS', 300)
    max_output = _limit('ARGUS_MAX_OUTPUT_BYTES', 5 * 1024 * 1024)

    if not os.path.exists(CODE_PATH):
        print(f'no script mounted at {CODE_PATH}', file=sys.stderr)
        print(MARKER + json.dumps({'exit_code': 126, 'timed_out': False, 'truncated': False}))
        return 126

    command = [sys.executable, CODE_PATH] if language == 'python' else ['/bin/bash', CODE_PATH]
    timed_out = False
    try:
        completed = subprocess.run(command, capture_output=True, timeout=wall, cwd='/tmp', check=False)
        stdout, stderr, exit_code = completed.stdout, completed.stderr, completed.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout, stderr, exit_code = exc.stdout or b'', exc.stderr or b'', 124
    except OSError as exc:
        print(f'could not start the interpreter: {type(exc).__name__}', file=sys.stderr)
        print(MARKER + json.dumps({'exit_code': 126, 'timed_out': False, 'truncated': False}))
        return 126

    truncated = len(stdout) > max_output or len(stderr) > max_output
    out = stdout[:max_output].decode('utf-8', 'replace')
    err = stderr[:max_output].decode('utf-8', 'replace')
    if out:
        print(out, end='' if out.endswith('\n') else '\n')
    if err:
        print(err, end='' if err.endswith('\n') else '\n', file=sys.stderr)
    print(MARKER + json.dumps({'exit_code': exit_code, 'timed_out': timed_out, 'truncated': truncated}))
    return 0 if exit_code == 0 and not timed_out else (124 if timed_out else 1)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
