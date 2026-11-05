# Quality gates

Every push runs these gates in `.github/workflows/test.yml`. None of them may
be skipped to get a green build; fix the finding or record the debt here.

| Gate | Command | Policy |
|---|---|---|
| Tests (SQLite) | `python -m pytest -q --ignore=tests/test_frontend.py` | Must pass on Python 3.12 and 3.13 |
| Tests (PostgreSQL) | same, against Postgres 16 with migrations applied | Must pass |
| Browser e2e | `python -m pytest tests/test_frontend.py` (Playwright/Chromium) | Must pass |
| Lint | `python -m ruff check app tests sandbox` | Zero errors |
| Type ratchet | `python scripts/mypy_ratchet.py` | Error count may only go down |
| Security scan | `bandit -r app -ll -ii -b bandit-baseline.json`, `pip-audit` | No new medium+ findings |
| Containers | Docker build + smoke, Compose stack + smoke | Must pass |
| Infra | `terraform fmt/validate`, `tflint`, `helm lint --strict`, kubeconform | Must pass |

## Recorded debt

- **mypy**: 103 errors in 54 files at the last ratchet lowering
  (`docs/mypy-baseline.txt`). The ratchet fails CI if the count grows. Lower
  the baseline in the same change that fixes errors. Do not raise it, and do
  not weaken `[tool.mypy]` to make the count drop.
- **Cyclomatic complexity (ruff C901, max 18)**: the files listed under
  `[tool.ruff.lint.per-file-ignores]` in `pyproject.toml` predate the gate.
  New files are held to the limit. Remove a file from the list when its
  functions are split below 18.
- **Test fixtures**: literal passwords, tokens and `/tmp` paths in `tests/`
  are fixtures, not credentials (ruff `S105/S106/S107/S108/S603/S608/B017/E402`
  ignored for `tests/**` only).

## Local run

```bash
.venv/Scripts/python -m ruff check app tests sandbox   # Windows
.venv/bin/python -m ruff check app tests sandbox       # Linux/macOS
python scripts/mypy_ratchet.py
python -m pytest -q
```
