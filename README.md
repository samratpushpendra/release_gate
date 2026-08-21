# release-gate (Python)

A deterministic policy endpoint that decides whether a GitHub Actions run may
promote a container image, combining least-privilege CI permissions, complete
matrix testing, action pinning, and hardened Docker image checks.

## Endpoint

`POST /release-gate`

Request body: see `policy.py` for the exact fields consumed
(`target`, `event`, `ref`, `workflow.*`, `image.*`).

Response:

```json
{ "decision": "promote | block", "violations": ["CODE", "..."] }
```

`decision` is `"promote"` only when `violations` is empty.

### Violation codes

| Code | Meaning |
|---|---|
| `EXCESS_PERMISSION` | `workflow.permissions` isn't exactly `{contents:read, packages:write, id-token:none}` |
| `UNSAFE_PR_TRIGGER` | `workflow.trigger` is `pull_request_target` |
| `TESTS_INCOMPLETE` | tests didn't pass, matrix incomplete, or `failFast` is true |
| `MUTABLE_ACTION` | a non-`actions/*` action isn't pinned to a 40-char lowercase hex SHA |
| `SINGLE_STAGE_IMAGE` | `image.multiStage` is not `true` |
| `ROOT_RUNTIME` | `image.runsAsRoot` is not `false` |
| `SECRET_IN_LAYER` | `image.secretMode` is not `none` or `buildkit` |
| `CRITICAL_CVE` | `image.criticalVulnerabilities` is not `0` |
| `UNPINNED_IMAGE` | `image.digestPinned` is not `true` |
| `INVALID_PRODUCTION_REF` | `target=production` but not a `push` to `refs/heads/main` |
| `APPROVAL_REQUIRED` | `target=production` but `workflow.environmentApproval` isn't `true` |

## Run locally

```bash
pip install -r requirements.txt
python app.py                              # starts the server on PORT (default 3000)
python -m unittest discover -s tests -v    # runs the deterministic policy test suite
```

## Deploy

Deploy `app.py` anywhere that runs Python (Render, Railway, Fly.io, a VM,
PythonAnywhere, etc.) behind a production WSGI server (e.g. gunicorn) so
`POST https://<host>/release-gate` is reachable. `PORT` is read from the
environment.

Example production start command:

```bash
gunicorn -w 2 -b 0.0.0.0:$PORT app:app
```

## CI

`.github/workflows/tds-ga7-release-gate.yml` runs the test suite and a live
smoke test against the endpoint on every push to `main`.
