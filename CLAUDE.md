# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

syPanel is a self-hosted web hosting control panel for Ubuntu 22.04/24.04 (Flask + SQLite, vanilla JS frontend). Status: Developer Preview. It has only been tested in sandbox mode, never end-to-end on a real VPS. The docs in `docs/` are in Indonesian: `ARCHITECTURE.md` (trust boundaries, storage), `API.md` (endpoint table), `FEATURE_MATRIX.md` (what is and isn't implemented), and `VERIFICATION.md`. Git remote: `github.com/Syamsuddin/syPANEL`, branch `main`.

## Commands

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt

python -m pytest tests -q                                    # full suite (sandbox, temp data dir)
python -m pytest tests/test_panel.py::test_update_resources  # single test
python -m pytest tests -q -k validation                      # by keyword

python manage.py create-admin     # prompts for a password (min. 12 chars); stored in ./var
python manage.py dev              # Flask on 127.0.0.1:8080 + worker subprocess; sandbox only

node --check sypanel/static/app.js
bash -n deploy/install.sh deploy/mail.sh deploy/enable-panel-ssl.sh
shasum -a 256 -c MANIFEST.sha256  # release manifest; goes stale when any listed file changes
```

There is no linter config and no JS build step. `tests/browser_smoke.cjs` is an optional Playwright check against a running sandbox. It needs `SYPANEL_TEST_URL`, `SYPANEL_TEST_USER` and `SYPANEL_TEST_PASSWORD`, and it refuses to run in live mode.

## Architecture

**Mutation pipeline.** Every change to the server is asynchronous:

1. `app.py` validates input with `core.validate(kind, data)`.
2. It inserts a `resources` row (`status='pending'`) and a `jobs` row whose payload is Fernet-encrypted, then returns HTTP 202.
3. `worker.py` claims one job at a time (`BEGIN IMMEDIATE`) and calls `core.agent(action, payload)`.
4. `agent.py`'s `Engine.dispatch` performs the operation.
5. The worker then sets the resource to `active`, deletes it on `.delete`, or sets it to `error`, and clears the job payload after success.

Jobs left `running` when the worker starts up are marked failed, never replayed. Actions are `<kind>.create|update|delete` plus `ssl`, `service`, `restore`. Reads (`metrics`, `logs`, `file`, `download`, `db_export`) call the agent synchronously from the request.

**Sandbox vs live** (`SYPANEL_MODE`, default `sandbox`). In sandbox, `core.agent()` builds an in-process `Engine(DATA/'sandbox', live=False)`. System config files are written under `var/sandbox/config/<absolute path>` (e.g. `var/sandbox/config/etc/nginx/conf.d/…`), and nothing calls `systemctl`, `nginx -t`, `mariadb`, etc. Tests assert on these generated files. In live mode, `core.agent()` sends JSON over a Unix socket to the root agent (`python -m sypanel.agent`). The agent authenticates the peer by `SO_PEERCRED` UID and only runs actions in its allowlist.

**Two independent state stores.** The panel keeps its state in SQLite (`resources`, owned by the `sypanel` user). The agent keeps its own state in `state.json`, keyed `"<kind>:<name>"` and writable only by root. The agent re-runs `core.validate` itself and never trusts the panel. A resource's `name` field is its unique key in both stores. Updates pass `_old_name` so the agent can re-key the entry. The two stores can drift after a partial failure, and there is no reconciliation.

**Agent apply/rollback pattern.** `Engine.dispatch`/`update` mutates `self.state` first, then applies it. `apply_config()` writes the file atomically, runs the service's config test (`nginx -t`, `php-fpmX -t`, `sshd -t`, `named-checkconf`), then reloads. On failure it restores the previous file and state and re-raises. DNS and mail are regenerated wholesale from state (`dns_apply`, `mail_apply`), not patched incrementally.

**File access.** Root never reads or writes inside a site's `public_html`, which the site user controls. In live mode, every file operation runs `sypanel/fileops.py` as a **standalone script** through `runuser -u <site uid>`, with path `/opt/sypanel/sypanel/fileops.py`. That includes the placeholder `index.html`, backups and restores. It must stay stdlib-only and must not use package-relative imports. It has two call styles:

- JSON on stdin for single operations (`list`, `read`, `write`, `mkdir`, `delete`), via `Engine.file`.
- A tar.gz stream through `argv[2]` = `archive` or `extract`, via `Engine.as_site`.

It walks paths with `O_NOFOLLOW` directory fds to block symlink and `..` escapes. Each site's OS user is `sy` + `sha256(domain)[:12]` (`Engine.uid`).

**Agent concurrency.** The agent handles each connection on its own thread. Actions in `READS` run in parallel. Every other action takes the global `LOCK`, so mutations stay serial. Anything slower than about 240 s fails, because that is how long `core.agent()` waits for a reply.

**Live layout** (created by `deploy/install.sh`):

- Services: `sypanel-agent` (root), `sypanel-web` (gunicorn on 127.0.0.1:8090 behind Nginx TLS on port 2409), `sypanel-worker`.
- Paths: code in `/opt/sypanel` (root-owned), panel data in `/var/lib/sypanel`, agent state in `/var/lib/sypanel-agent`, sites in `/srv/sypanel/sites/<domain>/public_html`.
- `sypanel-admin` wraps `manage.py` for live use.
- The installer refuses to run over an existing `/opt/sypanel`. There is no upgrade or migration path.

## Conventions and gotchas

- **Import-time side effects.** `sypanel.core` reads `SYPANEL_DATA`/`SYPANEL_MODE` and creates `encryption.key`/`session.key` when first imported. `sypanel.app` builds the app at import time (`app=create_app()`). `tests/test_panel.py` sets both env vars *before* importing `sypanel`. If you add another test file, move that setup into `tests/conftest.py`. Otherwise a file collected earlier (e.g. `test_agent.py`) would bind to `./var`.
- **Running jobs in tests.** A 202 response only means the job is queued. Call `worker.process_one()` to run it synchronously, then check the job status (see the `create()` helper in the tests).
- **Adding a resource kind** touches several places:
  - an entry in `FIELDS` and a branch in `validate()` in `core.py` (`KINDS` is derived from `FIELDS`)
  - an apply branch in `Engine.dispatch` (create/delete) and `Engine.update`, including the rollback block
  - `Engine.discard` if a failed create can leave leftovers
  - `meta`/`groups` in `static/app.js`
  - `docs/API.md`
- **Input whitelist.** `validate()` returns only `domain`, `name` and the kind's `FIELDS`. A new input field is silently dropped until you add it there.
- **Deleting unrecorded objects.** Deleting an object the agent has no state for (its create failed) goes to `Engine.discard`, which cleans up leftovers idempotently and succeeds, so the panel row can be removed.
- **Job safety.** A rename's new name is reserved while its job is queued (`claimed()` in `app.py`). Retry is refused when a newer job exists for the same resource. If the panel write fails after the agent has already succeeded, the worker clears the payload so the job can never be replayed.
- **Secrets.** Fields named `password`, `secret` or `token` are stripped by `core.public()` before they are stored in `resources.data` or agent state. The worker also redacts them from error messages. Keep any new secret field under one of those names. Database passwords go to `mariadb` through stdin, never argv.
- **Errors.** Raise `ValueError` with a user-facing message. The global error handler turns `ValueError`/`KeyError`/`TypeError` into a 400 with `str(e)`, and `sqlite3.IntegrityError` into a 409. All user-facing strings (errors, UI, CLI output) are in Indonesian; keep them that way.
- **No schema migrations.** `core.init()` only runs `CREATE TABLE IF NOT EXISTS`, so new columns will not reach existing databases.
- **Frontend.** `index.html` is a single-page shell and `app.js` renders every page. The CSP (`script-src 'self'`, `connect-src 'self'`) forbids inline scripts, inline event handlers, and external assets, so keep everything local. `style.css` is a single minified line.
- **Code style.** The Python is deliberately dense: several statements per line joined with `;`, short names, minimal whitespace. Match the surrounding style instead of reformatting it.
