# WORKFLOW_STATE — Authentik Proxy Header Auth for MLflow

## Task
Switch MLflow tracking-server authentication to Authentik PROXY HEADER auth
(per `authentik-proxy-user-data.md`), community/open-source code only, on the
fork's `master` branch. JIT provisioning, prefix-stripped group→role mapping
with reject-if-no-prefixed-group, trust boundary, skip native login UI.

## Current Auth Mechanism (findings)

MLflow server is a Flask app (`mlflow.server.app:app`) optionally wrapped in a
FastAPI app when run under uvicorn. Auth is an opt-in **app plugin** selected
via `mlflow server --app-name <name>`. Entry points live in `pyproject.toml`
under `[project.entry-points."mlflow.app"]`.

The community auth plugin is **`basic-auth`** → `mlflow.server.auth:create_app`
(a factory). `mlflow.app.client` → `mlflow.server.auth.client:AuthServiceClient`.

Key files:
- `mlflow/server/auth/__init__.py` (4660 lines) — the auth app factory
  `create_app`, the Flask `before_request` hook `_before_request`, the
  authorization-function dispatch `authenticate_request()`, the default
  `authenticate_request_basic_auth()`, the FastAPI auth
  `_authenticate_fastapi_request()` + `add_fastapi_permission_middleware()`,
  all RBAC validators, signup/login UI (`signup`, `create_user_ui`), admin
  bootstrap (`create_admin_user`).
- `mlflow/server/auth/config.py` — `AuthConfig` NamedTuple read from
  `basic_auth.ini` at import time; `DEFAULT_AUTHORIZATION_FUNCTION =
  "mlflow.server.auth:authenticate_request_basic_auth"`.
- `mlflow/server/auth/sqlalchemy_store.py` — `SqlAlchemyStore` (users, roles,
  role_permissions, user_role_assignments). `create_user`, `update_user`,
  `assign_role_to_user`, `create_role`, `add_role_permission`, etc.
- `mlflow/server/auth/entities.py` — `User(id, username, password_hash,
  is_admin)`, `Role(id, name, workspace, description, permissions)`,
  `RolePermission`, `UserRoleAssignment`.
- `mlflow/server/auth/permissions.py` — `READ/USE/EDIT/MANAGE/NO_PERMISSIONS`;
  `RESOURCE_TYPE_WORKSPACE` grants use `resource_pattern="*"`; workspace tiers
  are `USE` (member) and `MANAGE` (workspace admin).
- `mlflow/server/auth/db/models.py` — SQLAlchemy tables.
- `mlflow/server/auth/routes.py` — route constants (`SIGNUP`, user/role CRUD).
- `mlflow/environment_variables.py` — env-var pattern (`_EnvironmentVariable`,
  `_BooleanEnvironmentVariable`).

Auth flow:
1. `create_app(app)` sets Flask secret key + CSRF, `store.init_db`,
   `create_admin_user`, registers user/role RBAC routes + `signup` +
   `CREATE_USER_UI`, registers `before_request(_before_request)` +
   `after_request(_after_request)`. Under uvicorn it builds the FastAPI app
   and calls `add_fastapi_permission_middleware`.
2. Flask `_before_request`: skip unprotected routes (`/static`, `/health`,
   …); call `authenticate_request()` → the configured
   `auth_config.authorization_function` (default basic auth). Returns a
   werkzeug `Authorization` (success) or a `Response` (401). Sets
   `g.mlflow_authenticated_user`; admins skip validators; otherwise the
   route's validator runs.
3. `authenticate_request_basic_auth()` reads `request.authorization` (HTTP
   Basic), verifies via `store.authenticate_user` (PBKDF2), with an optional
   credential cache.
4. FastAPI `_authenticate_fastapi_request()` reads the `Authorization: Basic`
   header (or trusts the internal gateway token for `/gateway/`). The
   middleware rejects if `auth_config.authorization_function !=
   DEFAULT_AUTHORIZATION_FUNCTION` (FastAPI only supports basic auth).

User model: `User(username, password_hash, is_admin)`. **No email / display
name columns.** `is_admin` is a super-admin flag that bypasses all RBAC.
Workspace-scoped roles carry `role_permissions`; the simplified workspace
model has two tiers: `USE` (member) and `MANAGE` (workspace admin). Default
seeded workspace roles are named `admin` (MANAGE on `('workspace','*')`) and
`user` (USE on `('workspace','*')`) — see `_DEFAULT_WORKSPACE_ROLES`.
`DEFAULT_WORKSPACE_NAME = "default"`.

`authenticate_request()` is called multiple times per Flask request (e.g.
`_before_request`, `sender_is_admin`, validators). Basic-auth mitigates via a
credential cache; authentik will mitigate via a per-request `g` cache.

## Plan

Add a **new auth plugin** `authentik-auth` (additive; does not touch the
existing `basic-auth` plugin). Run with `mlflow server --app-name authentik-auth`.

### Refactor existing `create_app` + FastAPI middleware (minimal, backward-compatible)
Instead of duplicating `create_app` and the FastAPI middleware, add optional
params with defaults that preserve the current `basic-auth` behavior:
- `mlflow.server.auth.create_app(app, *, register_signup_ui=True,
  authorization_function=None, fastapi_auth_func=None)`:
  - when `authorization_function` is provided → swap the
    `mlflow.server.auth.auth_config` module global via `_replace` and
    `get_auth_func.cache_clear()` (so `_before_request`→`authenticate_request()`
    dispatches to header auth); otherwise keep the ini-configured function.
  - when `register_signup_ui=False` → skip registering `signup` /
    `CREATE_USER_UI` (skip native login UI).
  - pass `fastapi_auth_func` through to `add_fastapi_permission_middleware`.
- `add_fastapi_permission_middleware(app, auth_func=_authenticate_fastapi_request)`:
  use `auth_func` instead of the hardcoded basic-auth function. Relax the
  custom-authorization-function guard so it only fires for the default
  basic-auth FastAPI path with an ini-configured custom function (i.e.
  `auth_func is _authenticate_fastapi_request and auth_config.authorization_function
  != DEFAULT`). The authentik path passes its own `auth_func`, so the guard is
  skipped. All reads of `auth_config.authorization_function` are inside
  `mlflow/server/auth/__init__.py` (module-global reads), so the swap is
  visible everywhere it matters.

### Job-execution internal token (preserve functionality)
`MLFLOW_SERVER_ENABLE_JOB_EXECUTION` defaults to True; `mlflow/server/__init__.py`
generates `_MLFLOW_INTERNAL_GATEWAY_AUTH_TOKEN` only when
`app_name == "basic-auth"`. Extend that condition to
`app_name in ("basic-auth", "authentik-auth")`, and have
`_authenticate_fastapi_request_authentik` trust the internal token for
`/gateway/` routes (mirroring the existing basic-auth FastAPI path) so
server-spawned job subprocesses still authenticate.

### New module `mlflow/server/auth/authentik_proxy.py`
- Config via new env vars (see below).
- **Trust boundary**: `_is_from_trusted_proxy(remote_addr)` — stdlib
  `ipaddress` CIDR/IP match against `MLFLOW_AUTHENTIK_TRUSTED_PROXY_IPS`
  (default `127.0.0.1,::1`). If the immediate peer is not trusted, the
  `X-authentik-*` headers are **ignored** (never read) and the request is
  rejected 401 — this is the spoofing defence (we don't physically strip, we
  refuse to trust them). Optional shared-secret header
  (`MLFLOW_AUTHENTIK_SHARED_SECRET`) checked when configured.
- **Header parsing**: read `X-authentik-username` (fallback
  `X-authentik-email`), `X-authentik-email`, `X-authentik-name`,
  `X-authentik-groups` (pipe-separated).
- **Group→role mapping**: prefix `mlflow-` (configurable). De-prefixed names
  map to MLflow roles (best-judgement, documented):
  - `admin` → `is_admin = True` (super admin; bypasses all RBAC).
  - `editor` → workspace **MANAGE** role named `admin` in the `default`
    workspace (workspace-admin tier).
  - `user` → workspace **USE** role named `user` in the `default` workspace
    (member tier).
  - `viewer` and any other `mlflow-*` group → no workspace role; relies on
    `default_permission` (READ) for read-only access.
  - **Reject (403) if no `mlflow-*` group is present** — no default role.
  Rationale: MLflow's simplified workspace model has only two tiers
  (USE/MANAGE); finer-grained distinctions are per-resource grants.
- **JIT provisioning + reconciliation** `_jit_provision_and_reconcile`:
  - If user missing → `store.create_user(username, random_password,
    is_admin=desired_is_admin)` (random password ⇒ account cannot be used
    via basic auth; auth is header-only).
  - If `is_admin` differs → `store.update_user(username,
    is_admin=desired_is_admin)`.
  - Reconcile the two managed roles (`admin`/`user`) in the `default`
    workspace: create the role idempotently if missing (with the matching
    `('workspace','*')` permission), assign the desired one, unassign the
    other. Other manually-assigned roles are left untouched. Only write when
    state differs.
- **Flask authorization function** `authenticate_request_authentik_proxy()`
  returns a werkzeug `Authorization("basic", {"username": …, "password": ""})`
  on success (so the existing `isinstance(…, Authorization)` + `.username`
  contract holds) or a 401/403 `Response`. Result cached in Flask `g` per
  request to avoid re-running header parse + DB reconciliation on the
  multiple `authenticate_request()` calls per request.
- **FastAPI auth** `_authenticate_fastapi_request_authentik(request)` +
  `add_fastapi_permission_middleware_authentik(app)` mirroring the existing
  middleware but using header auth and **without** the
  custom-authorization-function guard (so `/gateway/`, `/v1/traces`,
  `/ajax-api/3.0/jobs`, `/ajax-api/3.0/mlflow/assistant` work).
- **Factory** `create_app(app=app)`: thin wrapper that calls
  `mlflow.server.auth.create_app(app, register_signup_ui=False,
  authorization_function="mlflow.server.auth.authentik_proxy:authenticate_request_authentik_proxy",
  fastapi_auth_func=_authenticate_fastapi_request_authentik)`. This reuses all
  existing setup (secret key, CSRF, `store.init_db`, `create_admin_user`,
  RBAC/user routes, `before_request`/`after_request`, FastAPI middleware) and
  only swaps the authorization function + skips the signup UI.

### Env vars (`mlflow/environment_variables.py`)
- `MLFLOW_AUTHENTIK_TRUSTED_PROXY_IPS` (str, default `"127.0.0.1,::1"`,
  comma-separated IPs/CIDRs; `"*"` = trust any — dangerous, documented).
- `MLFLOW_AUTHENTIK_SHARED_SECRET` (str, default `None`).
- `MLFLOW_AUTHENTIK_SHARED_SECRET_HEADER` (str, default
  `"X-authentik-proxy-secret"`).
- `MLFLOW_AUTHENTIK_GROUP_PREFIX` (str, default `"mlflow-"`).

### Entry points (`pyproject.toml`, `pyproject.release.toml`,
`libs/skinny/pyproject.toml`)
- `mlflow.app` → `authentik-auth = "mlflow.server.auth.authentik_proxy:create_app"`
- `mlflow.app.client` → `authentik-auth =
  "mlflow.server.auth.client:AuthServiceClient"` (reused; admin RBAC ops over
  REST — works when the client is itself behind the proxy).

### Tests (`tests/server/auth/test_authentik_proxy.py`)
- Pure-helper unit tests: `_parse_app_groups`, `_resolve_desired_role`,
  `_is_from_trusted_proxy` (CIDR matching, `*`, IPv6, untrusted → False).
- Flask `test_request_context` tests against an isolated `SqlAlchemyStore`:
  trusted-proxy + valid groups → Authorization with username; JIT creates
  user; `mlflow-admin` → `is_admin=True`; `mlflow-user` → assigned `user`
  role in default workspace; `mlflow-editor` → assigned `admin` role; no
  `mlflow-*` group → 403; untrusted source IP → 401 (**spoofed
  X-authentik-* headers from an untrusted IP are ignored** — the security
  guarantee); shared-secret mismatch → 401; per-request `g` cache hit.
- Reconciliation tests: stale `is_admin` demoted when groups drop `admin`;
  wrong managed role corrected when group changes; **manual role assignments
  preserved** across reconciliation.
- FastAPI auth test: `_authenticate_fastapi_request_authentik` with a
  Starlette request (trusted peer + headers → User; untrusted → None).
- `create_app` smoke test: with `register_signup_ui=False` the `signup` route
  is NOT registered (GET `/signup` → 404, not the form); RBAC routes are
  registered; `auth_config.authorization_function` swapped to the authentik
  function.

## Documented Assumptions
1. MLflow's `User` model has no email/display-name columns and adding them
   would require a DB migration (out of scope for "smallest solution"). So
   `X-authentik-email` / `X-authentik-name` are read but **not persisted**;
   `X-authentik-username` (fallback `X-authentik-email`) is the identity key.
2. JWT verification (higher-assurance option in the doc) is **not
   implemented**; we rely on the network trust boundary (source-IP/CIDR +
   optional shared secret) per the doc's primary recommendation. The app is
   expected to be reachable only via the outpost. This keeps the change
   dependency-free (no PyJWT/JWKS fetch in the hot path).
3. Group→role mapping is the documented best-judgement mapping above; it is
   not configurable beyond the prefix (operators configure group names in
   Authentik to match `admin`/`editor`/`user`/`viewer`).
4. Role reconciliation runs on every trusted request but only writes on
   change; the two managed roles (`admin`/`user` in the `default` workspace)
   are the only ones auto-managed — manual role assignments are preserved.
5. The local admin account from `basic_auth.ini` is still bootstrapped as an
   emergency/break-glass account (not used for normal header auth).

## Non-goals / Out of scope
- JWT/JWKS verification (documented assumption #2).
- Email/display-name persistence / user-model schema changes.
- Enterprise/commercial code paths.
- Frontend UI changes beyond skipping the signup route.
- Configurable per-group role mapping table (fixed best-judgement mapping).

## Next Agent
implementor (after debater sign-off).

---

## Implementation Log (executed by `implementor`)

### Files changed
- `mlflow/environment_variables.py` — added 4 new `_EnvironmentVariable`
  definitions (`MLFLOW_AUTHENTIK_TRUSTED_PROXY_IPS`,
  `MLFLOW_AUTHENTIK_SHARED_SECRET`,
  `MLFLOW_AUTHENTIK_SHARED_SECRET_HEADER`,
  `MLFLOW_AUTHENTIK_GROUP_PREFIX`) with `#:` doc comments.
- `pyproject.toml`, `pyproject.release.toml`, `libs/skinny/pyproject.toml` —
  registered `authentik-auth` under both `[project.entry-points."mlflow.app"]`
  and `[project.entry-points."mlflow.app.client"]` entry points.
- `mlflow/server/auth/__init__.py` — `create_app` refactored to accept
  keyword-only params `register_signup_ui`, `authorization_function`,
  `fastapi_auth_func` (all default-`None`/`True`); defaults preserve the
  historical `basic-auth` behaviour.  The module-global `auth_config` is
  rebound via `_replace` when `authorization_function` is supplied; the
  `get_auth_func` lru-cache is cleared.  The `signup` and `CREATE_USER_UI`
  routes are gated by `register_signup_ui`.  `add_fastapi_permission_middleware`
  now takes an `auth_func` kwarg (default falls back to
  `_authenticate_fastapi_request`); the custom-authorization-function guard
  is tightened to only fire for the default basic-auth FastAPI path.
- `mlflow/server/__init__.py` — job-execution internal-token condition
  extended from `app_name == "basic-auth"` to
  `app_name in ("basic-auth", "authentik-auth")`.
- `mlflow/server/auth/authentik_proxy.py` — **new module**, the
  `authentik-auth` plugin implementation: trust-boundary check, optional
  shared-secret check, header parsing, `mlflow-`-prefixed group→role
  mapping, JIT user provisioning + managed-role reconciliation, Flask
  authorization function (with per-request `g` cache), FastAPI auth
  function (with internal-token trust for `/gateway/`), and a thin
  `create_app` wrapper.
- `tests/server/auth/test_authentik_proxy.py` — **new test file** with 39
  unit/integration tests covering: helper unit tests, Flask
  `test_request_context` tests with an isolated `SqlAlchemyStore`, the
  spoofing defence, shared-secret enforcement, reject-if-no-prefixed-group,
  per-request `g` cache, reconciliation incl. manual-role preservation,
  FastAPI auth, internal-token trust for `/gateway/`, and a `create_app`
  smoke test.

### Deviations from the briefs (and why)
1. **TEST 5 isolation**: the `basic_auth.ini` `database_uri` is a relative
   path (`sqlite:///basic_auth.db`) that resolves against `cwd`.  The test
   fixtures therefore rebind `auth_config.database_uri` to the per-test
   `tmp_sqlite_uri` so each test gets a fresh DB rather than sharing
   `tests/basic_auth.db`.  Documented in the `isolated_store` fixture
   docstring.
2. **TEST 5 signup-route assertion**: the `test_signup_route_not_registered`
   test asserts directly on `app.url_map` because the `BEFORE_REQUEST_VALIDATORS`
   dict still contains a `(SIGNUP, GET) → validate_can_create_user` mapping;
   a `test_client` request hits `_before_request` first and gets 403
   before the missing route is even consulted.
3. **TEST 4 internal-token env name**: the FastAPI internal-token test uses
   `monkeypatch.setenv("_MLFLOW_INTERNAL_GATEWAY_AUTH_TOKEN", ...)` because
   the `_EnvironmentVariable.get()` reads from `os.environ` at call time;
   `monkeypatch.setattr` on the env-var module object alone is insufficient
   once the value has been imported into the `ap` module.
4. **TEST 4 `_ensure_managed_role`**: the helper now swallows
   `RESOURCE_ALREADY_EXISTS` on `create_role` as well as
   `add_role_permission` so it is fully idempotent (catches concurrent /
   pre-existing role rows from a manual `create_role` call, as exercised by
   `test_managed_role_corrected_on_group_change`).
5. **TEST 6 `httpx2`**: the conftest at `tests/server/conftest.py` imports
   `starlette.testclient.TestClient` which requires `httpx2` in this
   starlette version.  The test command therefore uses
   `uv run --frozen --extra auth --extra gateway --with 'httpx2' pytest …`
   to satisfy the conftest's transitive import.

### Validation performed
- `uv run --frozen --extra auth --extra gateway --with 'httpx2' pytest
  tests/server/auth/test_authentik_proxy.py -x` → **39 passed** in ~9s.
- `uv run --frozen --extra auth --extra gateway --with 'httpx2' pytest
  tests/server/auth/test_sqlalchemy_store.py -x` → **13 passed** (no store
  regression).
- `uv run --frozen --extra auth --extra gateway --with 'httpx2' pytest
  tests/server/auth/test_client_rbac.py -k "test_get_role or test_list_roles
  or test_create_role_duplicate"` → **4 passed** (no RBAC client
  regression).
- `uv run --frozen --extra auth --extra gateway --with 'httpx2' pytest
  tests/server/auth/test_auth_workspace.py -k "test_seed or
  test_after_request_delete"` → **4 passed** (no workspace test
  regression).
- `uv run --frozen --extra auth --extra gateway --with 'httpx2' ruff check`
  on all touched files → **All checks passed!**
- `uv run --frozen --extra auth --extra gateway --with 'httpx2' ruff
  format --check` on all touched files → **5 files already formatted**.

### Commit hash and push result
- Commit: _populated after Task 6 commit (see the `Next Agent` section)._
- Push: _populated after Task 6 push._

## Next Agent
tester (post-implementation review, then merge/test/exercise the new plugin
end-to-end if a test environment is available).

---

## Task Briefs

The implementor executes these in order. Each brief is self-contained. Use
`uv` at `/home/ask/.local/bin/uv` (the system `uv` is too old). Run tests with
`uv run --frozen pytest tests/server/auth/test_authentik_proxy.py` from the
repo root. Commit with `git commit -s` (DCO sign-off required by CI) and push
to `origin master` only after ALL briefs are done and tests pass.

### Task 1 — Env vars + entry points
**Context:** MLflow env vars are declared in `mlflow/environment_variables.py`
using `_EnvironmentVariable`/`_BooleanEnvironmentVariable`. App plugins are
registered as entry points in `pyproject.toml`, `pyproject.release.toml`, and
`libs/skinny/pyproject.toml` under `[project.entry-points."mlflow.app"]` and
`[project.entry-points."mlflow.app.client"]`.
**Objective:** Add the 4 Authentik config env vars and register the
`authentik-auth` plugin entry points.
**Scope:**
- In `mlflow/environment_variables.py`, append (after
  `MLFLOW_READ_REPLICA_BACKEND_STORE_URI`):
  - `MLFLOW_AUTHENTIK_TRUSTED_PROXY_IPS` = `_EnvironmentVariable("MLFLOW_AUTHENTIK_TRUSTED_PROXY_IPS", str, "127.0.0.1,::1")`
  - `MLFLOW_AUTHENTIK_SHARED_SECRET` = `_EnvironmentVariable("MLFLOW_AUTHENTIK_SHARED_SECRET", str, None)`
  - `MLFLOW_AUTHENTIK_SHARED_SECRET_HEADER` = `_EnvironmentVariable("MLFLOW_AUTHENTIK_SHARED_SECRET_HEADER", str, "X-authentik-proxy-secret")`
  - `MLFLOW_AUTHENTIK_GROUP_PREFIX` = `_EnvironmentVariable("MLFLOW_AUTHENTIK_GROUP_PREFIX", str, "mlflow-")`
  - Add a `#:` doc comment for each (see surrounding style).
- In all three pyproject files, add under `[project.entry-points."mlflow.app"]`:
  `authentik-auth = "mlflow.server.auth.authentik_proxy:create_app"` and under
  `[project.entry-points."mlflow.app.client"]`:
  `authentik-auth = "mlflow.server.auth.client:AuthServiceClient"`.
**Non-goals:** Do not create `authentik_proxy.py` yet (Task 2). Do not touch
the existing `basic-auth` entry points.
**Acceptance:** `python -c "from mlflow.environment_variables import MLFLOW_AUTHENTIK_TRUSTED_PROXY_IPS, MLFLOW_AUTHENTIK_SHARED_SECRET, MLFLOW_AUTHENTIK_SHARED_SECRET_HEADER, MLFLOW_AUTHENTIK_GROUP_PREFIX; print('ok')"` succeeds; the three pyproject files each contain the two new `authentik-auth` lines.

### Task 2 — Refactor `create_app` + FastAPI middleware to accept params
**Context:** `mlflow/server/auth/__init__.py` `create_app(app)` (≈line 4536)
registers `signup`/`CREATE_USER_UI` and wires `before_request`/`after_request`
+ `add_fastapi_permission_middleware`. `add_fastapi_permission_middleware(app)`
(≈line 4434) hardcodes `_authenticate_fastapi_request` and rejects when
`auth_config.authorization_function != DEFAULT_AUTHORIZATION_FUNCTION`.
`authenticate_request()` (≈line 2784) reads the module global
`auth_config.authorization_function` via `get_auth_func` (lru-cached).
**Objective:** Make `create_app` and the FastAPI middleware reusable by the
authentik plugin without duplicating them, preserving existing `basic-auth`
behavior exactly.
**Scope:**
- Change `create_app` signature to
  `def create_app(app: Flask = app, *, register_signup_ui: bool = True, authorization_function: str | None = None, fastapi_auth_func: Callable | None = None):`
  (import `Callable` if needed; it's already imported).
- Inside `create_app`, after `store.init_db(...)`/`create_admin_user(...)` and
  BEFORE registering routes: if `authorization_function is not None`, swap the
  module global:
  ```python
  global auth_config
  auth_config = auth_config._replace(authorization_function=authorization_function)
  get_auth_func.cache_clear()
  ```
  (Use `global auth_config` so the assignment rebinds the module global that
  `authenticate_request` reads.)
- Wrap the two `app.add_url_rule` calls for `SIGNUP` and `CREATE_USER_UI` in
  `if register_signup_ui:`. Keep all other route registrations unconditional.
- When building the FastAPI app at the end:
  `add_fastapi_permission_middleware(fastapi_app, auth_func=fastapi_auth_func)`
  (pass `None` through; the middleware treats `None` as the default).
- Change `add_fastapi_permission_middleware` signature to
  `def add_fastapi_permission_middleware(app: FastAPI, auth_func: Callable | None = None):`.
  Default `auth_func` to `_authenticate_fastapi_request` when `None`. Replace
  the call `user = _authenticate_fastapi_request(request)` with
  `user = auth_func(request)`. Change the custom-authorization-function guard
  to fire ONLY for the default basic-auth path:
  ```python
  if auth_func is _authenticate_fastapi_request and auth_config.authorization_function != DEFAULT_AUTHORIZATION_FUNCTION:
      return PlainTextResponse(... existing message ...)
  ```
  (This preserves the existing basic-auth behavior and skips the guard for the
  authentik path which supplies its own `auth_func`.)
**Non-goals:** Do not change `authenticate_request`, `authenticate_request_basic_auth`, `_before_request`, validators, or any basic-auth semantics. Do not create `authentik_proxy.py` yet.
**Acceptance:** Existing basic-auth tests still pass
(`uv run --frozen pytest tests/server/auth/test_auth.py -k "not slow" -x` —
run a representative subset if the full suite is too slow). `create_app()`
with default args still registers `/signup` (GET 200). `create_app(register_signup_ui=False)` does NOT register `/signup` (GET 404). `create_app(authorization_function="mlflow.server.auth:authenticate_request_basic_auth")` still works (no-op swap to the same function).

### Task 3 — Job-execution internal token for `authentik-auth`
**Context:** `mlflow/server/__init__.py` line 463 generates
`_MLFLOW_INTERNAL_GATEWAY_AUTH_TOKEN` only when
`app_name == "basic-auth"`. Job subprocesses use it to call `/gateway/`.
`MLFLOW_SERVER_ENABLE_JOB_EXECUTION` defaults True.
**Objective:** Let job execution work under `authentik-auth`.
**Scope:** Change the condition at `mlflow/server/__init__.py` ≈line 463 from
`if app_name == "basic-auth" and job_execution_enabled:` to
`if app_name in ("basic-auth", "authentik-auth") and job_execution_enabled:`.
**Non-goals:** No other changes to `_run_server`.
**Acceptance:** The line reads as specified; `grep` confirms both app names present.

### Task 4 — Create `mlflow/server/auth/authentik_proxy.py`
**Context:** This is the core module. Read WORKFLOW_STATE.md Plan section in
full. The existing `mlflow/server/auth/__init__.py` exports `store`,
`auth_config`, `make_forbidden_response`, `make_basic_auth_response`,
`get_auth_func`, `create_app`, `add_fastapi_permission_middleware`,
`_authenticate_fastapi_request`, `is_unprotected_route`, `_find_fastapi_validator`,
`get_routed_asgi_path` (from `mlflow.server.asgi_utils`). The store
(`SqlAlchemyStore`) has: `has_user`, `get_user`, `create_user(username,
password, is_admin=False)`, `update_user(username, password=None,
is_admin=None)`, `create_role(name, workspace, description=None)`,
`get_role_by_name(workspace, name)`, `add_role_permission(role_id,
resource_type, resource_pattern, permission)`, `assign_role_to_user(user_id,
role_id)`, `unassign_role_from_user(user_id, role_id)`, `list_user_roles_for_workspace(user_id, workspace)`.
`DEFAULT_WORKSPACE_NAME = "default"` (from `mlflow.utils.workspace_utils`).
Permissions: `MANAGE`, `USE` (from `mlflow.server.auth.permissions`).
`RESOURCE_TYPE_WORKSPACE = "workspace"`. werkzeug 3.1.8:
`Authorization("basic", {"username": u, "password": ""})` exposes `.username`.
**Objective:** Implement header auth with trust boundary, JIT provisioning,
group→role mapping, reject-if-no-prefixed-group, per-request cache, FastAPI
auth, and the `create_app` factory.
**Scope:** Create `mlflow/server/auth/authentik_proxy.py` with:
- Imports: stdlib `ipaddress`, `secrets`, `logging`; Flask `request`, `g`,
  `make_response`; werkzeug `Authorization`; starlette `Request as
  StarletteRequest`; `PlainTextResponse` + `HTTPStatus` from fastapi/starlette;
  env vars from `mlflow.environment_variables`; `MLFLOW_ENABLE_WORKSPACES` is
  NOT needed (roles work regardless); `from mlflow.server.auth import (
  store, auth_config, make_forbidden_response, make_basic_auth_response,
  get_auth_func, create_app as _basic_create_app, add_fastapi_permission_middleware,
  _authenticate_fastapi_request, is_unprotected_route, _find_fastapi_validator)`;
  `from mlflow.server.auth.permissions import MANAGE, USE,
  RESOURCE_TYPE_WORKSPACE`; `from mlflow.server.auth.sqlalchemy_store import
  SqlAlchemyStore` (only for typing); `from mlflow.utils.workspace_utils
  import DEFAULT_WORKSPACE_NAME`; `from mlflow.server.asgi_utils import
  get_routed_asgi_path`; `from mlflow.environment_variables import
  _MLFLOW_INTERNAL_GATEWAY_AUTH_TOKEN`; `from mlflow import MlflowException`.
- Module logger `_logger = logging.getLogger(__name__)`.
- Header name constants: `USERNAME_HEADER="X-authentik-username"`,
  `EMAIL_HEADER="X-authentik-email"`, `NAME_HEADER="X-authentik-name"`,
  `GROUPS_HEADER="X-authentik-groups"`.
- `_trusted_networks()` → parse `MLFLOW_AUTHENTIK_TRUSTED_PROXY_IPS` into a
  list of `ipaddress.ip_network` (strict=False); `"*"` → sentinel meaning
  trust-any. Cache via `@functools.lru_cache`. Log a warning at first parse if
  the value is `"*"`.
- `_is_from_trusted_proxy(remote_addr: str | None) -> bool`: handle `None`→
  False; `"*"`→ True; else `ipaddress.ip_address(remote_addr)` in any trusted
  network; on parse error → False.
- `_parse_app_groups(groups_raw: str, prefix: str) -> list[str]`: split on
  `|`, strip, keep those `startswith(prefix)`, return de-prefixed remainders
  (lowercased). Empty/None → `[]`.
- `_resolve_desired_role(app_groups: list[str]) -> tuple[bool, str | None]`:
  returns `(is_admin, workspace_role_name)` where `workspace_role_name` is one
  of `"admin"`, `"user"`, `None`. Mapping: `"admin"` in app_groups →
  `is_admin=True`; `"editor"` → `("admin" role)`; `"user"` → `("user" role)`;
  `"viewer"` or any other → `None`. When `is_admin=True`, workspace_role is
  `None` (super-admin bypasses RBAC, no workspace role needed). Document the
  mapping in a docstring.
- `_ensure_managed_role(store, name: str, permission: str) -> int`: get or
  create the role named `name` in `DEFAULT_WORKSPACE_NAME` (with description),
  then ensure it has a `('workspace','*')` permission row at `permission`
  (catch `RESOURCE_ALREADY_EXISTS` on both). Return role.id. Idempotent.
- `_jit_provision_and_reconcile(store, username: str, is_admin: bool,
  workspace_role: str | None) -> User`: if not `store.has_user(username)` →
  `store.create_user(username, secrets.token_urlsafe(32), is_admin=is_admin)`
  (catch `RESOURCE_ALREADY_EXISTS` → fall through to get_user). Then reconcile:
  (a) `user = store.get_user(username)`; if `user.is_admin != is_admin` →
  `store.update_user(username, is_admin=is_admin)`. (b) Reconcile managed
  roles in `DEFAULT_WORKSPACE_NAME`: list the user's roles there; determine
  desired role id (via `_ensure_managed_role` if `workspace_role` is not
  None); assign desired if not already; unassign the *other* managed role
  (`"admin"` if desired is `"user"`, `"user"` if desired is `"admin"`, both if
  desired is None) if present. Catch `MlflowException` per-op, log, and
  continue (partial failure self-heals next request). Return `store.get_user(username)`.
- `_check_shared_secret(headers) -> bool`: if
  `MLFLOW_AUTHENTIK_SHARED_SECRET.get()` is None → True; else compare
  `headers.get(MLFLOW_AUTHENTIK_SHARED_SECRET_HEADER.get())` with
  `secrets.compare_digest`.
- `make_authentik_unauthenticated_response()` → 401 plain text "Authentication
  required via the Authentik proxy." (no `WWW-Authenticate`).
- `authenticate_request_authentik_proxy() -> Authorization | Response`:
  - Per-request cache: if `getattr(g, "_authentik_auth_result", None)` is not
    None → return it.
  - Trust boundary: if not `_is_from_trusted_proxy(request.remote_addr)` →
    cache+return `make_authentik_unauthenticated_response()`.
  - Shared secret: if not `_check_shared_secret(request.headers)` → cache+
    return 401.
  - Read `username = request.headers.get(USERNAME_HEADER) or
    request.headers.get(EMAIL_HEADER)`; if not username → cache+return 401.
  - `app_groups = _parse_app_groups(request.headers.get(GROUPS_HEADER, ""),
    MLFLOW_AUTHENTIK_GROUP_PREFIX.get())`; if not app_groups → cache+return
    `make_forbidden_response()` (403).
  - `is_admin, workspace_role = _resolve_desired_role(app_groups)`.
  - `user = _jit_provision_and_reconcile(store, username, is_admin,
    workspace_role)`.
  - `result = Authorization("basic", {"username": username, "password": ""})`;
  cache in `g._authentik_auth_result`; return it.
  - Wrap provisioning in try/except MlflowException → log + return 401 (fail
    closed if the store is unavailable).
- `_authenticate_fastapi_request_authentik(request: StarletteRequest) ->
  User | None`: mirror `authenticate_request_authentik_proxy` but return
  `User | None` (None on any failure). Use `request.client.host` for the peer
  (guard `request.client is not None`), `request.headers` for headers. ALSO
  honor the internal gateway token for `/gateway/` routes: if
  `_MLFLOW_INTERNAL_GATEWAY_AUTH_TOKEN.get()` and
  `get_routed_asgi_path(request).startswith("/gateway/")` and the
  `Authorization: Basic <user>:<token>` password matches the internal token
  (use `secrets.compare_digest`), return `store.get_user(username)` (mirror
  the existing `_authenticate_fastapi_request` internal-token branch). This
  must be checked BEFORE the header path so job subprocesses authenticate.
- `add_fastapi_permission_middleware_authentik(app: FastAPI) -> None`: call
  the existing `add_fastapi_permission_middleware(app,
  auth_func=_authenticate_fastapi_request_authentik)`. (Reuse, do not
  duplicate.)
- `create_app(app: Flask = app)`: thin wrapper:
  ```python
  return _basic_create_app(
      app,
      register_signup_ui=False,
      authorization_function="mlflow.server.auth.authentik_proxy:authenticate_request_authentik_proxy",
      fastapi_auth_func=_authenticate_fastapi_request_authentik,
  )
  ```
  (Import the shared Flask `app`: `from mlflow.server import app`.)
**Non-goals:** No JWT verification. No email/name persistence. No schema
changes. Do not modify basic-auth functions.
**Acceptance:** Module imports cleanly
(`python -c "import mlflow.server.auth.authentik_proxy"`). The entry point
`mlflow.server.auth.authentik_proxy:create_app` is a function (factory).

### Task 5 — Tests `tests/server/auth/test_authentik_proxy.py`
**Context:** Test patterns: `tests/server/auth/test_sqlalchemy_store.py` uses
a `store` fixture = `SqlAlchemyStore().init_db(tmp_sqlite_uri)`. The
`tmp_sqlite_uri` fixture is in `tests/conftest.py`. Flask request context:
`with app.test_request_context("/", headers=..., environ_overrides={"REMOTE_ADDR": ...}):`.
The auth module reads the module-global `store` in `mlflow.server.auth`; for
unit tests, monkeypatch `mlflow.server.auth.authentik_proxy.store` to a fresh
isolated `SqlAlchemyStore` (and restore after). Use `pytest.mark.notrackingurimock`.
**Objective:** Prove the security guarantees and behavior.
**Scope:** Create `tests/server/auth/test_authentik_proxy.py` with:
- Helper-unit tests (no DB): `_parse_app_groups` (prefix strip, pipe split,
  empty, non-prefixed ignored); `_resolve_desired_role` (admin→(True,None),
  editor→(False,"admin"), user→(False,"user"), viewer→(False,None),
  unknown→(False,None), admin+user→(True,None)); `_is_from_trusted_proxy`
  (127.0.0.1 True, 10.0.0.1 False with default, `"*"` True, IPv6 ::1 True,
  bad addr False, CIDR 10.0.0.0/8 match).
- A `store` fixture (isolated) + monkeypatch the authentik module's `store`
  global to it.
- Flask `test_request_context` tests (set `REMOTE_ADDR` via
  `environ_overrides`, set headers):
  - trusted + `X-authentik-username=alice` + `X-authentik-groups=mlflow-user`
    → returns `Authorization`, `.username=="alice"`, user created in store
    with `is_admin=False`, assigned `user` role in default workspace.
  - `mlflow-admin` group → user `is_admin=True`, no workspace role.
  - `mlflow-editor` → assigned `admin` (MANAGE) role in default workspace.
  - `mlflow-viewer` → no workspace role assigned, user exists.
  - no `mlflow-*` group (e.g. `X-authentik-groups=other-team`) → 403 Response.
  - untrusted `REMOTE_ADDR` (e.g. `8.8.8.8`) WITH spoofed `X-authentik-*`
    headers → 401 Response, and NO user is created in the store (spoofing
    defence).
  - shared secret set (monkeypatch env) + mismatched header → 401; matched →
    success.
  - per-request `g` cache: call `authenticate_request_authentik_proxy()`
    twice in one request context → second call does not re-provision (e.g.
    assert `store.create_user` called once via mock, or assert `g` attribute
    set).
- Reconciliation tests (manually create a user with stale state first):
  - user with `is_admin=True` + `mlflow-user` group → after auth,
    `is_admin=False`.
  - user assigned `admin` role + `mlflow-user` group → after auth, assigned
    `user` role and unassigned `admin` role.
  - user with a manually-created extra role in default workspace +
    `mlflow-user` group → after auth, the extra role is STILL assigned
    (manual assignments preserved).
- FastAPI test: build a minimal Starlette request (or use
  `starlette.testclient.TestClient` on a tiny FastAPI app with the
  middleware) — trusted peer + headers → User returned; untrusted → None.
  (If constructing a Starlette Request directly is awkward, use a small
  FastAPI app + `TestClient` with `client.host` set via
  `transport`/`app` — keep it simple; a direct unit test of
  `_authenticate_fastapi_request_authentik` with a mocked request object
  exposing `.client.host`, `.headers`, `.scope` is acceptable.)
- `create_app` smoke test: call
  `mlflow.server.auth.authentik_proxy.create_app` with a fresh Flask app
  against an isolated store (monkeypatch `mlflow.server.auth.store` and
  `MLFLOW_FLASK_SERVER_SECRET_KEY`); assert GET `/signup` → 404; assert
  `mlflow.server.auth.auth_config.authorization_function` ends with
  `authenticate_request_authentik_proxy`; assert a known RBAC route (e.g.
  `LIST_USERS`) is registered (GET returns 401/403, not 404).
**Non-goals:** No full subprocess server-spawn test (too slow). No frontend
tests.
**Acceptance:** `uv run --frozen pytest tests/server/auth/test_authentik_proxy.py -x` passes.

### Task 6 — Lint, full test sweep, commit, push
**Context:** Repo uses ruff + pre-commit. DCO sign-off required (`-s`).
**Objective:** Finalize and ship.
**Scope:**
- `uv run ruff check mlflow/server/auth/authentik_proxy.py mlflow/environment_variables.py mlflow/server/auth/__init__.py mlflow/server/__init__.py tests/server/auth/test_authentik_proxy.py --fix` then `uv run ruff format` the same files.
- Run the new test file: `uv run --frozen pytest tests/server/auth/test_authentik_proxy.py -x`.
- Run a representative slice of existing auth tests to confirm no regression:
  `uv run --frozen pytest tests/server/auth/test_auth.py -k "test_create_user or test_get_user or test_signup or test_auth_enabled" -x` (pick a few fast ones; if those specific names don't exist, run the file with `-x --timeout=120` and abort if it hangs, then just run `tests/server/auth/test_sqlalchemy_store.py`).
- `git add -A` the changed/new files (mlflow/environment_variables.py,
  mlflow/server/__init__.py, mlflow/server/auth/__init__.py,
  mlflow/server/auth/authentik_proxy.py, pyproject.toml,
  pyproject.release.toml, libs/skinny/pyproject.toml,
  tests/server/auth/test_authentik_proxy.py, WORKFLOW_STATE.md).
- `git commit -s -m "feat(auth): add Authentik proxy-header auth plugin (authentik-auth)"` with a body summarizing: new `authentik-auth` app plugin authenticating via `X-authentik-*` headers from a trusted Authentik outpost; JIT user provisioning; `mlflow-` prefixed group→role mapping (admin→super-admin, editor→workspace MANAGE, user→workspace USE, viewer→read-only, no prefixed group→deny); trust boundary via source-IP/CIDR + optional shared secret (spoofed headers ignored); native signup UI skipped; `create_app`/FastAPI middleware refactored to accept params (backward compatible); job-execution internal token extended to the new plugin. Include `Co-Authored-By: Claude <noreply@anthropic.com>`.
- `git push origin master` and capture the output + commit hash.
**Non-goals:** Do not push to `upstream`. Do not open a PR.
**Acceptance:** Commit lands on `origin master`; `git log --oneline -1` shows the commit; push output shows success. Report the commit hash and push result back.
