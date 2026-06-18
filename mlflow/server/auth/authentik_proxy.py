"""
Authentik proxy-header auth plugin for the MLflow tracking server.

The ``mlflow server --app-name authentik-auth`` plugin authenticates users
solely from ``X-authentik-*`` proxy headers supplied by a trusted Authentik
outpost / proxy in front of the server.  The plugin performs:

* **Trust boundary check** on the immediate TCP peer (``request.remote_addr``
  on Flask, ``request.client.host`` on Starlette / FastAPI) against
  ``MLFLOW_AUTHENTIK_TRUSTED_PROXY_IPS`` (default ``"127.0.0.1,::1"``).  Any
  request from an untrusted source is rejected 401 — the ``X-authentik-*``
  headers are **never** read from an untrusted peer, even if they are
  present.  This is the spoofing defence.
* **Optional shared-secret check** on a configurable request header against
  ``MLFLOW_AUTHENTIK_SHARED_SECRET`` (constant-time compare).
* **Header parsing** — ``X-authentik-username`` (with ``X-authentik-email``
  fallback), ``X-authentik-email``, ``X-authentik-name``, and
  ``X-authentik-groups`` (pipe-separated).
* **Group-to-role mapping** with a configurable prefix
  (``MLFLOW_AUTHENTIK_GROUP_PREFIX``, default ``"mlflow-"``).  Groups whose
  names do not start with this prefix are ignored.  If no prefixed group
  is present the user is **denied (403)** and is not provisioned.
* **JIT provisioning + reconciliation** of the local user record and the two
  managed workspace roles (``admin`` / ``user`` in the ``default``
  workspace).  Manual role assignments are preserved.

The module reuses the existing basic-auth ``create_app`` and FastAPI
middleware plumbing; only the authorization function and the FastAPI
authenticator are swapped.  The native ``/signup`` form and
``CREATE_USER_UI`` route are intentionally NOT registered under
``authentik-auth``.

References
----------
Authentik "Proxy outpost / forward auth (single application)" — see the
``authentik-proxy-user-data.md`` design note shipped with this change.
"""

from __future__ import annotations

import functools
import ipaddress
import logging
import secrets
from typing import TYPE_CHECKING

from flask import Flask, g, make_response, request
from starlette.requests import Request as StarletteRequest
from werkzeug.datastructures import Authorization

from mlflow import MlflowException
from mlflow.environment_variables import (
    _MLFLOW_INTERNAL_GATEWAY_AUTH_TOKEN,
    MLFLOW_AUTHENTIK_GROUP_PREFIX,
    MLFLOW_AUTHENTIK_SHARED_SECRET,
    MLFLOW_AUTHENTIK_SHARED_SECRET_HEADER,
    MLFLOW_AUTHENTIK_TRUSTED_PROXY_IPS,
)
from mlflow.server import app as _shared_flask_app
from mlflow.server.asgi_utils import get_routed_asgi_path
from mlflow.server.auth import (
    add_fastapi_permission_middleware,
    make_forbidden_response,
    store,
)
from mlflow.server.auth import (
    create_app as _basic_create_app,
)
from mlflow.server.auth.permissions import MANAGE, RESOURCE_TYPE_WORKSPACE, USE
from mlflow.server.auth.sqlalchemy_store import SqlAlchemyStore
from mlflow.utils.workspace_utils import DEFAULT_WORKSPACE_NAME

if TYPE_CHECKING:
    from mlflow.server.auth.entities import User

_logger = logging.getLogger(__name__)

# --- Header name constants (Authentik proxy user-data spec) -----------------

USERNAME_HEADER = "X-authentik-username"
EMAIL_HEADER = "X-authentik-email"
NAME_HEADER = "X-authentik-name"
GROUPS_HEADER = "X-authentik-groups"

# --- Trust-boundary helpers --------------------------------------------------


@functools.lru_cache(maxsize=1)
def _trusted_networks() -> tuple[ipaddress._BaseNetwork, ...] | str:
    """
    Parse ``MLFLOW_AUTHENTIK_TRUSTED_PROXY_IPS`` into a tuple of
    :class:`ipaddress.ip_network` entries.  Returns the sentinel string
    ``"*"`` when configured to trust any peer.

    The result is cached for the process lifetime via ``lru_cache`` so the
    config is parsed at most once.
    """
    raw = MLFLOW_AUTHENTIK_TRUSTED_PROXY_IPS.get() or ""
    raw = raw.strip()
    if raw == "*":
        _logger.warning(
            "MLFLOW_AUTHENTIK_TRUSTED_PROXY_IPS is set to '*' — trusting proxy "
            "headers from any source. This is suitable only for local development."
        )
        return "*"
    networks: list[ipaddress._BaseNetwork] = []
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            _logger.warning(
                "Ignoring invalid entry %r in MLFLOW_AUTHENTIK_TRUSTED_PROXY_IPS", entry
            )
    return tuple(networks)


def _is_from_trusted_proxy(remote_addr: str | None) -> bool:
    """
    Return ``True`` iff the immediate peer ``remote_addr`` is in the configured
    trusted-proxy set.  ``None`` / empty / unparseable addresses return ``False``
    so we fail closed.
    """
    if not remote_addr:
        return False
    networks = _trusted_networks()
    if networks == "*":
        return True
    try:
        addr = ipaddress.ip_address(remote_addr)
    except ValueError:
        return False
    # ``networks`` is the lru_cache return value; in this branch it is a
    # tuple of ``_BaseNetwork`` (the union is the public type).
    for net in networks:
        if isinstance(net, ipaddress._BaseNetwork) and addr in net:
            return True
    return False


# --- Group/role helpers ------------------------------------------------------


def _parse_app_groups(groups_raw: str | None, prefix: str) -> list[str]:
    """
    Split the raw ``X-authentik-groups`` header (``"a|b|c"``) into a list of
    de-prefixed group names, keeping only those that start with ``prefix``.
    The comparison is case-sensitive on the prefix; the remainder is
    lowercased so that ``"mlflow-Admin"`` and ``"mlflow-admin"`` map to the
    same local role.
    """
    if not groups_raw:
        return []
    result: list[str] = []
    for raw_name in groups_raw.split("|"):
        name = raw_name.strip()
        if not name:
            continue
        if not name.startswith(prefix):
            continue
        result.append(name[len(prefix) :].strip().lower())
    return result


# Group→role mapping.  The mapping is documented in WORKFLOW_STATE.md
# ("Plan > New module ... Group→role mapping") and is intentionally fixed at
# this level — operators configure the Authentik group names to match
# ``admin`` / ``editor`` / ``user`` / ``viewer`` below the configured prefix.
_ADMIN_GROUP = "admin"
_EDITOR_GROUP = "editor"
_USER_GROUP = "user"
_VIEWER_GROUP = "viewer"
_ADMIN_WORKSPACE_ROLE = "admin"
_USER_WORKSPACE_ROLE = "user"


def _resolve_desired_role(app_groups: list[str]) -> tuple[bool, str | None]:
    """
    Resolve the desired MLflow authorization state from the de-prefixed group
    list.  Returns ``(is_admin, workspace_role_name)``:

    * ``is_admin=True`` ⇒ super-admin; bypasses all RBAC.  Wins over any
      other group in the list.
    * ``workspace_role_name`` is the name of the MLflow role in the
      ``default`` workspace the user should hold, one of ``"admin"`` (MANAGE
      tier — workspace admin), ``"user"`` (USE tier — member), or ``None``
      (no workspace role; read-only via ``default_permission``).
    * ``editor`` → ``"admin"`` role (MANAGE).  ``user`` → ``"user"`` role
      (USE).  ``viewer`` and any other prefixed group → no workspace role.
    * When ``is_admin=True`` the workspace role is forced to ``None`` because
      super-admin already bypasses RBAC.
    """
    is_admin = _ADMIN_GROUP in app_groups
    workspace_role: str | None
    if _EDITOR_GROUP in app_groups:
        workspace_role = _ADMIN_WORKSPACE_ROLE
    elif _USER_GROUP in app_groups:
        workspace_role = _USER_WORKSPACE_ROLE
    else:
        # ``viewer`` and any other ``mlflow-*`` group fall here.
        workspace_role = None
    if is_admin:
        workspace_role = None
    return is_admin, workspace_role


# --- Managed-role / user helpers --------------------------------------------


def _ensure_managed_role(s: SqlAlchemyStore, name: str, permission: str) -> int:
    """
    Idempotently get-or-create the role named ``name`` in
    :data:`DEFAULT_WORKSPACE_NAME` and ensure it has the workspace-wide
    ``("workspace", "*")`` grant at ``permission`` (USE or MANAGE).
    Returns the role id.

    Both the role creation and the workspace-wide permission insert are
    treated as idempotent: a ``RESOURCE_ALREADY_EXISTS`` failure on either
    is swallowed and the existing row is used.
    """
    try:
        role = s.get_role_by_name(DEFAULT_WORKSPACE_NAME, name)
    except MlflowException:
        try:
            role = s.create_role(
                name=name,
                workspace=DEFAULT_WORKSPACE_NAME,
                description=(
                    f"Auto-managed by authentik-auth plugin. {permission} on the "
                    f"'{DEFAULT_WORKSPACE_NAME}' workspace."
                ),
            )
        except MlflowException as exc:
            if getattr(exc, "error_code", None) != "RESOURCE_ALREADY_EXISTS":
                raise
            role = s.get_role_by_name(DEFAULT_WORKSPACE_NAME, name)
    # Ensure the workspace-wide permission row exists.  ``add_role_permission``
    # raises ``RESOURCE_ALREADY_EXISTS`` when the row is already present —
    # treat that as a successful no-op.
    try:
        s.add_role_permission(role.id, RESOURCE_TYPE_WORKSPACE, "*", permission)
    except MlflowException as exc:
        if getattr(exc, "error_code", None) != "RESOURCE_ALREADY_EXISTS":
            raise
    return role.id


def _jit_provision_and_reconcile(
    s: SqlAlchemyStore, username: str, is_admin: bool, workspace_role: str | None
) -> "User":
    """
    Make sure the local user ``username`` exists, then reconcile their
    ``is_admin`` flag and their managed workspace roles against the desired
    state derived from the proxy headers.

    * The user is created on first sight with a random unusable password (so
      they cannot authenticate via the basic-auth fallback).
    * ``is_admin`` is updated only when it differs.
    * The two managed roles (``admin``/MANAGE and ``user``/USE in the
      ``default`` workspace) are reconciled: the desired one is ensured
      assigned, the other is unassigned.  Any other roles the user holds
      manually are left untouched.
    * Per-operation ``MlflowException`` are logged and swallowed so that
      partial failures self-heal on the next request.
    """
    # 1. JIT-provision the user.
    if not s.has_user(username):
        random_password = secrets.token_urlsafe(32)
        try:
            s.create_user(username, random_password, is_admin=is_admin)
        except MlflowException as exc:
            if getattr(exc, "error_code", None) != "RESOURCE_ALREADY_EXISTS":
                raise
            # Another concurrent request created the user between our
            # has_user() and create_user() calls.  Fall through and
            # reconcile.

    # 2. Reconcile is_admin and refresh the entity.
    user = s.get_user(username)
    if user.is_admin != is_admin:
        try:
            s.update_user(username, is_admin=is_admin)
            user = s.get_user(username)
        except MlflowException:
            _logger.exception("Failed to update is_admin for user %r", username)

    # 3. Reconcile the two managed workspace roles.
    try:
        current_roles = s.list_user_roles_for_workspace(user.id, DEFAULT_WORKSPACE_NAME)
        current_managed_names = {
            r.name for r in current_roles if r.name in (_ADMIN_WORKSPACE_ROLE, _USER_WORKSPACE_ROLE)
        }
        desired_name: str | None = None
        desired_permission: str | None = None
        if workspace_role == _ADMIN_WORKSPACE_ROLE:
            desired_name = _ADMIN_WORKSPACE_ROLE
            desired_permission = MANAGE.name
        elif workspace_role == _USER_WORKSPACE_ROLE:
            desired_name = _USER_WORKSPACE_ROLE
            desired_permission = USE.name

        # Ensure the desired managed role exists and is assigned.
        if desired_name is not None and desired_permission is not None:
            desired_role_id = _ensure_managed_role(s, desired_name, desired_permission)
            if desired_name not in current_managed_names:
                try:
                    s.assign_role_to_user(user.id, desired_role_id)
                except MlflowException:
                    _logger.exception("Failed to assign role %r to user %r", desired_name, username)

        # Unassign the *other* managed role when present.
        for other_name in (_ADMIN_WORKSPACE_ROLE, _USER_WORKSPACE_ROLE):
            if other_name == desired_name:
                continue
            if other_name not in current_managed_names:
                continue
            other_role = s.get_role_by_name(DEFAULT_WORKSPACE_NAME, other_name)
            try:
                s.unassign_role_from_user(user.id, other_role.id)
            except MlflowException:
                _logger.exception("Failed to unassign role %r from user %r", other_name, username)
    except MlflowException:
        _logger.exception("Role reconciliation failed for user %r", username)

    return s.get_user(username)


# --- Shared-secret + 401/403 responses --------------------------------------


def _check_shared_secret(headers) -> bool:
    """
    Enforce the optional shared-secret check.  When the env var is unset /
    empty the check is a no-op and always returns ``True``.
    """
    expected = MLFLOW_AUTHENTIK_SHARED_SECRET.get()
    if not expected:
        return True
    header_name = MLFLOW_AUTHENTIK_SHARED_SECRET_HEADER.get() or "X-authentik-proxy-secret"
    provided = headers.get(header_name) or ""
    if not provided:
        return False
    return secrets.compare_digest(provided, expected)


def make_authentik_unauthenticated_response():
    """
    401 response used when the request fails the trust-boundary or
    shared-secret check.  No ``WWW-Authenticate`` header is included —
    Authentik supplies authentication upstream; the browser side never sees
    this server directly.
    """
    return make_response(("Authentication required via the Authentik proxy.", 401))


# --- Flask authorization function -------------------------------------------


def _g_cache_set(result) -> None:
    """Memoize the authentication result for the current Flask request."""
    g._authentik_auth_result = result


def _g_cache_get():
    """Return the previously memoized result, or ``None`` if absent."""
    return getattr(g, "_authentik_auth_result", None)


def authenticate_request_authentik_proxy() -> Authorization | object:
    """
    Flask ``before_request`` authorization function used by the
    ``authentik-auth`` app plugin.

    Mirrors the contract of :func:`mlflow.server.auth.authenticate_request_basic_auth`:
    returns a :class:`werkzeug.datastructures.Authorization` on success or a
    Flask ``Response`` on failure.

    The result is cached on :data:`flask.g` for the duration of the request
    because ``_before_request`` may invoke this function multiple times per
    request.
    """
    cached = _g_cache_get()
    if cached is not None:
        return cached

    # 1. Trust boundary — refuse to read headers from an untrusted peer.
    if not _is_from_trusted_proxy(request.remote_addr):
        resp = make_authentik_unauthenticated_response()
        _g_cache_set(resp)
        return resp

    # 2. Optional shared-secret check.
    if not _check_shared_secret(request.headers):
        resp = make_authentik_unauthenticated_response()
        _g_cache_set(resp)
        return resp

    # 3. Username: prefer the dedicated header, fall back to email.
    username = request.headers.get(USERNAME_HEADER) or request.headers.get(EMAIL_HEADER)
    if not username:
        resp = make_authentik_unauthenticated_response()
        _g_cache_set(resp)
        return resp

    # 4. Group-to-role mapping; reject if no prefixed group is present.
    app_groups = _parse_app_groups(
        request.headers.get(GROUPS_HEADER, ""),
        MLFLOW_AUTHENTIK_GROUP_PREFIX.get(),
    )
    if not app_groups:
        # Reject-if-no-prefixed-group: refuse 403 and do NOT provision the
        # user.
        resp = make_forbidden_response()
        _g_cache_set(resp)
        return resp

    is_admin, workspace_role = _resolve_desired_role(app_groups)

    # 5. JIT provision + reconcile.  Wrap in try/except so a transient store
    # failure produces a 401 (fail closed) instead of a 500.
    try:
        _jit_provision_and_reconcile(store, username, is_admin, workspace_role)
    except MlflowException:
        _logger.exception("JIT provisioning failed for user %r", username)
        resp = make_authentik_unauthenticated_response()
        _g_cache_set(resp)
        return resp

    # 6. Return a synthetic Basic-style Authorization that the existing
    # ``_before_request`` and validators understand.
    result = Authorization("basic", {"username": username, "password": ""})
    _g_cache_set(result)
    return result


# --- FastAPI / Starlette auth -----------------------------------------------


def _authenticate_fastapi_request_authentik(request: StarletteRequest):
    """
    FastAPI counterpart of :func:`authenticate_request_authentik_proxy`.
    Returns the authenticated :class:`User` on success or ``None`` on any
    failure (so the middleware rejects with 401).

    The internal gateway token is honored for ``/gateway/`` routes so
    server-spawned job subprocesses still authenticate.
    """
    # Internal-token check for server-spawned job subprocesses (mirrors the
    # existing basic-auth FastAPI path).  This must run before the proxy
    # header path because the job subprocesses do not have a trusted
    # client.host (uvicorn forks).
    internal_token = _MLFLOW_INTERNAL_GATEWAY_AUTH_TOKEN.get()
    if internal_token:
        try:
            request_path = get_routed_asgi_path(request)
        except Exception:
            request_path = ""
        if request_path.startswith("/gateway/"):
            auth = request.headers.get("Authorization")
            if auth:
                try:
                    scheme, credentials = auth.split(" ", 1)
                    if scheme.lower() == "basic":
                        import base64

                        decoded = base64.b64decode(credentials).decode("ascii")
                        internal_username, _, internal_password = decoded.partition(":")
                        if secrets.compare_digest(internal_password, internal_token):
                            user = store.get_user(internal_username)
                            if user is not None:
                                return user
                except Exception:
                    pass

    # Trust boundary.
    client = getattr(request, "client", None)
    peer = getattr(client, "host", None) if client is not None else None
    if not _is_from_trusted_proxy(peer):
        return None

    # Shared secret.
    if not _check_shared_secret(request.headers):
        return None

    # Username.
    username = request.headers.get(USERNAME_HEADER) or request.headers.get(EMAIL_HEADER)
    if not username:
        return None

    # Group→role mapping; reject when no prefixed group.
    app_groups = _parse_app_groups(
        request.headers.get(GROUPS_HEADER, ""),
        MLFLOW_AUTHENTIK_GROUP_PREFIX.get(),
    )
    if not app_groups:
        return None

    is_admin, workspace_role = _resolve_desired_role(app_groups)

    try:
        return _jit_provision_and_reconcile(store, username, is_admin, workspace_role)
    except MlflowException:
        _logger.exception("JIT provisioning failed for user %r", username)
        return None


def add_fastapi_permission_middleware_authentik(app) -> None:
    """
    Register the FastAPI permission middleware on ``app`` using the
    authentik proxy auth function.  Reuses the existing
    :func:`mlflow.server.auth.add_fastapi_permission_middleware` so the
    standard admin/RBAC/validator logic continues to apply.
    """
    add_fastapi_permission_middleware(app, auth_func=_authenticate_fastapi_request_authentik)


# --- Flask app factory -------------------------------------------------------


#: Public dotted path of the Flask authorization function.  Referenced by the
#: entry point in ``pyproject.toml`` and by the ``create_app`` wrapper below
#: — kept as a constant so the two stay in sync.
_AUTHENTIK_AUTHORIZATION_FUNCTION = (
    "mlflow.server.auth.authentik_proxy:authenticate_request_authentik_proxy"
)


def create_app(app: Flask = _shared_flask_app):
    """
    App factory registered as the ``authentik-auth`` entry point.  Thin
    wrapper over the basic-auth factory that:

    1. Skips registration of the native ``/signup`` and ``CREATE_USER_UI``
       routes (authentication is via Authentik, not the local form).
    2. Swaps the module-global ``auth_config.authorization_function`` to
       :func:`authenticate_request_authentik_proxy` so all
       ``authenticate_request()`` calls dispatch to header auth.
    3. Passes the authentik FastAPI authenticator into the FastAPI
       permission middleware.

    Defaults to the shared module-level Flask ``app``; callers (e.g. tests)
    may pass their own instance.
    """
    return _basic_create_app(
        app,
        register_signup_ui=False,
        authorization_function=_AUTHENTIK_AUTHORIZATION_FUNCTION,
        fastapi_auth_func=_authenticate_fastapi_request_authentik,
    )


# Re-export the symbols the FastAPI middleware + plugin contract expect.
__all__ = [
    "add_fastapi_permission_middleware_authentik",
    "authenticate_request_authentik_proxy",
    "create_app",
    "make_authentik_unauthenticated_response",
]
