"""
Unit tests for the ``authentik-auth`` MLflow auth plugin.

Covers:

* Pure-helper unit tests (``_parse_app_groups``, ``_resolve_desired_role``,
  ``_is_from_trusted_proxy``).
* Flask ``test_request_context`` tests against an isolated
  :class:`SqlAlchemyStore` — covers the JIT-provisioning + reconciliation
  flow, the trust-boundary spoofing defence, shared-secret enforcement,
  reject-if-no-prefixed-group, and the per-request ``g`` cache.
* Reconciliation tests including manual-role preservation.
* FastAPI auth function with a minimal Starlette ``Request``.
* ``create_app`` smoke test that the signup route is NOT registered and
  that the auth function has been swapped.
"""

from __future__ import annotations

import base64

import pytest
from flask import Flask
from starlette.requests import Request as StarletteRequest

import mlflow.server.auth as auth_module
from mlflow.environment_variables import (
    MLFLOW_AUTHENTIK_SHARED_SECRET,
    MLFLOW_AUTHENTIK_SHARED_SECRET_HEADER,
    MLFLOW_AUTHENTIK_TRUSTED_PROXY_IPS,
    MLFLOW_FLASK_SERVER_SECRET_KEY,
)
from mlflow.server.auth import authentik_proxy as ap
from mlflow.server.auth.entities import User
from mlflow.server.auth.permissions import MANAGE, RESOURCE_TYPE_WORKSPACE, USE
from mlflow.server.auth.routes import LIST_USERS, SIGNUP
from mlflow.server.auth.sqlalchemy_store import SqlAlchemyStore
from mlflow.utils.workspace_utils import DEFAULT_WORKSPACE_NAME

pytestmark = pytest.mark.notrackingurimock


# --- Fixtures ---------------------------------------------------------------


@pytest.fixture
def store(tmp_sqlite_uri):
    s = SqlAlchemyStore()
    s.init_db(tmp_sqlite_uri)
    return s


@pytest.fixture
def isolated_store(store, tmp_sqlite_uri, monkeypatch):
    """
    Replace the module-level ``store`` used by the authentik plugin with a
    fresh isolated :class:`SqlAlchemyStore` so tests do not touch any
    shared DB.  Also rebind the basic-auth ``auth_config.database_uri`` to
    the test's temp DB so the ``create_app`` factory initialises the
    test-scoped store rather than the default ``basic_auth.db``.  Also
    clear the ``_trusted_networks`` lru_cache so tests that mutate the
    trust list start from a known state.
    """
    # Re-point auth_config at the test's sqlite file BEFORE
    # ``create_app`` calls ``store.init_db(auth_config.database_uri)``.
    # ``auth_config`` is a NamedTuple so we must swap it via ``_replace``.
    monkeypatch.setattr(
        auth_module,
        "auth_config",
        auth_module.auth_config._replace(
            database_uri=tmp_sqlite_uri,
            read_database_uri=None,
        ),
    )
    monkeypatch.setattr(ap, "store", store)
    ap._trusted_networks.cache_clear()
    yield store
    ap._trusted_networks.cache_clear()


@pytest.fixture
def auth_app(monkeypatch, isolated_store, tmp_sqlite_uri):
    """
    Build a fresh Flask app wired up with the ``authentik-auth`` plugin and
    a known secret key.  Returns the Flask app.
    """
    monkeypatch.setenv(MLFLOW_FLASK_SERVER_SECRET_KEY.name, "test-key")
    monkeypatch.setattr(auth_module, "store", isolated_store)
    app = Flask("test-authentik")
    return ap.create_app(app)


# --- Helper unit tests ------------------------------------------------------


class TestParseAppGroups:
    def test_strips_prefix_and_splits_on_pipe(self):
        assert ap._parse_app_groups("mlflow-admin|mlflow-user", "mlflow-") == [
            "admin",
            "user",
        ]

    def test_ignores_non_prefixed(self):
        assert ap._parse_app_groups("mlflow-admin|other-team", "mlflow-") == ["admin"]

    def test_empty_returns_empty(self):
        assert ap._parse_app_groups("", "mlflow-") == []
        assert ap._parse_app_groups(None, "mlflow-") == []

    def test_lowercases_remainder(self):
        assert ap._parse_app_groups("mlflow-Admin", "mlflow-") == ["admin"]

    def test_strips_whitespace_around_groups(self):
        assert ap._parse_app_groups(" mlflow-admin | mlflow-user ", "mlflow-") == [
            "admin",
            "user",
        ]


class TestResolveDesiredRole:
    def test_admin(self):
        assert ap._resolve_desired_role(["admin"]) == (True, None)

    def test_editor_maps_to_admin_role(self):
        assert ap._resolve_desired_role(["editor"]) == (False, "admin")

    def test_user_maps_to_user_role(self):
        assert ap._resolve_desired_role(["user"]) == (False, "user")

    def test_viewer_no_workspace_role(self):
        assert ap._resolve_desired_role(["viewer"]) == (False, None)

    def test_unknown_no_workspace_role(self):
        assert ap._resolve_desired_role(["some-other-group"]) == (False, None)

    def test_admin_wins_over_user(self):
        # super-admin bypasses RBAC → no workspace role needed
        assert ap._resolve_desired_role(["admin", "user"]) == (True, None)


class TestIsFromTrustedProxy:
    def test_localhost_ipv4(self, monkeypatch):
        monkeypatch.setenv(MLFLOW_AUTHENTIK_TRUSTED_PROXY_IPS.name, "127.0.0.1,::1")
        ap._trusted_networks.cache_clear()
        assert ap._is_from_trusted_proxy("127.0.0.1") is True

    def test_localhost_ipv6(self, monkeypatch):
        monkeypatch.setenv(MLFLOW_AUTHENTIK_TRUSTED_PROXY_IPS.name, "127.0.0.1,::1")
        ap._trusted_networks.cache_clear()
        assert ap._is_from_trusted_proxy("::1") is True

    def test_untrusted_ip(self, monkeypatch):
        monkeypatch.setenv(MLFLOW_AUTHENTIK_TRUSTED_PROXY_IPS.name, "127.0.0.1,::1")
        ap._trusted_networks.cache_clear()
        assert ap._is_from_trusted_proxy("10.0.0.1") is False
        assert ap._is_from_trusted_proxy("8.8.8.8") is False

    def test_wildcard_trusts_any(self, monkeypatch):
        monkeypatch.setenv(MLFLOW_AUTHENTIK_TRUSTED_PROXY_IPS.name, "*")
        ap._trusted_networks.cache_clear()
        assert ap._is_from_trusted_proxy("8.8.8.8") is True

    def test_cidr_match(self, monkeypatch):
        monkeypatch.setenv(MLFLOW_AUTHENTIK_TRUSTED_PROXY_IPS.name, "10.0.0.0/8")
        ap._trusted_networks.cache_clear()
        assert ap._is_from_trusted_proxy("10.0.0.5") is True
        assert ap._is_from_trusted_proxy("10.255.255.255") is True
        assert ap._is_from_trusted_proxy("11.0.0.1") is False

    def test_bad_addr_returns_false(self):
        assert ap._is_from_trusted_proxy("not-an-ip") is False

    def test_none_returns_false(self):
        assert ap._is_from_trusted_proxy(None) is False


# --- Flask request-context tests -------------------------------------------


def _trusted_headers(remote_addr="127.0.0.1", **header_values):
    """Build headers and the kwargs for a ``test_request_context`` call."""
    headers = {
        ap.USERNAME_HEADER: header_values.get("username", "alice"),
        ap.GROUPS_HEADER: header_values.get("groups", "mlflow-user"),
        ap.EMAIL_HEADER: header_values.get("email", "alice@example.com"),
        ap.NAME_HEADER: header_values.get("name", "Alice"),
    }
    if "secret" in header_values:
        headers[MLFLOW_AUTHENTIK_SHARED_SECRET_HEADER.get()] = header_values["secret"]
    headers = {k: v for k, v in headers.items() if v is not None}
    return headers, {"environ_overrides": {"REMOTE_ADDR": remote_addr}}


class TestAuthenticateRequestAuthentikProxy:
    def test_user_group_provisions_user_with_user_role(self, auth_app, isolated_store):
        headers, ctx = _trusted_headers(username="alice", groups="mlflow-user")
        with auth_app.test_request_context("/", headers=headers, **ctx):
            result = ap.authenticate_request_authentik_proxy()

        assert result is not None
        # Returned object exposes ``.username`` (the Basic-style contract).
        assert getattr(result, "username", None) == "alice"

        user = isolated_store.get_user("alice")
        assert user is not None
        assert user.is_admin is False

        # ``user`` role assigned in the default workspace.
        roles = isolated_store.list_user_roles_for_workspace(user.id, DEFAULT_WORKSPACE_NAME)
        assert [r.name for r in roles] == ["user"]

    def test_admin_group_sets_is_admin(self, auth_app, isolated_store):
        headers, ctx = _trusted_headers(username="root", groups="mlflow-admin")
        with auth_app.test_request_context("/", headers=headers, **ctx):
            ap.authenticate_request_authentik_proxy()

        user = isolated_store.get_user("root")
        assert user is not None
        assert user.is_admin is True

        # Super-admin has no managed workspace role (RBAC is bypassed).
        roles = isolated_store.list_user_roles_for_workspace(user.id, DEFAULT_WORKSPACE_NAME)
        assert [r.name for r in roles] == []

    def test_editor_group_gets_admin_role(self, auth_app, isolated_store):
        headers, ctx = _trusted_headers(username="ed", groups="mlflow-editor")
        with auth_app.test_request_context("/", headers=headers, **ctx):
            ap.authenticate_request_authentik_proxy()

        user = isolated_store.get_user("ed")
        roles = isolated_store.list_user_roles_for_workspace(user.id, DEFAULT_WORKSPACE_NAME)
        assert [r.name for r in roles] == ["admin"]
        admin_role = roles[0]
        perms = isolated_store.list_role_permissions(admin_role.id)
        assert any(
            p.resource_type == RESOURCE_TYPE_WORKSPACE and p.permission == MANAGE.name
            for p in perms
        )

    def test_viewer_group_no_workspace_role(self, auth_app, isolated_store):
        headers, ctx = _trusted_headers(username="vw", groups="mlflow-viewer")
        with auth_app.test_request_context("/", headers=headers, **ctx):
            result = ap.authenticate_request_authentik_proxy()

        assert getattr(result, "username", None) == "vw"
        user = isolated_store.get_user("vw")
        assert user is not None
        assert user.is_admin is False
        roles = isolated_store.list_user_roles_for_workspace(user.id, DEFAULT_WORKSPACE_NAME)
        assert roles == []

    def test_no_prefixed_group_returns_403_and_no_provision(self, auth_app, isolated_store):
        headers, ctx = _trusted_headers(username="bob", groups="other-team|another-team")
        with auth_app.test_request_context("/", headers=headers, **ctx):
            result = ap.authenticate_request_authentik_proxy()

        # 403 response — should be a Flask Response, not an Authorization.
        from flask import Response

        assert isinstance(result, Response)
        assert result.status_code == 403
        assert not isolated_store.has_user("bob")

    def test_untrusted_peer_with_spoofed_headers_is_rejected(self, auth_app, isolated_store):
        """Spoofing defence: an attacker that can set ``X-authentik-*``
        headers directly (without going through the proxy) MUST be ignored
        when the source peer is not in the trusted set.
        """
        headers, ctx = _trusted_headers(
            remote_addr="8.8.8.8", username="mallory", groups="mlflow-admin"
        )
        with auth_app.test_request_context("/", headers=headers, **ctx):
            result = ap.authenticate_request_authentik_proxy()

        from flask import Response

        assert isinstance(result, Response)
        assert result.status_code == 401
        # No provisioning happens for an untrusted peer.
        assert not isolated_store.has_user("mallory")

    def test_shared_secret_mismatch_returns_401(self, auth_app, isolated_store, monkeypatch):
        monkeypatch.setenv(MLFLOW_AUTHENTIK_SHARED_SECRET.name, "s3cret")
        headers, ctx = _trusted_headers(secret="wrong", username="eve", groups="mlflow-user")
        with auth_app.test_request_context("/", headers=headers, **ctx):
            from flask import Response

            result = ap.authenticate_request_authentik_proxy()
            assert isinstance(result, Response)
            assert result.status_code == 401
            assert not isolated_store.has_user("eve")

    def test_shared_secret_match_authenticates(self, auth_app, isolated_store, monkeypatch):
        monkeypatch.setenv(MLFLOW_AUTHENTIK_SHARED_SECRET.name, "s3cret")
        headers, ctx = _trusted_headers(secret="s3cret", username="eve", groups="mlflow-user")
        with auth_app.test_request_context("/", headers=headers, **ctx):
            result = ap.authenticate_request_authentik_proxy()
        assert getattr(result, "username", None) == "eve"
        assert isolated_store.has_user("eve") is True

    def test_no_username_returns_401(self, auth_app, isolated_store):
        # No X-authentik-username and no X-authentik-email.
        headers = {ap.GROUPS_HEADER: "mlflow-user"}
        with auth_app.test_request_context(
            "/", headers=headers, environ_overrides={"REMOTE_ADDR": "127.0.0.1"}
        ):
            from flask import Response

            result = ap.authenticate_request_authentik_proxy()
            assert isinstance(result, Response)
            assert result.status_code == 401

    def test_email_fallback_for_username(self, auth_app, isolated_store):
        # Only email is set; username falls back to email.
        headers = {
            ap.EMAIL_HEADER: "charlie@example.com",
            ap.GROUPS_HEADER: "mlflow-user",
        }
        with auth_app.test_request_context(
            "/", headers=headers, environ_overrides={"REMOTE_ADDR": "127.0.0.1"}
        ):
            result = ap.authenticate_request_authentik_proxy()
        assert getattr(result, "username", None) == "charlie@example.com"
        assert isolated_store.has_user("charlie@example.com") is True

    def test_per_request_g_cache(self, auth_app, isolated_store):
        """The per-request ``g`` cache avoids re-provisioning on multiple
        ``authenticate_request_authentik_proxy`` calls in the same request.
        """
        headers, ctx = _trusted_headers(username="dora", groups="mlflow-user")
        with auth_app.test_request_context("/", headers=headers, **ctx):
            first = ap.authenticate_request_authentik_proxy()
            # ``g._authentik_auth_result`` should be set after the first call.
            from flask import g

            assert getattr(g, "_authentik_auth_result", None) is not None
            # Second call returns the cached object (identity check).
            second = ap.authenticate_request_authentik_proxy()
            assert first is second
            # The user is provisioned exactly once.
            assert isolated_store.has_user("dora") is True


# --- Reconciliation tests --------------------------------------------------


class TestReconciliation:
    def test_stale_is_admin_demoted(self, auth_app, isolated_store):
        # Pre-seed the user as a super-admin.
        isolated_store.create_user("exadmin", "valid-password-12345", is_admin=True)
        assert isolated_store.get_user("exadmin").is_admin is True

        # They now show up with only ``mlflow-user`` group → should be demoted.
        headers, ctx = _trusted_headers(username="exadmin", groups="mlflow-user")
        with auth_app.test_request_context("/", headers=headers, **ctx):
            ap.authenticate_request_authentik_proxy()

        user = isolated_store.get_user("exadmin")
        assert user.is_admin is False
        roles = isolated_store.list_user_roles_for_workspace(user.id, DEFAULT_WORKSPACE_NAME)
        assert [r.name for r in roles] == ["user"]

    def test_managed_role_corrected_on_group_change(self, auth_app, isolated_store):
        # Pre-seed the user with the "admin" role in the default workspace.
        user = isolated_store.create_user("promote", "valid-password-12345", is_admin=False)
        admin_role = isolated_store.create_role("admin", DEFAULT_WORKSPACE_NAME)
        isolated_store.add_role_permission(admin_role.id, RESOURCE_TYPE_WORKSPACE, "*", MANAGE.name)
        isolated_store.assign_role_to_user(user.id, admin_role.id)

        # Now they show up with only ``mlflow-user`` group → should be moved.
        headers, ctx = _trusted_headers(username="promote", groups="mlflow-user")
        with auth_app.test_request_context("/", headers=headers, **ctx):
            ap.authenticate_request_authentik_proxy()

        roles = isolated_store.list_user_roles_for_workspace(user.id, DEFAULT_WORKSPACE_NAME)
        assert [r.name for r in roles] == ["user"]
        # The ``admin`` role itself still exists in the workspace.
        admin_after = isolated_store.get_role_by_name(DEFAULT_WORKSPACE_NAME, "admin")
        assert admin_after.id == admin_role.id

    def test_manual_role_assignments_preserved(self, auth_app, isolated_store):
        # Pre-seed a user and manually create + assign a custom role.
        user = isolated_store.create_user("manual", "valid-password-12345", is_admin=False)
        custom_role = isolated_store.create_role(
            "custom-readers", DEFAULT_WORKSPACE_NAME, description="Manual"
        )
        isolated_store.add_role_permission(custom_role.id, RESOURCE_TYPE_WORKSPACE, "*", USE.name)
        isolated_store.assign_role_to_user(user.id, custom_role.id)

        # Authenticate with the ``mlflow-user`` group.
        headers, ctx = _trusted_headers(username="manual", groups="mlflow-user")
        with auth_app.test_request_context("/", headers=headers, **ctx):
            ap.authenticate_request_authentik_proxy()

        roles = isolated_store.list_user_roles_for_workspace(user.id, DEFAULT_WORKSPACE_NAME)
        role_names = {r.name for r in roles}
        # Both the auto-managed ``user`` role and the manually-assigned
        # ``custom-readers`` role are present.
        assert "user" in role_names
        assert "custom-readers" in role_names

    def test_idempotent_jit(self, auth_app, isolated_store):
        headers, ctx = _trusted_headers(username="idem", groups="mlflow-user")
        # First request → JIT provisioning.
        with auth_app.test_request_context("/", headers=headers, **ctx):
            ap.authenticate_request_authentik_proxy()
        # Second request → no double-provisioning; user is_admin matches.
        with auth_app.test_request_context("/", headers=headers, **ctx):
            ap.authenticate_request_authentik_proxy()
        user = isolated_store.get_user("idem")
        assert user.is_admin is False
        roles = isolated_store.list_user_roles_for_workspace(user.id, DEFAULT_WORKSPACE_NAME)
        assert [r.name for r in roles] == ["user"]

    def test_existing_managed_role_wrong_permission_is_corrected(self, auth_app, isolated_store):
        # Pre-seed the "user" managed role but with the *wrong* workspace
        # permission (MANAGE instead of USE).  The plugin must self-heal the
        # permission row on first auth request — otherwise users in the
        # ``mlflow-user`` group would silently inherit MANAGE.
        user_role = isolated_store.create_role("user", DEFAULT_WORKSPACE_NAME)
        isolated_store.add_role_permission(user_role.id, RESOURCE_TYPE_WORKSPACE, "*", MANAGE.name)
        perms_before = isolated_store.list_role_permissions(user_role.id)
        assert any(p.permission == MANAGE.name for p in perms_before)

        headers, ctx = _trusted_headers(username="heal", groups="mlflow-user")
        with auth_app.test_request_context("/", headers=headers, **ctx):
            ap.authenticate_request_authentik_proxy()

        perms_after = isolated_store.list_role_permissions(user_role.id)
        workspace_perms = [
            p
            for p in perms_after
            if p.resource_type == RESOURCE_TYPE_WORKSPACE and p.resource_pattern == "*"
        ]
        assert len(workspace_perms) == 1
        assert workspace_perms[0].permission == USE.name


# --- FastAPI auth test ------------------------------------------------------


def _make_starlette_request(headers: dict, client_host: str = "127.0.0.1") -> StarletteRequest:
    """
    Build a minimal Starlette ``Request`` with the given headers and
    ``client.host``.  Avoids spinning up a real ASGI test server.
    """
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/2.0/mlflow/users/get",
        "headers": [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in headers.items()],
        "client": (client_host, 12345),
        "query_string": b"",
    }
    return StarletteRequest(scope)


class TestFastAPIAuth:
    def test_trusted_peer_authenticates(self, isolated_store):
        headers = {
            ap.USERNAME_HEADER: "fastapi-user",
            ap.GROUPS_HEADER: "mlflow-user",
        }
        request = _make_starlette_request(headers, client_host="127.0.0.1")
        user = ap._authenticate_fastapi_request_authentik(request)
        assert isinstance(user, User)
        assert user.username == "fastapi-user"
        assert user.is_admin is False

    def test_untrusted_peer_rejected(self, isolated_store):
        headers = {
            ap.USERNAME_HEADER: "attacker",
            ap.GROUPS_HEADER: "mlflow-admin",
        }
        request = _make_starlette_request(headers, client_host="8.8.8.8")
        user = ap._authenticate_fastapi_request_authentik(request)
        assert user is None
        # And no user is provisioned.
        assert not isolated_store.has_user("attacker")

    def test_internal_token_trusted_for_gateway(self, isolated_store, monkeypatch):
        # Pre-provision the user.
        isolated_store.create_user("jobuser", "valid-password-12345", is_admin=False)
        # Set the internal token via os.environ (the env-var .get() reads
        # from there at call time).  The var name is intentionally
        # underscore-prefixed (it is generated at server startup and is
        # not meant to be set by hand).
        token = "internal-token-123"
        monkeypatch.setenv("_MLFLOW_INTERNAL_GATEWAY_AUTH_TOKEN", token)

        credentials = base64.b64encode(b"jobuser:" + token.encode()).decode("ascii")
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/gateway/some-endpoint/mlflow/invocations",
            "headers": [(b"authorization", b"Basic " + credentials.encode("ascii"))],
            "client": ("127.0.0.1", 12345),
            "query_string": b"",
        }
        request = StarletteRequest(scope)
        user = ap._authenticate_fastapi_request_authentik(request)
        assert isinstance(user, User)
        assert user.username == "jobuser"


# --- create_app smoke test --------------------------------------------------


class TestCreateApp:
    def test_signup_route_not_registered(self, auth_app, isolated_store):
        # The /signup form and CREATE_USER_UI route should not be wired up
        # under authentik-auth.  We assert directly on the URL map (Flask's
        # request dispatch runs ``_before_request`` first, which finds a
        # validator for ``(SIGNUP, GET)`` and returns 403 before the
        # non-existent route would have produced a 404).
        assert not any(rule.rule == SIGNUP for rule in auth_app.url_map.iter_rules())
        from mlflow.server.auth.routes import CREATE_USER_UI

        assert not any(rule.rule == CREATE_USER_UI for rule in auth_app.url_map.iter_rules())

    def test_rbac_routes_still_registered(self, auth_app):
        # The user/role RBAC REST endpoints are still wired up.
        assert any(rule.rule == LIST_USERS for rule in auth_app.url_map.iter_rules())

    def test_authorization_function_swapped(self, auth_app, isolated_store):
        # After create_app, the module-global auth_config is swapped to the
        # authentik function and the lru_cache cleared.
        assert (
            auth_module.auth_config.authorization_function
            == "mlflow.server.auth.authentik_proxy:authenticate_request_authentik_proxy"
        )
