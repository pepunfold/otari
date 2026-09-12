"""A real OpenID Connect provider, end to end: Keycloak in Docker, nothing mocked.

Every other OAuth/OIDC test in this suite stubs the provider's own outbound
calls, because a test cannot complete a consent screen; see
``test_oauth_api.py``'s own docstring for why, and ``test_oauth_live_provider.py``
for the same tradeoff against Google and GitHub. This file is that check for a
generic OIDC connection: the proof that discovery, PKCE, the server-side
``state``, the RFC 9207 ``iss`` check, and apron-auth's ID-token claim
validation all actually agree with a real, spec-conformant provider, not just
with each other's test doubles.

Keycloak is started the way ``postgres_url`` starts PostgreSQL
(``tests/integration/conftest.py``): Testcontainers, in this job, not a
docker-compose service and not a server shared with anything else in CI. It
needs Docker; without it this file's fixture fails to start rather than the
test silently skipping, the same tradeoff ``postgres_url`` already makes (see
AGENTS.md's Test Notes).
"""

import re
import time
from collections.abc import Generator
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from fastapi.testclient import TestClient
from testcontainers.core.container import DockerContainer

from gateway.core.config import GatewayConfig
from gateway.services.dashboard_session_service import SESSION_COOKIE_NAME

# This deployment's own address in every integration test that mints one:
# starlette's TestClient answers at this origin by construction, which is
# also why the realm export's one registered redirect URI names it.
ORIGIN = "http://testserver"

KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak:26.0"
REALM_NAME = "otari-test"
REALM_FILE = Path(__file__).parent / "oidc_fixtures" / "otari_test_realm.json"
# Matches the realm export: a confidential, PKCE-required client whose one
# registered redirect URI is this deployment's own, and one enabled user.
CLIENT_ID = "otari-gateway"
CLIENT_SECRET = "otari-test-client-secret"  # noqa: S105
TEST_USERNAME = "ada"
TEST_USER_EMAIL = "ada@example.com"
TEST_USER_PASSWORD = "a-real-password"  # noqa: S105
_READY_TIMEOUT_SECONDS = 120.0


@pytest.fixture(scope="session")
def keycloak_issuer() -> Generator[str]:
    """The running realm's issuer URL, the one value ``GatewayConfig.oauth_oidc_issuer_url`` needs.

    Session-scoped like ``postgres_url``: one container pays for the whole
    session (or this xdist worker's share of it), not one per test.
    """
    container = (
        DockerContainer(KEYCLOAK_IMAGE)
        .with_exposed_ports(8080, 9000)
        .with_env("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
        .with_env("KC_BOOTSTRAP_ADMIN_PASSWORD", "admin")  # noqa: S106
        .with_env("KC_HEALTH_ENABLED", "true")
        .with_volume_mapping(str(REALM_FILE), "/opt/keycloak/data/import/realm.json")
        .with_command("start-dev --import-realm")
    )
    container.start()
    try:
        host = container.get_container_host_ip()
        management_url = f"http://{host}:{container.get_exposed_port(9000)}"
        _wait_until_ready(management_url)
        issuer = f"http://{host}:{container.get_exposed_port(8080)}/realms/{REALM_NAME}"
        yield issuer
    finally:
        container.stop()


def _wait_until_ready(management_url: str, *, timeout: float = _READY_TIMEOUT_SECONDS) -> None:
    """Poll Keycloak's own health endpoint rather than sleeping a guessed duration.

    A cold JVM boot plus a realm import is a multi-second, variable-length
    startup; ``postgres_url``'s container has an equivalent wait built into
    its own client library; ``DockerContainer`` here is generic and has none,
    so this is that wait, written once for this one fixture.
    """
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            response = httpx.get(f"{management_url}/health/ready", timeout=2.0)
            if response.status_code == 200:
                return
        except httpx.HTTPError as exc:
            last_error = exc
        time.sleep(1.0)
    msg = f"Keycloak did not become ready within {timeout:.0f}s"
    raise TimeoutError(msg) from last_error


@pytest.fixture
def oidc_configured(
    test_config: GatewayConfig, keycloak_issuer: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Point this deployment's generic OIDC connection at the live realm."""
    monkeypatch.setattr(test_config, "public_base_url", ORIGIN)
    monkeypatch.setattr(test_config, "oauth_oidc_issuer_url", keycloak_issuer)
    monkeypatch.setattr(test_config, "oauth_oidc_client_id", CLIENT_ID)
    monkeypatch.setattr(test_config, "oauth_oidc_client_secret", CLIENT_SECRET)


def add_member(client: TestClient, master_key_header: dict[str, str], *, email: str) -> str:
    """Put an address on the roster, the way an operator does, and return its id.

    Duplicated from ``test_oauth_api.py`` rather than imported: ``tests/`` has
    no ``__init__.py`` (only ``tests/integration/`` does), so pytest's default
    import mode gives sibling test modules no stable package path to import
    each other through, and no other file in this suite does. Small enough
    that keeping this file self-contained costs less than that fragility.
    """
    response = client.post(
        "/v1/organizations/me/members",
        json={"email": email, "role": "member"},
        headers=master_key_header,
    )
    assert response.status_code == 201, response.text
    member: dict[str, Any] = response.json()
    return str(member["user_id"])


def _sign_in_at_keycloak(authorization_url: str) -> httpx.Response:
    """Drive Keycloak's own login form the way a browser would, and return its redirect.

    A plain ``httpx.Client`` rather than a browser: Keycloak's login page is an
    ordinary HTML form over a session cookie, nothing scripted stands between
    it and a submit. The one wrinkle is that cookie: Keycloak marks it
    ``Secure`` even over the plain HTTP this test talks (there is no TLS
    certificate to give a throwaway container), and ``httpx``'s cookie jar
    honors that attribute and withholds it from the next request exactly the
    way a real browser would. Forwarding the raw ``Set-Cookie`` values by hand
    is what a browser's TLS terminator would otherwise make unnecessary.
    """
    with httpx.Client(follow_redirects=False, timeout=10.0) as browser:
        started = browser.get(authorization_url)
        started.raise_for_status()
        cookie_header = "; ".join(
            value.split(";", 1)[0] for value in started.headers.get_list("set-cookie")
        )
        match = re.search(r'<form[^>]+action="([^"]+)"', started.text)
        assert match, "Keycloak's login page did not carry a login form to submit"
        action = match.group(1).replace("&amp;", "&")
        return browser.post(
            action,
            data={"username": TEST_USERNAME, "password": TEST_USER_PASSWORD},
            headers={"Cookie": cookie_header},
        )


def test_a_rostered_member_signs_in_through_a_real_oidc_provider(
    client: TestClient,
    master_key_header: dict[str, str],
    oidc_configured: None,
) -> None:
    """The proof this whole feature exists for.

    Every layer has to agree for this to reach 200: this deployment's real
    discovery fetch against Keycloak's own ``.well-known`` document, a real
    PKCE code challenge Keycloak's client enforces
    (``pkce.code.challenge.method`` in the realm export), the server-side
    ``state`` this deployment recorded and Keycloak's redirect carries back,
    the RFC 9207 ``iss`` Keycloak appends and this deployment checks against
    what it discovered, and the ``iss``, ``aud``, ``azp``, ``exp`` and
    ``at_hash`` claims apron-auth validates on the ID token Keycloak mints. A
    fake provider cannot stand in for any of that; a stub covering the identity
    handler alone (as ``test_oauth_api.py``'s do) proves none of it either.
    """
    user_id = add_member(client, master_key_header, email=TEST_USER_EMAIL)

    started = client.get("/v1/auth/oauth/oidc/authorize")
    assert started.status_code == 200, started.text
    authorization_url = started.json()["authorization_url"]

    redirected = _sign_in_at_keycloak(authorization_url)
    assert redirected.status_code == 302, redirected.text
    location = redirected.headers["location"]
    assert location.startswith(f"{ORIGIN}/auth/oidc/callback")
    query = parse_qs(urlsplit(location).query)
    assert "code" in query
    assert "iss" in query, "Keycloak did not send RFC 9207's iss; nothing here to check"

    response = client.post(
        "/v1/auth/oauth/oidc/callback",
        json={"code": query["code"][0], "state": query["state"][0], "iss": query["iss"][0]},
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["user_id"] == user_id
    assert SESSION_COOKIE_NAME in response.cookies


def test_a_second_attempt_with_the_first_codes_state_is_refused(
    client: TestClient,
    master_key_header: dict[str, str],
    oidc_configured: None,
) -> None:
    """Single-use end to end: Keycloak's own single-use code, and this deployment's state row."""
    add_member(client, master_key_header, email=TEST_USER_EMAIL)
    started = client.get("/v1/auth/oauth/oidc/authorize")
    authorization_url = started.json()["authorization_url"]
    redirected = _sign_in_at_keycloak(authorization_url)
    query = parse_qs(urlsplit(redirected.headers["location"]).query)
    body = {"code": query["code"][0], "state": query["state"][0], "iss": query["iss"][0]}

    first = client.post("/v1/auth/oauth/oidc/callback", json=body)
    assert first.status_code == 200, first.text

    replayed = client.post("/v1/auth/oauth/oidc/callback", json=body)
    assert replayed.status_code == 400
