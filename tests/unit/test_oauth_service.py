"""The OAuth half of dashboard sign-in: configuration, URLs, and the exchange.

Covers what this deployment owns, which is what ``services/oauth_service.py``
kept when the protocol mechanics moved onto apron-auth: which providers are
configured, which scopes are asked for, where the provider is told to send the
browser back to, the PKCE and ``state`` binding the flow rests on, and the
carry-over that must survive the port (a tri-state ``email_verified`` collapses
on the unverified side).

The live exchange itself is not here and cannot be: a green suite that stubs
apron-auth proves wiring and never that the request shape it sends is one a
provider accepts. ``tests/integration/test_oauth_live_provider.py`` is that
check, behind an opt-in flag.
"""

import logging
from collections.abc import Generator
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock
from urllib.parse import parse_qs, urlsplit

import pytest
from apron_auth import OAuthClient
from apron_auth.errors import ConfigurationError, IdentityFetchError, OidcDiscoveryError
from apron_auth.models import ServerMetadata, TokenSet
from apron_auth.providers import github as apron_github
from apron_auth.providers import google as apron_google
from apron_auth.providers import oidc as apron_oidc
from sqlalchemy.ext.asyncio import AsyncSession

from gateway.core.config import OAUTH_PROVIDERS, GatewayConfig
from gateway.log_config import logger as gateway_logger
from gateway.services import oauth_service
from gateway.services.tenancy.errors import (
    OAuthExchangeError,
    OAuthNotConfiguredError,
    OAuthProviderUnavailableError,
    OAuthProviderUnusableError,
    OAuthStateError,
)

# Providers apron-auth ships a fixed preset for: hardcoded endpoints, no
# discovery. ``oidc`` has none of that by design (an operator's own issuer
# cannot be a compile-time constant), so a test about preset internals
# specifically does not extend to it; those are parametrized over this
# narrower tuple rather than the full ``OAUTH_PROVIDERS``.
_PRESET_PROVIDERS = ("google", "github")

OIDC_METADATA = ServerMetadata(
    issuer="https://idp.example.com",
    authorize_url="https://idp.example.com/authorize",
    token_url="https://idp.example.com/token",
    jwks_url="https://idp.example.com/jwks",
    userinfo_url="https://idp.example.com/userinfo",
    code_challenge_methods=["S256"],
    token_endpoint_auth_methods=["client_secret_post"],
    iss_parameter_supported=True,
)


@pytest.fixture(autouse=True)
def _stub_oidc_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every test in this module gets a discoverable ``oidc`` connection with no network.

    Google's and GitHub's authorization URLs are built from apron-auth's own
    constants, so building one has never needed the network in this file.
    Building one for ``oidc`` does (discovery is the whole point), so this
    is what keeps that difference from leaking into every test that exercises
    all three providers alike. Discovery itself is apron-auth's, and covered
    there; ``tests/integration/test_oidc_keycloak.py`` is where this
    deployment exercises it unstubbed against a real provider.
    """
    monkeypatch.setattr(apron_oidc, "discover", AsyncMock(return_value=OIDC_METADATA))


class FakeSession:
    """Enough ``AsyncSession`` for the state store to stage a row against.

    The store's two statements are exercised for real against PostgreSQL in
    ``tests/integration/test_oauth_api.py``; what these tests need is a
    session that accepts them, so that building an authorization URL can be
    asserted on without a database.
    """

    def __init__(self) -> None:
        self.added: list[Any] = []

    async def execute(self, *_args: Any, **_kwargs: Any) -> Any:
        return SimpleNamespace(first=lambda: None)

    def add(self, instance: Any) -> None:
        self.added.append(instance)

    async def flush(self) -> None:
        return None


def fake_db() -> AsyncSession:
    return cast("AsyncSession", FakeSession())


FLOW_SECRET = "a-flow-secret"


async def authorize(config: GatewayConfig, provider: str) -> tuple[str, str]:
    """``authorization_url`` over a throwaway session, for the URL assertions."""
    return await oauth_service.authorization_url(
        config,
        provider,
        db=fake_db(),
        flow_secret=FLOW_SECRET,
    )


def configured(**overrides: Any) -> GatewayConfig:
    """A deployment with all three providers registered and an address of its own."""
    settings: dict[str, Any] = {
        "public_base_url": "https://otari.example.com",
        "oauth_google_client_id": "google-id",
        "oauth_google_client_secret": "google-secret",
        "oauth_github_client_id": "github-id",
        "oauth_github_client_secret": "github-secret",
        "oauth_oidc_issuer_url": "https://idp.example.com",
        "oauth_oidc_client_id": "oidc-id",
        "oauth_oidc_client_secret": "oidc-secret",
    }
    return GatewayConfig(**(settings | overrides))


@pytest.fixture(autouse=True)
def _forget_discovered_documents() -> Generator[None]:
    """Empty the process-lifetime discovery cache around every test.

    ``oauth_service`` reads an OIDC discovery document once and keeps it, which
    is right for a running deployment and wrong across tests: a document cached
    by one would be served to the next, which then never reaches the ``discover``
    stub it installed.
    """
    oauth_service._forget_discovered()
    yield
    oauth_service._forget_discovered()


class TestWhichProvidersAreOnOffer:
    def test_a_deployment_that_configured_none_offers_none(self) -> None:
        # The default, and what makes the sign-in screen carry no OAuth
        # affordance out of the box rather than a pair of dead buttons.
        assert GatewayConfig().oauth_providers == ()

    def test_both_halves_of_a_pair_are_needed(self) -> None:
        config = GatewayConfig(
            public_base_url="https://otari.example.com",
            oauth_google_client_id="google-id",
        )
        # An ID with no secret would fail at the provider, so the button is not
        # offered and then refused.
        assert config.oauth_providers == ()

    def test_a_gateway_that_does_not_know_its_own_address_offers_none(self) -> None:
        config = GatewayConfig(
            oauth_google_client_id="google-id",
            oauth_google_client_secret="google-secret",  # noqa: S106
        )
        # The redirect URI is derived from public_base_url, so without one there
        # is no authorization URL to build.
        assert config.oauth_providers == ()

    def test_providers_are_sorted_so_the_sign_in_screen_is_stable(self) -> None:
        assert configured().oauth_providers == ("github", "google", "oidc")

    def test_one_configured_provider_does_not_offer_the_other(self) -> None:
        config = GatewayConfig(
            public_base_url="https://otari.example.com",
            oauth_github_client_id="github-id",
            oauth_github_client_secret="github-secret",  # noqa: S106
        )
        assert config.oauth_providers == ("github",)

    def test_the_service_and_the_config_name_the_same_providers(self) -> None:
        # Asserted at import as well; restated here so the failure names the
        # rule rather than arriving as a collection error.
        assert set(oauth_service._PROVIDERS) == set(OAUTH_PROVIDERS)


class TestHalfConfiguredOAuthIsAnnounced:
    """A provider set up incompletely is otherwise entirely silent.

    It is absent from the bootstrap and absent from the sign-in screen, which is
    the correct behavior and also indistinguishable from never having been
    configured. The warning is the only thing that tells an operator which of
    the three settings they missed.
    """

    @pytest.fixture(autouse=True)
    def _capture_gateway_logs(self, caplog: pytest.LogCaptureFixture) -> Generator[None]:
        """Attach caplog to the gateway logger, which does not propagate.

        ``log_config`` sets ``propagate = False``, so caplog's root handler
        never sees these records; ``test_signup_api`` attaches the handler the
        same way for the same reason.
        """
        gateway_logger.addHandler(caplog.handler)
        try:
            yield
        finally:
            gateway_logger.removeHandler(caplog.handler)

    def test_a_missing_public_base_url_is_named(self, caplog: pytest.LogCaptureFixture) -> None:
        config = GatewayConfig(
            oauth_google_client_id="google-id",
            oauth_google_client_secret="google-secret",  # noqa: S106
        )

        with caplog.at_level(logging.WARNING, logger="gateway"):
            config.warn_about_half_configured_oauth()

        assert "public_base_url" in caplog.text
        assert "google" in caplog.text

    def test_a_missing_secret_is_named(self, caplog: pytest.LogCaptureFixture) -> None:
        config = GatewayConfig(
            public_base_url="https://otari.example.com",
            oauth_github_client_id="github-id",
        )

        with caplog.at_level(logging.WARNING, logger="gateway"):
            config.warn_about_half_configured_oauth()

        assert "oauth_github_client_secret" in caplog.text

    def test_a_missing_oidc_issuer_is_named(self, caplog: pytest.LogCaptureFixture) -> None:
        # The fourth setting no preset-backed provider has, so it is the one an
        # operator coming from the Google or GitHub instructions will miss.
        config = GatewayConfig(
            public_base_url="https://otari.example.com",
            oauth_oidc_client_id="oidc-id",
            oauth_oidc_client_secret="oidc-secret",  # noqa: S106
        )

        with caplog.at_level(logging.WARNING, logger="gateway"):
            config.warn_about_half_configured_oauth()

        assert "oauth_oidc_issuer_url" in caplog.text

    def test_an_issuer_with_no_credentials_is_not_mistaken_for_silence(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """An issuer alone is a configured connection, even with neither credential set.

        The credential pair is what decides that for every other provider, and
        reading only the pair here would skip this deployment as one that
        configured nothing, which is the one case where a warning is most
        wanted: the operator has started.
        """
        config = GatewayConfig(
            public_base_url="https://otari.example.com",
            oauth_oidc_issuer_url="https://idp.example.com",
        )

        with caplog.at_level(logging.WARNING, logger="gateway"):
            config.warn_about_half_configured_oauth()

        assert "oauth_oidc_client_id" in caplog.text
        assert "oauth_oidc_client_secret" in caplog.text

    def test_one_half_configured_provider_does_not_implicate_the_others(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        # Per provider, not per deployment: naming a connection nobody touched
        # would send an operator to look at settings they never set.
        config = GatewayConfig(oauth_google_client_id="google-id")

        with caplog.at_level(logging.WARNING, logger="gateway"):
            config.warn_about_half_configured_oauth()

        assert "google" in caplog.text
        assert "oidc" not in caplog.text
        assert "github" not in caplog.text

    def test_a_deployment_that_configured_nothing_says_nothing(self, caplog: pytest.LogCaptureFixture) -> None:
        # The ordinary state, not a mistake: warning here would put a line in
        # every default deployment's startup log.
        with caplog.at_level(logging.WARNING, logger="gateway"):
            GatewayConfig().warn_about_half_configured_oauth()

        assert caplog.text == ""

    def test_a_fully_configured_deployment_says_nothing(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING, logger="gateway"):
            configured().warn_about_half_configured_oauth()

        assert caplog.text == ""


class TestRedirectUri:
    @pytest.mark.parametrize("provider", OAUTH_PROVIDERS)
    def test_carries_no_fragment_so_a_provider_will_accept_it(self, provider: str) -> None:
        # RFC 6749 forbids a fragment in a redirection URI and Google rejects
        # one outright, which is why this is not a dashboard hash path.
        uri = oauth_service.redirect_uri(configured(), provider)

        assert urlsplit(uri).fragment == ""
        assert "#" not in uri

    def test_names_the_provider_so_two_clients_do_not_share_one_uri(self) -> None:
        assert oauth_service.redirect_uri(configured(), "google") == "https://otari.example.com/auth/google/callback"
        assert oauth_service.redirect_uri(configured(), "github") == "https://otari.example.com/auth/github/callback"

    def test_a_path_prefix_on_the_base_url_is_kept(self) -> None:
        # A gateway served under a prefix is a supported shape (``Mailer.link``
        # builds its links the same way), and a root-absolute answer would send
        # the callback to the wrong path on the right origin.
        config = configured(public_base_url="https://example.com/otari")

        assert oauth_service.redirect_uri(config, "google") == "https://example.com/otari/auth/google/callback"
        assert oauth_service.callback_landing_target(config, "google", "code=x") == (
            "https://example.com/otari/#/auth/google/callback?code=x"
        )

    def test_the_landing_target_carries_the_query_or_nothing(self) -> None:
        config = configured()

        assert oauth_service.callback_landing_target(config, "github", "") == (
            "https://otari.example.com/#/auth/github/callback"
        )

    def test_a_trailing_slash_on_the_base_url_does_not_double_up(self) -> None:
        config = configured(public_base_url="https://otari.example.com/")

        assert oauth_service.redirect_uri(config, "google") == "https://otari.example.com/auth/google/callback"


class TestAuthorizationUrl:
    @pytest.mark.asyncio
    async def test_google_asks_for_the_scopes_its_identity_handler_reads_back(self) -> None:
        url, state = await authorize(configured(), "google")
        query = parse_qs(urlsplit(url).query)

        assert urlsplit(url).netloc == "accounts.google.com"
        assert query["scope"] == ["openid email profile"]
        assert query["response_type"] == ["code"]
        assert query["client_id"] == ["google-id"]
        assert query["redirect_uri"] == ["https://otari.example.com/auth/google/callback"]
        assert query["state"] == [state]

    @pytest.mark.asyncio
    async def test_github_asks_for_the_scopes_its_identity_handler_reads_back(self) -> None:
        # /user plus /user/emails, which is what makes a verified address
        # available at callback time.
        url, _ = await authorize(configured(), "github")
        query = parse_qs(urlsplit(url).query)

        assert urlsplit(url).netloc == "github.com"
        assert query["scope"] == ["read:user user:email"]
        assert query["client_id"] == ["github-id"]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("provider", _PRESET_PROVIDERS)
    async def test_the_preset_does_not_widen_the_scopes(self, provider: str) -> None:
        # Each preset merges its own BASE_SCOPES over what it is given, which
        # for Google adds the long-form userinfo.email next to the `email`
        # already asked for. It grants nothing new and names a scope this
        # gateway did not choose on the consent screen, so `_as_configured_here`
        # pins the set. Nothing read this field while the URL was hand-built.
        # Not parametrized over "oidc": that connection's scopes are the
        # operator's to replace, per oauth_oidc_scopes; see TestOidcScopes.
        url, _ = await authorize(configured(), provider)
        query = parse_qs(urlsplit(url).query)

        assert query["scope"] == [" ".join(oauth_service._PROVIDERS[provider].scopes)]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("provider", OAUTH_PROVIDERS)
    async def test_no_offline_access_is_requested(self, provider: str) -> None:
        # Offline access exists to obtain a refresh token and nothing here
        # stores one, so asking would have Google mint a durable credential
        # this deployment discards and nobody revokes. A deliberate departure
        # from both the platform's URL and apron-auth's own preset, which set
        # access_type=offline (and the preset prompt=consent too).
        url, _ = await authorize(configured(), provider)
        query = parse_qs(urlsplit(url).query)

        assert "access_type" not in query
        assert "prompt" not in query

    @pytest.mark.parametrize("provider", OAUTH_PROVIDERS)
    def test_the_google_preset_would_have_asked_for_offline_access(self, provider: str) -> None:
        # The half that keeps the assertion above from passing vacuously: the
        # parameter really is one apron-auth's preset sets, so not sending it is
        # a choice this module makes rather than a default it inherits.
        provider_config, _ = apron_google.preset(
            client_id="id",
            client_secret="secret",  # noqa: S106
            scopes=["openid"],
        )

        assert provider_config.extra_params.get("access_type") == "offline"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("provider", OAUTH_PROVIDERS)
    async def test_a_code_challenge_is_sent(self, provider: str) -> None:
        # The whole point of the pending-state row: a verifier minted here now
        # has somewhere to live until the exchange, so the authorization request
        # can be bound to it. Without this an authorization code is spendable by
        # whoever holds it, which is what shipped in otari#765.
        url, _ = await authorize(configured(), provider)
        query = parse_qs(urlsplit(url).query)

        assert query["code_challenge_method"] == ["S256"]
        assert query["code_challenge"]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("provider", OAUTH_PROVIDERS)
    async def test_the_verifier_is_staged_and_never_the_challenge(self, provider: str) -> None:
        # A row that stored the challenge would prove nothing at exchange time:
        # the challenge is the public half and travels in the URL above.
        session = FakeSession()
        url, state = await oauth_service.authorization_url(
            configured(),
            provider,
            db=cast("AsyncSession", session),
            flow_secret=FLOW_SECRET,
        )
        query = parse_qs(urlsplit(url).query)
        (row,) = session.added

        assert row.code_verifier is not None
        assert row.code_verifier not in url
        assert row.provider == provider
        # Keyed by the digest, so a reader of the table cannot present the value.
        assert row.state_hash != state
        # The browser's flow secret is kept the same way.
        assert row.flow_hash != FLOW_SECRET
        assert FLOW_SECRET not in url
        assert query["code_challenge"] != [row.code_verifier]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("provider", OAUTH_PROVIDERS)
    async def test_an_unconfigured_provider_refuses_and_names_the_settings(self, provider: str) -> None:
        with pytest.raises(OAuthNotConfiguredError) as caught:
            await authorize(GatewayConfig(), provider)

        assert caught.value.status_code == 503
        assert f"oauth_{provider}_client_id" in caught.value.message
        assert "public_base_url" in caught.value.message

    @pytest.mark.asyncio
    async def test_a_provider_this_build_never_named_is_refused(self) -> None:
        with pytest.raises(OAuthNotConfiguredError):
            await authorize(configured(), "not-a-provider")


class TestFlowSecret:
    def test_a_missing_or_foreign_cookie_is_replaced(self) -> None:
        minted = oauth_service.flow_secret_for(None)

        assert len(minted) == 43
        assert oauth_service.flow_secret_for("") != ""
        assert oauth_service.flow_secret_for("not ours") != "not ours"
        assert oauth_service.flow_secret_for("x" * 43 + "!") != "x" * 43 + "!"

    def test_one_of_ours_is_reused_so_a_second_tab_does_not_break_the_first(self) -> None:
        existing = oauth_service.flow_secret_for(None)

        assert oauth_service.flow_secret_for(existing) == existing

    @pytest.mark.asyncio
    async def test_a_callback_without_the_cookie_is_refused_before_the_database(self) -> None:
        class _NoSession:
            async def execute(self, *_a: Any, **_k: Any) -> Any:
                raise AssertionError("the database must not be touched")

        with pytest.raises(OAuthStateError):
            await oauth_service.exchange_code(
                configured(),
                "google",
                code="c",
                state="s",
                flow_secret=None,
                db=cast("AsyncSession", _NoSession()),
            )


class TestState:
    @pytest.mark.asyncio
    async def test_is_unguessable_and_fresh_each_time(self) -> None:
        values = {(await authorize(configured(), "google"))[1] for _ in range(50)}

        assert len(values) == 50
        assert all(len(value) >= 32 for value in values)


class TestPkce:
    @pytest.mark.parametrize("provider", _PRESET_PROVIDERS)
    def test_the_preset_asks_for_it_and_this_flow_leaves_that_alone(self, provider: str) -> None:
        # apron-auth's own default, which otari#765 cleared and this restores.
        # Asserted against the preset rather than the URL so a later release
        # flipping the default cannot pass unnoticed behind a green suite.
        # oidc has no preset to assert this against; TestAuthorizationUrl's
        # test_a_code_challenge_is_sent covers PKCE on its actual URL instead.
        preset = apron_google.preset if provider == "google" else apron_github.preset
        provider_config, _ = preset(
            client_id="id",
            client_secret="secret",  # noqa: S106
            scopes=["openid"],
        )

        assert provider_config.use_pkce is True
        assert oauth_service._as_configured_here(provider_config, provider).use_pkce is True


class TestExchange:
    """The exchange with apron-auth's network calls stubbed out."""

    @staticmethod
    def _stub_client(monkeypatch: pytest.MonkeyPatch, profile: Any) -> None:
        class _Client:
            async def exchange_code(self, **_: Any) -> object:
                return object()

            async def fetch_identity(self, _tokens: object) -> Any:
                return profile

        async def _client(*_args: Any, **_kwargs: Any) -> _Client:
            return _Client()

        monkeypatch.setattr(oauth_service, "_client", _client)

    @staticmethod
    def _profile(**overrides: Any) -> SimpleNamespace:
        fields: dict[str, Any] = {
            "email": "member@example.com",
            "name": "A Member",
            "email_verified": True,
        }
        return SimpleNamespace(**(fields | overrides))

    @pytest.mark.asyncio
    async def test_returns_the_identity_the_provider_vouches_for(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._stub_client(monkeypatch, self._profile())

        identity = await oauth_service.exchange_code(
            configured(), "google", code="c", state="s", flow_secret=FLOW_SECRET, db=fake_db()
        )

        assert identity.provider == "google"
        assert identity.email == "member@example.com"
        assert identity.full_name == "A Member"
        assert identity.email_verified is True

    @pytest.mark.asyncio
    async def test_an_unasserted_email_verified_collapses_to_unverified(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # apron-auth reports email_verified as tri-state. This edition resolves
        # on a bool, and silence is not an assertion: it must not be laundered
        # into a verified identity. otari-ai#1551 moves resolution onto the
        # tri-state model, once, on the platform.
        self._stub_client(monkeypatch, self._profile(email_verified=None))

        identity = await oauth_service.exchange_code(
            configured(), "google", code="c", state="s", flow_secret=FLOW_SECRET, db=fake_db()
        )

        assert identity.email_verified is False

    @pytest.mark.asyncio
    async def test_an_explicit_false_is_unverified_too(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._stub_client(monkeypatch, self._profile(email_verified=False))

        identity = await oauth_service.exchange_code(
            configured(), "google", code="c", state="s", flow_secret=FLOW_SECRET, db=fake_db()
        )

        assert identity.email_verified is False

    @pytest.mark.asyncio
    async def test_a_failed_exchange_does_not_carry_the_providers_words_to_the_caller(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # apron-auth's exchange errors carry the provider's RFC 6749 error and
        # error_description verbatim, and this message reaches both the client
        # and the log aggregator (CWE-532). The cause stays on the traceback.
        secret = "invalid_grant: code was already redeemed by client 1234"  # noqa: S105

        class _Client:
            async def exchange_code(self, **_: Any) -> object:
                raise RuntimeError(secret)

            async def fetch_identity(self, _tokens: object) -> Any:  # pragma: no cover - never reached
                raise AssertionError

        async def _client(*_a: Any, **_k: Any) -> _Client:
            return _Client()

        monkeypatch.setattr(oauth_service, "_client", _client)

        with pytest.raises(OAuthExchangeError) as caught:
            await oauth_service.exchange_code(
                configured(), "google", code="c", state="s", flow_secret=FLOW_SECRET, db=fake_db()
            )

        assert secret not in caught.value.message
        assert caught.value.message == "Google did not complete the sign-in. Try again."
        assert isinstance(caught.value.__cause__, RuntimeError)
        assert secret in str(caught.value.__cause__)

    @pytest.mark.asyncio
    async def test_a_failed_identity_fetch_is_the_same_refusal(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class _Client:
            async def exchange_code(self, **_: Any) -> object:
                return object()

            async def fetch_identity(self, _tokens: object) -> Any:
                raise RuntimeError("userinfo 500")

        async def _client(*_a: Any, **_k: Any) -> _Client:
            return _Client()

        monkeypatch.setattr(oauth_service, "_client", _client)

        with pytest.raises(OAuthExchangeError):
            await oauth_service.exchange_code(
                configured(),
                "github",
                code="c",
                state="s",
                flow_secret=FLOW_SECRET,
                db=fake_db(),
            )

    @pytest.mark.asyncio
    async def test_an_unconfigured_provider_refuses_before_any_outbound_call(self) -> None:
        with pytest.raises(OAuthNotConfiguredError):
            await oauth_service.exchange_code(
                GatewayConfig(),
                "google",
                code="c",
                state="s",
                flow_secret=FLOW_SECRET,
                db=fake_db(),
            )


class TestOidcConnection:
    """The generic connection's own pieces: discovery, and scopes an operator can replace."""

    @pytest.mark.asyncio
    async def test_the_authorization_url_is_built_from_what_discovery_returned(self) -> None:
        url, _ = await authorize(configured(), "oidc")

        # The endpoint is the discovered one, not a constant: a preset provider
        # could pass this by hardcoding, and oidc has nothing to hardcode.
        assert url.startswith(f"{OIDC_METADATA.authorize_url}?")

    @pytest.mark.asyncio
    async def test_pkce_is_on_and_the_row_keeps_the_verifier(self) -> None:
        session = FakeSession()
        url, _ = await oauth_service.authorization_url(
            configured(), "oidc", db=cast("AsyncSession", session), flow_secret=FLOW_SECRET
        )
        query = parse_qs(urlsplit(url).query)
        (row,) = session.added

        # With no nonce, PKCE is the only thing binding the code to this
        # browser, so its presence is load-bearing rather than incidental.
        assert query["code_challenge_method"] == ["S256"]
        assert query["code_challenge"]
        assert row.code_verifier

    @pytest.mark.asyncio
    async def test_the_default_set_is_what_an_identity_is_built_from(self) -> None:
        url, _ = await authorize(configured(), "oidc")

        # Sorted, because apron-auth merges its own ``openid`` in and returns
        # the union ordered; scope order carries no meaning to a provider.
        assert parse_qs(urlsplit(url).query)["scope"] == ["email openid profile"]

    @pytest.mark.asyncio
    async def test_what_an_operator_configures_replaces_the_default_set(self) -> None:
        """Replaced, not added to: an IdP that refuses ``profile`` has to be able to drop it."""
        url, _ = await authorize(configured(oauth_oidc_scopes="groups"), "oidc")

        assert parse_qs(urlsplit(url).query)["scope"] == ["groups openid"]

    @pytest.mark.asyncio
    async def test_openid_survives_an_operator_who_asks_for_nothing(self) -> None:
        """``openid`` is not the operator's to drop: without it there is no ID token."""
        url, _ = await authorize(configured(oauth_oidc_scopes=""), "oidc")

        assert parse_qs(urlsplit(url).query)["scope"] == ["openid"]

    @pytest.mark.asyncio
    async def test_a_discovery_failure_is_distinct_from_not_configured(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def _broken_discover(*_a: Any, **_k: Any) -> Any:
            raise OidcDiscoveryError("issuer unreachable")

        monkeypatch.setattr(apron_oidc, "discover", _broken_discover)

        with pytest.raises(OAuthProviderUnavailableError) as caught:
            await authorize(configured(), "oidc")

        # Every setting is in fact set here, so telling the operator to "set"
        # one would be the wrong message; that wording is
        # OAuthNotConfiguredError's alone.
        assert "Set oauth_oidc" not in caught.value.message

    @pytest.mark.asyncio
    async def test_a_provider_we_cannot_negotiate_with_is_distinct_from_an_outage(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Discovery answered; what it named is unusable, and no retry changes that."""

        def _unusable_preset(*_a: Any, **_k: Any) -> Any:
            raise ConfigurationError("advertises no S256 code-challenge method")

        monkeypatch.setattr(apron_oidc, "preset", _unusable_preset)

        with pytest.raises(OAuthProviderUnusableError) as caught:
            await authorize(configured(), "oidc")

        assert "Try again" not in caught.value.message

    @pytest.mark.asyncio
    async def test_a_bug_here_is_not_laundered_into_a_provider_refusal(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The reason the catch names two error types rather than ``Exception``.

        A refusal means "the provider did something": rendering our own bug as
        one sends an operator to look at an IdP that is working fine, and hides
        a 500 that should have been one.
        """

        def _raises_a_bug(*_a: Any, **_k: Any) -> Any:
            raise TypeError("a mistake in this module, not the provider's doing")

        monkeypatch.setattr(apron_oidc, "preset", _raises_a_bug)

        with pytest.raises(TypeError):
            await authorize(configured(), "oidc")

    @pytest.mark.asyncio
    async def test_the_providers_own_reason_is_logged_where_an_operator_reads_it(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The route renders these itself, so this is the only place the reason is written down."""

        async def _broken_discover(*_a: Any, **_k: Any) -> Any:
            raise OidcDiscoveryError("issuer unreachable")

        monkeypatch.setattr(apron_oidc, "discover", _broken_discover)

        # ``gateway`` does not propagate (``log_config.setup_logging``), so
        # caplog's own handler has to be attached to it, the way
        # ``TestHalfConfiguredOAuthIsAnnounced`` above already does.
        gateway_logger.addHandler(caplog.handler)
        try:
            with caplog.at_level(logging.WARNING, logger=gateway_logger.name), pytest.raises(
                OAuthProviderUnavailableError
            ):
                await authorize(configured(), "oidc")
        finally:
            gateway_logger.removeHandler(caplog.handler)

        assert "OIDC discovery" in caplog.text
        # The provider's own reason, which the response deliberately omits.
        assert "issuer unreachable" in caplog.text


    @pytest.mark.asyncio
    async def test_the_document_is_read_once_and_then_reused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Discovery is a per-process read, not a per-sign-in one.

        Without this the outbound round trip sits in front of ``/authorize``
        and ``/callback`` both, on every attempt, and both are public.
        """
        discover = AsyncMock(return_value=OIDC_METADATA)
        monkeypatch.setattr(apron_oidc, "discover", discover)

        await authorize(configured(), "oidc")
        await authorize(configured(), "oidc")

        assert discover.await_count == 1

    @pytest.mark.asyncio
    async def test_another_issuer_is_not_served_the_first_ones_document(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Keyed by what it was fetched for, rather than one slot for whatever came first."""
        discover = AsyncMock(return_value=OIDC_METADATA)
        monkeypatch.setattr(apron_oidc, "discover", discover)

        await authorize(configured(), "oidc")
        await authorize(configured(oauth_oidc_issuer_url="https://elsewhere.example.com"), "oidc")

        assert discover.await_count == 2

    @pytest.mark.asyncio
    async def test_a_relocated_document_is_fetched_rather_than_assumed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The override belongs in the key too: same issuer, different document URL.

        ``oauth_oidc_discovery_url`` exists for an IdP that does not serve its
        document at the standard suffix, so two deployments of one issuer can
        read it from two places.
        """
        discover = AsyncMock(return_value=OIDC_METADATA)
        monkeypatch.setattr(apron_oidc, "discover", discover)

        await authorize(configured(), "oidc")
        await authorize(configured(oauth_oidc_discovery_url="https://idp.example.com/oidc.json"), "oidc")

        assert discover.await_count == 2

    @pytest.mark.asyncio
    async def test_a_failed_read_is_not_remembered(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An IdP that was down when somebody first pressed the button is tried again.

        The alternative is a cache that turns one outage into a sign-in that
        stays broken until the process restarts.
        """
        attempts = 0

        async def _unreachable_once(*_a: Any, **_k: Any) -> Any:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise OidcDiscoveryError("issuer unreachable")
            return OIDC_METADATA

        monkeypatch.setattr(apron_oidc, "discover", _unreachable_once)

        with pytest.raises(OAuthProviderUnavailableError):
            await authorize(configured(), "oidc")
        url, _ = await authorize(configured(), "oidc")

        assert attempts == 2
        assert url.startswith(f"{OIDC_METADATA.authorize_url}?")


class TestOidcExchange:
    """``exchange_code`` for ``oidc``: that the handler is built from what was discovered.

    The ID token's own claim validation is apron-auth's
    (``OidcIdentityHandler``) and covered there, unstubbed against a real
    provider in ``tests/integration/test_oidc_keycloak.py``. What matters here
    is the wiring: that the issuer the handler checks against is the
    *discovered* one and the audience is this deployment's own client ID, since
    a handler built from either wrong value would validate happily and vouch
    for the wrong person.
    """

    @staticmethod
    def _stub_exchange(monkeypatch: pytest.MonkeyPatch) -> None:
        """Answer the token endpoint without one, leaving the identity wiring real."""

        async def _exchange_code(_self: Any, **_: Any) -> Any:
            # Where a provider's own ID token lands: the token endpoint returns it
            # as an ordinary field, which ``TokenSet`` collects into ``metadata`` and
            # ``IdentityMaterial.from_tokens`` reads back out.
            return TokenSet(access_token="at", metadata={"id_token": "header.payload.signature"})  # noqa: S106

        monkeypatch.setattr(OAuthClient, "exchange_code", _exchange_code)

    @pytest.mark.asyncio
    async def test_the_handler_checks_the_discovered_issuer_and_this_clients_audience(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._stub_exchange(monkeypatch)
        captured: dict[str, Any] = {}

        def _identity_handler(metadata: Any, **kwargs: Any) -> Any:
            captured["issuer"] = metadata.issuer
            captured.update(kwargs)

            class _Handler:
                async def fetch_identity(self, _material: Any, _config: Any) -> Any:
                    return SimpleNamespace(email="ada@example.com", name="Ada Lovelace", email_verified=True)

            return _Handler()

        monkeypatch.setattr(apron_oidc, "identity_handler", _identity_handler)

        identity = await oauth_service.exchange_code(
            configured(), "oidc", code="c", state="s", flow_secret=FLOW_SECRET, db=fake_db()
        )

        assert captured["issuer"] == OIDC_METADATA.issuer
        assert captured["client_id"] == "oidc-id"
        # The route's provider name, not the ``oidc:<issuer>`` one apron-auth
        # namespaces its profiles with: what crosses IdentityProviderPort is
        # this deployment's own provider string.
        assert identity.provider == "oidc"
        assert identity.email == "ada@example.com"

    @pytest.mark.asyncio
    async def test_an_id_token_that_does_not_validate_is_an_exchange_failure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._stub_exchange(monkeypatch)

        def _identity_handler(*_a: Any, **_k: Any) -> Any:
            class _Handler:
                async def fetch_identity(self, _material: Any, _config: Any) -> Any:
                    raise IdentityFetchError("OpenID ID token claims did not validate: aud")

            return _Handler()

        monkeypatch.setattr(apron_oidc, "identity_handler", _identity_handler)

        with pytest.raises(OAuthExchangeError) as caught:
            await oauth_service.exchange_code(
                configured(), "oidc", code="c", state="s", flow_secret=FLOW_SECRET, db=fake_db()
            )

        # The provider's own words stay on the traceback, not in the response.
        assert "aud" not in caught.value.message


class TestProviderLabel:
    def test_writes_each_provider_the_way_it_writes_itself(self) -> None:
        assert oauth_service.provider_label("google") == "Google"
        assert oauth_service.provider_label("github") == "GitHub"

    def test_falls_back_rather_than_raising_inside_an_error_message(self) -> None:
        # The only caller is a refusal, and one that fails to render is worse
        # than one naming a provider nobody configured.
        assert oauth_service.provider_label("acme-oidc") == "acme-oidc"
