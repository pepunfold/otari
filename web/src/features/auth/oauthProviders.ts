import type { IconType } from "react-icons"
import { FaGithub } from "react-icons/fa"
import { FcGoogle } from "react-icons/fc"
import { FiLogIn } from "react-icons/fi"

/**
 * The OAuth providers this dashboard can sign in with, and what to call them.
 *
 * The names are the gateway's (`core/config.py`'s `OAUTH_PROVIDERS`): they are
 * the path segment `/v1/auth/oauth/{provider}/…` takes and the values
 * `/v1/bootstrap`'s `oauth_providers` carries. This table adds only what a
 * server has no business deciding, which is how the provider's name is written
 * on a button.
 *
 * Which of them a deployment actually offers is never decided here. The
 * bootstrap answers that, one entry per provider an operator configured, so a
 * provider nobody set up is absent from the sign-in screen rather than rendered
 * disabled.
 */

/** A provider name the gateway and this dashboard both know. */
export type OAuthProvider = "github" | "google" | "oidc"

/**
 * How each provider writes its own name.
 *
 * `oidc`'s entry is a generic fallback, not a brand name: a generic
 * connection has none of its own, which is why the bootstrap carries
 * `oauth_oidc_label` for an operator to supply one (`useDeployment()`,
 * read where a button is actually rendered). This map is what is left once
 * that is unset, and what every caller with no deployment context to read
 * from uses instead: `OAuthCallbackPage`'s error copy, for one.
 */
export const OAUTH_PROVIDER_LABELS: Record<OAuthProvider, string> = {
  github: "GitHub",
  google: "Google",
  oidc: "SSO",
}

/**
 * Each provider's own mark, for the button that signs in with it.
 *
 * `Fc`/`Fa` are the same two marks `otari-ai/frontend`'s login route uses,
 * from the `react-icons` sets this dashboard already draws its nav from:
 * `Fc` is the full-color Google G, and `Fa` the GitHub logo. `oidc` gets no
 * brand mark of its own (an operator's own IdP is not one this dashboard
 * could draw), so it uses `react-icons/fi`'s generic sign-in glyph instead,
 * the icon set `web/AGENTS.md` reserves for exactly this (an icon that is
 * not standing in for a specific brand).
 */
export const OAUTH_PROVIDER_ICONS: Record<OAuthProvider, IconType> = {
  github: FaGithub,
  google: FcGoogle,
  oidc: FiLogIn,
}

/**
 * Whether a string names a provider this dashboard can render.
 *
 * The bootstrap's `oauth_providers` is typed as a plain string list, because
 * the gateway's own vocabulary is open: an overlay may bind an identity adapter
 * for a connection this build never named. So a value is narrowed here rather
 * than assumed, and one this dashboard has no label for is skipped instead of
 * rendered as a button reading `undefined`.
 */
export function isOAuthProvider(value: string): value is OAuthProvider {
  return Object.hasOwn(OAUTH_PROVIDER_LABELS, value)
}

/** The providers from a bootstrap that this dashboard can render, in its order. */
export function renderableOAuthProviders(
  configured: readonly string[],
): OAuthProvider[] {
  return configured.filter(isOAuthProvider)
}

/** How to name a provider in a sentence, falling back to the raw name. */
export function oauthProviderLabel(provider: string): string {
  return isOAuthProvider(provider) ? OAUTH_PROVIDER_LABELS[provider] : provider
}

/**
 * The same, for a caller that can read the bootstrap.
 *
 * Every other provider's name is a brand name this dashboard already knows.
 * `oidc`'s is whichever IdP an operator pointed it at, which only the bootstrap
 * can say (`oauth_oidc_label`), so it is threaded in rather than looked up. An
 * older gateway that carries no such field, and an operator who set none, both
 * land on the generic entry in `OAUTH_PROVIDER_LABELS`.
 */
export function oauthProviderLabelFor(
  provider: string,
  oidcLabel: string | null | undefined,
): string {
  return provider === "oidc" && oidcLabel
    ? oidcLabel
    : oauthProviderLabel(provider)
}
