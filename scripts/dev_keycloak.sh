#!/usr/bin/env bash
# Spin up a Keycloak realm to sign in against, and print the config.yml block
# that points Otari's generic OIDC connection at it.
#
# This is the manual counterpart to tests/integration/test_oidc_keycloak.py,
# which drives the same realm shape through Testcontainers. The difference is
# the redirect URI: the test's realm registers http://testserver, the origin
# starlette's TestClient answers at, and nothing in a browser can reach that.
# This one registers the address you actually open.
#
#   scripts/dev_keycloak.sh up      start Keycloak and print a config to paste
#   scripts/dev_keycloak.sh down    stop and remove the container
#   scripts/dev_keycloak.sh logs    follow the container's log
#
# Override any of the settings below by exporting them first, e.g.
#   OTARI_PORT=9000 scripts/dev_keycloak.sh up
set -euo pipefail

KEYCLOAK_IMAGE="${KEYCLOAK_IMAGE:-quay.io/keycloak/keycloak:26.0}"
CONTAINER_NAME="${CONTAINER_NAME:-otari-dev-keycloak}"
KEYCLOAK_PORT="${KEYCLOAK_PORT:-8380}"
REALM_NAME="${REALM_NAME:-otari-dev}"
CLIENT_ID="${CLIENT_ID:-otari-gateway}"
CLIENT_SECRET="${CLIENT_SECRET:-otari-dev-client-secret}"
SSO_USER="${SSO_USER:-ada}"
SSO_EMAIL="${SSO_EMAIL:-ada@example.com}"
SSO_PASSWORD="${SSO_PASSWORD:-a-real-password}"

# Where Otari itself will answer. The redirect URI is derived from this on both
# sides: Otari builds it from public_base_url, Keycloak matches it against what
# the realm registered, and a mismatch is refused by the provider before Otari
# sees anything.
OTARI_HOST_NAME="${OTARI_HOST_NAME:-localhost}"
OTARI_PORT="${OTARI_PORT:-8000}"
OTARI_BASE_URL="http://${OTARI_HOST_NAME}:${OTARI_PORT}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Bind-mounted into the container, so it has to outlive this script: a temp file
# swept on exit would leave `docker start` unable to remount it, and stopping the
# container to watch the outage refusal is a thing worth doing here.
REALM_FILE="${REPO_ROOT}/.otari-dev-keycloak-realm.json"
FIXTURE_REALM="${REPO_ROOT}/tests/integration/oidc_fixtures/otari_test_realm.json"
READY_TIMEOUT_SECONDS="${READY_TIMEOUT_SECONDS:-120}"

ISSUER="http://${OTARI_HOST_NAME}:${KEYCLOAK_PORT}/realms/${REALM_NAME}"

die() {
  printf 'error: %s\n' "$1" >&2
  exit 1
}

require_docker() {
  command -v docker >/dev/null 2>&1 || die "docker is not on PATH"
  docker info >/dev/null 2>&1 || die "docker is installed but not running"
}

require_free_ports() {
  # Checked here so a clash reads as "pick another port" rather than as
  # docker's own endpoint-binding message, which does not mention the knob.
  local port
  for port in "${KEYCLOAK_PORT}" "$((KEYCLOAK_PORT + 1000))"; do
    if (exec 3<>"/dev/tcp/127.0.0.1/${port}") 2>/dev/null; then
      exec 3>&-
      die "port ${port} is already in use; re-run with KEYCLOAK_PORT=<free port> (its health port is that + 1000)"
    fi
  done
}

write_realm() {
  # Derived from the realm the integration test imports rather than written out
  # again here, so the parts that make a sign-in work stay one fact: a
  # confidential client, PKCE required, standard flow only, and one enabled user
  # whose address is verified (Otari resolves an OAuth sign-in against the
  # roster on a verified email, and refuses an unverified one).
  #
  # Only what cannot be shared is patched. The test's realm registers
  # http://testserver, the origin starlette's TestClient answers at and that no
  # browser can reach; this one registers the address you actually open. The
  # names and secrets are patched too, so the env overrides at the top of this
  # script mean something.
  [ -f "${FIXTURE_REALM}" ] || die "cannot find ${FIXTURE_REALM#"${REPO_ROOT}/"}"
  command -v python3 >/dev/null 2>&1 || die "python3 is needed to derive the realm from the test fixture"

  FIXTURE_REALM="${FIXTURE_REALM}" \
  OUT="$1" \
  REALM_NAME="${REALM_NAME}" \
  CLIENT_ID="${CLIENT_ID}" \
  CLIENT_SECRET="${CLIENT_SECRET}" \
  SSO_USER="${SSO_USER}" \
  SSO_EMAIL="${SSO_EMAIL}" \
  SSO_PASSWORD="${SSO_PASSWORD}" \
  REDIRECT_URI="${OTARI_BASE_URL}/auth/oidc/callback" \
  WEB_ORIGIN="${OTARI_BASE_URL}" \
  python3 <<'REALM_PY'
import json
import os

with open(os.environ["FIXTURE_REALM"], encoding="utf-8") as handle:
    realm = json.load(handle)

# The alarm for the day the fixture grows a second client or user: patching
# blind would then configure one of them and silently leave the other alone.
if len(realm.get("clients", [])) != 1 or len(realm.get("users", [])) != 1:
    raise SystemExit(
        "the test realm no longer holds exactly one client and one user; "
        "teach scripts/dev_keycloak.sh which to patch"
    )

realm["realm"] = os.environ["REALM_NAME"]

client = realm["clients"][0]
client["clientId"] = os.environ["CLIENT_ID"]
client["name"] = os.environ["CLIENT_ID"]
client["secret"] = os.environ["CLIENT_SECRET"]
client["redirectUris"] = [os.environ["REDIRECT_URI"]]
client["webOrigins"] = [os.environ["WEB_ORIGIN"]]

user = realm["users"][0]
user["username"] = os.environ["SSO_USER"]
user["email"] = os.environ["SSO_EMAIL"]
user["credentials"] = [
    {"type": "password", "value": os.environ["SSO_PASSWORD"], "temporary": False}
]

with open(os.environ["OUT"], "w", encoding="utf-8") as handle:
    json.dump(realm, handle, indent=2)
REALM_PY
}

wait_until_ready() {
  # Keycloak's own health endpoint on the management port, rather than a
  # guessed sleep: a cold JVM boot plus a realm import is variable-length.
  local deadline=$((SECONDS + READY_TIMEOUT_SECONDS))
  while ((SECONDS < deadline)); do
    if curl -fsS "http://127.0.0.1:$((KEYCLOAK_PORT + 1000))/health/ready" >/dev/null 2>&1; then
      return 0
    fi
    if ! docker ps --format '{{.Names}}' | grep -qx "${CONTAINER_NAME}"; then
      docker logs "${CONTAINER_NAME}" 2>&1 | tail -30 >&2
      die "the Keycloak container exited during startup (log above)"
    fi
    sleep 2
  done
  die "Keycloak did not become ready within ${READY_TIMEOUT_SECONDS}s"
}

print_config() {
  # Printed rather than written: this is a starting point to paste into your
  # own config.yml, not a file to keep in sync with one. Flush left so it
  # pastes as valid YAML.
  cat <<YAML
database_url: "sqlite:///./otari-oidc-dev.db"
host: "0.0.0.0"
port: ${OTARI_PORT}
master_key: "$1"
public_base_url: "${OTARI_BASE_URL}"
oauth_oidc_issuer_url: "${ISSUER}"
oauth_oidc_client_id: "${CLIENT_ID}"
oauth_oidc_client_secret: "${CLIENT_SECRET}"
oauth_oidc_display_name: "Keycloak (dev)"
YAML
}

cmd_up() {
  require_docker
  require_free_ports

  if docker ps -a --format '{{.Names}}' | grep -qx "${CONTAINER_NAME}"; then
    die "a container named ${CONTAINER_NAME} already exists; run '$0 down' first"
  fi

  write_realm "${REALM_FILE}"
  # The image runs as its own unprivileged `keycloak` user, and a file it cannot
  # read fails the import with nothing but "Failed to run import" to say why.
  # Nothing is in here that is not already in this script and in the generated
  # config.
  chmod 0644 "${REALM_FILE}"

  printf 'Starting %s on port %s...\n' "${KEYCLOAK_IMAGE}" "${KEYCLOAK_PORT}"
  docker run -d \
    --name "${CONTAINER_NAME}" \
    -p "${KEYCLOAK_PORT}:8080" \
    -p "$((KEYCLOAK_PORT + 1000)):9000" \
    -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
    -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
    -e KC_HEALTH_ENABLED=true \
    -v "${REALM_FILE}:/opt/keycloak/data/import/realm.json:ro" \
    "${KEYCLOAK_IMAGE}" \
    start-dev --import-realm >/dev/null

  wait_until_ready
  printf 'Keycloak is ready.\n\n'

  local master_key
  master_key="sk-dev-$(openssl rand -hex 16 2>/dev/null || head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"

  cat <<SUMMARY
Sign in with

  email      ${SSO_EMAIL}
  password   ${SSO_PASSWORD}

Keycloak admin console  http://${OTARI_HOST_NAME}:${KEYCLOAK_PORT}/admin (admin / admin)

Put ${SSO_EMAIL} on the roster before signing in; OIDC authenticates an
identity, it does not create one.

config.yml:

SUMMARY
  print_config "${master_key}"
  printf '\nTear down with: %s down\n' "$0"
}

cmd_down() {
  require_docker
  docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
  rm -f "${REALM_FILE}"
  printf 'Removed %s. ./otari-oidc-dev.db is left in place.\n' "${CONTAINER_NAME}"
}

cmd_logs() {
  require_docker
  docker logs -f "${CONTAINER_NAME}"
}

case "${1:-up}" in
  up) cmd_up ;;
  down) cmd_down ;;
  logs) cmd_logs ;;
  *) die "unknown command '${1}'; expected up, down, or logs" ;;
esac
