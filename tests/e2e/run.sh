#!/usr/bin/env bash
# End-to-end tests: starts WordPress with Two Factor and its WebAuthn provider in
# Docker, signs in with software passkeys, then removes the containers.
#   tests/e2e/run.sh          run and clean up
#   KEEP=1 tests/e2e/run.sh   leave the site running at http://localhost:8088
set -euo pipefail
cd "$(dirname "$0")"
export PLUGIN_DIR="$(cd ../.. && pwd)"
compose() { docker compose -f compose.yml -p pf-e2e "$@"; }
wp() { compose run --rm -T cli "$@"; }

[ "${KEEP:-}" = 1 ] || trap 'compose down -v >/dev/null 2>&1' EXIT
compose up -d --quiet-pull wordpress
for i in $(seq 1 60); do
  curl -fs -o /dev/null http://localhost:8088/wp-login.php && break
  curl -s -o /dev/null -w '%{http_code}' http://localhost:8088/ | grep -qE '200|302' && break
  sleep 2
done
wp core is-installed 2>/dev/null || wp core install --url=http://localhost:8088 --title=PF --admin_user=admin \
  --admin_password="$(head -c 24 /dev/urandom | base64)" --admin_email=admin@example.test --skip-email
wp plugin install two-factor two-factor-provider-webauthn --activate
wp plugin activate passkey-first

PF_BASE=http://localhost:8088 PF_WP_CLI="docker compose -f $(pwd)/compose.yml -p pf-e2e run --rm -T cli" php e2e.php
