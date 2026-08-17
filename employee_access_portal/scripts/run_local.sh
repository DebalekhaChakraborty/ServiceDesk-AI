#!/usr/bin/env bash
#
# Run the Employee Access Portal LOCALLY on dev-linux-instance, reachable only
# through the existing IAP/SSH tunnel.
#
# Design notes:
#
#   * The container publishes on 127.0.0.1 only. The Node process inside binds
#     0.0.0.0 (Cloud Run requires that), so loopback-only exposure is enforced
#     by Docker's publish address rather than by editing server.js.
#
#   * The Entra client secret is read from Secret Manager at START TIME and is
#     never written to a tracked file, never echoed, and never passed as a
#     command-line argument (argv is world-readable via /proc). It reaches the
#     container through a 0600 env file that is deleted immediately after the
#     container is created.
#
#   * PORTAL_SESSION_SECRET is a NEW local-only value. The Cloud Run session
#     secret is untouched, so local and cloud sessions cannot be interchanged.
#
# Usage:  scripts/run_local.sh [start|stop|status|logs]

set -euo pipefail

PORTAL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME_DIR="${PORTAL_DIR}/runtime"
SESSION_SECRET_FILE="${RUNTIME_DIR}/.portal_session_secret"

CONTAINER="eap-local"
IMAGE="employee-access-portal:local"
BIND_ADDR="127.0.0.1"
PORT="8080"

# Reused from the existing Cloud Run deployment - identifiers, not secrets.
TENANT_ID="${ENTRA_PORTAL_TENANT_ID:-8bd45b04-aa1e-4de5-b83c-68ab45726aa5}"
CLIENT_ID="${ENTRA_PORTAL_CLIENT_ID:-cdad4869-9d85-4c8e-a64a-a3ca99eaf60e}"
SECRET_NAME="servicedesk-entra-portal-client-secret"

# Dograh endpoints as seen FROM THE BROWSER through the IAP tunnel.
DOGRAH_EMBED_ORIGIN="${DOGRAH_EMBED_ORIGIN:-http://localhost:3010}"
DOGRAH_API_ENDPOINT="${DOGRAH_API_ENDPOINT:-http://localhost:8001}"

PY="${PY:-/home/AI_POC/venvs/debalekha/bin/python}"
DOCKER="${DOCKER:-sudo -n docker}"

die() { echo "ERROR: $*" >&2; exit 1; }

require_files() {
  [[ -f "${SESSION_SECRET_FILE}" ]] || die "missing ${SESSION_SECRET_FILE} (mode 0600)"
  [[ -f "${PORTAL_DIR}/../dograh_voice/runtime/.voice_identity_secret" ]] \
    || die "missing voice identity signing secret"
}

# Print nothing; write the assembled environment to the file named in $1.
write_env_file() {
  local target="$1"
  local voice_secret_file="${PORTAL_DIR}/../dograh_voice/runtime/.voice_identity_secret"

  ( umask 077
    {
      printf 'NODE_ENV=production\n'
      printf 'PORT=%s\n' "${PORT}"
      printf 'PORTAL_BASE_URL=http://localhost:%s\n' "${PORT}"
      printf 'ENTRA_PORTAL_TENANT_ID=%s\n' "${TENANT_ID}"
      printf 'ENTRA_PORTAL_CLIENT_ID=%s\n' "${CLIENT_ID}"
      printf 'ENTRA_PORTAL_CLIENT_SECRET=%s\n' "$("${PY}" - <<'PYEOF'
import base64, google.auth, google.auth.transport.requests as gt, requests, sys
creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
creds.refresh(gt.Request())
project = creds.quota_project_id
url = (f"https://secretmanager.googleapis.com/v1/projects/{project}"
       "/secrets/servicedesk-entra-portal-client-secret/versions/latest:access")
r = requests.get(url, headers={"Authorization": f"Bearer {creds.token}",
                               "x-goog-user-project": project}, timeout=30)
if r.status_code != 200:
    sys.exit(f"secret access failed: HTTP {r.status_code}")
sys.stdout.write(base64.b64decode(r.json()["payload"]["data"]).decode())
PYEOF
)"
      printf 'PORTAL_SESSION_SECRET=%s\n' "$(cat "${SESSION_SECRET_FILE}")"
      printf 'VOICE_IDENTITY_SIGNING_SECRET=%s\n' "$(cat "${voice_secret_file}")"
      printf 'DOGRAH_EMBED_TOKEN=%s\n' "$(embed_token)"
      printf 'DOGRAH_EMBED_ORIGIN=%s\n' "${DOGRAH_EMBED_ORIGIN}"
      printf 'DOGRAH_API_ENDPOINT=%s\n' "${DOGRAH_API_ENDPOINT}"
      printf 'VOICE_IDENTITY_TTL_SECONDS=300\n'
      printf 'VOICE_GATEWAY_URL=http://172.18.0.1:8010\n'
      printf 'RECOVERY_ADMIN_KEY=%s\n' "$(recovery_admin_key)"
    } > "${target}"
  )
}

# Derived from the recovery store key; authorises ENROLLMENT calls only.
recovery_admin_key() {
  ( cd "${PORTAL_DIR}/../dograh_voice" && "${PY}" - <<'PYEOF'
from voice_gateway.recovery_store import enrollment_admin_key
print(enrollment_admin_key(), end="")
PYEOF
  )
}

# The embed token is public to the browser but still not worth echoing.
embed_token() {
  ( cd "${PORTAL_DIR}/../dograh_voice" && "${PY}" - <<'PYEOF'
from provisioning.dograh_client import DograhClient
tokens = DograhClient().get_embed_tokens(1)
tokens = tokens if isinstance(tokens, list) else [tokens]
active = [t for t in tokens if t and t.get("is_active")]
if not active:
    raise SystemExit("no active Dograh embed token for workflow 1")
print(active[0]["token"], end="")
PYEOF
  )
}

start() {
  require_files
  ${DOCKER} build -q -t "${IMAGE}" "${PORTAL_DIR}" >/dev/null
  ${DOCKER} rm -f "${CONTAINER}" >/dev/null 2>&1 || true

  local env_file
  env_file="$(mktemp "${RUNTIME_DIR}/.env.XXXXXX")"
  chmod 600 "${env_file}"
  # Remove the file whatever happens next, including on failure.
  trap 'rm -f "${env_file}"' EXIT

  write_env_file "${env_file}"

  ${DOCKER} run -d \
    --name "${CONTAINER}" \
    --restart unless-stopped \
    -p "${BIND_ADDR}:${PORT}:${PORT}" \
    --env-file "${env_file}" \
    "${IMAGE}" >/dev/null

  rm -f "${env_file}"
  trap - EXIT

  for _ in $(seq 1 30); do
    if curl -fsS "http://${BIND_ADDR}:${PORT}/healthz" >/dev/null 2>&1; then
      echo "portal healthy on ${BIND_ADDR}:${PORT}"
      return 0
    fi
    sleep 1
  done
  die "portal did not become healthy; see: ${DOCKER} logs ${CONTAINER}"
}

case "${1:-start}" in
  start)  start ;;
  stop)   ${DOCKER} rm -f "${CONTAINER}" >/dev/null && echo "stopped" ;;
  status) ${DOCKER} ps --filter "name=${CONTAINER}" --format '{{.Names}}\t{{.Status}}\t{{.Ports}}' ;;
  logs)   ${DOCKER} logs --tail 50 "${CONTAINER}" ;;
  *)      die "usage: $0 [start|stop|status|logs]" ;;
esac
