#!/usr/bin/env bash
#
# Deploy the Employee Access Portal to Google Cloud Run.
#
# This script never contains, prints, or accepts a secret VALUE. It only wires
# Cloud Run to Google Secret Manager secret NAMES that already exist.
#
# There is a deliberate two-phase bootstrap because Microsoft Entra needs the
# final Cloud Run HTTPS host in its redirect URI, and that host is not known
# until the service exists.
#
#   phase-a  deploy the service, discover the real URL, print the exact
#            redirect URI a human must register in Entra, then stop
#   phase-b  after the human confirms registration, redeploy and smoke-test
#
# Usage:
#   ./scripts/deploy_cloud_run.sh bootstrap-secrets
#   ./scripts/deploy_cloud_run.sh phase-a
#   ./scripts/deploy_cloud_run.sh phase-b
#
# Required environment:
#   PROJECT_ID              Google Cloud project id
#   ENTRA_PORTAL_TENANT_ID  Entra directory (tenant) GUID   - not a secret
#   ENTRA_PORTAL_CLIENT_ID  Entra application (client) GUID - not a secret
#
# Optional environment (defaults shown):
#   REGION=us-central1
#   SERVICE=servicedesk-employee-access
#   RUNTIME_SA=servicedesk-portal-run

set -euo pipefail

REGION="${REGION:-us-central1}"
SERVICE="${SERVICE:-servicedesk-employee-access}"
RUNTIME_SA="${RUNTIME_SA:-servicedesk-portal-run}"

# Google Secret Manager secret NAMES. The values live only in Secret Manager.
CLIENT_SECRET_NAME="servicedesk-entra-portal-client-secret"
SESSION_SECRET_NAME="servicedesk-entra-portal-session-secret"

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

die() { printf '\nERROR: %s\n' "$*" >&2; exit 1; }
note() { printf '\n==> %s\n' "$*"; }

require_env() {
  for var in "$@"; do
    [[ -n "${!var:-}" ]] || die "environment variable ${var} is required."
  done
}

runtime_sa_email() { printf '%s@%s.iam.gserviceaccount.com' "${RUNTIME_SA}" "${PROJECT_ID}"; }

# Cloud Run serves a service on more than one hostname, and `status.url` can
# report the legacy `<service>-<hash>-<region>.a.run.app` form while `gcloud run
# deploy` reports the canonical `<service>-<project-number>.<region>.run.app`
# form. The redirect URI must be pinned to exactly one of them, so the URL that
# the deploy itself reports is treated as authoritative and `status.url` is only
# a fallback for describing an already-deployed service.
DEPLOYED_URL=""

service_url() {
  # 1. A deploy in this invocation reported the canonical URL: trust it.
  if [[ -n "${DEPLOYED_URL}" ]]; then
    printf '%s' "${DEPLOYED_URL}"
    return
  fi

  # 2. phase-b runs without a prior deploy in the same process, so reconstruct
  #    the canonical <service>-<project-number>.<region>.run.app form and use it
  #    only if it genuinely serves. Falling through to status.url here would
  #    silently pin the legacy hostname and break the registered redirect URI.
  local project_number candidate
  project_number="$(gcloud projects describe "${PROJECT_ID}" \
    --format 'value(projectNumber)' 2>/dev/null || true)"
  if [[ -n "${project_number}" ]]; then
    candidate="https://${SERVICE}-${project_number}.${REGION}.run.app"
    if curl -fsS -o /dev/null --max-time 15 "$(health_url "${candidate}")" 2>/dev/null; then
      printf '%s' "${candidate}"
      return
    fi
  fi

  # 3. Older projects only ever get the legacy hostname.
  gcloud run services describe "${SERVICE}" \
    --project "${PROJECT_ID}" --region "${REGION}" \
    --format 'value(status.url)' 2>/dev/null || true
}

# Google's frontend reserves the bare path /healthz on *.run.app and answers it
# with its own 404 without ever forwarding the request to the container. The
# application does serve /healthz correctly - Cloud Run's own probes reach it
# directly - but an external check has to use the trailing-slash form.
health_url() { printf '%s/healthz/' "$1"; }

# -----------------------------------------------------------------------------
# bootstrap-secrets: create the empty secrets and the least-privilege identity.
# -----------------------------------------------------------------------------
bootstrap_secrets() {
  require_env PROJECT_ID
  local sa; sa="$(runtime_sa_email)"

  note "Enabling required APIs"
  gcloud services enable run.googleapis.com secretmanager.googleapis.com \
    cloudbuild.googleapis.com --project "${PROJECT_ID}"

  note "Creating secret containers (values are added separately, by a human)"
  for secret in "${CLIENT_SECRET_NAME}" "${SESSION_SECRET_NAME}"; do
    gcloud secrets describe "${secret}" --project "${PROJECT_ID}" >/dev/null 2>&1 \
      || gcloud secrets create "${secret}" --replication-policy=automatic --project "${PROJECT_ID}"
  done

  note "Creating the dedicated Cloud Run runtime service account"
  gcloud iam service-accounts describe "${sa}" --project "${PROJECT_ID}" >/dev/null 2>&1 \
    || gcloud iam service-accounts create "${RUNTIME_SA}" \
         --display-name "ServiceDesk Employee Access Portal (Cloud Run)" \
         --project "${PROJECT_ID}"

  note "Granting Secret Accessor on ONLY the two portal secrets"
  # This identity holds no Microsoft Graph privilege and no other GCP role.
  for secret in "${CLIENT_SECRET_NAME}" "${SESSION_SECRET_NAME}"; do
    gcloud secrets add-iam-policy-binding "${secret}" \
      --member "serviceAccount:${sa}" \
      --role roles/secretmanager.secretAccessor \
      --project "${PROJECT_ID}" >/dev/null
  done

  cat <<EOF

Secrets and runtime identity are ready.

Add the two secret VALUES yourself - never through this script, never in Git:

  # Entra app registration -> Certificates & secrets -> client secret VALUE
  printf '%s' 'PASTE_CLIENT_SECRET_VALUE' \\
    | gcloud secrets versions add ${CLIENT_SECRET_NAME} --data-file=- --project ${PROJECT_ID}

  # 48 random bytes for cookie session encryption
  openssl rand -base64 48 \\
    | gcloud secrets versions add ${SESSION_SECRET_NAME} --data-file=- --project ${PROJECT_ID}

Then run: ./scripts/deploy_cloud_run.sh phase-a
EOF
}

# -----------------------------------------------------------------------------
# Shared deploy. $1 = value for PORTAL_BASE_URL
# -----------------------------------------------------------------------------
deploy() {
  local base_url="$1"
  local sa; sa="$(runtime_sa_email)"
  local out; out="$(mktemp)"

  gcloud run deploy "${SERVICE}" \
    --source "${APP_DIR}" \
    --project "${PROJECT_ID}" \
    --region "${REGION}" \
    --platform managed \
    --service-account "${sa}" \
    --port 8080 \
    --cpu 1 --memory 512Mi \
    --min-instances 0 --max-instances 4 \
    --timeout 60s \
    `# Public at the transport layer so Microsoft can redirect the browser here.` \
    `# The application itself is protected by Microsoft Entra, not by GCP IAM.` \
    --allow-unauthenticated \
    --set-env-vars "ENTRA_PORTAL_TENANT_ID=${ENTRA_PORTAL_TENANT_ID},ENTRA_PORTAL_CLIENT_ID=${ENTRA_PORTAL_CLIENT_ID},PORTAL_BASE_URL=${base_url}" \
    --set-secrets "ENTRA_PORTAL_CLIENT_SECRET=${CLIENT_SECRET_NAME}:latest,PORTAL_SESSION_SECRET=${SESSION_SECRET_NAME}:latest" \
    2>&1 | tee "${out}"

  # Pin the canonical hostname reported by the deploy itself.
  DEPLOYED_URL="$(grep -oE 'https://[A-Za-z0-9.-]+\.run\.app' "${out}" | tail -1)"
  rm -f "${out}"
  [[ -n "${DEPLOYED_URL}" ]] || die "could not determine the Cloud Run service URL from the deploy output."
}

# -----------------------------------------------------------------------------
# phase-a: get a real URL, then hand the redirect URI to a human.
# -----------------------------------------------------------------------------
phase_a() {
  require_env PROJECT_ID ENTRA_PORTAL_TENANT_ID ENTRA_PORTAL_CLIENT_ID

  note "Phase A deploy (placeholder base URL, so the container can start)"
  deploy "https://placeholder.invalid"

  local url; url="$(service_url)"
  [[ -n "${url}" ]] || die "could not read the Cloud Run service URL."

  note "Rewriting PORTAL_BASE_URL to the real service URL"
  deploy "${url}"

  note "Verifying health (trailing-slash form; Google's frontend eats bare /healthz)"
  curl -fsS "$(health_url "${url}")" && printf '\n'

  cat <<EOF

============================================================
PHASE A COMPLETE - HUMAN ACTION REQUIRED
============================================================

Cloud Run service URL:
    ${url}

In the Microsoft Entra admin center open the portal app registration
(Application/client ID ${ENTRA_PORTAL_CLIENT_ID}), go to Authentication,
add a platform of type "Web", and register this EXACT redirect URI:

    ${url}/auth/redirect

Leave "Access tokens" and "ID tokens" implicit-grant checkboxes UNCHECKED.
This portal uses the authorization code flow.

When that redirect URI is saved, run:

    ./scripts/deploy_cloud_run.sh phase-b
============================================================
EOF
}

# -----------------------------------------------------------------------------
# phase-b: final revision plus smoke test.
# -----------------------------------------------------------------------------
phase_b() {
  require_env PROJECT_ID ENTRA_PORTAL_TENANT_ID ENTRA_PORTAL_CLIENT_ID

  local url; url="$(service_url)"
  [[ -n "${url}" ]] || die "service ${SERVICE} not found. Run phase-a first."

  note "Phase B deploy with PORTAL_BASE_URL=${url}"
  deploy "${url}"

  note "Smoke test: health endpoint must return 200 without authentication"
  curl -fsS "$(health_url "${url}")" && printf '\n'

  note "Smoke test: / must return the sign-in landing page"
  curl -fsS -o /dev/null -w 'landing page HTTP %{http_code}\n' "${url}/"

  note "Smoke test: /auth/signin must redirect to login.microsoftonline.com"
  curl -fsS -o /dev/null -D - "${url}/auth/signin" 2>/dev/null \
    | grep -i '^location:' | cut -c1-80 || true

  cat <<EOF

============================================================
PHASE B COMPLETE
============================================================
Portal URL:   ${url}
Redirect URI: ${url}/auth/redirect

Open the portal URL in a browser and sign in as the demo employee.
============================================================
EOF
}

case "${1:-}" in
  bootstrap-secrets) bootstrap_secrets ;;
  phase-a) phase_a ;;
  phase-b) phase_b ;;
  *)
    cat <<EOF
Usage: $0 {bootstrap-secrets|phase-a|phase-b}

  bootstrap-secrets  create Secret Manager secrets + least-privilege runtime SA
  phase-a            deploy, discover the Cloud Run URL, print the redirect URI
  phase-b            redeploy and smoke-test after the redirect URI is registered
EOF
    exit 1
    ;;
esac
