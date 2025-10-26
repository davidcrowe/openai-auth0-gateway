    #!/usr/bin/env bash
set -euo pipefail

# Deploys the gateway to Cloud Run using env from .env and prints the base URL.
# Requirements: gcloud CLI authenticated; a GCP project with Cloud Run + Cloud Build enabled.

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT_DIR"

if [[ ! -f ".env" ]]; then
  echo "Missing .env at repo root. Copy examples/cloud-run/.env.example to .env and fill values." >&2
  exit 1
fi

SERVICE_NAME=${SERVICE_NAME:-openai-auth0-gateway}
REGION=${REGION:-us-central1}
PROJECT_ID=${PROJECT_ID:-$(grep -E '^GOOGLE_PROJECT_ID=' .env | cut -d= -f2)}

if [[ -z "${PROJECT_ID}" ]]; then
  echo "GOOGLE_PROJECT_ID must be set in .env or PROJECT_ID env var." >&2
  exit 1
fi

# Build
echo "Building container…"
gcloud builds submit --project "${PROJECT_ID}" --tag "gcr.io/${PROJECT_ID}/${SERVICE_NAME}"

# Collect env vars (strip blank/comment lines)
ENV_VARS="$(grep -v '^\s*$\|^\s*#' .env | tr '\n' ',' | sed 's/,$//')"

# Deploy
echo "Deploying to Cloud Run…"
gcloud run deploy "${SERVICE_NAME}" \
  --project "${PROJECT_ID}" \
  --region "${REGION}" \
  --image "gcr.io/${PROJECT_ID}/${SERVICE_NAME}" \
  --platform managed \
  --allow-unauthenticated \
  --set-env-vars "${ENV_VARS}" \
  --memory=512Mi --cpu=1 --port=8080

URL=$(gcloud run services describe "${SERVICE_NAME}" --project "${PROJECT_ID}" --region "${REGION}" --format 'value(status.url)')
echo
echo "Deployed: ${URL}"
echo "Health:   ${URL}/health"
echo "Auth0:    ${URL}/health/auth0"
