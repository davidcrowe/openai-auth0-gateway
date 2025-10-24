# Deploy to Cloud Run

gcloud builds submit --tag gcr.io/PROJECT_ID/openai-auth0-gateway
gcloud run deploy toolgateway \
  --image gcr.io/PROJECT_ID/openai-auth0-gateway \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars \
OAUTH_ISSUER=https://YOUR_TENANT.us.auth0.com,\
OAUTH_AUDIENCE=https://inner.app/api,\
FUNCTIONS_BASE=https://us-central1-YOUR_GCP_PROJECT.cloudfunctions.net,\
APP_ORIGIN=*,\
MGMT_DOMAIN=YOUR_TENANT.us.auth0.com,\
MGMT_CLIENT_ID=xxxx,\
MGMT_CLIENT_SECRET=xxxx,\
LOG_WEBHOOK_SECRET=replace-me,\
GOOGLE_CONNECTION_NAME=google-oauth2,\
GATEWAY_HMAC_SECRET=replace-me
