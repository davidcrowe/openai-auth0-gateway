# OpenAI ↔ Auth0 OAuth Gateway (with DCR)
# Securely connect ChatGPT Connectors to Auth0 using RS256 JWTs, per-tool scopes, and automatic Dynamic Client Registration (DCR) promotion.
# Keywords: ChatGPT Connector, Auth0, OAuth2, Dynamic Client Registration, RS256, PKCE, OpenAI Apps SDK

**Instantly enable secure user-login and tool invocation for ChatGPT Connectors (Apps SDK/MCP) using Auth0**  
A minimal, production-ready gateway** that allows a ChatGPT Connector to:
- trigger user login via Auth0,
- receive an **RS256 JWT** (with your audience) instead of opaque tokens,
- call your backend tools with **per-tool scopes** (enforcing user-specific access),
- automatically promote dynamically registered ChatGPT clients in Auth0 (DCR) to *first-party + PKCE*, and enable your designated login connection (e.g., Google).

> Open-source utility for securely linking ChatGPT apps to any OAuth2 backend via Auth0.
> Maintained by [Reducibl — Applied AI Studio](https://reducibl.com)

---

## ✅ Why this matters (and why most integrations fail)

If you’re building a ChatGPT Connector that accesses user-specific data, you’ll face these issues:
- ChatGPT performs **Dynamic Client Registration (DCR)** in Auth0 → the new client is created as **third-party** by default, blocking login flows.
- Auth0 may issue **opaque (JWE) access tokens**, but your gateway needs a **JWT (RS256)** with correct `audience` to validate.
- Without correct **scopes** and **audience**, your connector will run into 401/403 errors (“insufficient_scope”, “invalid_token”, “ACCESS_TOKEN_IS_ENCRYPTED_JWE”).
- Many devs stop at “works in local test” but fail once ChatGPT does DCR and real login — that gap is rarely documented end-to-end.

This gateway solves all of that, providing a **plug-and-play OAuth layer** for ChatGPT Connectors with Auth0 and your tool backend.

---

## 🚀 Features

- `/.well-known/oauth-protected-resource` endpoint (RFC 9728) that advertises your resource, issuer and scopes.
- Automatic handling of **DCR**: ChatGPT registers a new client → Auth0 Log Stream triggers a webhook → the gateway **promotes** the client to first-party + PKCE, and enables your login connection.
- **RS256 JWT verification** using JWKS from your Auth0 tenant; strict `issuer` and `audience` checks.
- Per-tool scope map so each tool (e.g., `chatWithEmbeddingsv3`, `listEvents`) requires exactly the correct permission.
- Transparent fan-out to your backend services via `FUNCTIONS_BASE/{toolName}`.
- Minimal setup — entirely environment-variable driven, deploys to Google Cloud Run (or any Node host) with no CLI.

---

## 🧩 Architecture at a glance
```text
ChatGPT Connector → your gateway → Auth0 DCR → Auth0 client promoted
          ↓                           ↑
 /.well-known/oauth-protected-resource  Log Stream → Webhook
          ↓
   User login via Auth0 (e.g., Google)
          ↓
   Auth0 issues RS256 access token (aud=your API)
          ↓
   Gateway verifies token + scopes → proxy to your backend
          ↓
   Your tool executes with user-specific context
```

---

## 🛠 Prerequisites
- An **Auth0 tenant** (developer or production).  
- A **Node-capable host** for the gateway (e.g., Google Cloud Run).  
- A backend service (Cloud Functions, AWS Lambda, etc.) that exposes your tools (e.g., `chatWithEmbeddingsv3`).

---

## 🔧 Quickstart

### 1. Clone & install
```bash
git clone https://github.com/YOUR_ORG/openai-auth0-gateway.git
cd openai-auth0-gateway
npm ci
cp .env.sample .env

2. Configure .env

Edit `.env` with your values:

```env
OAUTH_ISSUER=https://YOUR_TENANT.us.auth0.com
OAUTH_AUDIENCE=https://your.api/identifier
FUNCTIONS_BASE=https://us-central1-YOUR_PROJECT.cloudfunctions.net
APP_ORIGIN=*
MGMT_DOMAIN=YOUR_TENANT.us.auth0.com
MGMT_CLIENT_ID=…
MGMT_CLIENT_SECRET=…
LOG_WEBHOOK_SECRET=replace-with-random
GOOGLE_CONNECTION_NAME=google-oauth2
GATEWAY_HMAC_SECRET=replace-with-random
```

```

3. Auth0 tenant setup

Create API (Identifier = OAUTH_AUDIENCE) → RS256 signing → define scopes (your.api:tool1, your.api:tool2).

Enable Allow Dynamic Client Registration in API settings.

Create M2M App → authorize Auth0 Management API with scopes: read:clients update:clients read:connections update:connections.

Set up your login connection (Google, Email, etc.).

Create Log Stream → Webhook
URL = https://YOUR_GATEWAY/auth0-log-webhook
Header = Authorization: Bearer LOG_WEBHOOK_SECRET
Event filter: include Success API Operation.

4. Deploy gateway

See examples/cloud-run-deploy.md.

5. Smoke test

Follow examples/curl-smoke-tests.md.

6. Connect from ChatGPT

Add a WebApp connector, point to your gateway domain, authorize login, test a tool call.

🔁 Reuse for another app

You can reuse the gateway code for multiple apps:

Deploy another instance with a new OAUTH_AUDIENCE and FUNCTIONS_BASE.

Use the same Auth0 tenant and Log Stream/webhook.

Auth0 will auto-promote each new ChatGPT client under your DCR-enabled API.

No code change needed — just new env settings.

🧠 Troubleshooting

| Error | Meaning | Fix |
|-------|----------|-----|
| `ACCESS_TOKEN_IS_ENCRYPTED_JWE` | Opaque token returned | Ensure `audience` is your API ID |
| `insufficient_scope` | Missing permissions | Enable RBAC + “Add permissions in the access token” |
| `conn_lookup_http_403` | Management API lacks permissions | Add `read:connections`, `update:connections` |
| No login prompt | Missing metadata | Ensure `/.well-known/oauth-protected-resource` returns correct fields |

📜 License

MIT

📞 Maintainers

Built and maintained by Reducibl – Applied AI Studio.  
Questions, issues, and PRs are welcome!