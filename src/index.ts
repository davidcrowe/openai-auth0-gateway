import express from "express";
import bodyParser from "body-parser";
import { toolGatewayImpl, wellKnownOauthProtectedResource, auth0LogWebhook } from "./handlers/toolGatewayHandler.js";

const app = express();
app.use(bodyParser.json({ limit: "2mb" }));

// Health
app.get("/", (_req, res) => res.status(200).json({ ok: true, msg: "openai-auth0-gateway" }));

// Well-knowns
app.get("/.well-known/oauth-protected-resource", wellKnownOauthProtectedResource);
app.get("/.well-known/openid-configuration", toolGatewayImpl);             // proxy via handler
app.get("/.well-known/oauth-authorization-server", toolGatewayImpl);       // proxy via handler

// MCP JSON-RPC + tool POSTs
app.post("/", toolGatewayImpl);
app.post("/mcp", toolGatewayImpl);
app.options("/mcp", toolGatewayImpl);

// Auth0 Log Stream webhook (DCR auto-fix)
app.post("/auth0-log-webhook", auth0LogWebhook);

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`[srv] listening on :${PORT}`));
