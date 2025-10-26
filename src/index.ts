import express from "express";
import bodyParser from "body-parser";
import { toolGatewayImpl, wellKnownOauthProtectedResource, auth0LogWebhook } from "./handlers/toolGatewayHandler.js";
import { healthRoutes } from "./routes/health.js";  // NEW

const app = express();
app.use(bodyParser.json({ limit: "2mb" }));

// Health (root ping + detailed checks)
app.get("/", (_req, res) => res.status(200).json({ ok: true, msg: "openai-auth0-gateway" }));
app.use("/health", healthRoutes(process.env));   // NEW

// Well-knowns
app.get("/.well-known/oauth-protected-resource", wellKnownOauthProtectedResource);
app.get("/.well-known/openid-configuration", toolGatewayImpl);             // proxy via handler
app.get("/.well-known/oauth-authorization-server", toolGatewayImpl);       // proxy via handler

// MCP JSON-RPC + tool POSTs
app.post("/", toolGatewayImpl);
app.post("/mcp", toolGatewayImpl);
app.options("/mcp", toolGatewayImpl);

// Auth0 Log Stream webhook (DCR auto-fix)
// CHANGE this path to match docs: /auth0/logs
app.post("/auth0/logs", auth0LogWebhook);        // was /auth0-log-webhook

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`[srv] listening on :${PORT}`));
