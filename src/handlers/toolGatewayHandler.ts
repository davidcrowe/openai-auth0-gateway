// functions/src/handlers/toolGatewayHandler.ts
import type { Request, Response } from "express";
import crypto, { createHmac } from "crypto";

// ---------- Config --------
const FUNCTIONS_BASE = (process.env.FUNCTIONS_BASE ??
  "https://us-central1-<YOUR_PROJECT_ID>.cloudfunctions.net"
).replace(/\/+$/, "");

// AFTER  (neutral default; trailing slash trimmed)
const OAUTH_ISSUER = (process.env.OAUTH_ISSUER ?? "https://YOUR_TENANT.us.auth0.com/").replace(/\/+$/, "");

// Explicit issuer discovery locations (we will proxy them with 200 JSON) //
const RAW_OIDC_DISCOVERY =
  process.env.OIDC_DISCOVERY ?? `${OAUTH_ISSUER}/.well-known/openid-configuration`;
const OIDC_DISCOVERY = RAW_OIDC_DISCOVERY.startsWith("http")
  ? RAW_OIDC_DISCOVERY
  : `${OAUTH_ISSUER}/${RAW_OIDC_DISCOVERY.replace(/^\/+/, "")}`;

const OAUTH_AUTHZ_SERVER = `${OAUTH_ISSUER}/.well-known/oauth-authorization-server`;

const OAUTH_AUDIENCE = process.env.OAUTH_AUDIENCE || undefined; // must match your Auth0 API Identifier when set
const JWKS_URI_FALLBACK = process.env.JWKS_URI ?? `${OAUTH_ISSUER}/.well-known/jwks.json`;

// Advisory defaults; client honors required_scopes below.
const OAUTH_SCOPES = (process.env.OAUTH_SCOPES ?? "openid email profile").trim();

const GATEWAY_HMAC_SECRET = process.env.GATEWAY_HMAC_SECRET || "dev-only-change-me";
const APP_ORIGIN = process.env.APP_ORIGIN || "*";

// Map tool -> scopes it requires
// Example JSON: {"chatWithEmbeddingsv3":["app.write"],"listEvents":["app.read"]}
const DEFAULT_TOOL_SCOPES: Record<string, string[]> = {
  // --- Inner examples (fallback) ---
  generateDreamSummary: ["inner.dreams:read"],
  generateDreamName: ["inner.dreams:read"],
  extractInnerDynamicsv2: ["inner.dreams:read"],
  extractDreamSymbols: ["inner.dreams:read"],
  generateDreamImagev2: ["inner.images:create"],
  listEvents: ["inner.events:read"],
  getEventContext: ["inner.events:read"],
  findSimilarEvents: ["inner.events:read"],
  chatWithEmbeddingsv3: ["inner.dreams:write"],
};

function parseToolScopesEnv(): Record<string, string[]> {
  const raw = process.env.TOOL_SCOPES_JSON;
  if (!raw) return DEFAULT_TOOL_SCOPES;
  try {
    const obj = JSON.parse(raw);
    if (obj && typeof obj === "object") return obj as Record<string, string[]>;
    return DEFAULT_TOOL_SCOPES;
  } catch {
    return DEFAULT_TOOL_SCOPES;
  }
}

const TOOL_SCOPES: Record<string, string[]> = parseToolScopesEnv();


// Union of all tool scopes (what the client should actually request)
const REQUIRED_SCOPES = Array.from(new Set(Object.values(TOOL_SCOPES).flat()));

// ---- Safe logging helpers (no secrets printed) ----
function logCfg() {
  console.log("[cfg]", {
    OAUTH_ISSUER,
    OAUTH_AUDIENCE,
    JWKS_URI_FALLBACK,
    FUNCTIONS_BASE,
    APP_ORIGIN
  });
}
logCfg();

function readAuth(req: Request) {
  const auth = req.header("authorization") || "";
  const hasAuth = auth.startsWith("Bearer ");
  const token = hasAuth ? auth.slice(7) : "";
  const tokenShape = token.includes(".") ? "jwt" : (token ? "opaque" : "none");
  return { hasAuth, token, tokenShape, len: token.length };
}

function logAuthShape(prefix: string, req: Request) {
  const { hasAuth, tokenShape, len } = readAuth(req);
  console.log(`[auth:${prefix}] hasAuth=%s tokenShape=%s len=%d path=%s method=%s`,
    hasAuth, tokenShape, len, req.path, req.method);
}

function logJwtClaims(prefix: string, token: string) {
  const dbg = decodeJwtUnsafe(token);
  console.log(`[auth:${prefix}] iss=%s aud=%s scope=%s perms=%s`,
    dbg?.iss, JSON.stringify(dbg?.aud), dbg?.scope, JSON.stringify(dbg?.permissions));
}

function b64urlDecodeToJson(s: string) {
  try {
    s += "=".repeat((4 - (s.length % 4)) % 4);
    const buf = Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
    return JSON.parse(buf.toString("utf8"));
  } catch { return undefined; }
}

function logTokenStructure(prefix: string, token: string) {
  const parts = token.split(".");
  const header = parts[0] ? b64urlDecodeToJson(parts[0]) : undefined;
  console.log(`[auth:${prefix}] parts=%d header.alg=%s header.typ=%s`,
    parts.length,
    header?.alg,
    header?.typ
  );
}

// ---------- Helpers ----------
function toolNameFromPath(path: string): string | null {
  const parts = path.split("/").filter(Boolean);
  return parts.length ? parts[parts.length - 1] : null;
}

function requireScopes(have: string[], need: string[]) {
  const ok = need.every((s) => have.includes(s));
  if (!ok) {
    const err: any = new Error("insufficient_scope");
    err.status = 403;
    err.code = "INSUFFICIENT_SCOPE";
    throw err;
  }
}

async function subjectToUid(sub: string, _email?: string): Promise<string> {
  return `auth0:${sub}`;
}

function signGatewayUid(uid: string): string {
  const ts = Math.floor(Date.now() / 1000);
  const base = `${uid}.${ts}`;
  const sig = createHmac("sha256", GATEWAY_HMAC_SECRET).update(base).digest("hex");
  return `${base}.${sig}`;
}

function buildWwwAuthenticate(req: Request): string {
  const xfProto = req.get("x-forwarded-proto") || req.protocol || "https";
  const xfHost  = req.get("x-forwarded-host") || req.get("host");
  const base    = `${xfProto}://${xfHost}`;
  const metaUrl = `${base}/.well-known/oauth-protected-resource`;

  const scopeParam = (REQUIRED_SCOPES.length
    ? REQUIRED_SCOPES
    : OAUTH_SCOPES.split(" ").filter(Boolean)
  ).join(" ");

  const resourceParam = OAUTH_AUDIENCE ? `, resource="${OAUTH_AUDIENCE}"` : "";

  // RFC 9728: use resource_metadata
  return `Bearer resource_metadata="${metaUrl}", scope="${scopeParam}"${resourceParam}`;
}


// Small robust fetch with timeout + retry (no external deps)
async function fetchJsonWithRetry(url: string, tries = 3, timeoutMs = 4000): Promise<any> {
  let lastErr: unknown;
  for (let i = 0; i < tries; i++) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const r = await fetch(url, { headers: { accept: "application/json" }, signal: ctrl.signal } as any);
      clearTimeout(t);
      if (!r.ok) throw new Error(`http_${r.status}`);
      return await r.json();
    } catch (e) {
      lastErr = e;
      await new Promise(res => setTimeout(res, 150 * (i + 1)));
    } finally {
      clearTimeout(t);
    }
  }
  throw lastErr instanceof Error ? lastErr : new Error(String(lastErr));
}

type JsonRpcReq = { jsonrpc: "2.0"; id?: string | number | null; method: string; params?: any };
type JsonRpcRes =
  | { jsonrpc: "2.0"; id: string | number | null; result: any }
  | { jsonrpc: "2.0"; id: string | number | null; error: { code: number; message: string; data?: any } };

function jsonRpcResult(id: any, result: any): JsonRpcRes {
  return { jsonrpc: "2.0", id: id ?? null, result };
}
function jsonRpcError(id: any, code: number, message: string, data?: any): JsonRpcRes {
  return { jsonrpc: "2.0", id: id ?? null, error: { code, message, data } };
}

// ---- Tool JSON Schemas ----
const TOOL_SCHEMAS: Record<string, any> = {
  generateDreamSummary: { type: "object", required: ["text"], properties: {
    text: { type: "string", description: "Raw dream text" },
    maxSentences: { type: "integer", minimum: 1, maximum: 10 },
    locale: { type: "string" } } },
  generateDreamName: { type: "object", required: ["text"], properties: {
    text: { type: "string" },
    style: { type: "string", enum: ["poetic", "plain", "mysterious", "auto"] } } },
  extractInnerDynamicsv2: { type: "object", required: ["text"], properties: {
    text: { type: "string" },
    topK: { type: "integer", minimum: 1, maximum: 10, default: 5 } } },
  extractDreamSymbols: { type: "object", required: ["text"], properties: {
    text: { type: "string" },
    topK: { type: "integer", minimum: 1, maximum: 20, default: 8 } } },
  generateDreamImagev2: { type: "object", required: ["prompt"], properties: {
    prompt: { type: "string" },
    style: { type: "string" },
    aspectRatio: { type: "string", pattern: "^[0-9]+:[0-9]+$" } } },
  listEvents: { type: "object", properties: {
    sessionId: { type: "string" },
    limit: { type: "integer", minimum: 1, maximum: 200, default: 50 },
    since: { type: "string", format: "date-time" } } },
  getEventContext: { type: "object", required: ["eventId"], properties: {
    eventId: { type: "string" },
    includeNeighbors: { type: "boolean", default: false } } },
  findSimilarEvents: { type: "object", oneOf: [{ required: ["text"] }, { required: ["eventId"] }], properties: {
    text: { type: "string" },
    eventId: { type: "string" },
    topK: { type: "integer", minimum: 1, maximum: 50, default: 5 } } },
  chatWithEmbeddingsv3: { type: "object", required: ["messages"], properties: {
    messages: { type: "array", minItems: 1, items: {
      type: "object", required: ["role","content"], properties: {
        role: { type: "string", enum: ["user","assistant","system"] },
        content: { type: "string" } } } },
    sessionId: { type: "string" },
    topK: { type: "integer", minimum: 0, maximum: 50, default: 8 } } },
};

function mcpToolDescriptors() {
  return Object.entries(TOOL_SCOPES).map(([name, scopes]) => {
    const schema = { $schema: "http://json-schema.org/draft-07/schema#", ...(TOOL_SCHEMAS[name] || { type: "object" }) };
    const securitySchemes = scopes.length ? [{ type: "oauth2", scopes }] : [{ type: "noauth" }];
    return {
      name,
      title: name.replace(/([A-Z])/g, " $1").trim(),
      description: name,
      inputSchema: schema,
      input_schema: schema,
      requiredScopes: scopes,
      securitySchemes,
      executable: true
    };
  });
}

function looksLikeJsonRpc(body: any): boolean {
  try {
    const b = typeof body === "string" ? JSON.parse(body) : body;
    return b && b.jsonrpc === "2.0" && typeof b.method === "string";
  } catch { return false; }
}

function decodeJwtUnsafe(token: string) {
  try {
    const [, p] = token.split(".");
    return JSON.parse(Buffer.from(p.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
  } catch { return undefined; }
}

async function verifyBearer(req: Request) {
  logAuthShape("verifyBearer", req);

  const auth = req.header("authorization") || "";
  if (!auth.startsWith("Bearer ")) {
    const err: any = new Error("NO_AUTH");
    err.status = 401;
    err.www = buildWwwAuthenticate(req) + ", error=\"invalid_token\"";
    throw err;
  }

  const accessToken = auth.slice(7);

  // NEW: log segment count & header BEFORE any rejection
  const segments = accessToken.split(".");
  const header = segments[0] ? b64urlDecodeToJson(segments[0]) : undefined;
  console.log(
    "[auth:token] segments=%d header.alg=%s header.typ=%s",
    segments.length, header?.alg, header?.typ
  );

  // If it’s not a 3-part JWS, give a precise error (don’t just say INVALID_TOKEN_FORMAT)
  if (segments.length !== 3) {
    const e: any = new Error(
      segments.length === 5
        ? "ACCESS_TOKEN_IS_ENCRYPTED_JWE"
        : "ACCESS_TOKEN_NOT_JWS"
    );
    e.status = 401;
    e.www = buildWwwAuthenticate(req) + ", error=\"invalid_token\"";
    throw e;
  }

  // continue with JWS verification
  const { createRemoteJWKSet, jwtVerify } = await import("jose");
  const JWKS = createRemoteJWKSet(new URL(JWKS_URI_FALLBACK));
  const issuerNoSlash = OAUTH_ISSUER.replace(/\/+$/, "");
  const issuerWithSlash = issuerNoSlash + "/";

  try {
    const { payload } = await jwtVerify(accessToken, JWKS, {
      issuer: [issuerNoSlash, issuerWithSlash],
      ...(OAUTH_AUDIENCE ? { audience: OAUTH_AUDIENCE } : {})
    });
    console.log("[auth:postVerify]", { sub: payload.sub, aud: payload.aud });
    return payload;
  } catch (err: any) {
    console.error("[auth:jwtVerify:error]", { message: err?.message, name: err?.name });
    const e: any = new Error("JWT_VERIFY_FAILED");
    e.status = 401;
    e.www = buildWwwAuthenticate(req) + ", error=\"invalid_token\"";
    throw e;
  }
}

async function verifyBearerAndScopes(req: Request, toolName: string) {
  const payload = await verifyBearer(req);

  const sub = String(payload.sub || "");
  if (!sub) {
    const err: any = new Error("TOKEN_NO_SUB");
    err.status = 401;
    err.www = buildWwwAuthenticate(req) + ", error=\"invalid_token\"";
    throw err;
  }

  const email = typeof (payload as any).email === "string" ? (payload as any).email : undefined;
  const scopeStr = typeof (payload as any).scope === "string" ? (payload as any).scope : "";
  const permissions = Array.isArray((payload as any).permissions) ? ((payload as any).permissions as string[]) : [];
  const scopes = Array.from(new Set([...scopeStr.split(" ").filter(Boolean), ...permissions]));

  const need = TOOL_SCOPES[toolName] || [];
  if (need.length) requireScopes(scopes, need);

  const uid = await subjectToUid(sub, email);
  const gatewaySig = signGatewayUid(uid);
  return { uid, gatewaySig };
}

// === MCP START ===
async function handleMcp(req: Request, res: Response) {
  // CORS like your gateway
  res.setHeader("Access-Control-Allow-Origin", APP_ORIGIN);
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Headers", "authorization,content-type,x-request-id");
  res.setHeader("Access-Control-Allow-Methods", "GET,HEAD,POST,OPTIONS");
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Access-Control-Expose-Headers", "WWW-Authenticate, Location");

  console.log("[mcp:req]", { path: req.path, method: req.method });

  if (req.method === "OPTIONS") { res.status(204).end(); return; }

  if (req.method !== "POST") {
    res.status(405).json({ ok: false, error: { code: "METHOD_NOT_ALLOWED" } });
    return;
  }

  let rpc: JsonRpcReq;
  try {
    rpc = (typeof req.body === "string") ? JSON.parse(req.body) : req.body;
  } catch {
    res.status(400).json(jsonRpcError(null, -32700, "Parse error"));
    return;
  }
  if (!rpc || rpc.jsonrpc !== "2.0" || typeof rpc.method !== "string") {
    res.status(400).json(jsonRpcError(rpc?.id ?? null, -32600, "Invalid Request"));
    return;
  }

  // initialize → return protocol + capabilities (no auth required)
  if (rpc.method === "initialize") {
    const result = {
      protocolVersion: "2025-06-18",
      capabilities: { tools: { listChanged: false } },
      serverInfo: { name: "inner-tool-gateway", version: "1.0.0" }
    };
    res.status(200).json(jsonRpcResult(rpc.id ?? null, result));
    return;
  }

  // notifications/initialized → ack (notification = no id)
  if (rpc.method === "notifications/initialized") {
    res.status(202).end();
    return;
  }

  // authenticated: list tools (force OAuth discovery)
  if (rpc.method === "tools/list") {
    const { hasAuth, tokenShape } = readAuth(req);
    if (!hasAuth || tokenShape !== "jwt") {
      const www = buildWwwAuthenticate(req) + ", error=\"invalid_token\"";
      res.setHeader("WWW-Authenticate", www);
      console.warn("[mcp] tools/list → 401 (prompting OAuth)", { hasAuth, tokenShape });
      res.status(401).json(jsonRpcError(rpc.id ?? null, -32001, "Unauthorized"));
      return;
    }

    try {
      await verifyBearer(req);
    } catch (e: any) {
      const www = e?.www || buildWwwAuthenticate(req);
      res.setHeader("WWW-Authenticate", www);
      console.warn("[mcp] tools/list auth fail", { message: e?.message });
      res.status(Number(e?.status) || 401).json(jsonRpcError(rpc.id ?? null, -32001, e?.message || "Unauthorized"));
      return;
    }

    console.log("[mcp] tools/list authed");
    const tools = mcpToolDescriptors();
    res.status(200).json(jsonRpcResult(rpc.id ?? null, { tools }));
    return;
  }

  // protected: call a tool
  if (rpc.method === "tools/call") {
    const name = rpc.params?.name;
    const args = rpc.params?.arguments ?? {};

    console.log("[mcp] tools/call name=%s", name);
    logAuthShape("mcp.tools/call", req);

    if (typeof name !== "string" || !TOOL_SCOPES[name]) {
      res.status(404).json(jsonRpcError(rpc.id ?? null, -32601, `Unknown tool: ${name}`));
      return;
    }

    // Early guard: reject non-JWT and prompt OAuth
    {
      const { hasAuth, tokenShape } = readAuth(req);
      if (!hasAuth || tokenShape !== "jwt") {
        const www = buildWwwAuthenticate(req) + ", error=\"invalid_token\"";
        res.setHeader("WWW-Authenticate", www);
        console.warn("[mcp] tools/call → 401 (non-JWT token)", { hasAuth, tokenShape, name });
        res.status(401).json(jsonRpcError(rpc.id ?? null, -32001, "Unauthorized"));
        return;
      }
    }

    let uid: string, gatewaySig: string;
    try {
      const verified = await verifyBearerAndScopes(req, name);
      uid = verified.uid; gatewaySig = verified.gatewaySig;
    } catch (e: any) {
      if (e?.www) res.setHeader("WWW-Authenticate", e.www);
      else res.setHeader("WWW-Authenticate", buildWwwAuthenticate(req));
      res.status(Number(e?.status) || 401)
        .json(jsonRpcError(rpc.id ?? null, -32001, e?.message || "Unauthorized"));
      return;
    }

    const requestId = req.header("x-request-id") || crypto.randomUUID();
    const url = `${FUNCTIONS_BASE}/${name}`;
    const r = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-request-id": requestId,
        "x-user-uid": uid!,
        "x-gateway-sig": gatewaySig!
      },
      body: JSON.stringify(args)
    } as any);

    const ct = r.headers.get("content-type") || "";
    const payloadOut = ct.includes("json") ? await r.json() : await r.text();

    if (!r.ok) {
      res.status(200).json(jsonRpcResult(rpc.id ?? null, {
        isError: true,
        content: [{ type: "error", error: { status: r.status, body: payloadOut } }]
      }));
      return;
    }

    res.status(200).json(jsonRpcResult(rpc.id ?? null, {
      isError: false,
      content: [{ type: "output_json", json: payloadOut }]
    }));
    return;
  }

  res.status(400).json(jsonRpcError(rpc.id ?? null, -32601, `Method not found: ${rpc.method}`));
}

// ---------- Well-known: oauth-protected-resource ----------
export async function wellKnownOauthProtectedResource(req: Request, res: Response): Promise<void> {
  const ua = req.get("user-agent") || "";
  const origin = req.get("origin") || "";
  const referer = req.get("referer") || "";
  const xfProto = req.get("x-forwarded-proto") || req.protocol || "https";
  const xfHost = req.get("x-forwarded-host") || req.get("host") || "";
  const fullUrl = `${xfProto}://${xfHost}${req.originalUrl || req.url}`;

  console.log("[wk] /.well-known/oauth-protected-resource served", {
    url: fullUrl, method: req.method, ua, origin, referer,
  });
  console.log("[wk.cfg]", {
    issuer: OAUTH_ISSUER,
    audience: OAUTH_AUDIENCE || null,
    jwks_uri_fallback: JWKS_URI_FALLBACK,
    required_scopes: REQUIRED_SCOPES,
  });

  try {
    const d = await fetchJsonWithRetry(`${OAUTH_ISSUER}/.well-known/openid-configuration`);
    
    // Minimal RFC 9728-style payload
    const scopes_supported = Array.from(
      new Set([...OAUTH_SCOPES.split(" ").filter(Boolean), ...REQUIRED_SCOPES])
    );

    // AFTER (only include resource if set)
    res.setHeader("Content-Type", "application/json");
    const payload: any = {
    authorization_servers: [OAUTH_ISSUER],
    scopes_supported
    };
    if (OAUTH_AUDIENCE) payload.resource = OAUTH_AUDIENCE;
    res.status(200).send(payload);


  } catch (e: any) {
    console.error("[wk.error]", { message: e?.message || String(e) });
    res.status(502).json({ error: "discovery_fetch_failed", detail: e?.message || String(e) });
  }
}

// ---------- Tool gateway (serves well-known + webhook + MCP + tools) ----------
export async function toolGatewayImpl(req: Request, res: Response): Promise<void> {
  // CORS
  res.setHeader("Access-Control-Allow-Origin", APP_ORIGIN);
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Headers", "authorization,content-type,x-request-id");
  res.setHeader("Access-Control-Allow-Methods", "GET,HEAD,POST,OPTIONS");
  res.setHeader("Access-Control-Expose-Headers", "WWW-Authenticate, Location");

  console.log("[rest:req]", { path: req.path, method: req.method });

  // Preflight
  if (req.method === "OPTIONS") { res.status(204).end(); return; }

  // ✅ 1) Auth0 Log Stream Webhook (MUST come before any auth/tool logic)
  if (req.path === "/auth0-log-webhook" && req.method === "POST") {
    return auth0LogWebhook(req, res); // this route does its own shared-secret auth
  }

  // ✅ 2) MCP JSON-RPC (either POST body looks like JSON-RPC, or explicit /mcp path)
  if (req.method === "POST" && looksLikeJsonRpc(req.body)) {
    await handleMcp(req, res);
    return;
  }
  if ((req.method === "POST" || req.method === "OPTIONS") && req.path === "/mcp") {
    await handleMcp(req, res);
    return;
  }

  const p = req.path;

  // ✅ 3) Health/root
  if ((req.method === "GET" || req.method === "HEAD") && (p === "/" || p === "")) {
    if (req.method === "HEAD") { res.status(200).end(); return; }
    res.setHeader("Content-Type", "application/json");
    res.status(200).send({
      ok: true,
      service: "tool-gateway",
      well_known: ["/.well-known/oauth-protected-resource", "/.well-known/openid-configuration"],
      message: "Send POST /mcp (MCP JSON-RPC), or POST /{toolName} with Bearer token to invoke a tool."
    });
    return;
  }

  // ✅ 4) Well-known endpoints
  if ((req.method === "GET" || req.method === "HEAD") && p === "/.well-known/oauth-protected-resource") {
    if (req.method === "HEAD") { res.status(200).end(); return; }
    return wellKnownOauthProtectedResource(req, res);
  }

    // AFTER
    if ((req.method === "GET" || req.method === "HEAD") && p === "/.well-known/oauth-authorization-server") {
    if (req.method === "HEAD") { res.status(200).end(); return; }
    try {
        const doc = await fetchJsonWithRetry(OAUTH_AUTHZ_SERVER);
        res.setHeader("Content-Type", "application/json");
        res.status(200).send(doc);
    } catch (e: any) {
        res.status(502).json({ error: "discovery_fetch_failed", detail: e?.message || String(e) });
    }
    return;
    }

  if ((req.method === "GET" || req.method === "HEAD") && p === "/.well-known/openid-configuration") {
    if (req.method === "HEAD") { res.status(200).end(); return; }
    try {
      const doc = await fetchJsonWithRetry(OIDC_DISCOVERY);
      res.setHeader("Content-Type", "application/json");
      res.status(200).send(doc);
    } catch (e: any) {
      res.status(502).json({ error: "discovery_fetch_failed", detail: e?.message || String(e) });
    }
    return;
  }

  // ✅ 5) Tools: POST only beyond this point
  if (req.method !== "POST") {
    res.status(405).json({ ok: false, error: { code: "METHOD_NOT_ALLOWED" } });
    return;
  }

  const requestId = req.header("x-request-id") || crypto.randomUUID();
  const started = Date.now();

  try {
    // --- Verify OAuth access token from ChatGPT ---
    const auth = req.header("authorization") || "";
    if (!auth.startsWith("Bearer ")) {
      res.setHeader("WWW-Authenticate", buildWwwAuthenticate(req) + ", error=\"invalid_token\"");
      res.status(401).json({ ok: false, error: { code: "NO_AUTH", message: "Missing Bearer token" }, requestId });
      console.warn("[rest] no Authorization header; sending WWW-Authenticate");
      return;
    }
    const accessToken = auth.slice(7);

    const parts = accessToken.split(".");
    if (parts.length !== 3) {
      res.setHeader(
        "WWW-Authenticate",
        buildWwwAuthenticate(req) + ", error=\"invalid_token\", error_description=\"Expecting JWS access token (3 parts)\""
      );
      console.warn("[rest] non-JWS token (parts=%d); prompting OAuth", parts.length);
      res.status(401).json({ ok: false, error: { code: "INVALID_TOKEN", message: "Expecting JWT/JWS access token" }, requestId });
      return;
    }

    logTokenStructure("rest.verify", accessToken);
    logJwtClaims("rest.claimsPreview", accessToken);

    const { createRemoteJWKSet, jwtVerify } = await import("jose");
    const JWKS = createRemoteJWKSet(new URL(JWKS_URI_FALLBACK));
    const issuerNoSlash = OAUTH_ISSUER.replace(/\/+$/, "");
    const issuerWithSlash = issuerNoSlash + "/";
    const { payload } = await jwtVerify(accessToken, JWKS, {
      issuer: [issuerNoSlash, issuerWithSlash],
      ...(OAUTH_AUDIENCE ? { audience: OAUTH_AUDIENCE } : {})
    });

    const sub = String(payload.sub || "");
    if (!sub) {
      res.setHeader("WWW-Authenticate", buildWwwAuthenticate(req) + ", error=\"invalid_token\"");
      res.status(401).json({ ok: false, error: { code: "TOKEN_NO_SUB", message: "Missing sub" }, requestId });
      return;
    }

    const scopeStr = typeof (payload as any).scope === "string" ? (payload as any).scope : "";
    const scopeList = scopeStr.split(" ").filter(Boolean);
    const permissions = Array.isArray((payload as any).permissions) ? ((payload as any).permissions as string[]) : [];
    const scopes = Array.from(new Set([...scopeList, ...permissions]));

    const name = toolNameFromPath(req.path);
    if (!name) {
      res.status(400).json({ ok: false, error: { code: "NO_TOOL", message: "Missing tool name" }, requestId });
      return;
    }
    const need = TOOL_SCOPES[name] || [];
    if (need.length) requireScopes(scopes, need);

    const email = typeof (payload as any).email === "string" ? (payload as any).email : undefined;
    const uid = await subjectToUid(sub, email);
    const gatewaySig = signGatewayUid(uid);

    const url = `${FUNCTIONS_BASE}/${name}`;
    const r = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-request-id": requestId,
        "x-user-uid": uid,
        "x-gateway-sig": gatewaySig
      },
      body: JSON.stringify(req.body ?? {})
    } as any);

    const ct = r.headers.get("content-type") || "";
    const payloadOut = ct.includes("json") ? await r.json() : await r.text();
    const elapsedMs = Date.now() - started;

    if (!r.ok) {
      res.status(r.status).json({
        ok: false,
        error: { code: `FN_${r.status}`, message: "Function error", details: payloadOut },
        requestId,
        elapsedMs,
        uid
      });
      return;
    }

    res.status(200).json({ ok: true, data: payloadOut, requestId, elapsedMs, uid });
  } catch (e: any) {
    const status = Number(e?.status) || 500;
    console.error("[rest:error]", { status, message: e?.message || String(e) });
    res.status(status).json({
      ok: false,
      error: { code: e?.code || "GATEWAY_ERROR", message: e?.message || String(e) }
    });
  }
}




// === Auth0 Log Stream Webhook ===
// Add near the top with your other config envs:
const MGMT_DOMAIN = process.env.MGMT_DOMAIN!;
const MGMT_CLIENT_ID = process.env.MGMT_CLIENT_ID!;
const MGMT_CLIENT_SECRET = process.env.MGMT_CLIENT_SECRET!;
const LOG_WEBHOOK_SECRET = process.env.LOG_WEBHOOK_SECRET || "dev-change-me";
const GOOGLE_CONNECTION_NAME = process.env.GOOGLE_CONNECTION_NAME || "google-oauth2";

type OAuthTokenRes = { access_token: string; token_type?: string; expires_in?: number };

async function getMgmtToken(): Promise<string> {
  const r = await fetch(`https://${MGMT_DOMAIN}/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      grant_type: "client_credentials",
      client_id: MGMT_CLIENT_ID,
      client_secret: MGMT_CLIENT_SECRET,
      audience: `https://${MGMT_DOMAIN}/api/v2/`
    })
  } as any);
  if (!r.ok) throw new Error(`mgmt_token_http_${r.status}`);
  const j = (await r.json()) as OAuthTokenRes;   // <-- typed
  if (!j?.access_token) throw new Error("mgmt_token_missing_access_token");
  return j.access_token;
}


// Helper: patch client → first-party + public + grants
async function promoteClient(mgmtToken: string, clientId: string) {
  const patchBody = {
    app_type: "regular_web",                // or "native" if you prefer
    is_first_party: true,
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"]
  };
  const r = await fetch(`https://${MGMT_DOMAIN}/api/v2/clients/${clientId}`, {
    method: "PATCH",
    headers: { "content-type": "application/json", authorization: `Bearer ${mgmtToken}` },
    body: JSON.stringify(patchBody)
  } as any);
  if (!r.ok) {
    const txt = await r.text();
    throw new Error(`promote_http_${r.status}:${txt}`);
  }
}

async function enableGoogleForClient(mgmtToken: string, clientId: string) {
  // 1) find the connection id for google-oauth2
  const rc = await fetch(`https://${MGMT_DOMAIN}/api/v2/connections?name=${encodeURIComponent(GOOGLE_CONNECTION_NAME)}`, {
    headers: { authorization: `Bearer ${mgmtToken}` }
  } as any);
  if (!rc.ok) throw new Error(`conn_lookup_http_${rc.status}`);
  const arr = (await rc.json()) as Array<{ id?: string; enabled_clients?: string[] }>;
  const conn = Array.isArray(arr) ? arr[0] : null;
  if (!conn || !conn.id) throw new Error(`connection_not_found:${GOOGLE_CONNECTION_NAME}`);

  // 2) add clientId to enabled_clients (idempotent)
  const enabled = new Set<string>(Array.isArray(conn.enabled_clients) ? conn.enabled_clients : []);
  enabled.add(clientId);

  const rp = await fetch(`https://${MGMT_DOMAIN}/api/v2/connections/${conn.id}`, {
    method: "PATCH",
    headers: { "content-type": "application/json", authorization: `Bearer ${mgmtToken}` },
    body: JSON.stringify({ enabled_clients: Array.from(enabled) })
  } as any);
  if (!rp.ok) {
    const txt = await rp.text();
    throw new Error(`conn_patch_http_${rp.status}:${txt}`);
  }
}


function extractClientIdFromLog(ev: any): string | null {
  return (
    ev?.data?.client?.client_id ??
    ev?.details?.response?.body?.client_id ??
    ev?.client_id ??
    ev?.data?.client_id ??
    null
  );
}

function isDcrEvent(ev: any): boolean {
  const type = (ev?.type || "").toLowerCase();          // e.g., "sapi"
  const desc = (ev?.description || "").toLowerCase();   // e.g., "Dynamic client registration"
  const path = String(ev?.details?.request?.path || "").toLowerCase(); // e.g., "/oidc/register"
  const method = String(ev?.details?.request?.method || "").toUpperCase();

  return (
    // classic DCR log text
    (type === "sapi" && desc.includes("dynamic client registration")) ||
    // DCR hits the OIDC registration endpoint
    path.includes("/oidc/register") ||
    // some tenants log it as management "create client"
    (method === "POST" && path === "/api/v2/clients")
  );
}

function extractClientIdFromDcr(ev: any): string | null {
  return (
    ev?.details?.response?.body?.client_id ??     // common
    ev?.data?.client?.client_id ??                // sometimes present
    ev?.client_id ??                              // fallback fields
    ev?.data?.client_id ??
    null
  );
}


async function findNewestChatGPTClientId(mgmtToken: string): Promise<string | null> {
  const url = `https://${MGMT_DOMAIN}/api/v2/clients` +
    "?is_global=false&per_page=10&sort=created_at:-1&fields=client_id,name,created_at,app_type,grant_types,token_endpoint_auth_method&include_fields=true";
  const r = await fetch(url, { headers: { authorization: `Bearer ${mgmtToken}` } } as any);
  if (!r.ok) {
    const txt = await r.text();
    console.warn("[dcr] clients list failed", r.status, txt);
    return null;
  }
  const arr = (await r.json()) as Array<any>;
  const now = Date.now();
  for (const c of arr) {
    const name = String(c?.name || "");
    const createdAt = Date.parse(c?.created_at || "");
    const within5min = isFinite(createdAt) && (now - createdAt) < 5 * 60 * 1000;
    const looksLikeDcr = name.toLowerCase().startsWith("chatgpt") || name.toLowerCase().includes("chat gpt");
    const publicPkce = (c?.token_endpoint_auth_method === "none") &&
                       Array.isArray(c?.grant_types) &&
                       c.grant_types.includes("authorization_code");
    if (within5min && looksLikeDcr && publicPkce && c?.client_id) {
      return c.client_id as string;
    }
  }
  return null;
}

function unwrap(ev: any): any {
  // Auth0 Log Streams often send { data: <actual-log> }
  return (ev && typeof ev === "object" && ev.data && typeof ev.data === "object")
    ? ev.data
    : ev;
}

function evtPath(e: any): string {
  return String(
    e?.details?.request?.path ||
    e?.details?.request?.url ||
    e?.http?.request?.path ||
    ""
  ).toLowerCase();
}

function isDcrEventRaw(ev: any): boolean {
  const e = unwrap(ev);
  const type = String(e?.type || "").toLowerCase();               // e.g., "sapi"
  const desc = String(e?.description || "").toLowerCase();        // "dynamic client registration"
  const path = evtPath(e);
  const method = String(e?.details?.request?.method || e?.http?.method || "").toUpperCase();

  return (
    // classic text
    (type === "sapi" && desc.includes("dynamic client registration")) ||
    // OIDC DCR endpoint
    path.includes("/oidc/register") ||
    // some tenants log it as client creation via Mgmt API
    (method === "POST" && (path === "/api/v2/clients" || path.endsWith("/api/v2/clients")))
  );
}

function extractClientIdFromDcrRaw(ev: any): string | null {
  const e = unwrap(ev);
  return (
    e?.details?.response?.body?.client_id ??
    e?.client_id ??
    e?.details?.request?.body?.client_id ?? // rare
    null
  );
}


export async function auth0LogWebhook(req: Request, res: Response) {
  // Simple bearer secret check
  const auth = req.header("authorization") || "";
  if (auth !== `Bearer ${LOG_WEBHOOK_SECRET}`) {
    res.status(401).json({ ok: false, error: "unauthorized" });
    return;
  }

  // Not configured → advertise clearly (nice for OSS quickstarts)
  if (!MGMT_DOMAIN || !MGMT_CLIENT_ID || !MGMT_CLIENT_SECRET) {
    res.status(501).json({
      ok: false,
      error: "not_configured",
      detail: "Set MGMT_DOMAIN, MGMT_CLIENT_ID, MGMT_CLIENT_SECRET to enable DCR promotion."
    });
    return;
  }

  let parsed: unknown = req.body;
  if (typeof parsed === "string") {
    try { parsed = JSON.parse(parsed); } catch { /* ignore */ }
  }
  const events: any[] = Array.isArray(parsed) ? (parsed as any[]) : [parsed as any];


  // DEBUG: show shape after unwrap so we can see fields
  try {
    const sample = (events || []).slice(0, 3).map((ev: any) => {
      const e = unwrap(ev);
      return {
        type: e?.type,
        desc: e?.description,
        path: evtPath(e) || undefined,
        method: e?.details?.request?.method || e?.http?.method,
        hasRespClientId: !!e?.details?.response?.body?.client_id
      };
    });
    console.log("[webhook:sample]", sample);
  } catch { /* ignore */ }

  const dcrEvents = events.filter(isDcrEventRaw);

  if (dcrEvents.length === 0) {
    res.status(200).json({ ok: true, filtered: true });
    return;
  }

  try {
    const mgmtToken = await getMgmtToken();
    for (const raw of dcrEvents) {
      let cid = extractClientIdFromDcrRaw(raw);
      if (!cid) {
        console.warn("[dcr] no client_id in event; attempting fallback lookup");
        cid = await findNewestChatGPTClientId(mgmtToken); // keep this helper from earlier patch
      }
      if (!cid) {
        console.warn("[dcr] could not determine client_id; skipping event");
        continue;
      }

      console.log("[dcr] promoting client", { client_id: cid });

      try {
        await promoteClient(mgmtToken, cid);
      } catch (e: any) {
        const msg = String(e?.message || "");
        if (msg.startsWith("promote_http_404")) {
          console.warn("[dcr] 404 promoting client; retrying with fallback search");
          const alt = await findNewestChatGPTClientId(mgmtToken);
          if (alt && alt !== cid) {
            console.log("[dcr] retry promoting", { client_id: alt });
            await promoteClient(mgmtToken, alt);
            cid = alt;
          } else {
            throw e;
          }
        } else {
          throw e;
        }
      }

      await enableGoogleForClient(mgmtToken, cid);
      console.log("[dcr] promoted+enabled", { client_id: cid });
    }
    res.status(200).json({ ok: true, promoted: dcrEvents.length });
  } catch (e: any) {
    console.error("[dcr:error]", e?.message || e);
    res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
}
