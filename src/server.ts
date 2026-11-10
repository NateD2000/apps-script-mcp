// Apps Script MCP connector for claude.ai.
//
// A remote MCP server (Streamable HTTP, JSON responses) that lets Claude read and
// edit Google Apps Script projects through the Apps Script API.
//
// It is its own OAuth 2.1 authorization server for Claude (DCR + PKCE S256) and
// sends the user through Google sign-in behind the scenes. It is stateless: client
// ids, auth codes and tokens are AES-GCM sealed blobs, so no database is needed.
// Only the Google accounts in ALLOWED_EMAILS can finish sign-in.
//
// Environment:
//   GOOGLE_CLIENT_ID      (required) Google OAuth web client id
//   GOOGLE_CLIENT_SECRET  (required) Google OAuth web client secret
//   ALLOWED_EMAILS        (required) comma-separated Google accounts allowed to sign in
//   TOKEN_SECRET          (optional) sealing key material; defaults to GOOGLE_CLIENT_SECRET
//   PUBLIC_BASE_URL       (required) public URL of this service, no trailing slash, e.g.
//                         https://apps-script-mcp-123456789.us-central1.run.app
//   PORT                  (optional) port to listen on; Cloud Run sets it (main.ts reads it)
//   EXTRA_REDIRECT_URIS   (optional) comma-separated extra allowed OAuth redirect URIs
//   ENABLE_DRIVE_LISTING  (optional) "true" adds the list_script_projects tool. It needs Google's
//                         restricted drive.metadata.readonly scope, which unverified apps may be
//                         refused, so it is off by default.

export const FUNCTION_NAME = "apps-script-mcp";
const SERVER_VERSION = "1.0.0";
const SUPPORTED_PROTOCOLS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
const MCP_SCOPE = "apps_script";

const GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
const GOOGLE_REVOKE_URL = "https://oauth2.googleapis.com/revoke";
const GOOGLE_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo";
const SCRIPT_API = "https://script.googleapis.com/v1";
const DRIVE_API = "https://www.googleapis.com/drive/v3";

export const GOOGLE_SCOPES = [
  "openid",
  "email",
  "https://www.googleapis.com/auth/script.projects",
  "https://www.googleapis.com/auth/script.deployments",
  "https://www.googleapis.com/auth/script.processes",
];
const DRIVE_SCOPE = "https://www.googleapis.com/auth/drive.metadata.readonly";
const REQUIRED_GOOGLE_SCOPE = "https://www.googleapis.com/auth/script.projects";

const CLAUDE_CALLBACK = "https://claude.ai/api/mcp/auth_callback";
const TXN_TTL = 15 * 60; // seconds to finish Google sign-in
const CODE_TTL = 5 * 60; // auth code lifetime
const MAX_AT_TTL = 3600; // access token lifetime cap

// ---------------------------------------------------------------- config

export interface Config {
  baseUrl: string;
  mcpUrl: string;
  googleClientId: string;
  googleClientSecret: string;
  allowedEmails: string[];
  tokenSecret: string;
  extraRedirects: string[];
  driveListing?: boolean;
}

function env(name: string): string {
  return (Deno.env.get(name) ?? "").trim();
}

export function loadConfig(): Config | string {
  const googleClientId = env("GOOGLE_CLIENT_ID");
  const googleClientSecret = env("GOOGLE_CLIENT_SECRET");
  const allowedEmails = env("ALLOWED_EMAILS").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
  const missing = [
    !googleClientId && "GOOGLE_CLIENT_ID",
    !googleClientSecret && "GOOGLE_CLIENT_SECRET",
    !allowedEmails.length && "ALLOWED_EMAILS",
    !env("PUBLIC_BASE_URL") && "PUBLIC_BASE_URL",
  ].filter(Boolean);
  if (missing.length) return `Missing settings: ${missing.join(", ")}`;
  const baseUrl = env("PUBLIC_BASE_URL").replace(/\/+$/, "");
  return {
    baseUrl,
    mcpUrl: `${baseUrl}/mcp`,
    googleClientId,
    googleClientSecret,
    allowedEmails,
    tokenSecret: env("TOKEN_SECRET") || googleClientSecret,
    extraRedirects: env("EXTRA_REDIRECT_URIS").split(",").map((s) => s.trim()).filter(Boolean),
    driveListing: env("ENABLE_DRIVE_LISTING").toLowerCase() === "true",
  };
}

// ---------------------------------------------------------------- sealing

const enc = new TextEncoder();
const dec = new TextDecoder();
const keyCache = new Map<string, Promise<CryptoKey>>();

function sealKey(secret: string): Promise<CryptoKey> {
  let k = keyCache.get(secret);
  if (!k) {
    k = (async () => {
      const base = await crypto.subtle.importKey("raw", enc.encode(secret), "HKDF", false, ["deriveKey"]);
      return crypto.subtle.deriveKey(
        { name: "HKDF", hash: "SHA-256", salt: enc.encode("apps-script-mcp"), info: enc.encode("seal v1") },
        base,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"],
      );
    })();
    keyCache.set(secret, k);
  }
  return k;
}

export function b64url(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function unb64url(s: string): Uint8Array<ArrayBuffer> {
  const b = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
  const out = new Uint8Array(new ArrayBuffer(b.length));
  for (let i = 0; i < b.length; i++) out[i] = b.charCodeAt(i);
  return out;
}

const PREFIX: Record<string, string> = { client: "asc_", txn: "ast_", code: "asx_", at: "asa_", rt: "asr_" };

export async function seal(cfg: Config, purpose: string, data: Record<string, unknown>): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: enc.encode(purpose) },
      await sealKey(cfg.tokenSecret),
      enc.encode(JSON.stringify(data)),
    ),
  );
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv);
  out.set(ct, iv.length);
  return PREFIX[purpose] + b64url(out);
}

// deno-lint-ignore no-explicit-any
export async function unseal(cfg: Config, purpose: string, token: string | null | undefined): Promise<any | null> {
  if (!token || !token.startsWith(PREFIX[purpose])) return null;
  try {
    const raw = unb64url(token.slice(PREFIX[purpose].length));
    if (raw.length < 29) return null;
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: raw.subarray(0, 12), additionalData: enc.encode(purpose) },
      await sealKey(cfg.tokenSecret),
      raw.subarray(12),
    );
    return JSON.parse(dec.decode(pt));
  } catch {
    return null;
  }
}

const now = () => Math.floor(Date.now() / 1000);

// Outbound fetch for the OAuth calls; makeHandler swaps it in tests.
let httpFetch: typeof fetch = (input, init) => fetch(input, init);

async function sha256b64url(s: string): Promise<string> {
  return b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s))));
}

// ---------------------------------------------------------------- http helpers

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS, DELETE",
  "Access-Control-Allow-Headers": "Authorization, Content-Type, Mcp-Protocol-Version, Mcp-Session-Id",
  "Access-Control-Expose-Headers": "WWW-Authenticate, Mcp-Protocol-Version",
};

function json(body: unknown, status = 200, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...CORS, ...extra },
  });
}

function oauthError(error: string, description: string, status = 400): Response {
  return json({ error, error_description: description }, status);
}

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}

function page(title: string, bodyHtml: string, status = 200): Response {
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>${esc(title)}</title>
<style>body{font-family:system-ui,-apple-system,sans-serif;max-width:32rem;margin:3rem auto;padding:0 1rem;line-height:1.5;color:#1f2328;background:#fff}
h1{font-size:1.4rem}.btn{display:inline-block;background:#1a73e8;color:#fff;padding:.7rem 1.2rem;border-radius:.5rem;text-decoration:none;font-weight:600}
.warn{background:#fff4e5;border:1px solid #f0b46b;padding:.7rem;border-radius:.5rem}code{background:#f3f4f6;padding:0 .25rem;border-radius:.25rem}
@media (prefers-color-scheme:dark){body{background:#111;color:#e6e6e6}code{background:#2a2a2a}.warn{background:#3a2a10;border-color:#8a5a20}}</style>
</head><body><h1>${esc(title)}</h1>${bodyHtml}</body></html>`;
  return new Response(html, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Frame-Options": "DENY",
      "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
      "Referrer-Policy": "no-referrer",
    },
  });
}

async function readParams(req: Request): Promise<URLSearchParams> {
  const ct = (req.headers.get("content-type") ?? "").toLowerCase();
  const text = await req.text();
  if (ct.includes("application/json")) {
    try {
      const o = JSON.parse(text);
      const p = new URLSearchParams();
      for (const [k, v] of Object.entries(o ?? {})) if (v != null) p.set(k, String(v));
      return p;
    } catch {
      return new URLSearchParams();
    }
  }
  return new URLSearchParams(text);
}

// ---------------------------------------------------------------- redirect rules

function isLoopback(u: URL): boolean {
  return u.protocol === "http:" && (u.hostname === "localhost" || u.hostname === "127.0.0.1" || u.hostname === "[::1]");
}

function redirectAllowedForRegistration(cfg: Config, uri: string): boolean {
  if (uri === CLAUDE_CALLBACK || cfg.extraRedirects.includes(uri)) return true;
  try {
    const u = new URL(uri);
    return isLoopback(u) && !u.username && !u.password && !u.hash;
  } catch {
    return false;
  }
}

// RFC 8252: loopback redirects match regardless of port.
function redirectMatches(registered: string[], uri: string): boolean {
  if (registered.includes(uri)) return true;
  let u: URL;
  try {
    u = new URL(uri);
  } catch {
    return false;
  }
  if (!isLoopback(u)) return false;
  return registered.some((r) => {
    try {
      const v = new URL(r);
      return isLoopback(v) && v.hostname === u.hostname && v.pathname === u.pathname && v.search === u.search;
    } catch {
      return false;
    }
  });
}

// ---------------------------------------------------------------- metadata

function protectedResourceMetadata(cfg: Config) {
  return {
    resource: cfg.mcpUrl,
    authorization_servers: [cfg.baseUrl],
    scopes_supported: [MCP_SCOPE],
    bearer_methods_supported: ["header"],
    resource_name: "Apps Script",
  };
}

function authServerMetadata(cfg: Config) {
  return {
    issuer: cfg.baseUrl,
    authorization_endpoint: `${cfg.baseUrl}/authorize`,
    token_endpoint: `${cfg.baseUrl}/token`,
    registration_endpoint: `${cfg.baseUrl}/register`,
    revocation_endpoint: `${cfg.baseUrl}/revoke`,
    jwks_uri: `${cfg.baseUrl}/jwks`,
    scopes_supported: [MCP_SCOPE, "offline_access"],
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    token_endpoint_auth_methods_supported: ["none", "client_secret_post", "client_secret_basic"],
    revocation_endpoint_auth_methods_supported: ["none"],
    code_challenge_methods_supported: ["S256"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    client_id_metadata_document_supported: false,
  };
}

function prmUrl(cfg: Config) {
  return `${cfg.baseUrl}/.well-known/oauth-protected-resource`;
}

function unauthorized(cfg: Config, error?: string, description?: string): Response {
  let h = `Bearer resource_metadata="${prmUrl(cfg)}", scope="${MCP_SCOPE}"`;
  if (error) h += `, error="${error}"`;
  if (description) h += `, error_description="${description.replace(/"/g, "'")}"`;
  return json(
    { jsonrpc: "2.0", id: null, error: { code: -32001, message: description ?? "Authorization required" } },
    401,
    { "WWW-Authenticate": h },
  );
}

// ---------------------------------------------------------------- OAuth endpoints

async function handleRegister(cfg: Config, req: Request): Promise<Response> {
  // deno-lint-ignore no-explicit-any
  let body: any;
  try {
    body = await req.json();
  } catch {
    return oauthError("invalid_client_metadata", "Body must be JSON");
  }
  const uris: unknown = body?.redirect_uris;
  if (!Array.isArray(uris) || !uris.length || uris.length > 10 || uris.some((u) => typeof u !== "string")) {
    return oauthError("invalid_redirect_uri", "redirect_uris must be a non-empty list of strings");
  }
  const bad = (uris as string[]).filter((u) => !redirectAllowedForRegistration(cfg, u));
  if (bad.length) return oauthError("invalid_redirect_uri", `Redirect URI not allowed: ${bad.join(", ")}`);
  const name = typeof body.client_name === "string" ? body.client_name.slice(0, 80) : "MCP client";
  const iat = now();
  const clientId = await seal(cfg, "client", { ru: uris, n: name, iat });
  return json(
    {
      client_id: clientId,
      client_id_issued_at: iat,
      client_name: name,
      redirect_uris: uris,
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
      scope: MCP_SCOPE,
    },
    201,
  );
}

function clientLabel(redirect: string): { host: string; local: boolean } {
  try {
    const u = new URL(redirect);
    return { host: u.host, local: isLoopback(u) };
  } catch {
    return { host: redirect, local: false };
  }
}

async function handleAuthorize(cfg: Config, url: URL): Promise<Response> {
  const p = url.searchParams;
  const client = await unseal(cfg, "client", p.get("client_id"));
  if (!client) {
    return page("Sign-in failed", "<p>Unknown client. Remove the connector in Claude and add it again.</p>", 400);
  }
  const redirectUri = p.get("redirect_uri") ?? (client.ru.length === 1 ? client.ru[0] : "");
  if (!redirectMatches(client.ru, redirectUri)) {
    return page("Sign-in failed", "<p>The redirect address doesn't match this client.</p>", 400);
  }
  const state = p.get("state");
  const back = (error: string, desc: string) => {
    const r = new URL(redirectUri);
    r.searchParams.set("error", error);
    r.searchParams.set("error_description", desc);
    if (state != null) r.searchParams.set("state", state);
    r.searchParams.set("iss", cfg.baseUrl);
    return Response.redirect(r.toString(), 302);
  };
  if (p.get("response_type") !== "code") {
    return back("unsupported_response_type", "Only response_type=code is supported");
  }
  const cc = p.get("code_challenge");
  if (!cc || (p.get("code_challenge_method") ?? "plain") !== "S256" || !/^[A-Za-z0-9_-]{43,128}$/.test(cc)) {
    return back("invalid_request", "PKCE with S256 is required");
  }
  const resource = p.get("resource");
  if (resource && resource.replace(/\/+$/, "") !== cfg.mcpUrl && resource.replace(/\/+$/, "") !== cfg.baseUrl) {
    return back("invalid_target", "Unknown resource");
  }
  const txn = await seal(cfg, "txn", { cid: p.get("client_id"), ru: redirectUri, cc, st: state, exp: now() + TXN_TTL });
  const g = new URL(GOOGLE_AUTH_URL);
  g.searchParams.set("client_id", cfg.googleClientId);
  g.searchParams.set("redirect_uri", `${cfg.baseUrl}/oauth/google/callback`);
  g.searchParams.set("response_type", "code");
  g.searchParams.set("scope", [...GOOGLE_SCOPES, ...(cfg.driveListing ? [DRIVE_SCOPE] : [])].join(" "));
  g.searchParams.set("access_type", "offline");
  g.searchParams.set("prompt", "consent");
  g.searchParams.set("include_granted_scopes", "true");
  if (cfg.allowedEmails.length === 1) g.searchParams.set("login_hint", cfg.allowedEmails[0]);
  g.searchParams.set("state", txn);

  const { host, local } = clientLabel(redirectUri);
  const warn = local
    ? `<p class="warn">This request will return to a program on this computer (<code>${
      esc(host)
    }</code>). Continue only if you just started it, for example in Claude Code.</p>`
    : "";
  return page(
    "Connect Apps Script",
    `<p><strong>${
      esc(client.n)
    }</strong> wants to read and edit your Google Apps Script projects. You'll be sent back to <code>${
      esc(host)
    }</code> when you're done.</p>${warn}
<p>Next, Google asks you to sign in and approve access. Leave every box ticked.</p>
<p><a class="btn" href="${esc(g.toString())}">Continue to Google</a></p>`,
  );
}

async function googleToken(cfg: Config, params: Record<string, string>) {
  const res = await httpFetch(GOOGLE_TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ client_id: cfg.googleClientId, client_secret: cfg.googleClientSecret, ...params }),
  });
  // deno-lint-ignore no-explicit-any
  const body: any = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, body };
}

async function revokeGoogle(token: string) {
  await httpFetch(GOOGLE_REVOKE_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ token }),
  }).catch(() => {});
}

async function handleGoogleCallback(cfg: Config, url: URL): Promise<Response> {
  const p = url.searchParams;
  const txn = await unseal(cfg, "txn", p.get("state"));
  if (!txn || txn.exp < now()) {
    return page(
      "Sign-in expired",
      "<p>This sign-in took too long or was already used. Go back to Claude and connect again.</p>",
      400,
    );
  }
  const back = (params: Record<string, string>) => {
    const r = new URL(txn.ru);
    for (const [k, v] of Object.entries(params)) r.searchParams.set(k, v);
    if (txn.st != null) r.searchParams.set("state", txn.st);
    r.searchParams.set("iss", cfg.baseUrl);
    return Response.redirect(r.toString(), 302);
  };
  if (p.get("error")) return back({ error: "access_denied", error_description: `Google sign-in: ${p.get("error")}` });
  const code = p.get("code");
  if (!code) return back({ error: "invalid_request", error_description: "Google returned no code" });

  const t = await googleToken(cfg, {
    grant_type: "authorization_code",
    code,
    redirect_uri: `${cfg.baseUrl}/oauth/google/callback`,
  });
  if (!t.ok || !t.body.access_token) {
    return page(
      "Sign-in failed",
      `<p>Google didn't accept the sign-in (${
        esc(String(t.body.error ?? t.status))
      }). Go back to Claude and try again.</p>`,
      502,
    );
  }
  const gat: string = t.body.access_token;
  const grt: string | undefined = t.body.refresh_token;

  const ui = await httpFetch(GOOGLE_USERINFO_URL, { headers: { Authorization: `Bearer ${gat}` } });
  // deno-lint-ignore no-explicit-any
  const info: any = await ui.json().catch(() => ({}));
  const email = String(info.email ?? "").toLowerCase();
  if (!ui.ok || !email || info.email_verified === false || !cfg.allowedEmails.includes(email)) {
    await revokeGoogle(grt ?? gat);
    return page(
      "Account not allowed",
      `<p>This connector only works for its owner's Google account. You signed in as <code>${
        esc(email || "unknown")
      }</code>.</p><p>Go back to Claude and connect again with the right account.</p>`,
      403,
    );
  }
  const granted = String(t.body.scope ?? "").split(" ");
  if (!granted.includes(REQUIRED_GOOGLE_SCOPE)) {
    await revokeGoogle(grt ?? gat);
    return page(
      "Access not granted",
      "<p>Google didn't grant access to your Apps Script projects. Go back to Claude, connect again, and leave every box ticked on Google's screen.</p>",
      403,
    );
  }
  if (!grt) {
    return page(
      "Sign-in failed",
      "<p>Google didn't return a long-lived sign-in. Go back to Claude and connect again.</p>",
      502,
    );
  }
  const ourCode = await seal(cfg, "code", {
    cid: txn.cid,
    ru: txn.ru,
    cc: txn.cc,
    gat,
    gexp: now() + Number(t.body.expires_in ?? 3600),
    grt,
    email,
    scope: granted.join(" "),
    exp: now() + CODE_TTL,
  });
  return back({ code: ourCode });
}

async function issueTokens(
  cfg: Config,
  d: { gat: string; gexp: number; grt: string; email: string; cid: string; scope: string },
) {
  const exp = Math.min(d.gexp - 60, now() + MAX_AT_TTL);
  const accessToken = await seal(cfg, "at", { gat: d.gat, email: d.email, cid: d.cid, exp });
  const refreshToken = await seal(cfg, "rt", { grt: d.grt, email: d.email, cid: d.cid, scope: d.scope, iat: now() });
  return json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: Math.max(60, exp - now()),
    refresh_token: refreshToken,
    scope: `${MCP_SCOPE} offline_access`,
  });
}

function clientIdFrom(req: Request, p: URLSearchParams): string | null {
  const basic = req.headers.get("authorization");
  if (basic?.toLowerCase().startsWith("basic ")) {
    try {
      const [id] = atob(basic.slice(6).trim()).split(":");
      return decodeURIComponent(id);
    } catch {
      return null;
    }
  }
  return p.get("client_id");
}

async function handleToken(cfg: Config, req: Request): Promise<Response> {
  const p = await readParams(req);
  const clientId = clientIdFrom(req, p);
  const grant = p.get("grant_type");

  if (grant === "authorization_code") {
    const c = await unseal(cfg, "code", p.get("code"));
    if (!c || c.exp < now()) return oauthError("invalid_grant", "Code is invalid or expired");
    if (clientId && clientId !== c.cid) return oauthError("invalid_grant", "Code was issued to another client");
    if (p.get("redirect_uri") && p.get("redirect_uri") !== c.ru) {
      return oauthError("invalid_grant", "redirect_uri mismatch");
    }
    const verifier = p.get("code_verifier");
    if (!verifier || (await sha256b64url(verifier)) !== c.cc) {
      return oauthError("invalid_grant", "PKCE verification failed");
    }
    return issueTokens(cfg, c);
  }

  if (grant === "refresh_token") {
    const r = await unseal(cfg, "rt", p.get("refresh_token"));
    if (!r) return oauthError("invalid_grant", "Refresh token is invalid");
    if (clientId && clientId !== r.cid) {
      return oauthError("invalid_grant", "Refresh token was issued to another client");
    }
    if (!cfg.allowedEmails.includes(r.email)) return oauthError("invalid_grant", "Account no longer allowed");
    const t = await googleToken(cfg, { grant_type: "refresh_token", refresh_token: r.grt });
    if (!t.ok || !t.body.access_token) {
      const e = String(t.body.error ?? "");
      if (e === "invalid_grant" || t.status === 400 || t.status === 401) {
        return oauthError("invalid_grant", "Google sign-in expired or was revoked; reconnect the connector");
      }
      return oauthError("temporarily_unavailable", "Google token refresh failed", 503);
    }
    return issueTokens(cfg, {
      gat: t.body.access_token,
      gexp: now() + Number(t.body.expires_in ?? 3600),
      grt: t.body.refresh_token ?? r.grt,
      email: r.email,
      cid: r.cid,
      scope: r.scope,
    });
  }

  return oauthError("unsupported_grant_type", "Use authorization_code or refresh_token");
}

async function handleRevoke(cfg: Config, req: Request): Promise<Response> {
  const p = await readParams(req);
  const tok = p.get("token") ?? "";
  const r = await unseal(cfg, "rt", tok);
  if (r?.grt) await revokeGoogle(r.grt);
  const a = await unseal(cfg, "at", tok);
  if (a?.gat) await revokeGoogle(a.gat);
  return new Response(null, { status: 200, headers: { ...CORS, "Cache-Control": "no-store" } });
}

// ---------------------------------------------------------------- Google API client

export class GoogleAuthError extends Error {}

export class GoogleApi {
  constructor(private token: string, private fetchFn: typeof fetch = fetch) {}

  // deno-lint-ignore no-explicit-any
  async call(method: string, url: string, body?: unknown): Promise<any> {
    const res = await this.fetchFn(url, {
      method,
      headers: {
        Authorization: `Bearer ${this.token}`,
        ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const text = await res.text();
    // deno-lint-ignore no-explicit-any
    let data: any = {};
    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      data = { raw: text };
    }
    if (res.status === 401) throw new GoogleAuthError("Google sign-in expired");
    if (!res.ok) {
      const msg: string = data?.error?.message ?? data?.raw ?? `HTTP ${res.status}`;
      if (res.status === 403 && /Apps Script API/i.test(msg) && /enable|disabled|not been used/i.test(msg)) {
        throw new Error(
          "The Apps Script API is turned off for this Google account. Turn it on at https://script.google.com/home/usersettings and try again.",
        );
      }
      if (res.status === 403 && /has not been used in project|is disabled/i.test(msg)) {
        throw new Error(`An API is not enabled in the connector's Google Cloud project: ${msg}`);
      }
      throw new Error(`Google API error ${res.status}: ${msg}`);
    }
    return data;
  }
}

// ---------------------------------------------------------------- tools

type Args = Record<string, unknown>;
// deno-lint-ignore no-explicit-any
type ScriptFile = { name: string; type: string; source: string; [k: string]: any };

const FILE_TYPES = ["SERVER_JS", "HTML", "JSON"];

function str(a: Args, k: string, required = true): string {
  const v = a[k];
  if (v === undefined || v === null || v === "") {
    if (required) throw new Error(`Missing argument: ${k}`);
    return "";
  }
  if (typeof v !== "string") throw new Error(`Argument ${k} must be a string`);
  return v;
}

function int(a: Args, k: string): number | undefined {
  const v = a[k];
  if (v === undefined || v === null || v === "") return undefined;
  const n = Number(v);
  if (!Number.isInteger(n) || n < 0) throw new Error(`Argument ${k} must be a whole number`);
  return n;
}

function scriptId(a: Args): string {
  const id = str(a, "script_id").trim();
  // Accept a full editor URL too.
  const m = id.match(/\/(?:projects|d)\/([A-Za-z0-9_-]{20,})/);
  const out = m ? m[1] : id;
  if (!/^[A-Za-z0-9_-]{20,}$/.test(out)) throw new Error("script_id doesn't look like an Apps Script id");
  return out;
}

function normalizeName(name: string): string {
  return name.replace(/\.(gs|js|html|json)$/i, "");
}

function findFile(files: ScriptFile[], name: string): ScriptFile | undefined {
  const n = normalizeName(name);
  return files.find((f) => f.name === n) ?? files.find((f) => f.name.toLowerCase() === n.toLowerCase());
}

function ext(f: ScriptFile): string {
  return f.type === "HTML" ? ".html" : f.type === "JSON" ? ".json" : ".gs";
}

async function getFiles(api: GoogleApi, id: string, version?: number): Promise<ScriptFile[]> {
  const q = version ? `?versionNumber=${version}` : "";
  const data = await api.call("GET", `${SCRIPT_API}/projects/${encodeURIComponent(id)}/content${q}`);
  return (data.files ?? []) as ScriptFile[];
}

async function putFiles(api: GoogleApi, id: string, files: ScriptFile[]): Promise<ScriptFile[]> {
  const clean = files.map((f) => ({ name: f.name, type: f.type, source: f.source ?? "" }));
  const data = await api.call("PUT", `${SCRIPT_API}/projects/${encodeURIComponent(id)}/content`, {
    scriptId: id,
    files: clean,
  });
  return (data.files ?? clean) as ScriptFile[];
}

async function maybeSnapshot(api: GoogleApi, id: string, a: Args, what: string): Promise<string> {
  if (a.create_version_first !== true) return "";
  const v = await api.call("POST", `${SCRIPT_API}/projects/${encodeURIComponent(id)}/versions`, {
    description: `Before Claude edit: ${what}`.slice(0, 200),
  });
  return ` Saved the previous code as version ${v.versionNumber} first.`;
}

function lines(s: string): number {
  return s ? s.split("\n").length : 0;
}

export interface ToolDef {
  name: string;
  title: string;
  description: string;
  inputSchema: Record<string, unknown>;
  annotations: Record<string, unknown>;
  run: (api: GoogleApi, a: Args) => Promise<string>;
}

const SCRIPT_ID_PROP = {
  type: "string",
  description:
    "Apps Script project id (from the editor URL, script.google.com/d/<id>/edit). A full editor URL also works.",
};
const VERSION_FIRST_PROP = {
  type: "boolean",
  description:
    "Save the current code as a new numbered version before changing it, so it can be restored. Default false.",
};
const LIVE_NOTE =
  " Changes save to the project's current code right away, the same as pressing Save in the editor. Triggers and test deployments use the new code on their next run; versioned deployments don't change until updated.";

export const TOOLS: ToolDef[] = [
  {
    name: "list_script_projects",
    title: "List Apps Script projects",
    description:
      "List standalone Apps Script projects in the user's Google Drive, newest first. Scripts bound to a Sheet, Doc or Form don't appear here; open them by id instead.",
    inputSchema: {
      type: "object",
      properties: {
        name_contains: { type: "string", description: "Only projects whose name contains this text." },
        page_size: { type: "integer", minimum: 1, maximum: 100, description: "Default 25." },
        page_token: { type: "string", description: "nextPageToken from an earlier call." },
      },
    },
    annotations: { readOnlyHint: true, openWorldHint: false },
    run: async (api, a) => {
      let q = "mimeType='application/vnd.google-apps.script' and trashed=false";
      const nc = str(a, "name_contains", false);
      if (nc) q += ` and name contains '${nc.replace(/\\/g, "\\\\").replace(/'/g, "\\'")}'`;
      const u = new URL(`${DRIVE_API}/files`);
      u.searchParams.set("q", q);
      u.searchParams.set("orderBy", "modifiedTime desc");
      u.searchParams.set("pageSize", String(Math.min(int(a, "page_size") ?? 25, 100)));
      u.searchParams.set("fields", "nextPageToken,files(id,name,modifiedTime,owners(emailAddress))");
      u.searchParams.set("supportsAllDrives", "true");
      u.searchParams.set("includeItemsFromAllDrives", "true");
      const pt = str(a, "page_token", false);
      if (pt) u.searchParams.set("pageToken", pt);
      const d = await api.call("GET", u.toString());
      // deno-lint-ignore no-explicit-any
      const files = (d.files ?? []).map((f: any) => ({
        script_id: f.id,
        name: f.name,
        modified: f.modifiedTime,
        owner: f.owners?.[0]?.emailAddress,
        editor_url: `https://script.google.com/d/${f.id}/edit`,
      }));
      return JSON.stringify({ projects: files, next_page_token: d.nextPageToken ?? null }, null, 2);
    },
  },
  {
    name: "get_project",
    title: "Get project details",
    description: "Get an Apps Script project's title, parent file (for bound scripts), and create and update times.",
    inputSchema: { type: "object", properties: { script_id: SCRIPT_ID_PROP }, required: ["script_id"] },
    annotations: { readOnlyHint: true, openWorldHint: false },
    run: async (api, a) => {
      const id = scriptId(a);
      const d = await api.call("GET", `${SCRIPT_API}/projects/${encodeURIComponent(id)}`);
      return JSON.stringify(
        {
          script_id: d.scriptId,
          title: d.title,
          parent_id: d.parentId ?? null,
          created: d.createTime,
          updated: d.updateTime,
          creator: d.creator?.email,
          last_modified_by: d.lastModifyUser?.email,
          editor_url: `https://script.google.com/d/${d.scriptId}/edit`,
        },
        null,
        2,
      );
    },
  },
  {
    name: "get_project_content",
    title: "Read project code",
    description:
      "Read the code of an Apps Script project: every file, or one file by name. Reads the current saved code unless version_number is given.",
    inputSchema: {
      type: "object",
      properties: {
        script_id: SCRIPT_ID_PROP,
        file_name: {
          type: "string",
          description: "One file to read, for example Code or Code.gs. Omit for all files.",
        },
        version_number: {
          type: "integer",
          minimum: 1,
          description: "Read a saved version instead of the current code.",
        },
        list_only: { type: "boolean", description: "Only list file names, types and sizes." },
      },
      required: ["script_id"],
    },
    annotations: { readOnlyHint: true, openWorldHint: false },
    run: async (api, a) => {
      const id = scriptId(a);
      let files = await getFiles(api, id, int(a, "version_number"));
      const fn = str(a, "file_name", false);
      if (fn) {
        const f = findFile(files, fn);
        if (!f) throw new Error(`No file named ${fn}. Files: ${files.map((x) => x.name + ext(x)).join(", ")}`);
        files = [f];
      }
      if (a.list_only === true) {
        return JSON.stringify(
          files.map((f) => ({
            name: f.name + ext(f),
            type: f.type,
            lines: lines(f.source ?? ""),
            chars: (f.source ?? "").length,
          })),
          null,
          2,
        );
      }
      return files
        .map((f) => `===== ${f.name}${ext(f)} (${f.type}, ${lines(f.source ?? "")} lines) =====\n${f.source ?? ""}`)
        .join("\n\n");
    },
  },
  {
    name: "edit_file",
    title: "Edit code in a file",
    description:
      "Replace an exact piece of text in one file of an Apps Script project. old_string must match exactly once (including spaces and line breaks) unless replace_all is true. Best for small, targeted fixes." +
      LIVE_NOTE,
    inputSchema: {
      type: "object",
      properties: {
        script_id: SCRIPT_ID_PROP,
        file_name: { type: "string", description: "File to edit, for example Code or Code.gs." },
        old_string: { type: "string", description: "Exact text to find." },
        new_string: { type: "string", description: "Text to put in its place." },
        replace_all: { type: "boolean", description: "Replace every match instead of requiring exactly one." },
        create_version_first: VERSION_FIRST_PROP,
      },
      required: ["script_id", "file_name", "old_string", "new_string"],
    },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
    run: async (api, a) => {
      const id = scriptId(a);
      const fn = str(a, "file_name");
      const oldS = str(a, "old_string");
      const newS = typeof a.new_string === "string" ? a.new_string : "";
      if (oldS === newS) throw new Error("old_string and new_string are the same");
      const files = await getFiles(api, id);
      const f = findFile(files, fn);
      if (!f) throw new Error(`No file named ${fn}. Files: ${files.map((x) => x.name + ext(x)).join(", ")}`);
      const src = f.source ?? "";
      const count = src.split(oldS).length - 1;
      if (count === 0) throw new Error(`old_string was not found in ${f.name}${ext(f)}. Nothing changed.`);
      if (count > 1 && a.replace_all !== true) {
        throw new Error(
          `old_string matches ${count} places in ${f.name}${
            ext(f)
          }. Add more surrounding text, or set replace_all. Nothing changed.`,
        );
      }
      const snap = await maybeSnapshot(api, id, a, `edit ${f.name}`);
      f.source = a.replace_all === true ? src.split(oldS).join(newS) : src.replace(oldS, () => newS);
      await putFiles(api, id, files);
      return `Saved ${f.name}${ext(f)}: replaced ${a.replace_all === true ? count : 1} match${
        count > 1 && a.replace_all === true ? "es" : ""
      }. It now has ${lines(f.source)} lines.${snap}`;
    },
  },
  {
    name: "write_file",
    title: "Create or replace a file",
    description:
      "Create a file, or replace a whole file's code, in an Apps Script project. Other files stay as they are. Use edit_file for small changes." +
      LIVE_NOTE,
    inputSchema: {
      type: "object",
      properties: {
        script_id: SCRIPT_ID_PROP,
        file_name: {
          type: "string",
          description: "File name, for example Code, Utils.gs or Sidebar.html. The manifest is appsscript.",
        },
        source: { type: "string", description: "The file's full new content." },
        type: {
          type: "string",
          enum: FILE_TYPES,
          description: "SERVER_JS (default for new files), HTML, or JSON (manifest only).",
        },
        create_version_first: VERSION_FIRST_PROP,
      },
      required: ["script_id", "file_name", "source"],
    },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
    run: async (api, a) => {
      const id = scriptId(a);
      const fn = str(a, "file_name");
      const source = typeof a.source === "string" ? a.source : "";
      const type = str(a, "type", false);
      if (type && !FILE_TYPES.includes(type)) throw new Error(`type must be one of ${FILE_TYPES.join(", ")}`);
      const files = await getFiles(api, id);
      const f = findFile(files, fn);
      if (f?.type === "JSON" || normalizeName(fn) === "appsscript") {
        try {
          JSON.parse(source);
        } catch {
          throw new Error("The manifest (appsscript.json) must be valid JSON. Nothing changed.");
        }
      }
      const snap = await maybeSnapshot(api, id, a, `write ${normalizeName(fn)}`);
      let verb: string;
      if (f) {
        if (type && type !== f.type) throw new Error(`${f.name} is ${f.type}; can't change its type. Nothing changed.`);
        f.source = source;
        verb = "Replaced";
      } else {
        const t = type || (/\.html$/i.test(fn) ? "HTML" : "SERVER_JS");
        if (t === "JSON") throw new Error("Only the appsscript manifest can be JSON. Nothing changed.");
        files.push({ name: normalizeName(fn), type: t, source });
        verb = "Created";
      }
      await putFiles(api, id, files);
      const saved = findFile(files, fn)!;
      return `${verb} ${saved.name}${ext(saved)} (${lines(source)} lines).${snap}`;
    },
  },
  {
    name: "delete_file",
    title: "Delete a file",
    description: "Delete one file from an Apps Script project. The appsscript manifest can't be deleted." + LIVE_NOTE,
    inputSchema: {
      type: "object",
      properties: {
        script_id: SCRIPT_ID_PROP,
        file_name: { type: "string" },
        create_version_first: VERSION_FIRST_PROP,
      },
      required: ["script_id", "file_name"],
    },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
    run: async (api, a) => {
      const id = scriptId(a);
      const fn = str(a, "file_name");
      const files = await getFiles(api, id);
      const f = findFile(files, fn);
      if (!f) throw new Error(`No file named ${fn}.`);
      if (f.type === "JSON") throw new Error("The appsscript manifest can't be deleted.");
      const snap = await maybeSnapshot(api, id, a, `delete ${f.name}`);
      await putFiles(api, id, files.filter((x) => x !== f));
      return `Deleted ${f.name}${ext(f)}.${snap}`;
    },
  },
  {
    name: "create_project",
    title: "Create a project",
    description:
      "Create a new Apps Script project with a starter Code.gs and manifest. Give parent_id (a Sheet, Doc, Slides or Form id) to bind it to that file.",
    inputSchema: {
      type: "object",
      properties: {
        title: { type: "string" },
        parent_id: { type: "string", description: "Optional Drive file id to bind to." },
      },
      required: ["title"],
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    run: async (api, a) => {
      const body: Record<string, string> = { title: str(a, "title") };
      const parent = str(a, "parent_id", false);
      if (parent) body.parentId = parent;
      const d = await api.call("POST", `${SCRIPT_API}/projects`, body);
      return JSON.stringify(
        {
          script_id: d.scriptId,
          title: d.title,
          parent_id: d.parentId ?? null,
          editor_url: `https://script.google.com/d/${d.scriptId}/edit`,
        },
        null,
        2,
      );
    },
  },
  {
    name: "list_versions",
    title: "List saved versions",
    description: "List an Apps Script project's numbered versions (saved snapshots), newest first.",
    inputSchema: {
      type: "object",
      properties: { script_id: SCRIPT_ID_PROP, page_token: { type: "string" } },
      required: ["script_id"],
    },
    annotations: { readOnlyHint: true, openWorldHint: false },
    run: async (api, a) => {
      const id = scriptId(a);
      const u = new URL(`${SCRIPT_API}/projects/${encodeURIComponent(id)}/versions`);
      u.searchParams.set("pageSize", "50");
      const pt = str(a, "page_token", false);
      if (pt) u.searchParams.set("pageToken", pt);
      const d = await api.call("GET", u.toString());
      // deno-lint-ignore no-explicit-any
      const versions = (d.versions ?? []).map((v: any) => ({
        version: v.versionNumber,
        description: v.description ?? "",
        created: v.createTime,
      }));
      versions.sort((x: { version: number }, y: { version: number }) => y.version - x.version);
      return JSON.stringify({ versions, next_page_token: d.nextPageToken ?? null }, null, 2);
    },
  },
  {
    name: "create_version",
    title: "Save a version",
    description:
      "Save the project's current code as a new numbered version (a snapshot that can be read or deployed later).",
    inputSchema: {
      type: "object",
      properties: { script_id: SCRIPT_ID_PROP, description: { type: "string" } },
      required: ["script_id"],
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    run: async (api, a) => {
      const id = scriptId(a);
      const d = await api.call("POST", `${SCRIPT_API}/projects/${encodeURIComponent(id)}/versions`, {
        description: str(a, "description", false),
      });
      return `Saved version ${d.versionNumber}.`;
    },
  },
  {
    name: "restore_version",
    title: "Restore a saved version",
    description: "Put a saved version's code back as the project's current code, replacing all current files." +
      LIVE_NOTE,
    inputSchema: {
      type: "object",
      properties: {
        script_id: SCRIPT_ID_PROP,
        version_number: { type: "integer", minimum: 1 },
        create_version_first: VERSION_FIRST_PROP,
      },
      required: ["script_id", "version_number"],
    },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
    run: async (api, a) => {
      const id = scriptId(a);
      const v = int(a, "version_number");
      if (!v) throw new Error("Missing argument: version_number");
      const files = await getFiles(api, id, v);
      if (!files.length) throw new Error(`Version ${v} has no files.`);
      const snap = await maybeSnapshot(api, id, a, `restore version ${v}`);
      await putFiles(api, id, files);
      return `Restored version ${v} (${files.length} files) as the current code.${snap}`;
    },
  },
  {
    name: "list_deployments",
    title: "List deployments",
    description:
      "List an Apps Script project's deployments (web apps, API executables, add-ons) and the version each one runs.",
    inputSchema: { type: "object", properties: { script_id: SCRIPT_ID_PROP }, required: ["script_id"] },
    annotations: { readOnlyHint: true, openWorldHint: false },
    run: async (api, a) => {
      const id = scriptId(a);
      const d = await api.call("GET", `${SCRIPT_API}/projects/${encodeURIComponent(id)}/deployments?pageSize=50`);
      // deno-lint-ignore no-explicit-any
      const deployments = (d.deployments ?? []).map((x: any) => ({
        deployment_id: x.deploymentId,
        version: x.deploymentConfig?.versionNumber ?? "HEAD (current code)",
        description: x.deploymentConfig?.description ?? "",
        updated: x.updateTime,
        // deno-lint-ignore no-explicit-any
        entry_points: (x.entryPoints ?? []).map((e: any) => ({
          type: e.entryPointType,
          url: e.webApp?.url ?? e.executionApi?.entryPointConfig?.access ?? undefined,
        })),
      }));
      return JSON.stringify({ deployments }, null, 2);
    },
  },
  {
    name: "create_deployment",
    title: "Create a deployment",
    description: "Create a new deployment of a saved version. Create the version first with create_version.",
    inputSchema: {
      type: "object",
      properties: {
        script_id: SCRIPT_ID_PROP,
        version_number: { type: "integer", minimum: 1 },
        description: { type: "string" },
      },
      required: ["script_id", "version_number"],
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    run: async (api, a) => {
      const id = scriptId(a);
      const d = await api.call("POST", `${SCRIPT_API}/projects/${encodeURIComponent(id)}/deployments`, {
        versionNumber: int(a, "version_number"),
        manifestFileName: "appsscript",
        description: str(a, "description", false),
      });
      return `Created deployment ${d.deploymentId} running version ${d.deploymentConfig?.versionNumber}.`;
    },
  },
  {
    name: "update_deployment",
    title: "Update a deployment",
    description:
      "Point an existing deployment (for example a web app) at another saved version. Its URL stays the same, and users get the new version right away.",
    inputSchema: {
      type: "object",
      properties: {
        script_id: SCRIPT_ID_PROP,
        deployment_id: { type: "string" },
        version_number: { type: "integer", minimum: 1 },
        description: { type: "string" },
      },
      required: ["script_id", "deployment_id", "version_number"],
    },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
    run: async (api, a) => {
      const id = scriptId(a);
      const dep = str(a, "deployment_id");
      const d = await api.call(
        "PUT",
        `${SCRIPT_API}/projects/${encodeURIComponent(id)}/deployments/${encodeURIComponent(dep)}`,
        {
          deploymentConfig: {
            scriptId: id,
            versionNumber: int(a, "version_number"),
            manifestFileName: "appsscript",
            description: str(a, "description", false),
          },
        },
      );
      return `Deployment ${d.deploymentId} now runs version ${d.deploymentConfig?.versionNumber}.`;
    },
  },
  {
    name: "list_executions",
    title: "List recent runs",
    description:
      "List recent runs of a project's functions (from triggers, the editor, web apps and so on), newest first, with status and duration. Use it to check whether a trigger ran and whether it failed. The Apps Script API doesn't return log text.",
    inputSchema: {
      type: "object",
      properties: {
        script_id: SCRIPT_ID_PROP,
        function_name: { type: "string", description: "Only runs of this function." },
        status: {
          type: "string",
          enum: ["COMPLETED", "FAILED", "RUNNING", "CANCELED", "TIMED_OUT", "PAUSED", "DELAYED", "UNKNOWN"],
          description: "Only runs with this status.",
        },
        page_size: { type: "integer", minimum: 1, maximum: 200, description: "Default 25." },
        page_token: { type: "string" },
      },
      required: ["script_id"],
    },
    annotations: { readOnlyHint: true, openWorldHint: false },
    run: async (api, a) => {
      const id = scriptId(a);
      const u = new URL(`${SCRIPT_API}/processes:listScriptProcesses`);
      u.searchParams.set("scriptId", id);
      u.searchParams.set("pageSize", String(Math.min(int(a, "page_size") ?? 25, 200)));
      const fn = str(a, "function_name", false);
      if (fn) u.searchParams.set("scriptProcessFilter.functionName", fn);
      const st = str(a, "status", false);
      if (st) u.searchParams.set("scriptProcessFilter.statuses", st);
      const pt = str(a, "page_token", false);
      if (pt) u.searchParams.set("pageToken", pt);
      const d = await api.call("GET", u.toString());
      // deno-lint-ignore no-explicit-any
      const runs = (d.processes ?? []).map((p: any) => ({
        function: p.functionName,
        type: p.processType,
        status: p.processStatus,
        started: p.startTime,
        duration: p.duration,
        user_access: p.userAccessLevel,
      }));
      return JSON.stringify({ runs, next_page_token: d.nextPageToken ?? null }, null, 2);
    },
  },
];

// ---------------------------------------------------------------- MCP

// deno-lint-ignore no-explicit-any
type Rpc = { jsonrpc?: string; id?: any; method?: string; params?: any };

function rpcResult(id: unknown, result: unknown) {
  return { jsonrpc: "2.0", id, result };
}
function rpcError(id: unknown, code: number, message: string) {
  return { jsonrpc: "2.0", id: id ?? null, error: { code, message } };
}

const INSTRUCTIONS =
  "Tools for Google Apps Script projects. Projects are identified by script id or editor URL. Read code with get_project_content before editing. Prefer edit_file for small changes; write_file replaces a whole file. Edits save to the project's current code immediately, so triggers pick them up on their next run. Set create_version_first when a change is risky. Use list_executions to check whether triggers ran or failed.";

function toolsFor(cfg: Config): ToolDef[] {
  return cfg.driveListing ? TOOLS : TOOLS.filter((t) => t.name !== "list_script_projects");
}

async function dispatch(cfg: Config, msg: Rpc, api: GoogleApi): Promise<unknown | null> {
  const isNotification = msg.id === undefined || msg.id === null;
  if (msg.jsonrpc !== "2.0" || typeof msg.method !== "string") {
    return isNotification ? null : rpcError(msg.id, -32600, "Invalid request");
  }
  switch (msg.method) {
    case "initialize": {
      const asked = msg.params?.protocolVersion;
      const protocolVersion = SUPPORTED_PROTOCOLS.includes(asked) ? asked : SUPPORTED_PROTOCOLS[0];
      return rpcResult(msg.id, {
        protocolVersion,
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: "apps-script", title: "Apps Script", version: SERVER_VERSION },
        instructions: INSTRUCTIONS,
      });
    }
    case "ping":
      return isNotification ? null : rpcResult(msg.id, {});
    case "tools/list":
      return rpcResult(msg.id, {
        tools: toolsFor(cfg).map(({ name, title, description, inputSchema, annotations }) => ({
          name,
          title,
          description,
          inputSchema,
          annotations: { title, ...annotations },
        })),
      });
    case "tools/call": {
      const tool = toolsFor(cfg).find((t) => t.name === msg.params?.name);
      if (!tool) return rpcError(msg.id, -32602, `Unknown tool: ${msg.params?.name}`);
      try {
        const text = await tool.run(api, (msg.params?.arguments ?? {}) as Args);
        return rpcResult(msg.id, { content: [{ type: "text", text }], isError: false });
      } catch (e) {
        if (e instanceof GoogleAuthError) throw e;
        return rpcResult(msg.id, { content: [{ type: "text", text: (e as Error).message }], isError: true });
      }
    }
    case "resources/list":
      return rpcResult(msg.id, { resources: [] });
    case "prompts/list":
      return rpcResult(msg.id, { prompts: [] });
    default:
      if (isNotification) return null;
      return rpcError(msg.id, -32601, `Method not found: ${msg.method}`);
  }
}

async function handleMcp(cfg: Config, req: Request, fetchFn: typeof fetch): Promise<Response> {
  if (req.method === "GET" || req.method === "DELETE") {
    return new Response(null, { status: 405, headers: { Allow: "POST", ...CORS } });
  }
  if (req.method !== "POST") return new Response(null, { status: 405, headers: { Allow: "POST", ...CORS } });

  const auth = req.headers.get("authorization") ?? "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m) return unauthorized(cfg);
  const at = await unseal(cfg, "at", m[1].trim());
  if (!at) return unauthorized(cfg, "invalid_token", "Token is invalid");
  if (at.exp < now()) return unauthorized(cfg, "invalid_token", "Token expired");
  if (!cfg.allowedEmails.includes(at.email)) return unauthorized(cfg, "invalid_token", "Account no longer allowed");

  // deno-lint-ignore no-explicit-any
  let body: any;
  try {
    body = await req.json();
  } catch {
    return json(rpcError(null, -32700, "Parse error"), 400);
  }
  const api = new GoogleApi(at.gat, fetchFn);
  try {
    if (Array.isArray(body)) {
      if (!body.length) return json(rpcError(null, -32600, "Empty batch"), 400);
      const out = (await Promise.all(body.map((b) => dispatch(cfg, b, api)))).filter((x) => x !== null);
      return out.length ? json(out) : new Response(null, { status: 202, headers: CORS });
    }
    const out = await dispatch(cfg, body, api);
    return out === null ? new Response(null, { status: 202, headers: CORS }) : json(out);
  } catch (e) {
    if (e instanceof GoogleAuthError) return unauthorized(cfg, "invalid_token", "Google sign-in expired");
    return json(rpcError(body?.id, -32603, "Internal error"), 500);
  }
}

// ---------------------------------------------------------------- router

export function routePath(pathname: string): string {
  let p = pathname;
  if (p.startsWith("/functions/v1")) p = p.slice("/functions/v1".length);
  if (p === `/${FUNCTION_NAME}` || p.startsWith(`/${FUNCTION_NAME}/`)) p = p.slice(FUNCTION_NAME.length + 1);
  return p.replace(/\/+$/, "") || "/";
}

export function makeHandler(getConfig: () => Config | string = loadConfig, fetchFn: typeof fetch = fetch) {
  httpFetch = fetchFn;
  return async function handler(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const path = routePath(url.pathname);
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });

    const cfg = getConfig();
    if (typeof cfg === "string") {
      console.error(cfg);
      return json({ error: "server_not_configured", error_description: cfg }, 503);
    }

    try {
      switch (path) {
        case "/":
          if (req.method === "POST") return await handleMcp(cfg, req, fetchFn); // tolerate the base URL as the MCP URL
          return page(
            "Apps Script connector",
            `<p>This is a Claude connector for Google Apps Script.</p><p>Add <code>${
              esc(cfg.mcpUrl)
            }</code> as a custom connector in Claude.</p>`,
          );
        case "/mcp":
          return await handleMcp(cfg, req, fetchFn);
        case "/.well-known/oauth-protected-resource":
        case "/.well-known/oauth-protected-resource/mcp":
          return json(protectedResourceMetadata(cfg));
        case "/.well-known/oauth-authorization-server":
        case "/.well-known/openid-configuration":
          return json(authServerMetadata(cfg));
        case "/jwks":
          return json({ keys: [] });
        case "/register":
          return req.method === "POST"
            ? await handleRegister(cfg, req)
            : new Response(null, { status: 405, headers: CORS });
        case "/authorize":
          return await handleAuthorize(cfg, url);
        case "/oauth/google/callback":
          return await handleGoogleCallback(cfg, url);
        case "/token":
          return req.method === "POST"
            ? await handleToken(cfg, req)
            : new Response(null, { status: 405, headers: CORS });
        case "/revoke":
          return req.method === "POST"
            ? await handleRevoke(cfg, req)
            : new Response(null, { status: 405, headers: CORS });
        default:
          return json({ error: "not_found" }, 404);
      }
    } catch (e) {
      console.error("Unhandled error", e);
      return json({ error: "server_error" }, 500);
    }
  };
}
