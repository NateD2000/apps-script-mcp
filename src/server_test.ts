import { assert, assertEquals, assertMatch, assertStringIncludes } from "@std/assert";
import { b64url, type Config, makeHandler, routePath } from "./server.ts";

const BASE = "https://apps-script-mcp-123456789.us-central1.run.app";
const cfg: Config = {
  baseUrl: BASE,
  mcpUrl: `${BASE}/mcp`,
  googleClientId: "gcid",
  googleClientSecret: "gsecret",
  allowedEmails: ["owner@example.com"],
  tokenSecret: "test-secret",
  extraRedirects: [],
  driveListing: true,
};

// ---- fake Google
type File = { name: string; type: string; source: string };
const store: Record<string, File[]> = {};
const versions: Record<string, { versionNumber: number; files: File[] }[]> = {};
let userEmail = "owner@example.com";
let grantedScope = "openid email https://www.googleapis.com/auth/script.projects";
let refreshBroken = false;
let googleAccessToken = "g-at-1";
const calls: string[] = [];

// deno-lint-ignore require-await
const fakeFetch: typeof fetch = async (input, init) => {
  const url = new URL(typeof input === "string" ? input : (input as Request).url);
  const method = init?.method ?? "GET";
  calls.push(`${method} ${url.origin}${url.pathname}`);
  const body = init?.body;
  const j = (o: unknown, s = 200) =>
    new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json" } });

  if (url.href.startsWith("https://oauth2.googleapis.com/token")) {
    const p = new URLSearchParams(String(body));
    assertEquals(p.get("client_secret"), "gsecret");
    if (p.get("grant_type") === "authorization_code") {
      assertEquals(p.get("redirect_uri"), `${BASE}/oauth/google/callback`);
      return j({
        access_token: googleAccessToken,
        expires_in: 3599,
        refresh_token: "g-rt",
        scope: grantedScope,
        token_type: "Bearer",
      });
    }
    if (refreshBroken) return j({ error: "invalid_grant" }, 400);
    googleAccessToken = "g-at-2";
    return j({ access_token: googleAccessToken, expires_in: 3599, scope: grantedScope });
  }
  if (url.href.startsWith("https://oauth2.googleapis.com/revoke")) return j({});
  if (url.href.startsWith("https://openidconnect.googleapis.com/v1/userinfo")) {
    return j({ email: userEmail, email_verified: true });
  }
  const auth = (init?.headers as Record<string, string>)?.Authorization;
  if (auth !== `Bearer ${googleAccessToken}`) return j({ error: { message: "bad token" } }, 401);

  const m = url.pathname.match(/^\/v1\/projects\/([^/]+)(\/.*)?$/);
  if (url.host === "script.googleapis.com" && m) {
    const id = decodeURIComponent(m[1]);
    const rest = m[2] ?? "";
    if (!store[id]) return j({ error: { message: "Requested entity was not found." } }, 404);
    if (rest === "/content" && method === "GET") {
      const v = url.searchParams.get("versionNumber");
      if (v) return j({ scriptId: id, files: versions[id].find((x) => x.versionNumber === Number(v))!.files });
      return j({ scriptId: id, files: store[id] });
    }
    if (rest === "/content" && method === "PUT") {
      const b = JSON.parse(String(body));
      store[id] = b.files;
      return j({ scriptId: id, files: b.files });
    }
    if (rest === "/versions" && method === "POST") {
      versions[id] ??= [];
      const n = versions[id].length + 1;
      versions[id].push({ versionNumber: n, files: structuredClone(store[id]) });
      return j({ versionNumber: n });
    }
    if (rest === "") return j({ scriptId: id, title: "Holmes", updateTime: "2026-11-08T00:00:00Z" });
  }
  if (url.host === "script.googleapis.com" && url.pathname === "/v1/processes:listScriptProcesses") {
    return j({
      processes: [{
        functionName: "main",
        processType: "TIME_DRIVEN",
        processStatus: "FAILED",
        startTime: "t",
        duration: "1s",
      }],
    });
  }
  if (url.host === "script.googleapis.com" && url.pathname === "/v1/projects/disabled/content") {
    return j({
      error: {
        message:
          "User has not enabled the Apps Script API. Enable it by visiting https://script.google.com/home/usersettings",
      },
    }, 403);
  }
  if (url.host === "www.googleapis.com" && url.pathname === "/drive/v3/files") {
    assertStringIncludes(url.searchParams.get("q")!, "application/vnd.google-apps.script");
    return j({ files: [{ id: "S".repeat(30), name: "Holmes Calendar Sync", modifiedTime: "x" }] });
  }
  return j({ error: { message: "unexpected " + url.href } }, 500);
};

const handler = makeHandler(() => cfg, fakeFetch);
const req = (path: string, init?: RequestInit) => handler(new Request(BASE + path, init));
const SID = "1bp68K5SDl9RDSerc3sljo2q5W5ol_qukANsyTStYEH3YO2JmrREi8qTr";

async function pkce() {
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)));
  const challenge = b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
  return { verifier, challenge };
}

async function register(redirect = "https://claude.ai/api/mcp/auth_callback") {
  const r = await req("/register", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ redirect_uris: [redirect], client_name: "Claude" }),
  });
  assertEquals(r.status, 201);
  return (await r.json()).client_id as string;
}

async function fullFlow(redirect = "https://claude.ai/api/mcp/auth_callback") {
  const clientId = await register(redirect);
  const { verifier, challenge } = await pkce();
  const a = new URL(BASE + "/authorize");
  a.search = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirect,
    code_challenge: challenge,
    code_challenge_method: "S256",
    state: "xyz",
    scope: "apps_script offline_access",
    resource: `${BASE}/mcp`,
  }).toString();
  const page = await handler(new Request(a));
  assertEquals(page.status, 200);
  const html = await page.text();
  const href = html.match(/href="([^"]+)"/)![1].replace(/&amp;/g, "&");
  const g = new URL(href);
  assertStringIncludes(g.searchParams.get("scope")!, "drive.metadata.readonly");
  assertEquals(g.origin + g.pathname, "https://accounts.google.com/o/oauth2/v2/auth");
  assertEquals(g.searchParams.get("access_type"), "offline");
  const cb = await req(`/oauth/google/callback?code=gcode&state=${encodeURIComponent(g.searchParams.get("state")!)}`);
  return { cb, clientId, verifier, redirect };
}

async function tokens() {
  const { cb, clientId, verifier, redirect } = await fullFlow();
  assertEquals(cb.status, 302);
  const back = new URL(cb.headers.get("location")!);
  assertEquals(back.origin + back.pathname, "https://claude.ai/api/mcp/auth_callback");
  assertEquals(back.searchParams.get("state"), "xyz");
  const t = await req("/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: back.searchParams.get("code")!,
      redirect_uri: redirect,
      client_id: clientId,
      code_verifier: verifier,
    }),
  });
  assertEquals(t.status, 200);
  return { ...(await t.json()), clientId };
}

async function rpc(token: string, method: string, params?: unknown, id: number | null = 1) {
  const r = await req("/mcp", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(id === null ? { jsonrpc: "2.0", method, params } : { jsonrpc: "2.0", id, method, params }),
  });
  return r;
}

async function tool(token: string, name: string, args: Record<string, unknown>) {
  const r = await rpc(token, "tools/call", { name, arguments: args });
  assertEquals(r.status, 200);
  return (await r.json()).result as { content: { text: string }[]; isError: boolean };
}

function reset() {
  store[SID] = [
    { name: "appsscript", type: "JSON", source: '{"timeZone":"America/Denver"}' },
    { name: "Code", type: "SERVER_JS", source: "function isScriptBlock_(e) {\n  return isLegacyBlock_(e);\n}\n" },
  ];
  versions[SID] = [];
  userEmail = "owner@example.com";
  grantedScope = "openid email https://www.googleapis.com/auth/script.projects";
  refreshBroken = false;
  googleAccessToken = "g-at-1";
}

Deno.test("routePath handles plain and prefixed paths", () => {
  assertEquals(routePath("/apps-script-mcp/mcp"), "/mcp");
  assertEquals(
    routePath("/functions/v1/apps-script-mcp/.well-known/oauth-protected-resource"),
    "/.well-known/oauth-protected-resource",
  );
  assertEquals(routePath("/apps-script-mcp"), "/");
  assertEquals(routePath("/mcp/"), "/mcp");
});

Deno.test("unauthenticated MCP call returns 401 with resource metadata pointer", async () => {
  const r = await req("/mcp", { method: "POST", body: "{}" });
  assertEquals(r.status, 401);
  assertMatch(
    r.headers.get("www-authenticate")!,
    /resource_metadata="https:\/\/apps-script-mcp-123456789\.us-central1\.run\.app\/\.well-known\/oauth-protected-resource"/,
  );
  const prm = await (await req("/.well-known/oauth-protected-resource")).json();
  assertEquals(prm.resource, `${BASE}/mcp`);
  assertEquals(prm.authorization_servers, [BASE]);
  const as = await (await req("/.well-known/openid-configuration")).json();
  assertEquals(as.issuer, BASE);
  assertEquals(as.code_challenge_methods_supported, ["S256"]);
  assert(as.registration_endpoint.endsWith("/register"));
  assert(as.scopes_supported.includes("offline_access"));
});

Deno.test("registration rejects unknown redirect URIs", async () => {
  const r = await req("/register", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ redirect_uris: ["https://evil.example/cb"] }),
  });
  assertEquals(r.status, 400);
  assertEquals((await r.json()).error, "invalid_redirect_uri");
});

Deno.test("authorize rejects redirect not registered to the client", async () => {
  const clientId = await register();
  const { challenge } = await pkce();
  const r = await req(
    `/authorize?response_type=code&client_id=${encodeURIComponent(clientId)}&redirect_uri=${
      encodeURIComponent("https://evil.example/cb")
    }&code_challenge=${challenge}&code_challenge_method=S256`,
  );
  assertEquals(r.status, 400);
});

Deno.test("full flow: tokens, initialize, list, read, edit, versions, refresh", async () => {
  reset();
  const t = await tokens();
  assertMatch(t.access_token, /^asa_/);
  assertMatch(t.refresh_token, /^asr_/);
  assertEquals(t.token_type, "Bearer");

  const init = await (await rpc(t.access_token, "initialize", {
    protocolVersion: "2025-06-18",
    capabilities: {},
    clientInfo: { name: "c", version: "1" },
  })).json();
  assertEquals(init.result.protocolVersion, "2025-06-18");
  assertEquals(init.result.serverInfo.name, "apps-script");
  assertEquals((await rpc(t.access_token, "notifications/initialized", undefined, null)).status, 202);

  const list = await (await rpc(t.access_token, "tools/list")).json();
  const names = list.result.tools.map((x: { name: string }) => x.name);
  for (
    const n of [
      "list_script_projects",
      "get_project_content",
      "edit_file",
      "write_file",
      "list_executions",
      "restore_version",
    ]
  ) assert(names.includes(n), n);

  const projects = await tool(t.access_token, "list_script_projects", {});
  assertStringIncludes(projects.content[0].text, "Holmes Calendar Sync");

  const content = await tool(t.access_token, "get_project_content", {
    script_id: `https://script.google.com/d/${SID}/edit`,
  });
  assertStringIncludes(content.content[0].text, "===== Code.gs");
  assertStringIncludes(content.content[0].text, "isLegacyBlock_");

  const edit = await tool(t.access_token, "edit_file", {
    script_id: SID,
    file_name: "Code.gs",
    old_string: "  return isLegacyBlock_(e);",
    new_string: '  if (pv.tempo === "1") return false;\n  return isLegacyBlock_(e);',
    create_version_first: true,
  });
  assertEquals(edit.isError, false, edit.content[0].text);
  assertStringIncludes(edit.content[0].text, "version 1");
  assertStringIncludes(store[SID][1].source, 'pv.tempo === "1"');
  assertEquals(store[SID][0].name, "appsscript"); // other files kept

  const miss = await tool(t.access_token, "edit_file", {
    script_id: SID,
    file_name: "Code",
    old_string: "nope",
    new_string: "x",
  });
  assertEquals(miss.isError, true);

  const write = await tool(t.access_token, "write_file", {
    script_id: SID,
    file_name: "Utils.gs",
    source: "function u() {}",
  });
  assertStringIncludes(write.content[0].text, "Created Utils.gs");
  assertEquals(store[SID].length, 3);

  const badManifest = await tool(t.access_token, "write_file", {
    script_id: SID,
    file_name: "appsscript",
    source: "{bad",
  });
  assertEquals(badManifest.isError, true);

  const restore = await tool(t.access_token, "restore_version", { script_id: SID, version_number: 1 });
  assertEquals(restore.isError, false, restore.content[0].text);
  assertEquals(store[SID].length, 2);
  assert(!store[SID][1].source.includes("pv.tempo"));

  const runs = await tool(t.access_token, "list_executions", { script_id: SID, status: "FAILED" });
  assertStringIncludes(runs.content[0].text, "TIME_DRIVEN");

  // Refresh rotates both tokens and swaps the Google token.
  const r = await req("/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: t.refresh_token, client_id: t.clientId }),
  });
  assertEquals(r.status, 200);
  const t2 = await r.json();
  assert(t2.refresh_token !== t.refresh_token);
  // Old access token now carries a stale Google token -> 401 so Claude refreshes.
  const stale = await rpc(t.access_token, "tools/call", { name: "get_project", arguments: { script_id: SID } });
  assertEquals(stale.status, 401);
  const fresh = await tool(t2.access_token, "get_project", { script_id: SID });
  assertStringIncludes(fresh.content[0].text, "Holmes");
});

Deno.test("PKCE mismatch and code reuse by another client fail", async () => {
  reset();
  const { cb, clientId } = await fullFlow();
  const code = new URL(cb.headers.get("location")!).searchParams.get("code")!;
  const bad = await req("/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      client_id: clientId,
      code_verifier: "x".repeat(43),
    }),
  });
  assertEquals(bad.status, 400);
  assertEquals((await bad.json()).error, "invalid_grant");
  const other = await register();
  const bad2 = await req("/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      client_id: other,
      code_verifier: "x".repeat(43),
    }),
  });
  assertEquals((await bad2.json()).error, "invalid_grant");
});

Deno.test("wrong Google account is refused", async () => {
  reset();
  userEmail = "someone@else.com";
  const { cb } = await fullFlow();
  assertEquals(cb.status, 403);
  assertStringIncludes(await cb.text(), "someone@else.com");
});

Deno.test("missing Apps Script scope is refused", async () => {
  reset();
  grantedScope = "openid email";
  const { cb } = await fullFlow();
  assertEquals(cb.status, 403);
});

Deno.test("revoked Google refresh gives invalid_grant", async () => {
  reset();
  const t = await tokens();
  refreshBroken = true;
  const r = await req("/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: t.refresh_token }),
  });
  assertEquals(r.status, 400);
  assertEquals((await r.json()).error, "invalid_grant");
});

Deno.test("loopback redirect matches on any port", async () => {
  reset();
  const { cb } = await fullFlow("http://localhost/callback");
  // fullFlow used the registered URI itself; now try another port on a fresh client
  assertEquals(cb.status, 302);
  const clientId = await register("http://127.0.0.1/callback");
  const { challenge } = await pkce();
  const r = await req(
    `/authorize?response_type=code&client_id=${encodeURIComponent(clientId)}&redirect_uri=${
      encodeURIComponent("http://127.0.0.1:53111/callback")
    }&code_challenge=${challenge}&code_challenge_method=S256&state=s`,
  );
  assertEquals(r.status, 200);
  assertStringIncludes(await r.text(), "program on this computer");
});

Deno.test("tampered token is rejected", async () => {
  reset();
  const t = await tokens();
  const bad = t.access_token.slice(0, -2) + (t.access_token.endsWith("A") ? "BB" : "AA");
  assertEquals((await rpc(bad, "tools/list")).status, 401);
});

Deno.test("drive listing tool is hidden unless enabled", async () => {
  reset();
  const h2 = makeHandler(() => ({ ...cfg, driveListing: false }), fakeFetch);
  const t = await tokens();
  const r = await h2(
    new Request(BASE + "/mcp", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${t.access_token}` },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    }),
  );
  const names = (await r.json()).result.tools.map((x: { name: string }) => x.name);
  assert(!names.includes("list_script_projects"));
  assertEquals(names.length, 13);
});
