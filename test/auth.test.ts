import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

process.env.ADMIN_PASSWORD = "correct horse";
process.env.BASE_URL = "http://localhost:8080";
const { SingleUserProvider, hashPassword, verifyPassword } = await import("../src/auth.ts");
const { Store } = await import("../src/store.ts");

const fakeRes = () => {
  const out = { status: 0, body: "" };
  const res = { status: (s: number) => ((out.status = s), res), type: () => res, send: (b: string) => ((out.body = b), res) };
  return { out, res: res as unknown as import("express").Response };
};

test("password hashing round-trips and the hash takes precedence over a plain password", () => {
  const h = hashPassword("secret-123");
  assert.match(h, /^scrypt\$/);
  process.env.ADMIN_PASSWORD_HASH = h;
  try {
    assert.equal(verifyPassword("secret-123"), true);
    assert.equal(verifyPassword("correct horse"), false, "plain ADMIN_PASSWORD is ignored while a hash is set");
  } finally {
    delete process.env.ADMIN_PASSWORD_HASH;
  }
  assert.equal(verifyPassword("correct horse"), true);
});

test("full authorization code flow with PKCE, refresh and revocation", async () => {
  const store = new Store(join(mkdtempSync(join(tmpdir(), "bank-")), "store.json"));
  const provider = new SingleUserProvider(store);
  const client = await provider.clientsStore.registerClient!({ redirect_uris: ["https://claude.ai/api/mcp/auth_callback"], client_name: "Claude", token_endpoint_auth_method: "none" });
  assert.ok(client.client_id);
  assert.equal(client.client_secret, undefined, "public client gets no secret");

  const { out, res } = fakeRes();
  await provider.authorize(client, { codeChallenge: "challenge", redirectUri: client.redirect_uris[0]!, state: "xyz", scopes: ["bank:read"] }, res);
  assert.equal(out.status, 200);
  const requestId = /name="request" value="([^"]+)"/.exec(out.body)?.[1];
  assert.ok(requestId, "login page carries the request id");

  const wrong = provider.completeLogin(requestId!, "nope", "1.2.3.4");
  assert.ok("error" in wrong && wrong.requestId === requestId);

  const ok = provider.completeLogin(requestId!, "correct horse", "1.2.3.4");
  assert.ok("redirect" in ok);
  const url = new URL(ok.redirect);
  assert.equal(url.origin + url.pathname, client.redirect_uris[0]);
  assert.equal(url.searchParams.get("state"), "xyz");
  const code = url.searchParams.get("code")!;

  const again = provider.completeLogin(requestId!, "correct horse", "1.2.3.4");
  assert.ok("done" in again, "a repeat submit of a used sign-in page reports done, not an error");
  assert.ok("error" in provider.completeLogin("never-issued", "correct horse", "1.2.3.4"), "an unknown request id is an error");

  assert.equal(await provider.challengeForAuthorizationCode(client, code), "challenge");
  const tokens = await provider.exchangeAuthorizationCode(client, code, undefined, client.redirect_uris[0]);
  assert.ok(tokens.access_token && tokens.refresh_token);
  await assert.rejects(provider.exchangeAuthorizationCode(client, code), /Invalid/);

  const info = await provider.verifyAccessToken(tokens.access_token);
  assert.equal(info.clientId, client.client_id);
  assert.deepEqual(info.scopes, ["bank:read"]);
  assert.ok(!JSON.stringify(store.data).includes(tokens.access_token), "tokens are stored hashed");

  const refreshed = await provider.exchangeRefreshToken(client, tokens.refresh_token!);
  assert.notEqual(refreshed.access_token, tokens.access_token);
  await assert.rejects(provider.exchangeRefreshToken(client, tokens.refresh_token!), /Invalid/, "refresh tokens rotate");

  await provider.revokeToken!(client, { token: refreshed.access_token });
  await assert.rejects(provider.verifyAccessToken(refreshed.access_token), /Invalid/);
});

test("five wrong passwords lock the address out", async () => {
  const provider = new SingleUserProvider(new Store(join(mkdtempSync(join(tmpdir(), "bank-")), "store.json")));
  const client = await provider.clientsStore.registerClient!({ redirect_uris: ["https://claude.ai/cb"] });
  for (let i = 0; i < 5; i++) {
    const { out, res } = fakeRes();
    await provider.authorize(client, { codeChallenge: "c", redirectUri: "https://claude.ai/cb" }, res);
    const id = /name="request" value="([^"]+)"/.exec(out.body)![1]!;
    provider.completeLogin(id, "wrong", "9.9.9.9");
  }
  const { out, res } = fakeRes();
  await provider.authorize(client, { codeChallenge: "c", redirectUri: "https://claude.ai/cb" }, res);
  const id = /name="request" value="([^"]+)"/.exec(out.body)![1]!;
  const r = provider.completeLogin(id, "correct horse", "9.9.9.9");
  assert.ok("error" in r && /Too many/.test(r.error));
});

async function loginWith(provider: InstanceType<typeof SingleUserProvider>, password: string, ip: string) {
  const client = await provider.clientsStore.registerClient!({ redirect_uris: ["https://claude.ai/cb"] });
  const { out, res } = fakeRes();
  await provider.authorize(client, { codeChallenge: "c", redirectUri: "https://claude.ai/cb" }, res);
  const id = /name="request" value="([^"]+)"/.exec(out.body)![1]!;
  return provider.completeLogin(id, password, ip);
}

test("wrong passwords from many addresses lock sign-in for every address, for 15 minutes (#8)", async (t) => {
  t.mock.timers.enable({ apis: ["Date"], now: Date.parse("2026-09-28T12:00:00Z") });
  const provider = new SingleUserProvider(new Store(join(mkdtempSync(join(tmpdir(), "bank-")), "store.json")));
  // One wrong password from each of 20 addresses, as with a faked X-Forwarded-For: no address reaches its own limit.
  for (let i = 0; i < 20; i++) await loginWith(provider, "wrong", `10.0.0.${i}`);
  const locked = await loginWith(provider, "correct horse", "10.0.1.1");
  assert.ok("error" in locked && /Too many/.test(locked.error), "the right password from a new address is refused while locked");
  t.mock.timers.tick(16 * 60 * 1000);
  assert.ok("redirect" in (await loginWith(provider, "correct horse", "10.0.1.1")), "the lock ends after 15 minutes");
});

test("an address that stayed under the limit starts from zero after 15 minutes (#8)", async (t) => {
  t.mock.timers.enable({ apis: ["Date"], now: Date.parse("2026-09-28T12:00:00Z") });
  const provider = new SingleUserProvider(new Store(join(mkdtempSync(join(tmpdir(), "bank-")), "store.json")));
  for (let i = 0; i < 4; i++) await loginWith(provider, "wrong", "7.7.7.7");
  t.mock.timers.tick(16 * 60 * 1000);
  await loginWith(provider, "wrong", "7.7.7.7");
  assert.ok("redirect" in (await loginWith(provider, "correct horse", "7.7.7.7")), "four old failures and one new one do not lock the address");
});

test("revokeAll drops every token", async () => {
  const store = new Store(join(mkdtempSync(join(tmpdir(), "bank-")), "store.json"));
  const events: unknown[] = [];
  const provider = new SingleUserProvider(store, { onLogin: (e) => events.push(e) });
  const client = await provider.clientsStore.registerClient!({ redirect_uris: ["https://claude.ai/cb"], client_name: "Claude" });
  const { out, res } = fakeRes();
  await provider.authorize(client, { codeChallenge: "c", redirectUri: "https://claude.ai/cb" }, res);
  const id = /name="request" value="([^"]+)"/.exec(out.body)![1]!;
  const ok = provider.completeLogin(id, "correct horse", "5.5.5.5");
  assert.ok("redirect" in ok);
  assert.deepEqual(events, [{ ok: true, ip: "5.5.5.5", clientName: "Claude" }]);
  const tokens = await provider.exchangeAuthorizationCode(client, new URL(ok.redirect).searchParams.get("code")!, undefined, "https://claude.ai/cb");
  await provider.verifyAccessToken(tokens.access_token);
  provider.revokeAll();
  await assert.rejects(provider.verifyAccessToken(tokens.access_token), /Invalid/);
  await assert.rejects(provider.exchangeRefreshToken(client, tokens.refresh_token!), /Invalid/);
});

test("clients may only redirect to allowed hosts", async () => {
  const provider = new SingleUserProvider(new Store(join(mkdtempSync(join(tmpdir(), "bank-")), "store.json")));
  await assert.rejects(async () => provider.clientsStore.registerClient!({ redirect_uris: ["https://evil.example/cb"] }), /not allowed/);
  await provider.clientsStore.registerClient!({ redirect_uris: ["https://claude.ai/api/mcp/auth_callback", "http://localhost:53421/callback"] });
  await assert.rejects(async () => provider.clientsStore.registerClient!({ redirect_uris: ["https://claude.ai.evil.example/cb"] }), /not allowed/);
});

test("well-known MCP client domains are allowed by default", async () => {
  const { redirectAllowed } = await import("../src/auth.ts");
  for (const u of ["https://claude.ai/api/mcp/auth_callback", "https://chatgpt.com/connector_platform_oauth_redirect", "https://chat.mistral.ai/oauth/callback", "https://cursor.com/oauth/callback", "http://localhost:3456/cb"]) assert.equal(redirectAllowed(u), true, u);
  for (const u of ["https://evil.example/cb", "https://chatgpt.com.evil.example/cb", "https://notclaude.ai/cb"]) assert.equal(redirectAllowed(u), false, u);
});

// Clients only use their refresh token after a 401 with WWW-Authenticate. Anything else (the 400
// invalid_client this used to give) makes them drop the connection once the hour-long access token expires.
test("an expired or unknown access token is rejected as invalid_token, which /mcp answers with 401", async () => {
  const { InvalidTokenError } = await import("@modelcontextprotocol/sdk/server/auth/errors.js");
  const { requireBearerAuth } = await import("@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js");
  const express = (await import("express")).default;

  const store = new Store(join(mkdtempSync(join(tmpdir(), "bank-")), "store.json"));
  const provider = new SingleUserProvider(store);
  const client = await provider.clientsStore.registerClient!({ redirect_uris: ["https://cursor.com/agents/mcp/oauth/callback"], client_name: "Cursor", token_endpoint_auth_method: "none" });
  const { out, res } = fakeRes();
  await provider.authorize(client, { codeChallenge: "c", redirectUri: client.redirect_uris[0]! }, res);
  const id = /name="request" value="([^"]+)"/.exec(out.body)![1]!;
  const ok = provider.completeLogin(id, "correct horse", "1.2.3.4");
  assert.ok("redirect" in ok);
  const tokens = await provider.exchangeAuthorizationCode(client, new URL(ok.redirect).searchParams.get("code")!, undefined, client.redirect_uris[0]);
  for (const t of Object.values(store.data.oauth.tokens)) if (t.kind === "access") t.expires = Math.floor(Date.now() / 1000) - 1;

  await assert.rejects(provider.verifyAccessToken(tokens.access_token), (e) => e instanceof InvalidTokenError && /expired/.test((e as Error).message));
  await assert.rejects(provider.verifyAccessToken("never-issued"), (e) => e instanceof InvalidTokenError);

  const app = express();
  app.post("/mcp", requireBearerAuth({ verifier: provider, resourceMetadataUrl: "http://localhost:8080/.well-known/oauth-protected-resource/mcp" }), (_req, r) => void r.json({ ok: true }));
  const server = app.listen(0);
  try {
    const port = (server.address() as import("node:net").AddressInfo).port;
    for (const bearer of [tokens.access_token, "never-issued"]) {
      const r = await fetch(`http://127.0.0.1:${port}/mcp`, { method: "POST", headers: { authorization: `Bearer ${bearer}` } });
      assert.equal(r.status, 401);
      assert.match(r.headers.get("www-authenticate") ?? "", /error="invalid_token"/);
      assert.equal(((await r.json()) as { error: string }).error, "invalid_token");
    }
    // The refresh token still works, which is what the client does next.
    const refreshed = await provider.exchangeRefreshToken(client, tokens.refresh_token!);
    const r = await fetch(`http://127.0.0.1:${port}/mcp`, { method: "POST", headers: { authorization: `Bearer ${refreshed.access_token}` } });
    assert.equal(r.status, 200);
  } finally {
    server.close();
  }
});
