import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createApp } from "../apps/server/src/app.ts";
import type { Config } from "../apps/server/src/config.ts";
import { createStore, type Store } from "../apps/server/src/db.ts";
import { decryptSecret, encryptSecret } from "../packages/integrations/src/vault.ts";

const sessionId = "00000000-0000-4000-8000-000000000001";
const session = {
  id: sessionId,
  title: "Saved page",
  url: "https://example.com/",
  status: "active",
  updatedAt: "2026-09-15T00:00:00.000Z",
};

type App = Awaited<ReturnType<typeof createApp>>;

interface Fixture {
  app: App["app"];
  auth: App["auth"];
  agent: App["agent"];
  db: Store;
  key: string;
  fillCalls: Record<string, unknown>[];
}

/** A fake browser worker behind a valted server app: fills answer, reads refresh metadata. */
async function fixture(t: test.TestContext): Promise<Fixture> {
  const fillCalls: Record<string, unknown>[] = [];
  const server = createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(Buffer.from(chunk));
    const url = request.url ?? "";
    if (url.endsWith("/fill")) {
      const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : {};
      fillCalls.push(body);
      response.writeHead(200, { "content-type": "application/json" });
      response.end(
        JSON.stringify({
          filled: { username: true, password: true },
          submitted: true,
          host: "example.com",
        }),
      );
      return;
    }
    if (url.endsWith("/read")) {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(
        JSON.stringify({
          url: "https://example.com/",
          title: "Saved page",
          text: "Welcome",
          truncated: false,
        }),
      );
      return;
    }
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify(session));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert(address && typeof address !== "string");
  const directory = await mkdtemp(join(tmpdir(), "openmuse-vault-"));
  const db = await createStore();
  const key = randomBytes(32).toString("base64");
  const config: Config = {
    mode: "sample",
    port: 8787,
    host: "127.0.0.1",
    publicUrl: "http://localhost:8787",
    dataDir: directory,
    agentBackend: "sample",
    intelligenceApiKey: "test-project-key-never-sent",
    googleRedirectUri: "http://localhost:8787/api/google/callback",
    allowedOrigins: [],
    workerUrl: `http://127.0.0.1:${address.port}`,
    workerToken: "test-worker-token-at-least-32-characters",
    vaultKey: key,
    encryptionKey: key,
  };
  const { app, auth, agent } = await createApp(db, config);
  t.after(async () => {
    await agent.stop();
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await db.close();
    await rm(directory, { recursive: true, force: true });
  });
  return { app, auth, db, agent, key, fillCalls };
}

async function headers(f: Fixture) {
  const { token } = await f.auth.session();
  return { Authorization: `Bearer ${token}`, "Content-Type": "application/json" } as const;
}

async function saveEntry(
  f: Fixture,
  h: Record<string, string>,
  host = "example.com",
  label = "Example login",
) {
  const created = await f.app.request("/api/vault", {
    method: "POST",
    headers: h,
    body: JSON.stringify({
      label,
      host,
      username: "user@example.com",
      password: "openmuse-secret-42",
    }),
  });
  assert.equal(created.status, 201, await created.clone().text());
  return (await created.json()) as { id: string; host: string; label: string };
}

test("the vault API never returns secret material and answers fills through the worker", async (t) => {
  const f = await fixture(t);
  const h = await headers(f);
  const entry = await saveEntry(f, h);
  assert.equal(entry.host, "example.com");
  assert.equal(JSON.stringify(entry).includes("openmuse-secret"), false);
  assert.equal("secret" in entry, false);
  assert.equal("password" in entry, false);

  const sites = await (await f.app.request("/api/vault", { headers: h })).json();
  assert.equal(sites.length, 1);
  assert.equal(JSON.stringify(sites).includes("openmuse-secret"), false);
  assert.equal(
    JSON.stringify(sites).toLowerCase().includes("canary"),
    false,
    "the audit decoy is never listed",
  );

  assert.equal(
    (
      await f.app.request("/api/vault", {
        method: "POST",
        headers: h,
        body: JSON.stringify({ label: "x", host: "example.com", password: "different one" }),
      })
    ).status,
    409,
    "a second login for the same host is refused",
  );
  assert.equal(
    (
      await f.app.request("/api/vault", {
        method: "POST",
        headers: h,
        body: JSON.stringify({ label: "x", host: "xn--e1afmkfd.example", password: "p" }),
      })
    ).status,
    400,
  );

  await f.db.put("local-user", "browsers", session);
  const fill = await f.app.request("/api/vault/fill", {
    method: "POST",
    headers: h,
    body: JSON.stringify({ sessionId, ref: { id: entry.id }, submit: true }),
  });
  assert.equal(fill.status, 200, await fill.clone().text());
  const result = await fill.json();
  assert.deepEqual(result, { status: "filled", host: "example.com", label: entry.label });
  const call = f.fillCalls[0];
  assert.equal(typeof call.envelope, "string");
  assert.equal(String(call.envelope).startsWith("v1."), true);
  assert.equal(call.host, "example.com");
  assert.equal(call.username, "user@example.com");
  assert.equal(JSON.stringify(call).includes("openmuse-secret"), false);
  // Owner isolation: another owner's row stays invisible and unfillable.
  await f.db.put("someone-else", "credentials", {
    id: "site:hidden.org",
    label: "Hidden",
    host: "hidden.org",
    username: "",
    secret: encryptSecret("hidden-secret-99", randomBytes(32).toString("base64")),
    createdAt: new Date().toISOString(),
  });
  assert.equal((await (await f.app.request("/api/vault", { headers: h })).json()).length, 1);
  assert.equal(
    (
      await f.app.request("/api/vault/fill", {
        method: "POST",
        headers: h,
        body: JSON.stringify({ sessionId, ref: { id: "site:hidden.org" } }),
      })
    ).status,
    404,
  );

  const updated = await f.app.request(`/api/vault/${entry.id}`, {
    method: "PUT",
    headers: h,
    body: JSON.stringify({ username: "me@example.org" }),
  });
  assert.equal(updated.status, 200, await updated.clone().text());
  assert.equal(
    (await (await f.app.request(`/api/vault/${entry.id}`, { headers: h })).json()).username,
    "me@example.org",
  );

  assert.equal(
    (await f.app.request(`/api/vault/${entry.id}`, { method: "DELETE", headers: h })).status,
    200,
  );
  assert.equal((await (await f.app.request("/api/vault", { headers: h })).json()).length, 0);
});

test("chat fill approvals execute once and only when the request is fresh", async (t) => {
  const f = await fixture(t);
  const h = await headers(f);
  const entry = await saveEntry(f, h);
  await f.db.put("local-user", "browsers", session);
  const fresh = "11111111-2222-4333-8444-555555555555";
  const stale = "22222222-3333-4333-8444-555555555555";
  const pendingDeny = "33333333-4444-4333-8444-555555555555";
  await f.db.put("local-user", "vault-fills", {
    id: fresh,
    vaultId: entry.id,
    host: "example.com",
    sessionId,
    submit: false,
    status: "pending",
    createdAt: new Date(Date.now() - 5_000).toISOString(),
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
  });
  await f.db.put("local-user", "vault-fills", {
    id: stale,
    vaultId: entry.id,
    host: "example.com",
    sessionId,
    submit: false,
    status: "expired",
    createdAt: new Date(Date.now() - 120_000).toISOString(),
    expiresAt: new Date(Date.now() - 60_000).toISOString(),
  });
  await f.db.put("local-user", "vault-fills", {
    id: pendingDeny,
    vaultId: entry.id,
    host: "example.com",
    sessionId,
    submit: false,
    status: "pending",
    createdAt: new Date(Date.now() - 5_000).toISOString(),
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
  });

  const staleDecide = await f.app.request(`/api/vault/fills/${stale}/decide`, {
    method: "POST",
    headers: h,
    body: JSON.stringify({ decision: "approve" }),
  });
  assert.equal(staleDecide.status, 409);
  assert.equal(f.fillCalls.length, 0, "expired requests never decrypt anything");

  const approve = await f.app.request(`/api/vault/fills/${fresh}/decide`, {
    method: "POST",
    headers: h,
    body: JSON.stringify({ decision: "approve" }),
  });
  assert.equal(approve.status, 200, await approve.clone().text());
  assert.equal((await approve.json()).status, "filled");
  const replay = await f.app.request(`/api/vault/fills/${fresh}/decide`, {
    method: "POST",
    headers: h,
    body: JSON.stringify({ decision: "approve" }),
  });
  assert.equal(replay.status, 409, "a handled request cannot run twice");
  assert.equal(f.fillCalls.length, 1);

  const denied = await f.app.request(`/api/vault/fills/${pendingDeny}/decide`, {
    method: "POST",
    headers: h,
    body: JSON.stringify({ decision: "deny" }),
  });
  assert.equal(denied.status, 200, await denied.clone().text());
  assert.equal((await denied.json()).status, "denied");
  assert.equal(f.fillCalls.length, 1, "declines never touch the worker");
});

test("fills are rate limited per site before any credential use", async (t) => {
  const f = await fixture(t);
  const h = await headers(f);
  const entry = await saveEntry(f, h);
  await f.db.put("local-user", "browsers", session);
  for (let attempt = 0; attempt < 5; attempt++) {
    assert.equal(
      (
        await f.app.request("/api/vault/fill", {
          method: "POST",
          headers: h,
          body: JSON.stringify({ sessionId, ref: { id: entry.id } }),
        })
      ).status,
      200,
      `attempt ${attempt + 1} succeeds within the window`,
    );
  }
  const sixth = await f.app.request("/api/vault/fill", {
    method: "POST",
    headers: h,
    body: JSON.stringify({ sessionId, ref: { id: entry.id } }),
  });
  assert.equal(sixth.status, 429);
  assert.equal(f.fillCalls.length, 5, "the rejected attempt never reached the worker");

  const other = await saveEntry(f, h, "other.example", "Other");
  assert.equal(
    (
      await f.app.request("/api/vault/fill", {
        method: "POST",
        headers: h,
        body: JSON.stringify({ sessionId, ref: { id: other.id } }),
      })
    ).status,
    200,
    "a different saved site has its own bucket",
  );
});

test("the canary audit proves isolation and powers the alarm", async (t) => {
  const f = await fixture(t);
  const h = await headers(f);
  const before = await (
    await f.app.request("/api/vault/audit", { method: "POST", headers: h })
  ).json();
  assert.equal(before.leaked, false);

  // Saving the first login plants the decoy row.
  await saveEntry(f, h);
  const canary = await f.db.get<{ secret: string }>(
    "local-user",
    "credentials",
    "site:canary.invalid",
  );
  assert.ok(canary, "the decoy is stored as an envelope");
  // Plant the decoy plaintext inside a designated audit surface, exactly the way
  // a leaking implementation would surface it.
  const canaryText = decryptSecret(canary.secret, f.key);
  await f.db.put("local-user", "conversations", {
    id: "default",
    messages: [{ role: "assistant", content: `password: ${canaryText}` }],
  });
  const verdict = await (
    await f.app.request("/api/vault/audit", { method: "POST", headers: h })
  ).json();
  assert.deepEqual(
    { leaked: verdict.leaked, kind: verdict.kind },
    { leaked: true, kind: "conversations" },
  );
  assert.equal(
    JSON.stringify(verdict).includes(canaryText),
    false,
    "the alarm never echoes the decoy",
  );
  assert.equal((await f.db.list("local-user", "notifications")).length, 1);

  await f.db.put("local-user", "conversations", { id: "default", messages: [] });
  const clean = await (
    await f.app.request("/api/vault/audit", { method: "POST", headers: h })
  ).json();
  assert.equal(clean.leaked, false);
});
