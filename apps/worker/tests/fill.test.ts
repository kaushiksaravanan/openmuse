import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { decryptSecret, encryptSecret } from "../../../packages/integrations/src/vault.ts";
import { createBrowserManager } from "../src/browser.ts";
import { mintFillToken } from "../src/vault.ts";
import { createBrowserFixture, fixtureOrigin, fixtureTitle } from "./fixtures.ts";

const fixture = await createBrowserFixture();
const key = randomBytes(32).toString("base64");

async function browserWithoutVault() {
  const dataDir = await mkdtemp(join(tmpdir(), "openmuse-fill-novault-"));
  return createBrowserManager({ dataDir }, fixture.createProxy);
}

async function browserWithVault() {
  const dataDir = await mkdtemp(join(tmpdir(), "openmuse-fill-"));
  return createBrowserManager({ dataDir, vaultKey: key }, fixture.createProxy);
}

test("real Chromium fills a matching login page from an encrypted envelope only", {
  timeout: 60_000,
}, async () => {
  const browser = await browserWithVault();
  const id = randomUUID();
  try {
    await browser.create(id, `${fixtureOrigin}/page`);
    const opened = await browser.read(id);
    assert.equal(opened.title, fixtureTitle);
    await browser.navigate(id, `${fixtureOrigin}/login`);
    const envelope = encryptSecret("openmuse-typed-only", key);
    const fillToken = mintFillToken(key, id, "1.1.1.1");
    const result = await browser.fill(id, {
      host: "1.1.1.1",
      username: "human@example.com",
      envelope,
      fillToken,
      submit: true,
    });
    assert.deepEqual(result, {
      filled: { username: true, password: true },
      submitted: true,
      host: "1.1.1.1",
    });
    assert.deepEqual(fixture.unexpected, []);
    const page = await browser.read(id);
    assert.match(page.text, /authenticated human@example\.com/, "username filled the form");
    // The page never receives the plaintext outside the typed field: it cannot
    // be echoed back into readable text or readback.
    assert.equal(page.text.includes("openmuse-typed-only"), false);
    // The envelope on disk stays sealed even after a fill.
    assert.equal(decryptSecret(envelope, key), "openmuse-typed-only");
    assert.equal(fixture.paths.filter((path) => path === "/login").length, 1);
  } finally {
    await browser.close();
    await rm(join("/tmp", `openmuse-downloads-${id}`), { recursive: true, force: true });
  }
});

test("a fill without VAULT_KEY is refused before any credential math", {
  timeout: 60_000,
}, async () => {
  const browser = await browserWithoutVault();
  const id = randomUUID();
  try {
    await browser.create(id, `${fixtureOrigin}/page`);
    await assert.rejects(
      browser.fill(id, { host: "1.1.1.1", envelope: "v1.x", fillToken: "1.s", submit: false }),
      { code: "FILL_NOT_CONFIGURED" },
    );
  } finally {
    await browser.close();
  }
});

test("the worker refuses fills that do not match the live page host", {
  timeout: 60_000,
}, async () => {
  const browser = await browserWithVault();
  const id = randomUUID();
  try {
    await browser.create(id, `${fixtureOrigin}/page`);
    await assert.rejects(
      browser.fill(id, {
        host: "example.com",
        envelope: encryptSecret("openmuse-typed-only", key),
        fillToken: mintFillToken(key, id, "example.com"),
        submit: false,
      }),
      { code: "FILL_HOST_MISMATCH" },
    );
  } finally {
    await browser.close();
  }
});

test("the worker refuses filled pages without a password field", { timeout: 60_000 }, async () => {
  const browser = await browserWithVault();
  const id = randomUUID();
  try {
    await browser.create(id, `${fixtureOrigin}/page`);
    await browser.navigate(id, `${fixtureOrigin}/page`);
    await assert.rejects(
      browser.fill(id, {
        host: "1.1.1.1",
        envelope: encryptSecret("openmuse-typed-only", key),
        fillToken: mintFillToken(key, id, "1.1.1.1"),
        submit: false,
      }),
      { code: "FILL_NO_FIELD" },
    );
  } finally {
    await browser.close();
  }
});

test("invalid tokens and envelopes are rejected before typing", { timeout: 60_000 }, async () => {
  const browser = await browserWithVault();
  const id = randomUUID();
  try {
    await browser.create(id, `${fixtureOrigin}/login`);
    await assert.rejects(
      browser.fill(id, {
        host: "1.1.1.1",
        envelope: encryptSecret("openmuse-typed-only", key),
        fillToken: "1234567890123.tampered",
        submit: false,
      }),
      { code: "FILL_TOKEN_INVALID" },
    );
    await assert.rejects(
      browser.fill(id, {
        host: "1.1.1.1",
        envelope: encryptSecret("openmuse-typed-only", randomBytes(32).toString("base64")),
        fillToken: mintFillToken(key, id, "1.1.1.1"),
        submit: false,
      }),
      { code: "FILL_INVALID_ENVELOPE" },
    );
    await assert.rejects(
      browser.fill(id, {
        host: "1.1.1.1",
        envelope: "v1.notabase64url!!",
        fillToken: mintFillToken(key, id, "1.1.1.1"),
        submit: false,
      }),
      { code: "FILL_INVALID_ENVELOPE" },
    );
  } finally {
    await browser.close();
  }
});

test.after(async () => {
  await fixture.close();
  assert.deepEqual(fixture.unexpected, []);
});
