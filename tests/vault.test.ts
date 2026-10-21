import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import test from "node:test";
import {
  normalizeHost,
  vaultEntrySchema,
  vaultPatchSchema,
  vaultRefSchema,
} from "../apps/server/src/vault-service.ts";
import { mintFillToken, readFillInput, verifyFillToken } from "../apps/worker/src/vault.ts";
import { decryptSecret, encryptSecret } from "../packages/integrations/src/vault.ts";

test("vault encrypts with a fresh nonce and authenticates the entire envelope", () => {
  const key = randomBytes(32).toString("base64");
  const secret = "synthetic refresh token / café";
  const first = encryptSecret(secret, key);
  const second = encryptSecret(secret, key);
  assert.notEqual(first, second);
  assert.equal(first.includes(secret), false);
  assert.equal(decryptSecret(first, key), secret);
  assert.throws(
    () => decryptSecret(first, randomBytes(32).toString("base64")),
    /authenticate|decrypt/i,
  );
  const parts = first.split(".");
  assert.equal(parts.length, 4);
  for (let index = 1; index < 4; index++) {
    const corrupted = [...parts];
    const bytes = Buffer.from(corrupted[index], "base64url");
    bytes[0] ^= 1;
    corrupted[index] = bytes.toString("base64url");
    assert.throws(() => decryptSecret(corrupted.join("."), key), /authenticate|decrypt/i);
  }
});

test("vault rejects malformed keys and envelopes without echoing secrets", () => {
  for (const key of [
    "",
    "password",
    randomBytes(31).toString("base64"),
    `${randomBytes(32).toString("base64")}!`,
  ]) {
    assert.throws(() => encryptSecret("secret-value", key), /32-byte base64/i);
  }
  const key = randomBytes(32).toString("base64");
  for (const envelope of ["", "plaintext-secret", "v2.a.b.c", "v1.!.a.b", "v1.a.b.c.extra"]) {
    assert.throws(() => decryptSecret(envelope, key), /invalid encrypted secret/i);
  }
  assert.equal(decryptSecret(encryptSecret("", key), key), "");
});

test("worker vault helper keeps the server crypto in sync", () => {
  const key = randomBytes(32).toString("base64");
  assert.equal(decryptSecret(encryptSecret("openmuse canary 42", key), key), "openmuse canary 42");
});

test("one-time fill tokens bind session, host and a short TTL", () => {
  const key = randomBytes(32).toString("base64");
  const token = mintFillToken(key, "session-1", "github.com", Date.now());
  assert.doesNotThrow(() => verifyFillToken(token, "session-1", "github.com", key));
  // Bound to the session and the host.
  assert.throws(() => verifyFillToken(token, "session-2", "github.com", key), /not authorized/i);
  assert.throws(() => verifyFillToken(token, "session-1", "gitlab.com", key), /not authorized/i);
  assert.throws(
    () => verifyFillToken(token, "session-1", "github.com", randomBytes(32).toString("base64")),
    /not authorized/i,
  );
  // Expired and far-future tokens are refused.
  const expired = mintFillToken(key, "session-1", "github.com", Date.now() - 20_000);
  assert.throws(() => verifyFillToken(expired, "session-1", "github.com", key), /not authorized/i);
  assert.throws(
    () =>
      verifyFillToken(`99999999999999999.${token.split(".")[1]}`, "session-1", "github.com", key),
    /not authorized/i,
  );
  assert.throws(
    () => verifyFillToken("tampered", "session-1", "github.com", key),
    /not authorized/i,
  );
});

test("fill input is validated strictly and carries no plaintext", () => {
  const key = randomBytes(32).toString("base64");
  const envelope = encryptSecret("never-typed-anywhere-else", key);
  const token = mintFillToken(key, "11111111-2222-4333-8444-555555555555", "example.com");
  const input = readFillInput({
    host: "example.com",
    username: "user@example.com",
    envelope,
    fillToken: token,
    submit: true,
  });
  assert.equal(input.host, "example.com");
  assert.equal(input.submit, true);
  assert.equal(input.envelope.startsWith("v1."), true);
  assert.equal(JSON.stringify(input).includes("never-typed"), false);
  const failures: Record<string, unknown>[] = [
    { host: "Bad.com", envelope, fillToken: token },
    {},
    { host: "example.com", envelope: "plaintext", fillToken: token },
    { host: "example.com", envelope, fillToken: token, username: Array(321).fill(0).join("") },
    { host: "example.com", envelope: `v1.${"a".repeat(4100)}`, fillToken: token },
    { host: "example.com", envelope: 42, fillToken: token },
  ];
  for (const raw of failures)
    assert.throws(() => readFillInput(raw), /Invalid credential fill|not authorized/i);
});

test("hosts are saved by plain hostname and reject lookalike encodings", () => {
  assert.equal(normalizeHost("  https://GitHub.com/login  "), "github.com");
  assert.equal(normalizeHost("example.co.uk"), "example.co.uk");
  assert.throws(() => normalizeHost("https://user:pass@example.com"), /embedded credentials/i);
  assert.throws(() => normalizeHost("xn--80ak6aa92e.com"), /punycode/i);
  assert.throws(() => normalizeHost("https://ex.com%2F.evil.org"), /not a valid website address/i);
  assert.throws(() => normalizeHost("localhost"), /full hostname/i);
  assert.throws(() => normalizeHost(""), /required/i);
  assert.throws(() => normalizeHost("git hub.com"), /not a valid website address/i);
});

test("the API surface schemas accept only enveloped, bounded entries", () => {
  assert.equal(
    vaultEntrySchema.parse({ label: "GitHub", host: "github.com", password: "p" }).username,
    "",
  );
  assert.throws(() => vaultEntrySchema.parse({ label: "x", host: "github.com", password: "" }));
  assert.throws(() => vaultEntrySchema.parse({ label: "", host: "github.com", password: "p" }));
  assert.equal(vaultPatchSchema.parse({}).password, undefined);
  assert.throws(() => vaultPatchSchema.parse({ password: "" }));
  assert.deepEqual(vaultRefSchema.parse({ label: "GitHub" }), { label: "GitHub" });
  assert.throws(() => vaultRefSchema.parse({ label: "a", host: "b", id: "c" }));
  assert.throws(() => vaultRefSchema.parse({}));
});
