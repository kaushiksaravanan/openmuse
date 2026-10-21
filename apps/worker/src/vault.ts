import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import { WorkerError } from "./errors.ts";

/**
 * Local copy of packages/integrations/src/vault.ts. The worker image copies only
 * its own src folder, so the credential-broker carries its own decrypt code.
 */
function decodeKey(key: string): Buffer {
  const bytes = Buffer.from(key, "base64");
  if (bytes.length !== 32 || bytes.toString("base64") !== key) {
    throw new Error("Credential encryption requires a 32-byte base64 key");
  }
  return bytes;
}

export function decryptSecret(encrypted: string, key: string): string {
  const keyBytes = decodeKey(key);
  const [version, nonceString, tagString, ciphertextString, extra] = encrypted.split(".");
  if (
    version !== "v1" ||
    nonceString === undefined ||
    tagString === undefined ||
    ciphertextString === undefined ||
    extra !== undefined
  ) {
    throw new Error("Invalid encrypted secret");
  }
  const encoded = [nonceString, tagString, ciphertextString];
  const [nonce, tag, ciphertext] = encoded.map((value) => Buffer.from(value, "base64url"));
  if (
    nonce.length !== 12 ||
    tag.length !== 16 ||
    encoded.some(
      (value, index) => Buffer.from(value, "base64url").toString("base64url") !== encoded[index],
    )
  ) {
    throw new Error("Invalid encrypted secret");
  }
  const decipher = createDecipheriv("aes-256-gcm", keyBytes, nonce);
  decipher.setAAD(Buffer.from("openmuse:credential:v1"));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
}

export function encryptSecret(plaintext: string, key: string): string {
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", decodeKey(key), nonce);
  cipher.setAAD(Buffer.from("openmuse:credential:v1"));
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return [
    "v1",
    nonce.toString("base64url"),
    cipher.getAuthTag().toString("base64url"),
    ciphertext.toString("base64url"),
  ].join(".");
}

/**
 * A fill request is authorized for exactly one session, one hostname and ten
 * seconds. The worker verifies it before any credential material is decrypted.
 */
export function mintFillToken(
  key: string,
  sessionId: string,
  host: string,
  now = Date.now(),
): string {
  const expires = String(now + 10_000);
  const signature = createHmac("sha256", key)
    .update(`${sessionId}\n${host}\n${expires}`)
    .digest("base64url");
  return `${expires}.${signature}`;
}

export function verifyFillToken(token: string, sessionId: string, host: string, key: string): void {
  const unauthorized = () =>
    new WorkerError("FILL_TOKEN_INVALID", "The credential fill request was not authorized.", 403);
  const [expires, signature] = token.split(".");
  const now = Date.now();
  if (
    !signature ||
    !/^\d+$/.test(expires ?? "") ||
    Number(expires) < now ||
    Number(expires) > now + 15_000
  )
    throw unauthorized();
  const expected = createHmac("sha256", key)
    .update(`${sessionId}\n${host}\n${expires}`)
    .digest("base64url");
  if (Buffer.byteLength(signature) !== Buffer.byteLength(expected)) throw unauthorized();
  if (!timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) throw unauthorized();
}

export interface FillInput {
  host: string;
  username?: string;
  envelope: string;
  fillToken: string;
  submit: boolean;
}

const HOST = /^[a-z\d.-]{1,253}$/;

export function readFillInput(raw: Record<string, unknown>): FillInput {
  const fail = () => new WorkerError("INVALID_INPUT", "Invalid credential fill request.");
  const host = raw.host;
  if (typeof host !== "string" || !HOST.test(host.toLowerCase()) || host !== host.toLowerCase())
    throw fail();
  if (
    typeof raw.envelope !== "string" ||
    !raw.envelope.startsWith("v1.") ||
    raw.envelope.length > 4096
  )
    throw fail();
  if (typeof raw.fillToken !== "string" || raw.fillToken.length > 256) throw fail();
  if (raw.username === undefined) {
    // No username to type; the fill only enters the password.
  } else if (typeof raw.username !== "string" || raw.username.length > 320) {
    throw fail();
  }
  return {
    host,
    username: typeof raw.username === "string" ? raw.username : undefined,
    envelope: raw.envelope as string,
    fillToken: raw.fillToken,
    submit: raw.submit === true,
  };
}
