import { createHash, randomBytes, randomUUID } from "node:crypto";
import { z } from "zod";
import { decryptSecret, encryptSecret } from "../../../packages/integrations/src/vault.ts";
import { mintFillToken } from "../../worker/src/vault.ts";
import type { BrowserService } from "./browser.ts";
import type { Config } from "./config.ts";
import type { Store } from "./db.ts";
import { AppError } from "./errors.ts";

export const vaultEntrySchema = z.object({
  label: z.string().trim().min(1).max(200),
  host: z.string().trim().min(1).max(253),
  username: z.string().trim().max(320).default(""),
  password: z.string().min(1).max(1024),
});
export const vaultPatchSchema = z.object({
  label: z.string().trim().min(1).max(200).optional(),
  username: z.string().trim().max(320).optional(),
  password: z.string().min(1).max(1024).optional(),
});

export const vaultSessionId =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/** Stored rows live in the owner-scoped "credentials" kind beside the Google tokens. */
export interface StoredEntry {
  id: string;
  label: string;
  host: string;
  username: string;
  secret: string;
  createdAt: string;
}
export interface VaultEntryMeta {
  id: string;
  label: string;
  host: string;
  username: string;
  createdAt: string;
}
export interface PendingFill {
  id: string;
  vaultId: string;
  host: string;
  sessionId: string;
  submit: boolean;
  status: "pending" | "executing" | "succeeded" | "failed" | "denied" | "expired";
  createdAt: string;
  expiresAt: string;
}

const HOSTNAME = /^[a-z\d]+(?:-[a-z\d]+)*(?:\.[a-z\d]+(?:-[a-z\d]+)*)+$/;
const PENDING_TTL = 15 * 60_000;

/**
 * Save a site by hostname only: reject embedded credentials, IDs and homograph
 * twins so a fill can be bound to the exact host the entry was saved for.
 */
export function normalizeHost(input: string): string {
  const trimmed = input.trim().toLowerCase();
  if (!trimmed) throw new AppError("A website address is required");
  if (trimmed.length > 253) throw new AppError("That website address is too long");
  if (!trimmed.includes(".")) throw new AppError("Save a full hostname, for example github.com");
  let hostname: string;
  try {
    const url = new URL(trimmed.includes("://") ? trimmed : `https://${trimmed}`);
    if (url.protocol !== "https:" && url.protocol !== "http:")
      throw new AppError("Only http and https website addresses are saved");
    if (url.username)
      throw new AppError("Website addresses with embedded credentials are not saved");
    hostname = url.hostname;
  } catch (error) {
    if (error instanceof AppError) throw error;
    throw new AppError("That is not a valid website address");
  }
  if (!HOSTNAME.test(hostname) || hostname.includes(".."))
    throw new AppError(
      "Save the site by its normal hostname, for example github.com — encoded or punycode names are rejected",
    );
  if (hostname.split(".").some((label) => label.startsWith("xn--")))
    throw new AppError(
      "Internationalized (punycode) addresses are rejected to avoid lookalike sites",
    );
  return hostname;
}

export const vaultRefSchema = z.union([
  z.strictObject({ id: z.string().min(1).max(300) }),
  z.strictObject({ label: z.string().trim().min(1).max(200) }),
  z.strictObject({ host: z.string().trim().min(1).max(253) }),
]);
export type SiteRef = z.infer<typeof vaultRefSchema>;

/** Kinds whose stored values must never contain a credential. */
const AUDIT_KINDS = [
  "activity",
  "agent-settings",
  "browsers",
  "browser-downloads",
  "chat-browsers",
  "conversation-settings",
  "conversations",
  "drafts",
  "files",
  "goals",
  "ideas",
  "memories",
  "monitors",
  "notifications",
  "sessions",
  "tasks",
  "vault-fills",
] as const;

/** A login fill must stay far below brute-force territory. */
const FILL_LIMIT_WINDOW = 10; // ten-minute slots
const FILL_LIMIT_WINDOW_MAX = 5;
const FILL_LIMIT_DAY_MAX = 30;

/**
 * The credential broker: the only component that may hold a saved password's
 * envelope, and the only one that hands it (encrypted) to the browser worker.
 * Its public surface never returns secret material, and every fill is bound to
 * a worker-matched hostname with a ten-second one-use token.
 */
export class VaultService {
  private fillWindows = new Map<
    string,
    { window: number; count: number; day: number; dayStamp: number }
  >();

  constructor(
    private readonly db: Store,
    private readonly config: Config,
    private readonly browser: BrowserService,
  ) {}

  configured(): boolean {
    return Boolean(this.config.vaultKey && this.config.workerUrl && this.config.workerToken);
  }
  private get key(): string {
    const key = this.config.vaultKey;
    if (!key) throw new AppError("Set VAULT_KEY (32-byte base64) to use the vault", 503);
    const bytes = Buffer.from(key, "base64");
    if (bytes.length !== 32 || bytes.toString("base64") !== key)
      throw new AppError("VAULT_KEY must be 32 random bytes encoded as base64", 503);
    return key;
  }
  private meta(entry: StoredEntry): VaultEntryMeta {
    return {
      id: entry.id,
      label: entry.label,
      host: entry.host,
      username: entry.username,
      createdAt: entry.createdAt,
    };
  }
  private async entries(owner: string): Promise<StoredEntry[]> {
    const rows = await this.db.list<StoredEntry>(owner, "credentials");
    return rows.filter(
      (row) =>
        row.id.startsWith("site:") &&
        row.id !== "site:canary.invalid" &&
        typeof row.host === "string",
    );
  }
  private async entry(owner: string, id: string): Promise<StoredEntry> {
    if (!id.startsWith("site:")) throw new AppError("Vault entry not found", 404);
    const stored = await this.db.get<StoredEntry>(owner, "credentials", id);
    if (!stored || typeof stored.secret !== "string")
      throw new AppError("Vault entry not found", 404);
    return stored;
  }

  async list(owner: string): Promise<VaultEntryMeta[]> {
    return (await this.entries(owner)).map((entry) => this.meta(entry));
  }
  async create(owner: string, input: z.infer<typeof vaultEntrySchema>): Promise<VaultEntryMeta> {
    const key = this.key;
    const host = normalizeHost(input.host);
    const entry: StoredEntry = {
      id: `site:${host}`,
      label: input.label,
      host,
      username: input.username,
      secret: encryptSecret(input.password, key),
      createdAt: new Date().toISOString(),
    };
    const existing = await this.db.get<StoredEntry>(owner, "credentials", entry.id);
    if (existing) throw new AppError(`A login for ${host} is already saved`, 409);
    await this.db.put(owner, "credentials", entry);
    await this.ensureCanary(owner);
    return this.meta(entry);
  }
  async update(owner: string, id: string, patch: z.infer<typeof vaultPatchSchema>) {
    const key = this.key;
    const entry = await this.entry(owner, id);
    const updated: StoredEntry = {
      ...entry,
      label: patch.label ?? entry.label,
      username: patch.username ?? entry.username,
      secret: patch.password ? encryptSecret(patch.password, key) : entry.secret,
    };
    await this.db.put(owner, "credentials", updated);
    return this.meta(updated);
  }
  async remove(owner: string, id: string): Promise<void> {
    await this.entry(owner, id);
    await this.db.remove(owner, "credentials", id);
    for (const fill of await this.db.list<PendingFill>(owner, "vault-fills"))
      if (fill.vaultId === id && fill.status === "pending")
        await this.db.remove(owner, "vault-fills", fill.id);
  }

  private async resolve(owner: string, rawRef: unknown): Promise<StoredEntry> {
    const ref = vaultRefSchema.parse(rawRef);
    const entries = await this.entries(owner);
    if ("id" in ref) {
      const match = entries.find((entry) => entry.id === ref.id);
      if (match) return match;
      throw new AppError("Vault entry not found", 404);
    }
    if ("label" in ref) {
      const matches = entries.filter(
        (entry) => entry.label.toLowerCase() === ref.label.toLowerCase(),
      );
      if (matches.length > 1)
        throw new AppError(
          "More than one saved login uses that label. Name the site instead.",
          409,
        );
      if (matches.length === 1) return matches[0];
    }
    if ("host" in ref || "label" in ref) {
      const host = normalizeHost("host" in ref ? ref.host : (ref.label as string));
      const match = entries.find((entry) => entry.host === host);
      if (match) return match;
    }
    throw new AppError("No saved login matches that site", 404);
  }

  /** Chat helpers: resolve a saved entry reference into its metadata (never its secret). */
  async findByRef(owner: string, rawRef: unknown): Promise<VaultEntryMeta> {
    return this.meta(await this.resolve(owner, rawRef));
  }

  private assertRate(owner: string, host: string): void {
    const now = Date.now();
    const stamp = Math.floor(now / (FILL_LIMIT_WINDOW * 60_000));
    const dayStamp = Math.floor(now / 86_400_000);
    const bucket = this.fillWindows.get(`${owner}:${host}`) ?? {
      window: stamp,
      count: 0,
      day: 0,
      dayStamp,
    };
    if (bucket.window !== stamp) {
      bucket.window = stamp;
      bucket.count = 0;
    }
    if (bucket.dayStamp !== dayStamp) {
      bucket.dayStamp = dayStamp;
      bucket.day = 0;
    }
    if (bucket.count >= FILL_LIMIT_WINDOW_MAX)
      throw new AppError(
        "Too many login attempts for this site. Wait before requesting another fill.",
        429,
      );
    if (bucket.day >= FILL_LIMIT_DAY_MAX)
      throw new AppError(
        "This site reached its daily login attempt limit. Try again tomorrow or fill it yourself.",
        429,
      );
    bucket.count += 1;
    bucket.day += 1;
    this.fillWindows.set(`${owner}:${host}`, bucket);
  }

  private async record(
    owner: string,
    title: string,
    detail: string,
    status: string,
  ): Promise<void> {
    await this.db.put(owner, "activity", {
      id: randomUUID(),
      title,
      detail,
      date: new Date().toISOString(),
      status,
    });
  }

  private assertFillInput(sessionId: string): void {
    if (!vaultSessionId.test(sessionId))
      throw new AppError("That browser session no longer exists", 404);
  }

  /**
   * Chat path: mint a pending fill for approval in the app. Never executes;
   * returns only identifiers, hostnames and statuses.
   */
  async request(
    owner: string,
    rawRef: unknown,
    sessionId: string,
    submit: boolean,
  ): Promise<{ status: "needs_approval"; fillId: string; host: string; label: string }> {
    const entry = await this.resolve(owner, rawRef);
    this.assertRate(owner, entry.host);
    this.assertFillInput(sessionId);
    await this.browser.get(owner, sessionId);
    const fill: PendingFill = {
      id: randomUUID(),
      vaultId: entry.id,
      host: entry.host,
      sessionId,
      submit,
      status: "pending",
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + PENDING_TTL).toISOString(),
    };
    await this.db.put(owner, "vault-fills", fill);
    await this.record(
      owner,
      `Login fill · ${entry.host}`,
      "Requested in chat; awaiting your approval",
      "awaiting_review",
    );
    return { status: "needs_approval", fillId: fill.id, host: entry.host, label: entry.label };
  }

  private async executeFill(
    owner: string,
    fill: { host: string; vaultId: string; sessionId: string; submit: boolean },
  ): Promise<{ status: "filled"; host: string }> {
    const entry = await this.entry(owner, fill.vaultId);
    const fillToken = mintFillToken(this.key, fill.sessionId, entry.host);
    // The envelope crosses this boundary already encrypted; the worker is the
    // only process that turns it back into plaintext, inside Chromium's own call.
    const result = await this.browser.fill(owner, fill.sessionId, {
      host: entry.host,
      username: entry.username || undefined,
      envelope: entry.secret,
      fillToken,
      submit: fill.submit,
    });
    await this.record(
      owner,
      `Login fill · ${entry.host}`,
      fill.submit ? "Filled and submitted the login" : "Filled the login",
      "succeeded",
    );
    return { status: "filled", host: result.host };
  }

  /** Direct path for the user's own request in the app. */
  async fillNow(owner: string, rawRef: unknown, sessionId: string, submit: boolean) {
    const entry = await this.resolve(owner, rawRef);
    this.assertRate(owner, entry.host);
    this.assertFillInput(sessionId);
    await this.browser.get(owner, sessionId);
    const result = await this.executeFill(owner, {
      vaultId: entry.id,
      host: entry.host,
      sessionId,
      submit,
    });
    return { ...result, label: entry.label };
  }
  async decide(owner: string, id: string, decision: "approve" | "deny") {
    const pending = await this.db.get<PendingFill>(owner, "vault-fills", id);
    if (!pending) throw new AppError("Login request not found", 404);
    if (pending.status === "denied")
      throw new AppError("This request was already declined. Request a fresh fill.", 409);
    if (pending.status === "expired")
      throw new AppError("This request expired. Request a fresh fill.", 409);
    if (decision === "deny") {
      const denied = await this.db.compareAndSwap<PendingFill>(
        owner,
        "vault-fills",
        id,
        { status: "pending" },
        { status: "denied" },
      );
      if (!denied) {
        const current = await this.db.get<PendingFill>(owner, "vault-fills", id);
        if (!current) throw new AppError("Login request not found", 404);
        throw new AppError("This request was already handled.", 409);
      }
      await this.record(
        owner,
        `Login fill · ${pending.host}`,
        "Declined; no credentials were used",
        "denied",
      );
      return { status: "denied", host: pending.host };
    }
    if (Date.parse(pending.expiresAt) <= Date.now()) {
      await this.db.compareAndSwap<PendingFill>(
        owner,
        "vault-fills",
        id,
        { status: "pending" },
        { status: "expired" },
      );
      throw new AppError("This request expired. Request a fresh fill.", 409);
    }
    const claimed = await this.db.compareAndSwap<PendingFill>(
      owner,
      "vault-fills",
      id,
      { status: "pending" },
      { status: "executing" },
    );
    if (!claimed) {
      const current = await this.db.get<PendingFill>(owner, "vault-fills", id);
      throw new AppError(`This request is already ${current?.status ?? "handled"}.`, 409);
    }
    try {
      const result = await this.executeFill(owner, claimed);
      await this.db.compareAndSwap<PendingFill>(
        owner,
        "vault-fills",
        id,
        { status: "executing" },
        { status: "succeeded" },
      );
      return result;
    } catch (error) {
      await this.db.compareAndSwap<PendingFill>(
        owner,
        "vault-fills",
        id,
        { status: "executing" },
        { status: "failed" },
      );
      await this.record(
        owner,
        `Login fill · ${claimed.host}`,
        "Fill failed on the page; no credentials were exposed",
        "failed",
      );
      throw error instanceof AppError
        ? error
        : new AppError("The login could not be filled on this page", 502);
    }
  }

  /**
   * Isolation audit: a decoy password is scanned against every stored surface
   * the agent or the app can write. Any hit is an alarm, not a credential leak
   * of a real login, and proves whether a read or exfiltration path exists.
   */
  async audit(
    owner: string,
  ): Promise<{ checked: boolean; leaked: boolean; kind?: string; id?: string }> {
    await this.ensureCanary(owner);
    const canary = await this.db.get<StoredEntry>(owner, "credentials", "site:canary.invalid");
    if (!canary) return { checked: false, leaked: false };
    let secret: string;
    try {
      secret = decryptSecret(canary.secret, this.key);
    } catch {
      return { checked: false, leaked: false };
    }
    for (const kind of AUDIT_KINDS) {
      for (const { owner: rowOwner, value } of await this.db.scan<Record<string, unknown>>(kind)) {
        if (rowOwner !== owner) continue;
        if (JSON.stringify(value).includes(secret)) {
          const id = typeof value.id === "string" ? value.id : "unknown";
          await this.db.insertIfAbsent(owner, "notifications", {
            id: createHash("sha256").update(`canary-leak:${kind}:${id}`).digest("hex"),
            title: "Credential isolation alarm",
            body: "The vault decoy password appeared in stored agent data. Investigate immediately.",
            createdAt: new Date().toISOString(),
            read: false,
          });
          await this.record(
            owner,
            "Credential isolation alarm",
            `The vault decoy password appeared in stored ${kind}.`,
            "failed",
          );
          return { checked: true, leaked: true, kind, id };
        }
      }
    }
    return { checked: true, leaked: false };
  }

  private async ensureCanary(owner: string): Promise<void> {
    try {
      const existing = await this.db.get<StoredEntry>(owner, "credentials", "site:canary.invalid");
      if (existing) return;
      await this.db.put(owner, "credentials", {
        id: "site:canary.invalid",
        label: "Audit decoy — the agent never fills this",
        host: "canary.invalid",
        username: "",
        secret: encryptSecret(`openmuse-canary-${randomBytes(16).toString("hex")}`, this.key),
        createdAt: new Date().toISOString(),
      });
    } catch {
      // The vault may be unconfigured during teardown; the audit skips in that case.
    }
  }
}
