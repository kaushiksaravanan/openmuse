import { mkdir, readdir, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { Browser, BrowserContext, Page } from "playwright";
import {
  capturePdfDownload,
  MAX_DOWNLOAD_BYTES,
  type PdfDownload,
  readDownloadFailures,
} from "./downloads.ts";
import { WorkerError } from "./errors.ts";
import { validatePublicUrl } from "./network.ts";
import { startEgressProxy } from "./proxy.ts";
import { decryptSecret, readFillInput, verifyFillToken } from "./vault.ts";

export interface Session {
  id: string;
  title: string;
  url: string;
  status: "active" | "closed" | "error";
  updatedAt: string;
}
type Running = {
  context: BrowserContext;
  page: Page;
  touched: number;
  pending: Set<Promise<void>>;
  downloadError?: boolean;
  // Set in desktop mode: the shared Chrome over CDP must never be closed with
  // the session; only this session's own page (tab) is.
  cdpBrowser?: Browser;
};
const SESSION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function validateSessionId(id: unknown): string {
  if (typeof id !== "string" || !SESSION_ID.test(id))
    throw new WorkerError("INVALID_SESSION", "A valid UUID session ID is required.");
  return id.toLowerCase();
}

export async function createBrowserManager(
  options: {
    dataDir: string;
    maxSessions?: number;
    idleTimeoutMs?: number;
    vaultKey?: string;
  },
  createProxy = startEgressProxy,
) {
  const { dataDir, maxSessions = 3, idleTimeoutMs = 30 * 60_000, vaultKey } = options;
  await mkdir(dataDir, { recursive: true, mode: 0o700 });
  const sessions = new Map<string, Session>();
  const running = new Map<string, Running>();
  const queues = new Map<string, Promise<unknown>>();
  const proxy = await createProxy();
  for (const id of await readdir(dataDir)) {
    if (!SESSION_ID.test(id)) continue;
    try {
      const stored = JSON.parse(
        await readFile(join(dataDir, id, "session.json"), "utf8"),
      ) as Session;
      sessions.set(id, { ...stored, id, status: "closed" });
    } catch {
      /* An incomplete first launch has no session metadata to restore. */
    }
    if (sessions.has(id)) await readDownloadFailures(join(dataDir, id), true);
  }
  const directory = (id: string) => join(dataDir, validateSessionId(id));
  async function persist(session: Session) {
    const path = join(directory(session.id), "session.json");
    await writeFile(`${path}.tmp`, JSON.stringify(session), { mode: 0o600 });
    await rename(`${path}.tmp`, path);
  }
  async function serial<T>(id: string, fn: () => Promise<T>): Promise<T> {
    const previous = queues.get(id) ?? Promise.resolve();
    const next = previous.catch(() => {}).then(fn);
    queues.set(id, next);
    try {
      return await next;
    } finally {
      if (queues.get(id) === next) queues.delete(id);
    }
  }
  function active(id: string) {
    const value = running.get(id);
    if (!value || value.page.isClosed())
      throw new WorkerError(
        "SESSION_CLOSED",
        "Open this browser session before using its console.",
        409,
      );
    value.touched = Date.now();
    return value;
  }
  async function refresh(id: string) {
    const instance = active(id);
    if (instance.page.url() !== "about:blank") await validatePublicUrl(instance.page.url());
    const session: Session = {
      id,
      title: (await instance.page.title()).slice(0, 300),
      url: instance.page.url(),
      status: "active",
      updatedAt: new Date().toISOString(),
    };
    sessions.set(id, session);
    await persist(session);
    return session;
  }
  async function downloads(id: string): Promise<PdfDownload[]> {
    if (!sessions.has(id))
      throw new WorkerError("SESSION_NOT_FOUND", "Browser session not found.", 404);
    const folder = join(directory(id), "downloads");
    await mkdir(folder, { recursive: true, mode: 0o700 });
    const list: PdfDownload[] = [];
    for (const name of await readdir(folder)) {
      if (!name.endsWith(".json")) continue;
      const item = JSON.parse(await readFile(join(folder, name), "utf8")) as PdfDownload;
      list.push(item);
    }
    return list;
  }
  async function navigate(id: string, url: string) {
    const target = await validatePublicUrl(url);
    const { page } = active(id);
    try {
      await page.goto(target.url.href, { waitUntil: "domcontentloaded", timeout: 20_000 });
      // Chromium can follow redirects outside Playwright's initial route hook.
      // The proxy blocks those sockets, but its 403 is still an HTTP response:
      // validate the final location so the API does not report it as success.
      await validatePublicUrl(page.url());
    } catch (error) {
      if (error instanceof WorkerError && error.code === "BLOCKED_URL") {
        await page.goto("about:blank", { timeout: 5000 });
      }
      // A successful attachment intentionally aborts page navigation.
      if (!(error instanceof Error && /Download is starting/.test(error.message))) {
        throw new WorkerError(
          "NAVIGATION_FAILED",
          "The page could not be loaded. It may be unreachable or contain a blocked destination.",
          502,
        );
      }
    }
    return refresh(id);
  }
  async function closeSession(id: string) {
    const instance = running.get(id);
    const stored = sessions.get(id);
    if (!stored) throw new WorkerError("SESSION_NOT_FOUND", "Browser session not found.", 404);
    if (instance) {
      if (instance.cdpBrowser) {
        // Desktop mode tears down only this session's tab; the shared visible
        // browser (and its logged-in profile) keeps running.
        await instance.page.close().catch(() => {});
      } else {
        try {
          await instance.context.storageState({ path: join(directory(id), "storage.json") });
        } catch {
          // Cookie persistence is best-effort during teardown. A crashed or
          // unreachable browser must still release its context and session slot.
        }
        await instance.context.close().catch(() => {});
      }
      await Promise.allSettled(instance.pending);
      running.delete(id);
    }
    const result: Session = { ...stored, status: "closed", updatedAt: new Date().toISOString() };
    sessions.set(id, result);
    await persist(result);
    return result;
  }
  // Self-contained page script: Playwright serializes only the function source,
  // so nothing here may capture a Node-side variable.
  const discoverFields = () => {
    const visible = (el: HTMLElement) =>
      !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);
    const mark = (el: HTMLElement | null) => {
      if (!el) return null;
      const uid = `f${Math.random().toString(36).slice(2, 10)}`;
      el.setAttribute("data-openmuse-fill", uid);
      return uid;
    };
    const inputs = Array.from(document.querySelectorAll<HTMLInputElement>("input")).filter(
      (el) => !el.disabled && !el.readOnly && visible(el) && el.type !== "hidden",
    );
    const password = inputs.find((el) => el.type === "password") ?? null;
    const username = password
      ? (inputs.find(
          (el) =>
            el !== password &&
            (el.autocomplete === "username" ||
              el.autocomplete === "email" ||
              el.type === "email" ||
              (el.type === "text" &&
                /user|login|email/i.test(`${el.id} ${el.name} ${el.placeholder}`))),
        ) ?? null)
      : null;
    const submit: HTMLElement | null = password?.form
      ? (Array.from(
          password.form.querySelectorAll<HTMLButtonElement | HTMLInputElement>(
            "button,input[type=submit]",
          ),
        ).find(
          (el) =>
            !el.disabled &&
            ((el instanceof HTMLButtonElement && el.type === "submit") ||
              (el instanceof HTMLInputElement && el.type === "submit")),
        ) ?? null)
      : null;
    return { password: mark(password), username: mark(username), submit: mark(submit) };
  };
  const clearMarkers = () => {
    for (const el of Array.from(document.querySelectorAll("[data-openmuse-fill]")))
      el.removeAttribute("data-openmuse-fill");
  };
  async function focusAndType(id: string, uid: string, text: string) {
    const { page } = active(id);
    await page.locator(`[data-openmuse-fill="${uid}"]`).evaluate((el: HTMLElement) => {
      el.focus();
    });
    // Trusted input events, the same channel as the console: the plaintext is
    // never set through a JS value assignment and never returns with the response.
    await page.keyboard.insertText(text);
  }
  // Pointer bounds follow the live page viewport (a desktop-browser attach is
  // larger than 1280x800), so coordinates stay 1:1 with the screenshot.
  async function inputCredentials(id: string, input: Record<string, unknown>) {
    const { page } = active(id);
    const { type, x, y, key, text, deltaY } = input;
    const viewport = page.viewportSize() ?? { width: 1280, height: 800 };
    const point = (value: unknown, max: number): value is number =>
      typeof value === "number" && Number.isFinite(value) && value >= 0 && value < max;
    const pressable =
      /^(Enter|Tab|Escape|Backspace|Delete|Insert|Space|ArrowUp|ArrowDown|ArrowLeft|ArrowRight|Home|End|PageUp|PageDown|Control\+a|Control\+c|Control\+v|Control\+l|Control\+t|Control\+w|Meta\+a|Shift\+Tab)$/;
    if (type === "click" && point(x, viewport.width) && point(y, viewport.height))
      await page.mouse.click(x, y);
    else if (type === "double_click" && point(x, viewport.width) && point(y, viewport.height))
      await page.mouse.dblclick(x, y);
    else if (type === "right_click" && point(x, viewport.width) && point(y, viewport.height))
      await page.mouse.click(x, y, { button: "right" });
    else if (type === "move" && point(x, viewport.width) && point(y, viewport.height))
      await page.mouse.move(x, y);
    else if (type === "text" && typeof text === "string" && text.length <= 10_000)
      await page.keyboard.insertText(text);
    else if (type === "key" && typeof key === "string" && pressable.test(key))
      await page.keyboard.press(key);
    else if (
      type === "scroll" &&
      typeof deltaY === "number" &&
      Number.isFinite(deltaY) &&
      Math.abs(deltaY) <= 5000
    )
      await page.mouse.wheel(0, deltaY);
    else throw new WorkerError("INVALID_INPUT", "Unsupported browser input or coordinates.");
    return refresh(id);
  }
  async function fillCredentials(id: string, raw: Record<string, unknown>) {
    if (!vaultKey)
      throw new WorkerError("FILL_NOT_CONFIGURED", "Credential fill requires a VAULT_KEY.", 503);
    const input = readFillInput(raw);
    const { page } = active(id);
    const pageHost = new URL(page.url()).hostname.toLowerCase();
    if (pageHost !== input.host)
      throw new WorkerError(
        "FILL_HOST_MISMATCH",
        "The current page does not match this saved login's site.",
        409,
      );
    verifyFillToken(input.fillToken, id, input.host, vaultKey);
    let password: string;
    try {
      // Decryption happens here, in the browser worker: the plaintext is never
      // materialized in the API or any tool response.
      password = decryptSecret(input.envelope, vaultKey);
    } catch {
      throw new WorkerError(
        "FILL_INVALID_ENVELOPE",
        "The encrypted credential could not be read.",
        400,
      );
    }
    const fields = await page.evaluate(discoverFields);
    const filled = { username: false, password: false };
    let submitted = false;
    const clear = () => page.evaluate(clearMarkers).catch(() => {});
    try {
      if (!fields.password)
        throw new WorkerError("FILL_NO_FIELD", "No login form is visible on this page.", 422);
      if (input.username && fields.username) {
        await focusAndType(id, fields.username, input.username);
        filled.username = true;
      }
      await focusAndType(id, fields.password, password);
      filled.password = true;
      if (input.submit && fields.submit)
        submitted = !!(await page
          .locator(`[data-openmuse-fill="${fields.submit}"]`)
          .click()
          .then(() => true)
          .catch(() => false));
    } catch (error) {
      await clear();
      throw error;
    }
    await clear();
    return { filled, submitted, host: input.host };
  }
  async function createSession(id: string, url: string) {
    await validatePublicUrl(url);
    if (running.has(id)) return navigate(id, url);
    if (running.size >= maxSessions)
      throw new WorkerError(
        "SESSION_LIMIT",
        `Close an active session before opening another (limit ${maxSessions}).`,
        409,
      );
    if (!sessions.has(id) && sessions.size >= 20)
      throw new WorkerError(
        "PROFILE_LIMIT",
        "The worker has reached its 20 saved-profile limit.",
        409,
      );
    const previous = sessions.get(id);
    const profileDir = join(directory(id), "profile");
    const tempDirectory = join("/tmp", `openmuse-downloads-${id}`);
    await mkdir(profileDir, { recursive: true, mode: 0o700 });
    await mkdir(tempDirectory, { recursive: true, mode: 0o700 });
    let context: BrowserContext;
    // Desktop mode attaches to the visible Chrome (anti-bot stealth binary,
    // the user's own logged-in profile) instead of launching a private
    // headless context.
    const cdpEndpoint = process.env.WORKER_CDP_ENDPOINT?.trim() || undefined;
    let cdpBrowser: Browser | undefined;
    try {
      const { chromium } = await import("playwright");
      if (cdpEndpoint) {
        cdpBrowser = await chromium.connectOverCDP(cdpEndpoint, { timeout: 25_000 });
        const shared = cdpBrowser.contexts()[0];
        if (!shared) {
          throw new WorkerError(
            "BROWSER_UNAVAILABLE",
            "The desktop browser has no open profile context yet.",
            503,
          );
        }
        context = shared;
      } else {
        // CloakBrowser stealth Chromium when CLOAK_EXECUTABLE_PATH points at its
        // binary; the bundled Playwright build stays the fallback for tests and
        // local development so they never need the extra download.
        const cloakExecutable = process.env.CLOAK_EXECUTABLE_PATH?.trim() || undefined;
        context = await chromium.launchPersistentContext(profileDir, {
          // Chromium does not need the worker API credential in its environment.
          env: {
            HOME: process.env.HOME ?? "/tmp",
            PATH: process.env.PATH ?? "/usr/bin:/bin",
            LANG: "C.UTF-8",
          },
          headless: true,
          ...(cloakExecutable ? { executablePath: cloakExecutable } : {}),
          viewport: { width: 1280, height: 800 },
          proxy: { server: proxy.url, bypass: "<-loopback>" },
          serviceWorkers: "block",
          acceptDownloads: true,
          downloadsPath: tempDirectory,
          timeout: 25_000,
          args: [
            "--disable-quic",
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
            "--disable-extensions",
            "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
          ],
        });
      }
    } catch (error) {
      // A CDP attach failure must only disconnect; the shared visible browser
      // and its tabs must never be closed from here.
      await cdpBrowser?.close().catch(() => {});
      cdpBrowser = undefined;
      if (!previous) await rm(directory(id), { recursive: true, force: true });
      await rm(tempDirectory, { recursive: true, force: true });
      if (error instanceof WorkerError) throw error;
      throw new WorkerError(
        "BROWSER_UNAVAILABLE",
        "Chromium could not start. Rebuild the browser-worker image and check its resource limits.",
        503,
      );
    }
    try {
      const statePath = join(directory(id), "storage.json");
      if (!cdpBrowser) {
        try {
          const state = JSON.parse(await readFile(statePath, "utf8")) as Awaited<
            ReturnType<BrowserContext["storageState"]>
          >;
          await context.addCookies(state.cookies);
        } catch (error) {
          if (!(error instanceof Error && "code" in error && error.code === "ENOENT")) throw error;
        }
        await context.route("**/*", async (route) => {
          try {
            await validatePublicUrl(route.request().url());
            await route.continue();
          } catch {
            await route.abort("blockedbyclient").catch(() => {});
          }
        });
        await context.routeWebSocket("**/*", (socket) => socket.close());
        for (const old of context.pages()) await old.close();
      }
      // Desktop mode leaves existing tabs alone: only the page this session
      // opens below is owned by the session.
      const page = await context.newPage();
      page.setDefaultTimeout(10_000);
      const instance: Running = { context, page, touched: Date.now(), pending: new Set() };
      if (cdpBrowser) instance.cdpBrowser = cdpBrowser;
      running.set(id, instance);
      if (!cdpBrowser)
        context.on("page", (popup) => {
          void popup.close();
        });
      page.on("dialog", (dialog) => {
        void dialog.dismiss();
      });
      page.on("download", (download) => {
        const pending = downloads(id).then((saved) =>
          capturePdfDownload({
            directory: directory(id),
            tempDirectory,
            download,
            limitReached: saved.length + instance.pending.size > 20,
          }),
        );
        instance.pending.add(pending);
        void pending.then(
          () => instance.pending.delete(pending),
          () => {
            instance.downloadError = true;
            instance.pending.delete(pending);
          },
        );
      });
      const initial: Session = {
        id,
        title: previous?.title ?? "New session",
        url,
        status: "active",
        updatedAt: new Date().toISOString(),
      };
      sessions.set(id, initial);
      await persist(initial);
      return await navigate(id, url);
    } catch (error) {
      await Promise.allSettled(running.get(id)?.pending ?? []);
      if (cdpBrowser) {
        // The tab, not the shared browser, is this session's failure surface.
        const created = running.get(id);
        if (created) await created.page.close().catch(() => {});
        await cdpBrowser.close().catch(() => {});
      } else {
        await context.close().catch(() => {});
      }
      running.delete(id);
      if (previous) {
        const failed: Session = {
          ...previous,
          url,
          status: "error",
          updatedAt: new Date().toISOString(),
        };
        sessions.set(id, failed);
        await persist(failed);
      } else {
        sessions.delete(id);
        await rm(directory(id), { recursive: true, force: true });
      }
      await rm(tempDirectory, { recursive: true, force: true });
      throw error;
    }
  }
  const sweeper = setInterval(() => {
    for (const [id, instance] of running)
      if (Date.now() - instance.touched > idleTimeoutMs) {
        void serial(id, () => closeSession(id)).catch(() => {});
      }
  }, 60_000);
  sweeper.unref();
  return {
    list: () => [...sessions.values()],
    create: (id: string, url: string) =>
      serial("create", () => serial(id, () => createSession(id, url))),
    navigate: (id: string, url: string) => serial(id, () => navigate(id, url)),
    closeSession: (id: string) => serial(id, () => closeSession(id)),
    screenshot: (id: string) =>
      serial(id, () => active(id).page.screenshot({ type: "png", timeout: 10_000 })),
    read: (id: string) =>
      serial(id, async () => {
        const { page } = active(id);
        await validatePublicUrl(page.url());
        // Evaluation is fixed by the worker; callers cannot inject JavaScript.
        const result = await page.evaluate(() => {
          const text = document.body?.innerText ?? "";
          return {
            url: location.href,
            title: document.title.slice(0, 300),
            text: text.slice(0, 100_000),
            truncated: text.length > 100_000,
          };
        });
        await validatePublicUrl(result.url);
        const session: Session = {
          id,
          url: result.url,
          title: result.title,
          status: "active",
          updatedAt: new Date().toISOString(),
        };
        sessions.set(id, session);
        await persist(session);
        return result;
      }),
    input: (id: string, input: Record<string, unknown>) =>
      serial(id, () => inputCredentials(id, input)),
    fill: (id: string, raw: Record<string, unknown>) => serial(id, () => fillCredentials(id, raw)),
    downloads: async (id: string) => {
      const saved = await downloads(id);
      if (running.get(id)?.downloadError)
        throw new WorkerError(
          "DOWNLOAD_STORE_FAILED",
          "A download outcome could not be saved. Check worker storage and try again.",
          500,
        );
      return { downloads: saved, failures: await readDownloadFailures(directory(id)) };
    },
    download: async (id: string, downloadId: string) => {
      validateSessionId(downloadId);
      const metadata = (await downloads(id)).find((item) => item.id === downloadId);
      if (!metadata) throw new WorkerError("DOWNLOAD_NOT_FOUND", "PDF download not found.", 404);
      const path = join(directory(id), "downloads", `${downloadId}.pdf`);
      const info = await stat(path);
      if (info.size > MAX_DOWNLOAD_BYTES)
        throw new WorkerError("DOWNLOAD_TOO_LARGE", "The PDF exceeds 10 MiB.", 413);
      return { metadata, bytes: await readFile(path) };
    },
    close: async () => {
      clearInterval(sweeper);
      await Promise.allSettled([...queues.values()]);
      await Promise.allSettled([...running.keys()].map(closeSession));
      await proxy.close();
    },
  };
}
