export interface Env {
  IMAGES: R2Bucket;

  ALLOWED_HOSTS: string; // comma-separated allowlist; fail-closed
  MAX_BYTES: string;     // e.g. "10485760"
  MAX_DIM: string;       // e.g. "4096"
  MAX_PIXELS: string;    // e.g. "16777216"
  CACHE_VERSION: string; // e.g. "v1"

  PURGE_TOKEN: string;   // required for purge endpoint
}

const COMMON_FORMATS: Array<"avif" | "webp" | "jpeg" | "png" | "orig"> = [
  "avif",
  "webp",
  "jpeg",
  "png",
  "orig",
];

function allowedHost(env: Env, host: string): boolean {
  const list = (env.ALLOWED_HOSTS || "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);

  // Fail closed: if unset, do NOT become an open proxy.
  if (list.length === 0) return false;

  host = host.toLowerCase();
  return list.some((allowed) => host === allowed || host.endsWith(`.${allowed}`));
}

function clampInt(n: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, Math.floor(n)));
}

function parseIntParam(reqUrl: URL, key: string, min: number, max: number): number | undefined {
  const v = reqUrl.searchParams.get(key);
  if (!v) return undefined;
  const n = Number(v);
  if (!Number.isFinite(n)) return undefined;
  return clampInt(n, min, max);
}

/**
 * Accept-based auto-format:
 * - If fmt is explicitly set, respect it (normalized)
 * - Else choose best supported by client: avif -> webp -> (orig)
 */
function negotiatedFormat(req: Request, reqUrl: URL): "avif" | "webp" | "jpeg" | "png" | "orig" {
  const explicit = (reqUrl.searchParams.get("fmt") || "").toLowerCase();
  if (explicit) {
    if (explicit === "jpg") return "jpeg";
    if (explicit === "avif" || explicit === "webp" || explicit === "jpeg" || explicit === "png") {
      return explicit as any;
    }
    if (explicit === "orig" || explicit === "original") return "orig";
  }

  const accept = (req.headers.get("Accept") || "").toLowerCase();
  if (accept.includes("image/avif")) return "avif";
  if (accept.includes("image/webp")) return "webp";
  return "orig";
}

async function sha256Hex(input: string): Promise<string> {
  const buf = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest("SHA-256", buf);
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * We must ensure cache keys vary by negotiated format and normalized transform params.
 * We do that by building an internal URL used for cache keying and hashing.
 */
function buildInternalCacheURL(reqUrl: URL, fmt: string, w?: number, h?: number, q?: number): URL {
  const u = new URL(reqUrl.toString());

  // Normalize transform params:
  // - Always set fmt (negotiated or explicit)
  // - Normalize w/h/q only if present
  u.searchParams.set("fmt", fmt);
  if (w) u.searchParams.set("w", String(w)); else u.searchParams.delete("w");
  if (h) u.searchParams.set("h", String(h)); else u.searchParams.delete("h");
  if (q) u.searchParams.set("q", String(q)); else u.searchParams.delete("q");

  return u;
}

async function readUpTo(resp: Response, maxBytes: number): Promise<ArrayBuffer> {
  const len = resp.headers.get("Content-Length");
  if (len && Number(len) > maxBytes) throw new Error("too_large");

  const buf = await resp.arrayBuffer();
  if (buf.byteLength > maxBytes) throw new Error("too_large");
  return buf;
}

function withCacheHeaders(resp: Response) {
  const h = new Headers(resp.headers);
  h.set("Cache-Control", "public, max-age=31536000, immutable");

  // Helpful for downstream/proxies; NOT relied on for caches.default keying
  h.set("Vary", "Accept");

  return new Response(resp.body, { status: resp.status, headers: h });
}

function isRedirect(status: number) {
  return status >= 300 && status < 400;
}

function requirePurgeAuth(req: Request, env: Env, reqUrl: URL): boolean {
  // Allow token in header OR query param
  const header = req.headers.get("X-Purge-Token") || "";
  const query = reqUrl.searchParams.get("token") || "";
  const token = header || query;
  return Boolean(env.PURGE_TOKEN) && token === env.PURGE_TOKEN;
}

async function computeKeys(env: Env, internalUrl: URL): Promise<{ edgeKey: string; r2Key: string }> {
  const edgeKey = internalUrl.toString();
  const version = env.CACHE_VERSION || "v1";
  const hash = await sha256Hex(`${version}::${edgeKey}`);
  const r2Key = `v/${version}/${hash}`;
  return { edgeKey, r2Key };
}

async function purgeVariant(env: Env, edgeKey: string, r2Key: string): Promise<void> {
  // Purge edge cache + R2 variant
  await caches.default.delete(edgeKey);
  await env.IMAGES.delete(r2Key);
}

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const reqUrl = new URL(req.url);

    // -------------------------
    // Purge endpoint (tooling)
    // -------------------------
    // POST /purge?url=...&w=...&h=...&q=...&fmt=avif|webp|jpeg|png|orig
    // Optional: &all=1 to purge common formats (avif/webp/jpeg/png/orig)
    if (reqUrl.pathname === "/purge") {
      if (req.method !== "POST") return new Response("Method Not Allowed", { status: 405 });
      if (!requirePurgeAuth(req, env, reqUrl)) return new Response("Forbidden", { status: 403 });

      const raw = reqUrl.searchParams.get("url");
      if (!raw) return new Response("Missing ?url=", { status: 400 });

      let sourceUrl: URL;
      try {
        sourceUrl = new URL(raw);
      } catch {
        return new Response("Invalid url", { status: 400 });
      }

      // For purge, still enforce allowlist so you don’t become a remote purge tool
      if ((sourceUrl.protocol !== "https:" && sourceUrl.protocol !== "http:") || !allowedHost(env, sourceUrl.hostname)) {
        return new Response("Source host not allowed", { status: 403 });
      }

      const maxDim = Math.max(1, Number(env.MAX_DIM || "4096"));
      const w = parseIntParam(reqUrl, "w", 1, maxDim);
      const h = parseIntParam(reqUrl, "h", 1, maxDim);
      const q = parseIntParam(reqUrl, "q", 1, 100);

      // Optional safety: max pixels
      const maxPixels = Math.max(1, Number(env.MAX_PIXELS || String(maxDim * maxDim)));
      if (w && h && w * h > maxPixels) return new Response("Requested size too large", { status: 400 });

      const all = reqUrl.searchParams.get("all") === "1";

      const fmtParam = (reqUrl.searchParams.get("fmt") || "").toLowerCase();
      const purgeFormats: typeof COMMON_FORMATS = all
        ? COMMON_FORMATS
        : [(fmtParam === "jpg" ? "jpeg" : (fmtParam as any)) || "orig"];

      // Build a “base” internal URL for keying (same request URL shape as /)
      // We include the original `url=` param in the key since your serving endpoint does too.
      const baseServingUrl = new URL(reqUrl.toString());
      baseServingUrl.pathname = "/"; // assumes your image endpoint is "/"
      // keep query params as-is (url,w,h,q,fmt)

      const results: Array<{ fmt: string; ok: boolean; error?: string }> = [];

      for (const fmt of purgeFormats) {
        try {
          const internalUrl = buildInternalCacheURL(baseServingUrl, fmt, w, h, q);
          const { edgeKey, r2Key } = await computeKeys(env, internalUrl);
          await purgeVariant(env, edgeKey, r2Key);
          results.push({ fmt, ok: true });
        } catch (e: any) {
          results.push({ fmt, ok: false, error: String(e?.message || e) });
        }
      }

      return new Response(JSON.stringify({ ok: true, purged: results }, null, 2), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }

    // -------------------------
    // Image endpoint
    // -------------------------
    if (req.method !== "GET" && req.method !== "HEAD") {
      return new Response("Method Not Allowed", { status: 405 });
    }

    const raw = reqUrl.searchParams.get("url");
    if (!raw) return new Response("Missing ?url=", { status: 400 });

    let sourceUrl: URL;
    try {
      sourceUrl = new URL(raw);
    } catch {
      return new Response("Invalid url", { status: 400 });
    }

    if (sourceUrl.protocol !== "https:" && sourceUrl.protocol !== "http:") {
      return new Response("Only http/https allowed", { status: 400 });
    }
    if (!allowedHost(env, sourceUrl.hostname)) {
      return new Response("Source host not allowed", { status: 403 });
    }

    const maxBytes = Math.max(1, Number(env.MAX_BYTES || "10485760"));
    const maxDim = Math.max(1, Number(env.MAX_DIM || "4096"));
    const maxPixels = Math.max(1, Number(env.MAX_PIXELS || String(maxDim * maxDim)));

    // Resize params (clamped)
    const w = parseIntParam(reqUrl, "w", 1, maxDim);
    const h = parseIntParam(reqUrl, "h", 1, maxDim);
    const q = parseIntParam(reqUrl, "q", 1, 100);

    // Safety: prevent huge pixel requests
    if (w && h && w * h > maxPixels) {
      return new Response("Requested size too large", { status: 400 });
    }

    // Accept-based auto-format (unless fmt explicitly set)
    const fmt = negotiatedFormat(req, reqUrl); // avif/webp/jpeg/png/orig

    // Build internal cache URL (forces fmt into key so caches.default doesn't collide across Accept)
    const internalUrl = buildInternalCacheURL(reqUrl, fmt, w, h, q);
    const { edgeKey, r2Key } = await computeKeys(env, internalUrl);

    // 1) Edge cache
    const hit = await caches.default.match(edgeKey);
    if (hit) return hit;

    // 2) R2
    const obj = await env.IMAGES.get(r2Key);
    if (obj) {
      const headers = new Headers();
      obj.writeHttpMetadata(headers);
      headers.set("ETag", obj.httpEtag);
      if (!headers.get("Content-Type")) headers.set("Content-Type", "application/octet-stream");

      let resp = new Response(obj.body, { status: 200, headers });
      resp = withCacheHeaders(resp);
      ctx.waitUntil(caches.default.put(edgeKey, resp.clone()));
      return resp;
    }

    // 3) Miss: fetch + transform (manual redirects; block 3xx)
    // NOTE: Requires Cloudflare Image Transformations enabled on the zone.
    const upstream = await fetch(sourceUrl.toString(), {
      redirect: "manual",
      headers: {
        "User-Agent": "awesome-image/1.0",
        Accept: req.headers.get("Accept") || "*/*",
      },
      cf: {
        cacheTtl: 0,
        cacheEverything: false,
        image: fmt === "orig"
          ? { width: w, height: h } // still allow resize even if keeping original format
          : { format: fmt, width: w, height: h, quality: q },
      } as any, // workers-types may not include cf.image in your TS version
    });

    if (isRedirect(upstream.status)) return new Response("Redirects not allowed", { status: 400 });
    if (!upstream.ok) return new Response(`Upstream error: ${upstream.status}`, { status: 502 });

    const contentType = upstream.headers.get("Content-Type") || "application/octet-stream";

    // Basic content-type sanity (if cf.image runs, this will usually be image/*)
    if (!contentType.startsWith("image/")) {
      return new Response("Upstream is not an image", { status: 415 });
    }

    let bytes: ArrayBuffer;
    try {
      bytes = await readUpTo(upstream, maxBytes);
    } catch (e: any) {
      if (e?.message === "too_large") return new Response("Image too large", { status: 413 });
      return new Response("Failed to read image", { status: 502 });
    }

    // Store variant + cache
    ctx.waitUntil(env.IMAGES.put(r2Key, bytes, { httpMetadata: { contentType } }));

    let resp = new Response(bytes, { status: 200, headers: { "Content-Type": contentType } });
    resp = withCacheHeaders(resp);

    ctx.waitUntil(caches.default.put(edgeKey, resp.clone()));
    return resp;
  },
};
