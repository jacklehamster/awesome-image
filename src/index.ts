export interface Env {
  IMAGES: R2Bucket;
  ALLOWED_HOSTS: string; // comma-separated, required (fail-closed)
  MAX_BYTES: string; // e.g. "10485760"
}

function normalizeParams(reqUrl: URL) {
  const keep = ["w", "h", "q", "fmt"];
  const parts: string[] = [];
  for (const k of keep) {
    const v = reqUrl.searchParams.get(k);
    if (v) parts.push(`${k}=${v}`);
  }
  return parts.join("&");
}

function allowedHost(env: Env, host: string): boolean {
  const list = (env.ALLOWED_HOSTS || "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  if (list.length === 0) return false; // fail closed
  host = host.toLowerCase();
  return list.some((allowed) => host === allowed || host.endsWith(`.${allowed}`));
}

function pickFormat(req: Request, reqUrl: URL): "avif" | "webp" | "jpeg" | "png" | undefined {
  // Explicit fmt param wins
  const fmt = (reqUrl.searchParams.get("fmt") || "").toLowerCase();
  if (fmt === "avif" || fmt === "webp" || fmt === "jpeg" || fmt === "jpg" || fmt === "png") {
    return fmt === "jpg" ? "jpeg" : (fmt as any);
  }

  // Otherwise negotiate from Accept header
  const accept = (req.headers.get("Accept") || "").toLowerCase();
  if (accept.includes("image/avif")) return "avif";
  if (accept.includes("image/webp")) return "webp";
  return undefined; // keep original
}

function parseIntParam(reqUrl: URL, key: string, min: number, max: number): number | undefined {
  const v = reqUrl.searchParams.get(key);
  if (!v) return undefined;
  const n = Number(v);
  if (!Number.isFinite(n)) return undefined;
  const clamped = Math.max(min, Math.min(max, Math.floor(n)));
  return clamped;
}

async function readUpTo(resp: Response, maxBytes: number): Promise<ArrayBuffer> {
  const len = resp.headers.get("Content-Length");
  if (len && Number(len) > maxBytes) throw new Error("too_large");
  const buf = await resp.arrayBuffer();
  if (buf.byteLength > maxBytes) throw new Error("too_large");
  return buf;
}

function cacheKeyFor(sourceUrl: URL, reqUrl: URL) {
  const p = normalizeParams(reqUrl);
  const src = sourceUrl.toString();
  return p ? `${src}::${p}` : src;
}

async function sha256Hex(input: string): Promise<string> {
  const buf = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest("SHA-256", buf);
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function withCacheHeaders(resp: Response) {
  const h = new Headers(resp.headers);
  h.set("Cache-Control", "public, max-age=31536000, immutable");
  h.set("Vary", "Accept");
  return new Response(resp.body, { status: resp.status, headers: h });
}

function isRedirect(status: number) {
  return status >= 300 && status < 400;
}

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    if (req.method !== "GET" && req.method !== "HEAD") {
      return new Response("Method Not Allowed", { status: 405 });
    }

    const reqUrl = new URL(req.url);
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

    // Transform options
    const fmt = pickFormat(req, reqUrl); // e.g. "avif"
    const w = parseIntParam(reqUrl, "w", 1, 4096);
    const h = parseIntParam(reqUrl, "h", 1, 4096);
    const q = parseIntParam(reqUrl, "q", 1, 100);

    // Cache keys (include fmt/w/h/q via normalizeParams)
    const ck = cacheKeyFor(sourceUrl, reqUrl);
    const hash = await sha256Hex(ck);
    const r2Key = `v/${hash}`;

    // Edge cache
    const cache = caches.default;
    const edgeKey = reqUrl.toString();

    const hit = await cache.match(edgeKey);
    if (hit) return hit;

    // R2
    const obj = await env.IMAGES.get(r2Key);
    if (obj) {
      const headers = new Headers();
      obj.writeHttpMetadata(headers);
      headers.set("ETag", obj.httpEtag);
      if (!headers.get("Content-Type")) headers.set("Content-Type", "application/octet-stream");
      let resp = new Response(obj.body, { status: 200, headers });
      resp = withCacheHeaders(resp);
      ctx.waitUntil(cache.put(edgeKey, resp.clone()));
      return resp;
    }

    // Upstream fetch WITH image transformations.
    // NOTE: This requires Cloudflare Image Resizing/Transformations to be enabled on your account/zone.
    const upstream = await fetch(sourceUrl.toString(), {
      redirect: "manual",
      headers: {
        "User-Agent": "img-cache-worker/1.0",
        Accept: req.headers.get("Accept") || "*/*",
      },
      cf: {
        cacheTtl: 0,
        cacheEverything: false,
        image: {
          // Only set properties if provided; undefined is fine
          format: fmt,     // "avif" | "webp" | ...
          width: w,
          height: h,
          quality: q,
        },
      } as any, // TS may not include cf.image in workers-types depending on version
    });

    if (isRedirect(upstream.status)) return new Response("Redirects not allowed", { status: 400 });
    if (!upstream.ok) return new Response(`Upstream error: ${upstream.status}`, { status: 502 });

    const contentType = upstream.headers.get("Content-Type") || "application/octet-stream";

    let bytes: ArrayBuffer;
    try {
      bytes = await readUpTo(upstream, maxBytes);
    } catch (e: any) {
      if (e?.message === "too_large") return new Response("Image too large", { status: 413 });
      return new Response("Failed to read image", { status: 502 });
    }

    // Store transformed result
    ctx.waitUntil(
      env.IMAGES.put(r2Key, bytes, {
        httpMetadata: { contentType },
      })
    );

    let resp = new Response(bytes, { status: 200, headers: { "Content-Type": contentType } });
    resp = withCacheHeaders(resp);
    ctx.waitUntil(cache.put(edgeKey, resp.clone()));
    return resp;
  },
};
