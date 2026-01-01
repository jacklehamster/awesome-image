export interface Env {
  IMAGES: R2Bucket;
  ALLOWED_HOSTS: string; // comma-separated, required (fail-closed)
  MAX_BYTES: string; // stringified integer, e.g. "10485760"
}

function normalizeParams(reqUrl: URL) {
  // Keep only transform-relevant params in a stable order
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

  // Fail closed: if unset, do NOT become an open proxy.
  if (list.length === 0) return false;

  host = host.toLowerCase();
  return list.some((allowed) => host === allowed || host.endsWith(`.${allowed}`));
}

async function readUpTo(resp: Response, maxBytes: number): Promise<ArrayBuffer> {
  const len = resp.headers.get("Content-Length");
  if (len && Number(len) > maxBytes) throw new Error("too_large");

  const buf = await resp.arrayBuffer();
  if (buf.byteLength > maxBytes) throw new Error("too_large");

  return buf;
}

function cacheKeyFor(sourceUrl: URL, reqUrl: URL) {
  // Stable cache key based on:
  // - full source URL (origin + path + query)
  // - transform params from request (w/h/q/fmt)
  const p = normalizeParams(reqUrl);
  const src = sourceUrl.toString();
  return p ? `${src}::${p}` : src;
}

async function sha256Hex(input: string): Promise<string> {
  const buf = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest("SHA-256", buf);
  return [...new Uint8Array(hash)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function withCacheHeaders(resp: Response) {
  const h = new Headers(resp.headers);
  h.set("Cache-Control", "public, max-age=31536000, immutable");
  h.set("Vary", "Accept");
  return new Response(resp.body, { status: resp.status, headers: h });
}

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    if (req.method !== "GET" && req.method !== "HEAD") {
      return new Response("Method Not Allowed", { status: 405 });
    }

    const reqUrl = new URL(req.url);

    // Source image URL passed in query param
    const raw = reqUrl.searchParams.get("url");
    if (!raw) return new Response("Missing ?url=", { status: 400 });

    let sourceUrl: URL;
    try {
      sourceUrl = new URL(raw);
    } catch {
      return new Response("Invalid url", { status: 400 });
    }

    // Basic proxy/SSRF protections
    if (sourceUrl.protocol !== "https:" && sourceUrl.protocol !== "http:") {
      return new Response("Only http/https allowed", { status: 400 });
    }
    if (!allowedHost(env, sourceUrl.hostname)) {
      return new Response("Source host not allowed", { status: 403 });
    }

    const maxBytes = Math.max(1, Number(env.MAX_BYTES || "10485760"));

    // Cache keys
    const ck = cacheKeyFor(sourceUrl, reqUrl);
    const hash = await sha256Hex(ck);
    const r2Key = `v/${hash}`;

    // 1) Edge cache first
    const cache = caches.default;
    const edgeKey = reqUrl.toString();
    const hit = await cache.match(edgeKey);
    if (hit) return hit;

    // 2) R2 lookup
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

    // 3) Miss: fetch from the provided URL (no redirects)
    const upstream = await fetch(sourceUrl.toString(), {
      redirect: "error",
      cf: { cacheTtl: 0, cacheEverything: false },
      headers: {
        "User-Agent": "img-cache-worker/1.0",
        Accept: req.headers.get("Accept") || "*/*",
      },
    });

    if (!upstream.ok) {
      return new Response(`Upstream error: ${upstream.status}`, { status: 502 });
    }

    const contentType = upstream.headers.get("Content-Type") || "application/octet-stream";
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

    // Save to R2 (async)
    ctx.waitUntil(
      env.IMAGES.put(r2Key, bytes, {
        httpMetadata: { contentType },
      })
    );

    // Respond + fill edge cache
    let resp = new Response(bytes, { status: 200, headers: { "Content-Type": contentType } });
    resp = withCacheHeaders(resp);

    ctx.waitUntil(cache.put(edgeKey, resp.clone()));
    return resp;
  },
};
