// server.js (ESM) — Render-ready, Fastify + Bare + Wisp
import dotenv from "dotenv";
dotenv.config();

import Fastify from "fastify";
import fastifyHelmet from "@fastify/helmet";
import fastifyStatic from "@fastify/static";
import fastifyCookie from "@fastify/cookie";
import wisp from "wisp-server-node";
import { createServer } from "node:http";
import { createBareServer } from "@tomphttp/bare-server-node";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { access } from "node:fs/promises";

import { epoxyPath } from "@mercuryworkshop/epoxy-transport";
import { libcurlPath } from '@mercuryworkshop/libcurl-transport';
import { baremuxPath } from "@mercuryworkshop/bare-mux/node";
import { bareModulePath } from "@mercuryworkshop/bare-as-module3";
import { uvPath } from "@titaniumnetwork-dev/ultraviolet";

import { MasqrMiddleware } from "./masqr.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// PORT supplied by Render in production; fallback for local dev
const PORT = Number(process.env.PORT) || 3000;

// Create raw Node server and Bare instance
const server = createServer();
const bare = createBareServer("/seal/");

// We'll store Fastify's handler here so our single Node server can delegate to it
let fastifyHandler = null;

// Single raw request listener:
// - Responds to "/" and "/health" for Render detection & health checks
// - Lets bare handle its routes (routeRequest)
// - Lets wisp handle normal http requests that end with "/wisp/"
// - Otherwise delegates to Fastify when ready
server.on("request", (req, res) => {
  try {
    // Basic detection / health endpoints
    if (req.url === "/" || req.url === "/health") {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end(req.url === "/health" ? "ok" : "Bare+Fastify server");
      return;
    }

    // Bare routing (static/bare endpoints)
    if (bare.shouldRoute(req)) {
      bare.routeRequest(req, res);
      return;
    }

    // Wisp plain HTTP request handler (non-upgrade)
    if (req.url.endsWith("/wisp/")) {
      try {
        wisp.routeRequest(req, res);
      } catch (e) {
        // fallback to Fastify or 500
        console.error("wisp routeRequest error:", e);
        res.writeHead(502, { "Content-Type": "text/plain" });
        res.end("wisp error");
      }
      return;
    }

    // Delegate to Fastify if it has registered its handler
    if (fastifyHandler) {
      return fastifyHandler(req, res);
    }

    // Default fallback (before Fastify ready)
    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("Not Found");
  } catch (err) {
    console.error("Raw request handler error:", err);
    try {
      res.writeHead(500, { "Content-Type": "text/plain" });
      res.end("Internal Server Error");
    } catch {}
  }
});

// Upgrade handling for websockets / bare / wisp
server.on("upgrade", (req, sock, head) => {
  if (bare.shouldRoute(req)) {
    return bare.routeUpgrade(req, sock, head);
  }
  if (req.url.endsWith("/wisp/")) {
    return wisp.routeRequest(req, sock, head);
  }
  sock.end();
});

// ---- Fastify setup: we return the same `server` instance via serverFactory
const app = Fastify({
  logger: false,
  serverFactory: (handler) => {
    // capture Fastify's handler so our single raw server can call it
    fastifyHandler = handler;
    return server;
  }
});

// Optional HTTPS redirect when Render terminates TLS (FORCE_HTTPS=true)
if (process.env.FORCE_HTTPS === "true") {
  app.addHook("onRequest", async (req, reply) => {
    const proto = req.headers["x-forwarded-proto"];
    if (proto === "http") {
      reply.redirect(301, `https://${req.headers.host}${req.raw.url}`);
    }
  });
}

// Security, cookies
await app.register(fastifyHelmet, { contentSecurityPolicy: false });
await app.register(fastifyCookie);

// Static mounts (skip missing roots without crashing)
const staticRoots = [
  { root: join(__dirname, "public"), prefix: "/", decorateReply: true },
  { root: libcurlPath, prefix: "/libcurl/" },
  { root: epoxyPath, prefix: "/epoxy/" },
  { root: baremuxPath, prefix: "/baremux/" },
  { root: bareModulePath, prefix: "/baremod/" },
  { root: join(__dirname, "public/js"), prefix: "/_dist_uv/" },
  { root: uvPath, prefix: "/_uv/" }
];

for (const r of staticRoots) {
  try {
    await access(r.root);
    await app.register(fastifyStatic, {
      root: r.root,
      prefix: r.prefix,
      decorateReply: r.decorateReply || false
    });
  } catch {
    app.log.info(`Static root not found, skipping: ${r.root}`);
  }
}

// uv route: prefer local built dist/uv if present, otherwise fall back to packaged uvPath
app.get("/uv/*", async (req, reply) => {
  const name = req.params["*"];
  const localRoot = join(__dirname, "dist/uv");
  try {
    await access(join(localRoot, name));
    return reply.sendFile(name, localRoot);
  } catch {
    return reply.sendFile(name, uvPath);
  }
});

// optional middleware
if (process.env.MASQR === "true") {
  app.addHook("onRequest", MasqrMiddleware);
}

// ---- Proxy helper (kept small & memory-cached) ----
const proxy = (urlFactory, defaultType = "application/javascript") => {
  const cache = new Map();

  return async (req, reply) => {
    const trackingDomains = [
      'trk.pinterest.com', 'widgets.pinterest.com', 'events.reddit.com',
      'ads.youtube.com', 'ads-api.tiktok.com', 'analytics.tiktok.com',
      'adservice.google.com', 'google-analytics.com', 'ad.doubleclick.net'
      // trim or expand as needed
    ];

    const target = typeof urlFactory === "function" ? urlFactory(req) : urlFactory;
    if (!target) return reply.code(400).send({ error: "bad target" });

    if (trackingDomains.some(d => target.includes(d))) {
      return reply.code(403).type("text/plain").send("Blocked tracking domain");
    }

    // strip cookies + set DNT
    req.headers.cookie = "";
    req.headers.dnt = "1";

    const cacheKey = req.method === "GET" ? target : null;
    if (cacheKey && cache.has(cacheKey)) {
      const cached = cache.get(cacheKey);
      for (const [k, v] of Object.entries(cached.headers || {})) reply.header(k, v);
      reply.type(cached.type || defaultType);
      return reply.send(cached.body);
    }

    try {
      const res = await fetch(target, { method: req.method, headers: req.headers });
      if (!res.ok) return reply.code(res.status).send();

      const headersToStrip = new Set([
        'content-security-policy', 'x-frame-options', 'x-content-type-options',
        'cross-origin-embedder-policy', 'cross-origin-opener-policy',
        'cross-origin-resource-policy', 'strict-transport-security',
        'set-cookie', 'server', 'x-powered-by', 'x-ua-compatible',
        'x-forwarded-for', 'x-real-ip'
      ]);

      const safeHeaders = {};
      for (const [k, v] of res.headers.entries()) {
        if (!headersToStrip.has(k.toLowerCase())) {
          reply.header(k, v);
          safeHeaders[k] = v;
        }
      }

      let bodyBuffer = Buffer.from(await res.arrayBuffer());
      const contentType = res.headers.get("content-type") || defaultType;
      reply.type(contentType);

      const acceptEncoding = (req.headers['accept-encoding'] || "");
      if (acceptEncoding.includes("br")) {
        const { brotliCompressSync } = await import("zlib");
        bodyBuffer = brotliCompressSync(bodyBuffer);
        reply.header("Content-Encoding", "br");
      } else if (acceptEncoding.includes("gzip")) {
        const { gzipSync } = await import("zlib");
        bodyBuffer = gzipSync(bodyBuffer);
        reply.header("Content-Encoding", "gzip");
      }

      if (cacheKey) {
        cache.set(cacheKey, { headers: safeHeaders, type: contentType, body: bodyBuffer });
        if (cache.size > 200) cache.delete(cache.keys().next().value);
      }

      return reply.send(bodyBuffer);
    } catch (err) {
      app.log.error("Proxy error:", err);
      return reply.code(502).send({ error: "Upstream request failed" });
    }
  };
};

// ---- Application routes (specific files first) ----
app.get("/js/script.js", proxy(() => "https://byod.privatedns.org/js/script.js"));

// Static HTML pages
app.get("/", async (req, reply) => reply.sendFile("index.html"));
app.get("/&", async (req, reply) => reply.sendFile("&.html"));
app.get("/~", async (req, reply) => reply.sendFile("~.html"));
app.get("/g", async (req, reply) => reply.sendFile("g.html"));
app.get("/a", async (req, reply) => reply.sendFile("a.html"));
app.get("/err", async (req, reply) => reply.sendFile("err.html"));
app.get("/500", async (req, reply) => reply.sendFile("500.html"));
app.get("/password", async (req, reply) => reply.sendFile("password.html"));

app.get("/return", async (req, reply) => {
  const q = req.query?.q;
  if (!q) return reply.code(401).send({ error: "query parameter?" });
  try {
    const r = await fetch(`https://duckduckgo.com/ac/?q=${encodeURIComponent(q)}`);
    const j = await r.json();
    return reply.send(j);
  } catch {
    return reply.code(500).send({ error: "request failed" });
  }
});

// ---- Not-found handler: acts as your previous "/*" proxy fallback ----
app.setNotFoundHandler((req, reply) => {
  // Only proxy GET requests (matches previous behavior)
  if (req.raw.method !== "GET") return reply.code(404).send({ error: "Not Found" });

  // Original pattern used req.params["*"], which captured the path after leading /
  // We reconstruct that: strip leading "/" from raw URL (including query)
  const target = req.raw.url?.slice(1) || "";
  if (!target) return reply.code(404).send({ error: "Not Found" });

  // Use the proxy helper to proxy the reconstructed target
  return proxy(() => target, "text/html")(req, reply);
});

// 404 fallback for non-GET already handled by setNotFoundHandler above
app.setErrorHandler((err, req, reply) => {
  app.log.error(err);
  reply.code(500).send({ error: "Internal Server Error" });
});

// ---- Startup ----
await app.ready(); // ensure plugins/routes/static are ready

// Only single listen on the raw Node server; Fastify will use the same server via serverFactory
server.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on ${PORT}`);
});
