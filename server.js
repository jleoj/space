// server.js (ESM)
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

// third-party asset paths used in your original file
import { epoxyPath } from "@mercuryworkshop/epoxy-transport";
import { libcurlPath } from '@mercuryworkshop/libcurl-transport';
import { baremuxPath } from "@mercuryworkshop/bare-mux/node";
import { bareModulePath } from "@mercuryworkshop/bare-as-module3";
import { uvPath } from "@titaniumnetwork-dev/ultraviolet";

import { MasqrMiddleware } from "./masqr.js";

// ---- utils ----
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// PORT
const PORT = Number(process.env.PORT) || 3000;

// Create the raw Node server and the bare server instance
const server = createServer();
const bare = createBareServer("/seal/");

// Important: provide a basic HTTP root handler so Render can detect the port.
// We'll attach a request handler to the raw server. Fastify's serverFactory
// will reuse this same server instance so we only have one listener.
server.on("request", (req, res) => {
  try {
    // simple health and root endpoints for detection and health checks
    if (req.url === "/" || req.url === "/health") {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end(req.url === "/health" ? "ok" : "Bare+Fastify server");
      return;
    }

    // Prefer bare routing when appropriate
    if (bare.shouldRoute(req)) {
      bare.routeRequest(req, res);
      return;
    }

    // If the URL ends with /wisp/ handle via wisp (upgrade-based)
    if (req.url.endsWith("/wisp/")) {
      // wisp.routeRequest expects (req, socket, head) when upgrade OR (req, res) for normal
      // Using routeRequest(req, res) here to forward normal HTTP requests
      wisp.routeRequest(req, res);
      return;
    }

    // default 404 fallback (Render will still see a valid HTTP listener)
    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("Not Found");
  } catch (err) {
    // fail safe
    console.error("Unhandled raw request error:", err);
    try {
      res.writeHead(500, { "Content-Type": "text/plain" });
      res.end("Internal Server Error");
    } catch {}
  }
});

// upgrade handling for WebSocket / bare / wisp
server.on("upgrade", (req, sock, head) => {
  if (bare.shouldRoute(req)) {
    return bare.routeUpgrade(req, sock, head);
  }
  if (req.url.endsWith("/wisp/")) {
    return wisp.routeRequest(req, sock, head);
  }
  sock.end();
});

// ---- Fastify setup using serverFactory to reuse the same `server` ----
const app = Fastify({
  logger: false,
  serverFactory: handler => {
    // attach Fastify's request handler to our node `server`
    server.on("request", (req, res) => {
      // If bare handles the request, do not pass it to Fastify
      if (bare.shouldRoute(req) || req.url.endsWith("/wisp/")) {
        // Let raw server handlers handle it (we already attach bare above)
        return;
      }
      handler(req, res);
    });

    // return the Node server — Fastify will not call .listen() itself
    return server;
  }
});

// Optional: redirect HTTP->HTTPS when Render terminates TLS and sets x-forwarded-proto
if (process.env.FORCE_HTTPS === "true") {
  app.addHook("onRequest", async (req, reply) => {
    const proto = req.headers["x-forwarded-proto"];
    if (proto === "http") {
      // preserve host + path
      reply.redirect(301, `https://${req.headers.host}${req.raw.url}`);
    }
  });
}

// Security headers
await app.register(fastifyHelmet, { contentSecurityPolicy: false });

// cookies
await app.register(fastifyCookie);

// Static mounts — make sure each root exists in production or Render will error at startup.
// For bundles that may not be present, we keep them but don't crash.
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
  // register each static route, but skip if the folder doesn't exist (non-fatal)
  try {
    await access(r.root);
    await app.register(fastifyStatic, {
      root: r.root,
      prefix: r.prefix,
      decorateReply: r.decorateReply || false
    });
  } catch {
    // missing optional asset dir — log but continue
    app.log.info(`Static root not found, skipping: ${r.root}`);
  }
}

// uv route: prefer local dist/uv if exists, otherwise fall back to uvPath
app.get("/uv/*", async (req, reply) => {
  const name = req.params["*"];
  const localRoot = join(__dirname, "dist/uv");
  try {
    await access(join(localRoot, name));
    return reply.sendFile(name, localRoot);
  } catch {
    // fallback to packaged uvPath
    return reply.sendFile(name, uvPath);
  }
});

// optional middleware
if (process.env.MASQR === "true") {
  app.addHook("onRequest", MasqrMiddleware);
}

// ---- Proxy helper ----
const proxy = (urlFactory, defaultType = "application/javascript") => {
  // basic in-memory cache for simple GET caching (very small)
  const cache = new Map();

  return async (req, reply) => {
    // blocklist of tracking domains (copied from your list — can be trimmed)
    const trackingDomains = [
      'trk.pinterest.com', 'widgets.pinterest.com', 'events.reddit.com',
      'ads.youtube.com', 'ads-api.tiktok.com', 'analytics.tiktok.com',
      'adservice.google.com', 'google-analytics.com', 'ad.doubleclick.net',
      /* ... keep as needed ... */
    ];

    const target = typeof urlFactory === "function" ? urlFactory(req) : urlFactory;
    if (trackingDomains.some(d => target.includes(d))) {
      return reply.code(403).type("text/plain").send("Blocked tracking domain");
    }

    // strip cookies / add DNT
    req.headers.cookie = "";
    req.headers.dnt = "1";

    const cacheKey = req.method === "GET" ? target : null;
    if (cacheKey && cache.has(cacheKey)) {
      const cached = cache.get(cacheKey);
      // set headers that are safe
      for (const [k, v] of Object.entries(cached.headers || {})) {
        reply.header(k, v);
      }
      reply.type(cached.type || defaultType);
      return reply.send(cached.body);
    }

    try {
      const res = await fetch(target, { method: req.method, headers: req.headers });
      if (!res.ok) return reply.code(res.status).send();

      // copy safe headers
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
      let contentType = res.headers.get("content-type") || defaultType;
      reply.type(contentType);

      // compression: compress if client accepts and response is compressible
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

      // cache GET results (tiny, memory-only)
      if (cacheKey) {
        cache.set(cacheKey, { headers: safeHeaders, type: contentType, body: bodyBuffer });
        // optional: simple size-based eviction
        if (cache.size > 200) {
          const firstKey = cache.keys().next().value;
          cache.delete(firstKey);
        }
      }

      return reply.send(bodyBuffer);
    } catch (err) {
      app.log.error("Proxy error:", err);
      return reply.code(502).send({ error: "Upstream request failed" });
    }
  };
};

// Routes using proxy
app.get("/*", proxy(req => `${req.params["*"]}`, "text/html")); // generic proxy for wildcard (be careful)
app.get("/js/script.js", proxy(() => "https://byod.privatedns.org/js/script.js"));

// Specific routes (static pages)
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

// 404 handler
app.setNotFoundHandler((req, reply) => {
  if (req.raw.method === "GET" && (req.headers.accept || "").includes("text/html")) {
    return reply.sendFile("err.html");
  }
  return reply.code(404).send({ error: "Not Found" });
});

// ---- Start sequence ----
await app.ready(); // initialize plugins, routes, static mounts, etc.

// Listen on the raw Node server (only one .listen call)
server.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on ${PORT}`);
});
