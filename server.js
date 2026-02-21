/**
 * server.js — Minimal production-ready HTTP forward proxy (Express-only dependency)
 *
 * Behavior:
 * - Accepts incoming HTTP requests.
 * - Authorizes caller by:
 *   1) API key (header/query) AND
 *   2) Source domain match (Origin/Referer/X-Source-Domain)
 * - Forwards the request to TARGET_BASE_URL, preserving method/path/query/body.
 * - Adds Basic Auth header (user/pass from env) to the outgoing request.
 *
 * Dependencies: express (only). Everything else is Node.js built-in.
 */

"use strict";

const http = require("http");
const { URL } = require("url");
const crypto = require("crypto");
const express = require("express");

/* ----------------------------- Configuration ----------------------------- */

function mustGetEnv(name) {
  const v = process.env[name];
  if (!v || !String(v).trim()) {
    throw new Error(`Missing required env var: ${name}`);
  }
  return String(v).trim();
}

function parseCsvEnv(name, def = "") {
  const raw = (process.env[name] ?? def).trim();
  if (!raw) return [];
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function parseBoolEnv(name, def = "false") {
  const v = String(process.env[name] ?? def).toLowerCase().trim();
  return v === "1" || v === "true" || v === "yes" || v === "on";
}

function normalizeHost(host) {
  // Accept "example.com" or "example.com:1234" and normalize to hostname only
  if (!host) return "";
  try {
    // If host already has scheme, URL will parse; otherwise prepend.
    const u = host.includes("://") ? new URL(host) : new URL(`http://${host}`);
    return (u.hostname || "").toLowerCase();
  } catch {
    // Fallback: strip port manually
    return host.split(":")[0].toLowerCase();
  }
}

const PORT = Number(process.env.PORT || "8080");
const TRUST_PROXY = parseBoolEnv("TRUST_PROXY", "true"); // if behind ingress/reverse proxy
const TARGET_BASE_URL = mustGetEnv("TARGET_BASE_URL"); // e.g. "http://upstream.internal:9000"
const BASIC_AUTH_USER = mustGetEnv("BASIC_AUTH_USER");
const BASIC_AUTH_PASS = mustGetEnv("BASIC_AUTH_PASS");

// Authorization inputs
const AUTHORIZED_SITES = parseCsvEnv("AUTHORIZED_SITES"); // e.g. "app.example.com,admin.example.com"
const AUTHORIZED_API_KEYS = parseCsvEnv("AUTHORIZED_API_KEYS"); // e.g. "k1,k2,k3"

// Where to read API key from the inbound request
const API_KEY_HEADER = (process.env.API_KEY_HEADER || "x-api-key").toLowerCase(); // inbound header name
const API_KEY_QUERY_PARAM = process.env.API_KEY_QUERY_PARAM || "api_key"; // inbound query param name

// Optional: require a specific explicit header for source domain instead of Origin/Referer
const SOURCE_DOMAIN_HEADER = (process.env.SOURCE_DOMAIN_HEADER || "x-source-domain").toLowerCase();

// Proxy behavior tuning
const MAX_BODY_BYTES = Number(process.env.MAX_BODY_BYTES || String(10 * 1024 * 1024)); // 10 MB default
const UPSTREAM_TIMEOUT_MS = Number(process.env.UPSTREAM_TIMEOUT_MS || "15000");
const SERVER_TIMEOUT_MS = Number(process.env.SERVER_TIMEOUT_MS || "16000");

// Optional header allowlist/denylist (defaults are safe)
const STRIP_INBOUND_HEADERS = new Set(
  parseCsvEnv(
    "STRIP_INBOUND_HEADERS",
    [
      "connection",
      "keep-alive",
      "proxy-authenticate",
      "proxy-authorization",
      "te",
      "trailer",
      "transfer-encoding",
      "upgrade",
      "host",
      "authorization", // do not let caller control outbound auth
    ].join(",")
  ).map((h) => h.toLowerCase())
);

const FORWARD_CLIENT_IP = parseBoolEnv("FORWARD_CLIENT_IP", "true"); // adds X-Forwarded-For

/* ------------------------------ Initialization --------------------------- */

const app = express();
app.disable("x-powered-by");
if (TRUST_PROXY) app.set("trust proxy", true);

// Capture raw body as Buffer for any content-type
app.use(
  express.raw({
    type: () => true,
    limit: MAX_BODY_BYTES,
  })
);

const target = new URL(TARGET_BASE_URL);
if (target.protocol !== "http:") {
  throw new Error("TARGET_BASE_URL must be http:// (HTTP only).");
}

const basicAuthValue =
  "Basic " + Buffer.from(`${BASIC_AUTH_USER}:${BASIC_AUTH_PASS}`, "utf8").toString("base64");

// Keep-alive for upstream performance (Node built-in)
const upstreamAgent = new http.Agent({
  keepAlive: true,
  maxSockets: Number(process.env.UPSTREAM_MAX_SOCKETS || "100"),
  timeout: UPSTREAM_TIMEOUT_MS,
});

function timingSafeEquals(a, b) {
  // Prevent trivial timing attacks on API key compares
  const ba = Buffer.from(String(a || ""), "utf8");
  const bb = Buffer.from(String(b || ""), "utf8");
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

function isApiKeyAuthorized(providedKey) {
  if (!AUTHORIZED_API_KEYS.length) return false;
  return AUTHORIZED_API_KEYS.some((k) => timingSafeEquals(k, providedKey));
}

function getProvidedApiKey(req) {
  const headerVal = req.headers[API_KEY_HEADER];
  if (typeof headerVal === "string" && headerVal.trim()) return headerVal.trim();

  const q = req.query?.[API_KEY_QUERY_PARAM];
  if (typeof q === "string" && q.trim()) return q.trim();

  return "";
}

function getSourceDomain(req) {
  // Priority:
  // 1) SOURCE_DOMAIN_HEADER (explicit)
  // 2) Origin hostname
  // 3) Referer hostname
  const explicit = req.headers[SOURCE_DOMAIN_HEADER];
  if (typeof explicit === "string" && explicit.trim()) return normalizeHost(explicit.trim());

  const origin = req.headers["origin"];
  if (typeof origin === "string" && origin.trim()) return normalizeHost(origin.trim());

  const referer = req.headers["referer"];
  if (typeof referer === "string" && referer.trim()) return normalizeHost(referer.trim());

  return "";
}

function isSiteAuthorized(sourceDomain) {
  if (!AUTHORIZED_SITES.length) return false;
  const d = normalizeHost(sourceDomain);
  if (!d) return false;
  // Exact match by default; if you need wildcard semantics, encode explicitly upstream.
  return AUTHORIZED_SITES.map((s) => normalizeHost(s)).includes(d);
}

function buildUpstreamHeaders(req) {
  const headers = {};
  for (const [k, v] of Object.entries(req.headers)) {
    const key = k.toLowerCase();
    if (STRIP_INBOUND_HEADERS.has(key)) continue;
    if (typeof v === "undefined") continue;
    headers[key] = v;
  }

  // Enforce Basic Auth to upstream
  headers["authorization"] = basicAuthValue;

  // Set host to upstream host
  headers["host"] = target.host;

  // Optionally forward client IP chain
  if (FORWARD_CLIENT_IP) {
    const existing = req.headers["x-forwarded-for"];
    const clientIp = req.ip;
    const chain = [existing, clientIp].filter(Boolean).join(", ");
    if (chain) headers["x-forwarded-for"] = chain;
    headers["x-forwarded-proto"] = "http";
  }

  return headers;
}

function upstreamRequestOptions(req) {
  // Preserve full path including query string.
  const url = new URL(req.originalUrl, "http://proxy.local"); // just to normalize
  const pathWithQuery = url.pathname + url.search;

  return {
    protocol: "http:",
    hostname: target.hostname,
    port: target.port ? Number(target.port) : 80,
    method: req.method,
    path: pathWithQuery,
    headers: buildUpstreamHeaders(req),
    agent: upstreamAgent,
    timeout: UPSTREAM_TIMEOUT_MS,
  };
}

/* --------------------------------- Routes -------------------------------- */

app.get("/healthz", (req, res) => {
  res.status(200).type("text/plain").send("ok");
});

// Proxy all remaining routes
app.all("*", (req, res) => {
  const providedKey = getProvidedApiKey(req);
  const sourceDomain = getSourceDomain(req);

  if (!isApiKeyAuthorized(providedKey) || !isSiteAuthorized(sourceDomain)) {
    // Do not leak which condition failed
    res.status(403).json({ error: "forbidden" });
    return;
  }

  const opts = upstreamRequestOptions(req);

  const upstreamReq = http.request(opts, (upstreamRes) => {
    // Copy status and headers (strip hop-by-hop)
    res.status(upstreamRes.statusCode || 502);

    for (const [k, v] of Object.entries(upstreamRes.headers)) {
      const key = k.toLowerCase();
      if (
        key === "connection" ||
        key === "keep-alive" ||
        key === "proxy-authenticate" ||
        key === "proxy-authorization" ||
        key === "te" ||
        key === "trailer" ||
        key === "transfer-encoding" ||
        key === "upgrade"
      ) {
        continue;
      }
      if (typeof v !== "undefined") res.setHeader(k, v);
    }

    upstreamRes.pipe(res);
  });

  upstreamReq.on("timeout", () => {
    upstreamReq.destroy(new Error("Upstream timeout"));
  });

  upstreamReq.on("error", () => {
    if (!res.headersSent) res.status(502);
    res.json({ error: "bad_gateway" });
  });

  // Write body (Buffer from express.raw); for GET/HEAD it will be empty buffer.
  if (req.body && Buffer.isBuffer(req.body) && req.body.length > 0) {
    upstreamReq.write(req.body);
  }
  upstreamReq.end();
});

/* ------------------------------ Server setup ------------------------------ */

const server = http.createServer(app);
server.requestTimeout = SERVER_TIMEOUT_MS;
server.headersTimeout = SERVER_TIMEOUT_MS;

server.listen(PORT, "0.0.0.0", () => {
  // Avoid noisy logs by default; enable if desired
  if (parseBoolEnv("LOG_STARTUP", "true")) {
    // eslint-disable-next-line no-console
    console.log(
      JSON.stringify({
        msg: "proxy_started",
        port: PORT,
        target: TARGET_BASE_URL,
        authorized_sites_count: AUTHORIZED_SITES.length,
        authorized_keys_count: AUTHORIZED_API_KEYS.length,
      })
    );
  }
});

// Graceful shutdown
function shutdown(signal) {
  // eslint-disable-next-line no-console
  console.error(JSON.stringify({ msg: "shutdown", signal }));
  server.close(() => {
    upstreamAgent.destroy();
    process.exit(0);
  });
  // Hard stop
  setTimeout(() => process.exit(1), 5000).unref();
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
