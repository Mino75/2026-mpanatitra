/**
 * server.js — HTTP forward proxy (Express-only dependency)
 *
 * Core:
 * - Accepts incoming HTTP requests (typically behind Traefik).
 * - Authorizes caller by API key, and optionally by source domain allowlist.
 * - Handles browser CORS + preflight (OPTIONS) so fetch() works reliably.
 * - Forwards request to TARGET_BASE_URL over HTTP, preserving method/path/query/body.
 * - Injects Basic Auth on outbound request (credentials from env).
 *
 * Dependencies: express (only). Everything else is Node.js built-in.
 */

import http from "http";
import { URL } from "url";
import crypto from "crypto";
import express from "express";

/* ----------------------------- Configuration ----------------------------- */

function mustGetEnv(name) {
  const v = process.env[name];
  if (!v || !String(v).trim()) {
    throw new Error(`Missing required env var: ${name}`);
  }
  return String(v).trim();
}

function parseCsvEnv(name, def = "") {
  const raw = String(process.env[name] ?? def).trim();
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
  if (!host) return "";
  try {
    const u = host.includes("://") ? new URL(host) : new URL(`http://${host}`);
    return (u.hostname || "").toLowerCase();
  } catch {
    return host.split(":")[0].toLowerCase();
  }
}

const PORT = Number(process.env.PORT || "8080");
const TRUST_PROXY = parseBoolEnv("TRUST_PROXY", "true");

// Upstream (internal service call)
const TARGET_BASE_URL = mustGetEnv("TARGET_BASE_URL"); // must be http://service:port (internal)
const BASIC_AUTH_USER = mustGetEnv("BASIC_AUTH_USER");
const BASIC_AUTH_PASS = mustGetEnv("BASIC_AUTH_PASS");

// Authorization inputs
const AUTHORIZED_API_KEYS = parseCsvEnv("AUTHORIZED_API_KEYS"); // CSV of allowed keys

// Optional source allowlist (NOT a strong security boundary; enable only if it matches your use-case)
const ENFORCE_SITE_ALLOWLIST = parseBoolEnv("ENFORCE_SITE_ALLOWLIST", "false");
const AUTHORIZED_SITES = parseCsvEnv("AUTHORIZED_SITES"); // CSV of allowed hostnames
const SOURCE_DOMAIN_HEADER = (process.env.SOURCE_DOMAIN_HEADER || "x-source-domain").toLowerCase();

// Where to read API key from inbound request
const API_KEY_HEADER = (process.env.API_KEY_HEADER || "x-api-key").toLowerCase();
const API_KEY_QUERY_PARAM = process.env.API_KEY_QUERY_PARAM || "api_key";
const ALLOW_API_KEY_IN_QUERY = parseBoolEnv("ALLOW_API_KEY_IN_QUERY", "false"); // default OFF

// Proxy tuning
const MAX_BODY_BYTES = Number(process.env.MAX_BODY_BYTES || String(10 * 1024 * 1024)); // 10 MB
const UPSTREAM_TIMEOUT_MS = Number(process.env.UPSTREAM_TIMEOUT_MS || "15000");
const SERVER_TIMEOUT_MS = Number(process.env.SERVER_TIMEOUT_MS || "16000");
const UPSTREAM_MAX_SOCKETS = Number(process.env.UPSTREAM_MAX_SOCKETS || "100");

// Forwarding / logging
const FORWARD_CLIENT_IP = parseBoolEnv("FORWARD_CLIENT_IP", "true");
const LOG_STARTUP = parseBoolEnv("LOG_STARTUP", "true");
const LOG_REQUESTS = parseBoolEnv("LOG_REQUESTS", "false");

// CORS (for browser fetch)
const CORS_ENABLED = parseBoolEnv("CORS_ENABLED", "true");
const CORS_ALLOW_ORIGINS = parseCsvEnv("CORS_ALLOW_ORIGINS", "*"); // "*" or CSV of exact origins
const CORS_ALLOW_CREDENTIALS = parseBoolEnv("CORS_ALLOW_CREDENTIALS", "false");
const CORS_MAX_AGE_SECONDS = Number(process.env.CORS_MAX_AGE_SECONDS || "600");

// Strip hop-by-hop and sensitive headers from inbound before forwarding
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
      "authorization", // caller must not control outbound auth
    ].join(",")
  ).map((h) => h.toLowerCase())
);

/* ------------------------------ Initialization --------------------------- */

const app = express();
app.disable("x-powered-by");
if (TRUST_PROXY) app.set("trust proxy", true);

// Capture raw body as Buffer for any content-type (single dependency constraint)
app.use(
  express.raw({
    type: () => true,
    limit: MAX_BODY_BYTES,
  })
);

const target = new URL(TARGET_BASE_URL);
if (target.protocol !== "http:") {
  throw new Error("TARGET_BASE_URL must be http:// (internal service call).");
}

const basicAuthValue =
  "Basic " + Buffer.from(`${BASIC_AUTH_USER}:${BASIC_AUTH_PASS}`, "utf8").toString("base64");

// Keep-alive for upstream performance
const upstreamAgent = new http.Agent({
  keepAlive: true,
  maxSockets: UPSTREAM_MAX_SOCKETS,
  timeout: UPSTREAM_TIMEOUT_MS,
});

/* ------------------------------ Helpers ---------------------------------- */

function timingSafeEquals(a, b) {
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

  if (ALLOW_API_KEY_IN_QUERY) {
    const q = req.query?.[API_KEY_QUERY_PARAM];
    if (typeof q === "string" && q.trim()) return q.trim();
    if (Array.isArray(q) && typeof q[0] === "string" && q[0].trim()) return q[0].trim();
  }

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

  const allowed = AUTHORIZED_SITES.map((s) => String(s || "").trim().toLowerCase()).filter(Boolean);

  return allowed.some((rule) => {
    // Support rules like "*.example.com"
    if (rule.startsWith("*.")) {
      const base = rule.slice(2);
      if (!base) return false;
      return d === base || d.endsWith("." + base);
    }

    // Plain domain matches itself and any subdomain
    if (d === rule) return true;
    return d.endsWith("." + rule);
  });
}

/* ------------------------------ CORS ------------------------------------- */

function isOriginAllowed(origin) {
  if (!origin) return false;
  if (CORS_ALLOW_ORIGINS.includes("*")) return true;
  return CORS_ALLOW_ORIGINS.includes(origin);
}

function setCorsHeaders(req, res) {
  if (!CORS_ENABLED) return;

  const origin = typeof req.headers.origin === "string" ? req.headers.origin.trim() : "";

  // If credentials are used, Access-Control-Allow-Origin cannot be "*"
  if (CORS_ALLOW_ORIGINS.includes("*") && !CORS_ALLOW_CREDENTIALS) {
    res.setHeader("Access-Control-Allow-Origin", "*");
  } else if (origin && isOriginAllowed(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }

  // Allow the headers that browsers commonly preflight for fetch
  res.setHeader(
    "Access-Control-Allow-Headers",
    [
      "content-type",
      "accept",
      "x-api-key",
      "x-source-domain",
      "x-requested-with",
      "authorization", // even if stripped inbound, the browser may request it in preflight
    ].join(", ")
  );

  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS");
  res.setHeader("Access-Control-Max-Age", String(CORS_MAX_AGE_SECONDS));

  if (CORS_ALLOW_CREDENTIALS) {
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
}

// Apply CORS headers for all responses (including errors)
app.use((req, res, next) => {
  setCorsHeaders(req, res);
  next();
});

// Fast preflight response
app.options("*", (req, res) => {
  // CORS headers already set by middleware above
  res.status(204).end();
});

/* ------------------------------ Forwarding ------------------------------- */

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

  // Ensure content-length matches the actual buffered body we send
  if (req.body && Buffer.isBuffer(req.body)) {
    if (req.body.length > 0) {
      headers["content-length"] = String(req.body.length);
    } else {
      delete headers["content-length"];
    }
  }

  // Optionally forward client IP chain + correct proto
  if (FORWARD_CLIENT_IP) {
    const existing = req.headers["x-forwarded-for"];
    const clientIp = req.ip;
    const chain = [existing, clientIp].filter(Boolean).join(", ");
    if (chain) headers["x-forwarded-for"] = chain;

    // Use Express protocol (respects trust proxy setting)
    headers["x-forwarded-proto"] = req.protocol || (req.secure ? "https" : "http");

    // Forward original host if present
    const xfHost = req.headers["x-forwarded-host"];
    if (typeof xfHost === "string" && xfHost.trim()) {
      headers["x-forwarded-host"] = xfHost.trim();
    }
  }

  return headers;
}

function upstreamRequestOptions(req) {
  // Preserve original path + query (req.originalUrl includes both)
  const url = new URL(req.originalUrl, "http://proxy.local");
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

// Main proxy route
app.all("*", (req, res) => {
  if (LOG_REQUESTS) {
    // eslint-disable-next-line no-console
    console.log(
      JSON.stringify({
        msg: "inbound_request",
        method: req.method,
        url: req.originalUrl,
        origin: req.headers.origin,
      })
    );
  }

  const providedKey = getProvidedApiKey(req);

  if (!isApiKeyAuthorized(providedKey)) {
    res.status(403).json({ error: "forbidden" });
    return;
  }

  if (ENFORCE_SITE_ALLOWLIST) {
    const sourceDomain = getSourceDomain(req);
    if (!isSiteAuthorized(sourceDomain)) {
      res.status(403).json({ error: "forbidden" });
      return;
    }
  }

  const opts = upstreamRequestOptions(req);

  const upstreamReq = http.request(opts, (upstreamRes) => {
    res.status(upstreamRes.statusCode || 502);

    // Copy upstream headers except hop-by-hop
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

  upstreamReq.on("error", (err) => {
    if (LOG_REQUESTS) {
      // eslint-disable-next-line no-console
      console.error(
        JSON.stringify({
          msg: "upstream_error",
          method: req.method,
          url: req.originalUrl,
          error: String(err?.message || err),
        })
      );
    }
    if (!res.headersSent) res.status(502);
    res.json({ error: "bad_gateway" });
  });

  // Write body (Buffer from express.raw)
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
  if (LOG_STARTUP) {
    // eslint-disable-next-line no-console
    console.log(
      JSON.stringify({
        msg: "proxy_started",
        port: PORT,
        target: TARGET_BASE_URL,
        authorized_keys_count: AUTHORIZED_API_KEYS.length,
        enforce_site_allowlist: ENFORCE_SITE_ALLOWLIST,
        authorized_sites_count: AUTHORIZED_SITES.length,
        allow_api_key_in_query: ALLOW_API_KEY_IN_QUERY,
        cors_enabled: CORS_ENABLED,
        cors_allow_origins: CORS_ALLOW_ORIGINS,
        cors_allow_credentials: CORS_ALLOW_CREDENTIALS,
      })
    );
  }
});

function shutdown(signal) {
  // eslint-disable-next-line no-console
  console.error(JSON.stringify({ msg: "shutdown", signal }));
  server.close(() => {
    upstreamAgent.destroy();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 5000).unref();
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
