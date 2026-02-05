import express from "express";
import { createProxyMiddleware, responseInterceptor } from "http-proxy-middleware";

const app = express();

/* ============================================================
   ENVIRONMENT VARIABLES (all optional thanks to defaults)
   ============================================================ */

/**
 * PORT
 * Local port where this proxy listens.
 * Traefik (or any reverse proxy) must forward traffic to this port.
 */
const PORT = parseInt(process.env.PORT || "3000", 10);

/**
 * UPSTREAM
 * Target website / application to proxy to.
 * Can be any HTTP(S) endpoint (WordPress, static site, API, etc).
 */
const UPSTREAM =
  process.env.UPSTREAM || "https://xingzheng.kahiether.com";

/**
 * INJECT_HTML
 * Raw HTML that will be injected into the response.
 * Typically a <script> tag.
 */
const INJECT_HTML =
  process.env.INJECT_HTML ||
  '<script defer src="https://analytics.kahiether.com/script.js" data-website-id="xxxx"></script>';

/**
 * INJECT_TARGET
 * HTML marker where injection happens.
 * Common values: </head> or </body>
 */
const INJECT_TARGET = process.env.INJECT_TARGET || "</head>";

/**
 * INJECT_MODE
 * "before"  => inject BEFORE target tag
 * "after"   => inject AFTER target tag
 */
const INJECT_MODE = (process.env.INJECT_MODE || "before").toLowerCase();

/**
 * INJECT_ONCE
 * true  => inject only the first occurrence
 * false => inject on every occurrence
 */
const INJECT_ONCE = (process.env.INJECT_ONCE || "true").toLowerCase() === "true";

/**
 * INJECT_CT_MATCH
 * Only inject when Content-Type contains this value.
 * Default: text/html
 */
const CT_MATCH = (process.env.INJECT_CT_MATCH || "text/html").toLowerCase();

/**
 * INJECT_IF_HEADER
 * Optional: inject ONLY if this response header exists.
 * Leave empty to disable.
 * Example: "content-type"
 */
const INJECT_IF_HEADER = (process.env.INJECT_IF_HEADER || "").toLowerCase();

/**
 * INJECT_EXCLUDE_PATHS
 * CSV list of regex patterns.
 * Requests matching these paths will NEVER be injected.
 */
const EXCLUDE_RAW =
  process.env.INJECT_EXCLUDE_PATHS || "^/wp-admin,^/wp-json,^/xmlrpc.php";

/**
 * HEALTH_PATH
 * Healthcheck endpoint for Docker / orchestrators.
 */
const HEALTH_PATH = process.env.HEALTH_PATH || "/healthz";

/* ============================================================ */

// Compile exclusion regexes
const EXCLUDE_PATTERNS = EXCLUDE_RAW
  .split(",")
  .map(s => s.trim())
  .filter(Boolean)
  .map(p => new RegExp(p));

function isExcludedPath(path) {
  return EXCLUDE_PATTERNS.some(rx => rx.test(path));
}

/**
 * Inject HTML payload into page.
 */
function injectIntoHtml(html) {
  if (!INJECT_HTML.trim()) return { out: html, changed: false };
  if (!html.includes(INJECT_TARGET)) return { out: html, changed: false };

  const payload =
    INJECT_MODE === "after"
      ? `${INJECT_TARGET}${INJECT_HTML}`
      : `${INJECT_HTML}${INJECT_TARGET}`;

  if (INJECT_ONCE) {
    const out = html.replace(INJECT_TARGET, payload);
    return { out, changed: out !== html };
  }

  const out = html.split(INJECT_TARGET).join(payload);
  return { out, changed: out !== html };
}

/**
 * Healthcheck endpoint
 */
app.get(HEALTH_PATH, (_, res) => res.status(200).send("ok"));

app.set("trust proxy", true);

/**
 * Main reverse-proxy middleware
 */
app.use(
  "/",
  createProxyMiddleware({
    target: UPSTREAM,
    changeOrigin: true,
    selfHandleResponse: true,

    // Disable upstream gzip to avoid decompression logic
    onProxyReq: (proxyReq, req) => {
      proxyReq.setHeader("accept-encoding", "identity");
      req.__skipInject = isExcludedPath(req.url);
    },

    onProxyRes: responseInterceptor(async (buffer, proxyRes, req) => {
      if (req.__skipInject) return buffer;

      const ct = String(proxyRes.headers["content-type"] || "").toLowerCase();

      // Only modify matching content-types
      if (CT_MATCH && !ct.includes(CT_MATCH)) return buffer;

      // Optional conditional header requirement
      if (INJECT_IF_HEADER) {
        const headers = Object.keys(proxyRes.headers).map(h => h.toLowerCase());
        if (!headers.includes(INJECT_IF_HEADER)) return buffer;
      }

      const html = buffer.toString("utf8");
      const { out, changed } = injectIntoHtml(html);

      if (!changed) return buffer;

      // Update Content-Length after mutation
      proxyRes.headers["content-length"] = Buffer.byteLength(out, "utf8").toString();

      return out;
    })
  })
);

/**
 * Start server
 */
app.listen(PORT, () => {
  console.log(JSON.stringify({
    listening: PORT,
    upstream: UPSTREAM,
    injectHtml: INJECT_HTML,
    target: INJECT_TARGET,
    mode: INJECT_MODE,
    once: INJECT_ONCE,
    ctMatch: CT_MATCH,
    ifHeader: INJECT_IF_HEADER || null,
    excludedPaths: EXCLUDE_PATTERNS.map(r => r.source),
    health: HEALTH_PATH
  }, null, 2));
});
