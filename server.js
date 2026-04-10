import express from "express";
import cookieParser from "cookie-parser";
import { createProxyMiddleware, responseInterceptor } from "http-proxy-middleware";
import path from "path";
import tls from "tls";

const TENANT = "trial0195-id";
const MIITEL_ORIGIN = `https://${TENANT}.miitel.jp`;
const EMAIL = "agent.qiscus1@qisc.us";
const PASSWORD = "Semuabisa123!";

const COOKIE_OPTS = {
  httpOnly: true,
  secure: false, // set to true when using HTTPS in production
  sameSite: "strict",
  path: "/",
};

// Helper: set token cookies from an auth_result object
function setTokenCookies(res, auth) {
  const accessMaxAge = (auth.expires_in || 3600) * 1000;
  res.cookie("miitel_access_token", auth.access_token, {
    ...COOKIE_OPTS,
    maxAge: accessMaxAge,
  });
  res.cookie("miitel_refresh_token", auth.refresh_token, {
    ...COOKIE_OPTS,
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
  });
  if (auth.id_token) {
    res.cookie("miitel_id_token", auth.id_token, {
      ...COOKIE_OPTS,
      maxAge: accessMaxAge,
    });
  }
  // Store expiry timestamp so we know when to refresh
  res.cookie("miitel_token_expires_at", String(Date.now() + accessMaxAge), {
    ...COOKIE_OPTS,
    maxAge: accessMaxAge,
  });
}

// Helper: refresh the access token using the refresh token
async function refreshAccessToken(refreshToken) {
  const response = await fetch(`${MIITEL_ORIGIN}/api/auth/v2/refresh`, {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/json",
    },
    body: JSON.stringify({ refresh_token: refreshToken }),
  });

  if (!response.ok) {
    const text = await response.text();
    console.error("Token refresh failed:", response.status, text);
    return null;
  }

  const data = await response.json();
  return data.auth_result;
}

const app = express();
app.use(cookieParser());
// Only parse JSON for our own /_auth routes — NOT for proxied requests.
// express.json() consumes the request body stream; if applied globally it
// empties POST bodies before they reach the proxy, causing empty requests.
app.use("/_auth", express.json());

// ── Security headers for our own pages ──
app.use((req, res, next) => {
  // Only apply to our own routes, not proxied MiiTel content
  if (req.path === "/" || req.path.startsWith("/_")) {
    // Block inline scripts except our own (nonce would be better for production)
    res.setHeader("Content-Security-Policy",
      "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-src *;"
    );
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  }
  next();
});

// ── Middleware: auto-refresh token if it's about to expire (< 5 min left) ──
app.use(async (req, res, next) => {
  const expiresAt = Number(req.cookies.miitel_token_expires_at);
  const refreshToken = req.cookies.miitel_refresh_token;

  // Only attempt refresh if we have a refresh token and the access token expires within 5 min
  if (refreshToken && expiresAt && Date.now() > expiresAt - 5 * 60 * 1000) {
    console.log("Access token expiring soon, refreshing...");
    const auth = await refreshAccessToken(refreshToken);
    if (auth) {
      setTokenCookies(res, auth);
      // Update the cookie value on the current request so the proxy picks it up
      req.cookies.miitel_access_token = auth.access_token;
      console.log("Token refreshed successfully.");
    } else {
      console.warn("Token refresh failed — user may need to re-login.");
    }
  }
  next();
});

// ── CSRF protection for /_auth/* routes ──
// Require X-Requested-With header on all /_auth endpoints.
// Browsers block cross-origin requests with custom headers (CORS preflight),
// so a malicious site cannot forge requests to these endpoints.
app.use("/_auth", (req, res, next) => {
  if (req.headers["x-requested-with"] !== "XMLHttpRequest") {
    return res.status(403).json({ error: "Forbidden: missing CSRF header" });
  }
  next();
});

// ── Our own routes (prefixed with /_auth to avoid clashing with MiiTel's /api) ──

app.post("/_auth/login", async (_req, res) => {
  try {
    const response = await fetch(`${MIITEL_ORIGIN}/api/auth/v2/authenticate`, {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
      },
      body: JSON.stringify({
        flow: "TENANT_USER_PASSWORD",
        params: {
          tenant_code: TENANT,
          email: EMAIL,
          password: PASSWORD,
        },
      }),
    });

    const text = await response.text();
    console.log("Miitel API status:", response.status);
    console.log("Miitel API response:", text);

    if (!response.ok) {
      // Return as JSON to prevent reflecting raw HTML from upstream
      return res.status(response.status).json({ error: "Login failed", status: response.status });
    }

    const data = JSON.parse(text);
    const auth = data.auth_result;

    setTokenCookies(res, auth);

    return res.json({ ok: true, expires_in: auth.expires_in });
  } catch (error) {
    console.error("Server error:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/_auth/logout", (_req, res) => {
  res.clearCookie("miitel_access_token", { path: "/" });
  res.clearCookie("miitel_refresh_token", { path: "/" });
  res.clearCookie("miitel_token_expires_at", { path: "/" });
  return res.json({ ok: true });
});

app.post("/_auth/status", (req, res) => {
  const loggedIn = !!req.cookies.miitel_access_token;
  const expiresAt = Number(req.cookies.miitel_token_expires_at) || 0;
  return res.json({ loggedIn, expiresAt });
});

app.post("/_auth/refresh", async (req, res) => {
  const refreshToken = req.cookies.miitel_refresh_token;
  if (!refreshToken) {
    return res.status(401).json({ error: "No refresh token" });
  }
  const auth = await refreshAccessToken(refreshToken);
  if (!auth) {
    return res.status(401).json({ error: "Refresh failed" });
  }
  setTokenCookies(res, auth);
  return res.json({ ok: true, expires_in: auth.expires_in });
});

// ── Token endpoint: only returns tokens if valid httpOnly cookie is present ──
// This is called by the launcher page (same origin) — not accessible cross-origin.
app.post("/_auth/tokens", (req, res) => {
  const accessToken = req.cookies.miitel_access_token;
  const refreshToken = req.cookies.miitel_refresh_token;
  const expiresAt = req.cookies.miitel_token_expires_at;

  if (!accessToken) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  return res.json({
    access_token: accessToken,
    refresh_token: refreshToken,
    refresh_token_expires_at: expiresAt,
    id_token: req.cookies.miitel_id_token || null,
  });
});

// ── Serve our frontend at / ──
app.get("/", (_req, res) => {
  res.sendFile(path.resolve("public/index.html"));
});

// Script injected into ALL proxied HTML pages (iframe + softphone popup).
const FRAME_BYPASS_SCRIPT = `<script>
if (window.self !== window.top) {
  try { Object.defineProperty(window, 'frameElement', { get: () => null }); } catch(e) {}
  try { Object.defineProperty(window, 'top', { get: () => window.self }); } catch(e) {}
  try { Object.defineProperty(window, 'parent', { get: () => window.self }); } catch(e) {}
}
</script>`;

// Injected only into the softphone popup (/softphone/ HTML).
// 1. Redirects wss:// SIP connections through our local tunnel so Origin can be spoofed.
// 2. Auto-logins and populates localStorage so the SPA has fresh tokens.
const SOFTPHONE_AUTOLOGIN_SCRIPT = `<script>
(function() {
  var _WS = window.WebSocket;
  function PatchedWS(url, protos) {
    var originalUrl = url;
    if (/^wss:\\/\\/[^\\/]*\\.miitel\\.net(:\\d+)?\\//i.test(url)) {
      // SIP server: must tunnel (Origin check)
      var u = new URL(url);
      var port = u.port || '443';
      url = 'ws://' + location.host + '/_wstunnel?h=' + encodeURIComponent(u.hostname + ':' + port) + '&p=' + encodeURIComponent(u.pathname + u.search);
    }
    // .miitel.jp (GraphQL): connect directly — let browser use native wss://
    var ws = protos !== undefined ? new _WS(url, protos) : new _WS(url);
    if (originalUrl !== url) {
      ws = new Proxy(ws, {
        get: function(target, prop) {
          if (prop === 'url') return originalUrl;
          var val = target[prop];
          return typeof val === 'function' ? val.bind(target) : val;
        },
        set: function(target, prop, value) {
          target[prop] = value;
          return true;
        }
      });
    }
    return ws;
  }
  PatchedWS.prototype = _WS.prototype;
  PatchedWS.CONNECTING = _WS.CONNECTING;
  PatchedWS.OPEN = _WS.OPEN;
  PatchedWS.CLOSING = _WS.CLOSING;
  PatchedWS.CLOSED = _WS.CLOSED;
  window.WebSocket = PatchedWS;
})();
(async function() {
  try {
    var h = { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' };
    await fetch('/_auth/login', { method: 'POST', headers: h });
    var tr = await fetch('/_auth/tokens', { method: 'POST', headers: h });
    if (tr.ok) {
      var t = await tr.json();
      localStorage.setItem('access_token', t.access_token);
      localStorage.setItem('refresh_token', t.refresh_token);
      localStorage.setItem('refresh_token_expires_at', t.refresh_token_expires_at);
      if (t.id_token) localStorage.setItem('id_token', t.id_token);
    }
  } catch(e) { console.warn('[autologin]', e); }
})();
</script>`;


// ── Reverse proxy: everything else → MiiTel with Bearer token from cookie ──
const proxyMiddleware = createProxyMiddleware({
    target: MIITEL_ORIGIN,
    changeOrigin: true,
    ws: true,
    selfHandleResponse: true, // required for responseInterceptor
    on: {
      proxyReq(proxyReq, req) {
        const cookieToken = req.cookies?.miitel_access_token;
        const spaAuth = req.headers.authorization;

        // Only inject token if the SPA's JS didn't already set one
        if (!spaAuth) {
          if (cookieToken) {
            proxyReq.setHeader("Authorization", `Bearer ${cookieToken}`);
          }
        }

        // Log auth status for API calls to help debug 401s
        if (req.url.startsWith("/api/")) {
          const authSource = spaAuth ? "SPA header" : cookieToken ? "cookie" : "NONE";
          console.log(`[proxy] ${req.method} ${req.url} | auth: ${authSource}`);
        } else {
          console.log(`[proxy] ${req.method} ${req.url} → ${MIITEL_ORIGIN}${req.url}`);
        }

        // MiiTel API requires X-TENANT-CODE header — the SPA derives it from
        // hostname (e.g. "trial0195-id" from "trial0195-id.miitel.jp"), but on
        // localhost it falls back to a dev tenant. Force the correct value.
        proxyReq.setHeader("X-TENANT-CODE", TENANT);
        // Override Referer/Origin so MiiTel's Cloudflare doesn't block localhost
        proxyReq.setHeader("Referer", MIITEL_ORIGIN + req.url);
        proxyReq.setHeader("Origin", MIITEL_ORIGIN);
      },
      proxyRes: responseInterceptor(async (buffer, proxyRes, req, res) => {
        // Strip headers that block iframe embedding — must delete from
        // proxyRes.headers (the source) since responseInterceptor copies them
        delete proxyRes.headers["x-frame-options"];
        delete proxyRes.headers["content-security-policy"];
        delete proxyRes.headers["content-security-policy-report-only"];
        // Also remove from res in case they were already copied
        res.removeHeader("x-frame-options");
        res.removeHeader("content-security-policy");
        res.removeHeader("content-security-policy-report-only");

        if (req.url.startsWith("/api/")) {
          console.log(`[proxy] ${req.method} ${req.url} ← ${proxyRes.statusCode}`);
          if (req.url.includes("sip_credentials")) {
            console.log("[sip-creds]", buffer.toString("utf8").slice(0, 500));
          }
        } else if (proxyRes.statusCode >= 400) {
          console.log(`[proxy] ${req.method} ${req.url} ← ${proxyRes.statusCode}`);
        }

        const contentType = proxyRes.headers["content-type"] || "";

        // Inject frame-bypass script into HTML responses
        if (contentType.includes("text/html")) {
          const body = buffer.toString("utf8");
          const isSoftphone = req.url.startsWith("/softphone/") || req.url === "/softphone";
          const script = FRAME_BYPASS_SCRIPT + (isSoftphone ? SOFTPHONE_AUTOLOGIN_SCRIPT : "");
          if (body.includes("<head")) {
            return body.replace(/(<head[^>]*>)/i, `$1${script}`);
          }
          return script + body;
        }

        return buffer;
      }),
    },
  });
app.use(proxyMiddleware);

const server = app.listen(3000, () => {
  console.log("Server running at http://localhost:3000");
});

// ── WebSocket tunnel ──
// The softphone script redirects wss://*.miitel.jp / wss://*.miitel.net to
// ws://localhost:3000/_wstunnel?h=<host:port>&p=<path>.
// Here we open a real TLS connection to the original host and spoof Origin.
server.on("upgrade", (req, socket, head) => {
  if (!req.url.startsWith("/_wstunnel?")) {
    // Let http-proxy-middleware handle .miitel.jp WebSocket upgrades (e.g. GraphQL)
    proxyMiddleware.upgrade(req, socket, head);
    return;
  }

  const params = new URLSearchParams(req.url.slice("/_wstunnel?".length));
  const host = params.get("h") || "";
  const wsPath = decodeURIComponent(params.get("p") || "/ws");

  // Safety: only tunnel to trusted miitel domains
  if (!host.match(/\.(miitel\.jp|miitel\.net)(:\d+)?$/)) {
    socket.end("HTTP/1.1 403 Forbidden\r\n\r\n");
    return;
  }

  const resolvedHost = host.startsWith(".") ? TENANT + host : host;
  const [hostname, portStr] = resolvedHost.split(":");
  const port = parseInt(portStr || "443");
  console.log(`[ws-tunnel] → wss://${resolvedHost}${wsPath}`);

  const upstream = tls.connect(port, hostname, { servername: hostname });

  upstream.on("error", (err) => {
    console.error("[ws-tunnel] error:", err.message);
    try { socket.end("HTTP/1.1 502 Bad Gateway\r\n\r\n"); } catch {}
  });

  upstream.on("secureConnect", () => {
    const lines = [
      `GET ${wsPath} HTTP/1.1`,
      `Host: ${hostname}`,
      `Origin: ${MIITEL_ORIGIN}`,
      `Upgrade: websocket`,
      `Connection: Upgrade`,
      `Sec-WebSocket-Version: 13`,
      `Sec-WebSocket-Key: ${req.headers["sec-websocket-key"]}`,
    ];
    if (req.headers["sec-websocket-protocol"]) {
      lines.push(`Sec-WebSocket-Protocol: ${req.headers["sec-websocket-protocol"]}`);
    }
    upstream.write(lines.join("\r\n") + "\r\n\r\n");
    if (head && head.length) upstream.write(head);

    let buf = Buffer.alloc(0);
    upstream.on("data", function onData(chunk) {
      buf = Buffer.concat([buf, chunk]);
      if (buf.indexOf("\r\n\r\n") !== -1) {
        upstream.removeListener("data", onData);
        const statusLine = buf.toString("utf8").split("\r\n")[0];
        console.log(`[ws-tunnel] ← ${statusLine}`);
        socket.write(buf);
        // Log first few SIP messages for debugging
        let logCount = 0;
        function decodeWsFrame(chunk, dir) {
          if (logCount >= 6) return;
          try {
            let i = 0;
            while (i < chunk.length && logCount < 6) {
              const byte1 = chunk[i], byte2 = chunk[i+1];
              const opcode = byte1 & 0x0f;
              const masked = (byte2 & 0x80) !== 0;
              let payLen = byte2 & 0x7f;
              i += 2;
              if (payLen === 126) { payLen = chunk.readUInt16BE(i); i += 2; }
              else if (payLen === 127) { payLen = Number(chunk.readBigUInt64BE(i)); i += 8; }
              const maskBytes = masked ? chunk.slice(i, i+4) : null;
              if (masked) i += 4;
              if (opcode === 1 || opcode === 2) { // text or binary
                const pay = chunk.slice(i, i + Math.min(payLen, 300));
                const text = masked ? Buffer.from(pay.map((b, j) => b ^ maskBytes[j%4])).toString() : pay.toString();
                console.log(`[sip-msg] ${dir}: ${text.slice(0,300)}`);
                logCount++;
              } else if (opcode === 8) {
                console.log(`[sip-msg] ${dir}: WS CLOSE frame`);
                logCount++;
              }
              i += payLen;
            }
          } catch(e) {}
        }
        upstream.on("data", (chunk) => { decodeWsFrame(chunk, "sip→br"); socket.write(chunk); });
        socket.on("data", (chunk) => { decodeWsFrame(chunk, "br→sip"); upstream.write(chunk); });
      }
    });
  });

  socket.on("error", (e) => { console.error("[ws-tunnel] browser socket error:", e.message); upstream.destroy(); });
  socket.on("close", (hadErr) => { console.log(`[ws-tunnel] browser closed (hadErr=${hadErr})`); upstream.destroy(); });
  upstream.on("close", (hadErr) => { console.log(`[ws-tunnel] upstream closed (hadErr=${hadErr})`); socket.destroy(); });
});
