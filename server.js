import express from "express";
import cookieParser from "cookie-parser";
import { createProxyMiddleware } from "http-proxy-middleware";
import path from "path";

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
  res.cookie("miitel_access_token", auth.access_token, {
    ...COOKIE_OPTS,
    maxAge: (auth.expires_in || 3600) * 1000,
  });
  res.cookie("miitel_refresh_token", auth.refresh_token, {
    ...COOKIE_OPTS,
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
  });
  // Store expiry timestamp so we know when to refresh
  res.cookie("miitel_token_expires_at", String(Date.now() + (auth.expires_in || 3600) * 1000), {
    ...COOKIE_OPTS,
    maxAge: (auth.expires_in || 3600) * 1000,
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
app.use(express.json());
app.use(cookieParser());

// ── Security headers for our own pages ──
app.use((req, res, next) => {
  // Only apply to our own routes, not proxied MiiTel content
  if (req.path === "/" || req.path.startsWith("/_")) {
    // Block inline scripts except our own (nonce would be better for production)
    res.setHeader("Content-Security-Policy",
      "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-src 'self';"
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
  });
});

// ── Serve our frontend at / ──
app.get("/", (_req, res) => {
  res.sendFile(path.resolve("public/index.html"));
});

// ── Reverse proxy: everything else → MiiTel with Bearer token from cookie ──
app.use(
  createProxyMiddleware({
    target: MIITEL_ORIGIN,
    changeOrigin: true,
    ws: true, // proxy WebSocket connections too
    on: {
      proxyReq(proxyReq, req) {
        // Only inject token if the SPA's JS didn't already set one
        if (!req.headers.authorization) {
          const token = req.cookies?.miitel_access_token;
          if (token) {
            proxyReq.setHeader("Authorization", `Bearer ${token}`);
          }
        }
        // MiiTel API requires X-TENANT-CODE header — the SPA derives it from
        // hostname (e.g. "trial0195-id" from "trial0195-id.miitel.jp"), but on
        // localhost it falls back to a dev tenant. Force the correct value.
        proxyReq.setHeader("X-TENANT-CODE", TENANT);
        // Log proxied requests for debugging
        console.log(`[proxy] ${req.method} ${req.url} → ${MIITEL_ORIGIN}${req.url}`);
      },
      proxyRes(proxyRes, req) {
        // Strip headers that block iframe embedding
        delete proxyRes.headers["x-frame-options"];
        delete proxyRes.headers["content-security-policy"];
        // Log response status for debugging
        if (proxyRes.statusCode >= 400) {
          console.log(`[proxy] ${req.method} ${req.url} ← ${proxyRes.statusCode}`);
        }
      },
    },
  })
);

app.listen(3000, () => {
  console.log("Server running at http://localhost:3000");
});
