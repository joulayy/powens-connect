/**
 * Powens Connect — Serverless handler (Vercel)
 *
 * Variables d'environnement à configurer dans Vercel :
 *   APP_PASSWORD         → mot de passe du dashboard
 *   COOKIE_SECRET        → clé HMAC (64 caractères hex aléatoires)
 *   BASE_URL             → URL Vercel, ex: https://powens-connect.vercel.app
 *   POWENS_DOMAIN        → joulaytest-sandbox
 *   POWENS_CLIENT_ID     → 48742070
 *   POWENS_CLIENT_SECRET → UHqtu7kqpjP8ip8EenWcb9iHryrF1GO8
 */

const https  = require("https");
const path   = require("path");
const fs     = require("fs");
const crypto = require("crypto");

// ── Config ───────────────────────────────────────────────────────────────────
const DOMAIN        = process.env.POWENS_DOMAIN        || "joulaytest-sandbox";
const CLIENT_ID     = process.env.POWENS_CLIENT_ID     || "48742070";
const CLIENT_SECRET = process.env.POWENS_CLIENT_SECRET || "UHqtu7kqpjP8ip8EenWcb9iHryrF1GO8";
const APP_PASSWORD  = process.env.APP_PASSWORD         || "powens2024";
const COOKIE_SECRET = process.env.COOKIE_SECRET        || "dev-secret-change-me-in-production!!";
const BASE_URL      = (process.env.BASE_URL || "http://localhost:3000").replace(/\/$/, "");

const API_BASE    = `https://${DOMAIN}.biapi.pro/2.0`;
const REDIRECT_URI = `${BASE_URL}/callback`;

// ── Cookie signé (HMAC-SHA256) ────────────────────────────────────────────────
// Le cookie contient les données de session + la session Powens, signé par le
// serveur. Impossible à falsifier côté client sans connaître COOKIE_SECRET.

function signCookie(data) {
  const payload = Buffer.from(JSON.stringify(data)).toString("base64url");
  const sig = crypto.createHmac("sha256", COOKIE_SECRET)
    .update(payload).digest("base64url");
  return `${payload}.${sig}`;
}

function verifyCookie(cookieStr) {
  if (!cookieStr) return null;
  try {
    const dot = cookieStr.lastIndexOf(".");
    const payload = cookieStr.slice(0, dot);
    const sig     = cookieStr.slice(dot + 1);
    const expected = crypto.createHmac("sha256", COOKIE_SECRET)
      .update(payload).digest("base64url");
    if (sig !== expected) return null;
    return JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  } catch { return null; }
}

function getCookieValue(req, name) {
  const cookies = req.headers.cookie || "";
  const match = cookies.split(";").find(c => c.trim().startsWith(`${name}=`));
  return match ? match.trim().slice(name.length + 1) : null;
}

function makeSessionCookie(session) {
  const value = signCookie(session);
  return `pc_auth=${value}; HttpOnly; Secure; SameSite=Lax; Max-Age=${60 * 60 * 24 * 30}; Path=/`;
}

function getSession(req) {
  const raw = getCookieValue(req, "pc_auth");
  return verifyCookie(raw); // { loggedIn: true, powens: {id, token} } ou null
}

// ── Appel API Powens ─────────────────────────────────────────────────────────
function powensRequest(apiPath, options = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(`${API_BASE}${apiPath}`);
    const reqOpts = {
      hostname: parsed.hostname,
      path: parsed.pathname + parsed.search,
      method: options.method || "GET",
      headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    };
    const req = https.request(reqOpts, res => {
      let data = "";
      res.on("data", c => (data += c));
      res.on("end", () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch  { resolve({ status: res.statusCode, body: data }); }
      });
    });
    req.on("error", reject);
    if (options.body)
      req.write(typeof options.body === "string" ? options.body : JSON.stringify(options.body));
    req.end();
  });
}

async function getWebviewUrl(session) {
  let powens = session?.powens || null;

  if (!powens) {
    // Créer un nouvel utilisateur Powens
    const auth = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64");
    const r = await powensRequest("/users", {
      method: "POST",
      headers: { Authorization: `Basic ${auth}` },
    });
    if (r.status >= 400) throw new Error(`Erreur création user: ${JSON.stringify(r.body)}`);
    powens = { id: r.body.id, token: r.body.auth_token };
  }

  const codeRes = await powensRequest("/auth/token/code", {
    headers: { Authorization: `Bearer ${powens.token}` },
  });
  if (codeRes.status >= 400) throw new Error(`Erreur code: ${JSON.stringify(codeRes.body)}`);

  const webviewUrl = `https://webview.powens.com/connect?domain=${DOMAIN}&client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&code=${codeRes.body.code}`;
  return { webviewUrl, powens };
}

// ── Pages HTML ────────────────────────────────────────────────────────────────
function loginPage(error = "") {
  return `<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8" /><meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Powens Connect — Connexion</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f7f7f5;min-height:100vh;display:flex;align-items:center;justify-content:center}
    .card{background:#fff;border-radius:16px;padding:2.5rem;max-width:360px;width:90%;box-shadow:0 4px 24px rgba(0,0,0,.09)}
    .logo{display:flex;align-items:center;gap:10px;margin-bottom:2rem}
    .logo-icon{width:36px;height:36px;background:#1a3fa8;border-radius:9px;display:flex;align-items:center;justify-content:center;color:#fff;font-size:16px;font-weight:700}
    .logo-text{font-size:16px;font-weight:600}
    h1{font-size:20px;font-weight:600;margin-bottom:6px}
    .sub{font-size:14px;color:#6b6b6b;margin-bottom:1.75rem}
    .lock{font-size:2rem;margin-bottom:1rem}
    label{font-size:13px;font-weight:500;display:block;margin-bottom:6px}
    input{width:100%;padding:11px 14px;font-size:15px;border:1.5px solid #e8e8e4;border-radius:9px;outline:none;font-family:inherit;transition:border-color .15s}
    input:focus{border-color:#1a3fa8}
    .err{font-size:13px;color:#c0392b;margin-top:8px}
    button{width:100%;margin-top:1.25rem;padding:12px;background:#1a1a1a;color:#fff;border:none;border-radius:9px;font-size:15px;font-weight:500;cursor:pointer;font-family:inherit;transition:opacity .15s}
    button:hover{opacity:.85}
  </style>
</head>
<body>
  <div class="card">
    <div class="logo"><div class="logo-icon">P</div><div class="logo-text">Powens Connect</div></div>
    <div class="lock">🔐</div>
    <h1>Accès sécurisé</h1>
    <p class="sub">Entrez votre mot de passe pour accéder au dashboard.</p>
    <form method="POST" action="/login">
      <label for="pwd">Mot de passe</label>
      <input type="password" id="pwd" name="password" autofocus autocomplete="current-password" />
      ${error ? `<div class="err">⚠ ${error}</div>` : ""}
      <button type="submit">Se connecter →</button>
    </form>
  </div>
</body>
</html>`;
}

// ── Helpers réponse ───────────────────────────────────────────────────────────
function sendJson(res, status, data, extraHeaders = {}) {
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    ...extraHeaders,
  });
  res.end(JSON.stringify(data));
}

function sendHtml(res, html, extraHeaders = {}) {
  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", ...extraHeaders });
  res.end(html);
}

function redirect(res, location, extraHeaders = {}) {
  res.writeHead(302, { Location: location, ...extraHeaders });
  res.end();
}

async function readBody(req) {
  return new Promise(resolve => {
    let body = "";
    req.on("data", c => (body += c));
    req.on("end", () => resolve(body));
  });
}

// ── Handler principal (export Vercel) ─────────────────────────────────────────
module.exports = async (req, res) => {
  const { pathname, query } = new URL(req.url, "http://x");

  if (req.method === "OPTIONS") {
    res.writeHead(204, {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    });
    res.end();
    return;
  }

  console.log(`${req.method} ${pathname}`);

  // ── Login ────────────────────────────────────────────────────────────────
  if (pathname === "/login") {
    if (req.method === "GET") return sendHtml(res, loginPage());
    if (req.method === "POST") {
      const body = await readBody(req);
      const params = new URLSearchParams(body);
      const password = params.get("password") || "";
      if (password === APP_PASSWORD) {
        const session = { loggedIn: true, powens: null };
        return redirect(res, "/", { "Set-Cookie": makeSessionCookie(session) });
      }
      return sendHtml(res, loginPage("Mot de passe incorrect."));
    }
  }

  // ── Logout ───────────────────────────────────────────────────────────────
  if (pathname === "/logout") {
    return redirect(res, "/login", {
      "Set-Cookie": "pc_auth=; Max-Age=0; Path=/",
    });
  }

  // ── Callback webview (pas d'auth requise) ────────────────────────────────
  if (pathname === "/callback") {
    if (query.get("error")) {
      return sendHtml(res, `<html><body style="font-family:sans-serif;padding:2rem">
        <h2>❌ Erreur: ${query.get("error")}</h2>
        <script>window.opener?.postMessage({type:'POWENS_ERROR'},'*');setTimeout(()=>window.close(),2000)</script>
      </body></html>`);
    }
    return sendHtml(res, `<html><body style="font-family:-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#f7f7f5;margin:0">
      <div style="text-align:center;padding:2rem;background:#fff;border-radius:16px;box-shadow:0 4px 20px rgba(0,0,0,.1);max-width:340px">
        <div style="font-size:3rem;margin-bottom:1rem">✅</div>
        <h2 style="font-size:18px;margin:0 0 8px">Banque connectée !</h2>
        <p style="color:#666;font-size:14px;margin:0">Retournez sur votre dashboard.<br>Cette fenêtre se ferme automatiquement.</p>
      </div>
      <script>
        window.opener?.postMessage({type:'POWENS_CONNECTED'},'*');
        setTimeout(()=>{ window.close(); window.location.href='/?connected=true'; }, 2000);
      </script>
    </body></html>`);
  }

  // ── Vérification auth ─────────────────────────────────────────────────────
  const session = getSession(req);
  if (!session?.loggedIn) return redirect(res, "/login");

  // ── Dashboard (index.html) ────────────────────────────────────────────────
  if (pathname === "/" || pathname === "/index.html") {
    const htmlFile = path.join(process.cwd(), "index.html");
    if (fs.existsSync(htmlFile)) {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      fs.createReadStream(htmlFile).pipe(res);
    } else {
      sendJson(res, 404, { error: "index.html introuvable" });
    }
    return;
  }

  // ── POST /api/add-connection ──────────────────────────────────────────────
  if (pathname === "/api/add-connection" && req.method === "POST") {
    try {
      const { webviewUrl, powens } = await getWebviewUrl(session);
      // Mettre à jour le cookie avec les credentials Powens (si nouveaux)
      const newSession = { ...session, powens };
      const cookie = makeSessionCookie(newSession);
      return sendJson(res, 200, { webviewUrl }, { "Set-Cookie": cookie });
    } catch (e) {
      return sendJson(res, 500, { error: e.message });
    }
  }

  // ── POST /api/create-user ────────────────────────────────────────────────
  if (pathname === "/api/create-user" && req.method === "POST") {
    try {
      const { webviewUrl, powens } = await getWebviewUrl(session);
      const newSession = { ...session, powens };
      const cookie = makeSessionCookie(newSession);
      return sendJson(res, 200, { userId: powens.id, webviewUrl }, { "Set-Cookie": cookie });
    } catch (e) {
      return sendJson(res, 500, { error: e.message });
    }
  }

  // ── GET /api/accounts ─────────────────────────────────────────────────────
  if (pathname === "/api/accounts" && req.method === "GET") {
    if (!session.powens) return sendJson(res, 401, { error: "Aucune session Powens. Connectez d'abord une banque." });
    try {
      const r = await powensRequest(
        `/users/${session.powens.id}/accounts?expand=connection,connection.connector`,
        { headers: { Authorization: `Bearer ${session.powens.token}` } }
      );
      return sendJson(res, r.status, r.body);
    } catch (e) {
      return sendJson(res, 500, { error: e.message });
    }
  }

  // ── DELETE /api/accounts/:id ──────────────────────────────────────────────
  if (pathname.startsWith("/api/accounts/") && req.method === "DELETE") {
    if (!session.powens) return sendJson(res, 401, { error: "Aucune session Powens." });
    const accountId = pathname.split("/").pop();
    try {
      const r = await powensRequest(
        `/users/${session.powens.id}/accounts/${accountId}`,
        {
          method: "PUT",
          headers: { Authorization: `Bearer ${session.powens.token}` },
          body: { disabled: true },
        }
      );
      return sendJson(res, r.status, r.body);
    } catch (e) {
      return sendJson(res, 500, { error: e.message });
    }
  }

  // ── GET /api/transactions ─────────────────────────────────────────────────
  if (pathname === "/api/transactions" && req.method === "GET") {
    if (!session.powens) return sendJson(res, 401, { error: "Aucune session Powens." });
    const limit = query.get("limit") || 30;
    try {
      const r = await powensRequest(
        `/users/${session.powens.id}/transactions?limit=${limit}&expand=category`,
        { headers: { Authorization: `Bearer ${session.powens.token}` } }
      );
      return sendJson(res, r.status, r.body);
    } catch (e) {
      return sendJson(res, 500, { error: e.message });
    }
  }

  sendJson(res, 404, { error: "Route inconnue" });
};
