/* Dekarson energicentral: inloggning mot Homey via Athom-molnet och säker proxy.
   Hemligheter (Cloudflare secrets): CLIENT_ID, CLIENT_SECRET, ALLOWED_EMAIL
   Variabel: SITE_ORIGIN (t.ex. https://dekarson.matthiasmodig.se)
   KV-bindning: KV */
const ATHOM = "https://api.athom.com";
const SESSION_TTL = 60 * 60 * 24 * 30;

const ALLOWED = [
  ["GET", /^\/api\/manager\/devices\/device\/?$/],
  ["GET", /^\/api\/manager\/zones\/zone\/?$/],
  ["GET", /^\/api\/manager\/insights\/log\/.*$/],
  ["GET", /^\/api\/manager\/logic\/variable\/?$/],
  ["GET", /^\/api\/manager\/flow\/(flow|advancedflow)\/?$/],
  ["PUT", /^\/api\/manager\/devices\/device\/[0-9a-f-]{36}\/capability\/[A-Za-z0-9_.]+$/],
  ["POST", /^\/api\/manager\/flow\/(flow|advancedflow)\/[0-9a-f-]{36}\/trigger$/],
];

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const cors = {
      "Access-Control-Allow-Origin": env.SITE_ORIGIN,
      "Access-Control-Allow-Headers": "Authorization, Content-Type",
      "Access-Control-Allow-Methods": "GET, PUT, POST, OPTIONS",
      "Access-Control-Max-Age": "86400",
      "Vary": "Origin",
    };
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    try {
      if (url.pathname === "/login") return await login(url, env);
      if (url.pathname === "/callback") return await callback(url, env, req);
      if (url.pathname === "/logout") {
        const s = bearer(req);
        if (s) await env.KV.delete("sess:" + s);
        return json({ ok: true }, 200, cors);
      }
      if (url.pathname === "/me") {
        const ok = await sessionOk(req, env);
        return json({ ok }, ok ? 200 : 401, cors);
      }
      if (url.pathname.startsWith("/api/")) {
        if (!(await sessionOk(req, env))) return json({ error: "Inte inloggad" }, 401, cors);
        const allowed = ALLOWED.some(([m, re]) => m === req.method && re.test(url.pathname));
        if (!allowed) return json({ error: "Anropet är inte tillåtet" }, 403, cors);
        return await proxy(req, url, env, cors);
      }
      return json({ ok: true, service: "dekarson-energicentral" }, 200, cors);
    } catch (e) {
      return json({ error: String(e && e.message || e) }, 502, cors);
    }
  },
};

const json = (o, status = 200, headers = {}) =>
  new Response(JSON.stringify(o), { status, headers: { "Content-Type": "application/json", ...headers } });
const bearer = (req) => (req.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "") || null;
const rand = () => [...crypto.getRandomValues(new Uint8Array(32))].map((b) => b.toString(16).padStart(2, "0")).join("");

async function sessionOk(req, env) {
  const s = bearer(req);
  return !!(s && s.length === 64 && (await env.KV.get("sess:" + s)));
}

function login(url, env) {
  const redirect = url.origin + "/callback";
  const state = rand().slice(0, 24);
  const u = new URL(ATHOM + "/oauth2/authorise");
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", env.CLIENT_ID);
  u.searchParams.set("redirect_uri", redirect);
  u.searchParams.set("state", state);
  return new Response(null, {
    status: 302,
    headers: { Location: u.toString(), "Set-Cookie": `st=${state}; Max-Age=600; Path=/; HttpOnly; Secure; SameSite=Lax` },
  });
}

async function tokenCall(env, params) {
  const r = await fetch(ATHOM + "/oauth2/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: "Basic " + btoa(env.CLIENT_ID + ":" + env.CLIENT_SECRET),
    },
    body: new URLSearchParams(params),
  });
  if (!r.ok) throw new Error("Athom token " + r.status + ": " + (await r.text()).slice(0, 200));
  const t = await r.json();
  return { access: t.access_token, refresh: t.refresh_token, exp: Date.now() + (t.expires_in || 3600) * 1000 - 60000 };
}

async function callback(url, env, req) {
  const code = url.searchParams.get("code");
  if (!code) return new Response("Ingen kod från Homey.", { status: 400 });
  const state = url.searchParams.get("state");
  const cookie = (req.headers.get("Cookie") || "").match(/(?:^|;\s*)st=([a-f0-9]+)/);
  if (!state || !cookie || cookie[1] !== state) return new Response("Ogiltig inloggning (state). Försök igen.", { status: 400 });
  const tok = await tokenCall(env, { grant_type: "authorization_code", code, redirect_uri: url.origin + "/callback" });
  const me = await (await fetch(ATHOM + "/user/me", { headers: { Authorization: "Bearer " + tok.access } })).json();
  if (!me.email || me.email.toLowerCase() !== String(env.ALLOWED_EMAIL).toLowerCase()) {
    return new Response("Det här kontot har inte åtkomst.", { status: 403 });
  }
  await env.KV.put("athom", JSON.stringify(tok));
  const sess = rand();
  await env.KV.put("sess:" + sess, "1", { expirationTtl: SESSION_TTL });
  return new Response(null, { status: 302, headers: { Location: env.SITE_ORIGIN + "/#session=" + sess } });
}

async function athomAccess(env) {
  let tok = JSON.parse((await env.KV.get("athom")) || "null");
  if (!tok) throw new Error("Ingen Homey-inloggning sparad. Logga in igen.");
  if (Date.now() > tok.exp) {
    const n = await tokenCall(env, { grant_type: "refresh_token", refresh_token: tok.refresh });
    tok = { access: n.access, refresh: n.refresh || tok.refresh, exp: n.exp };
    await env.KV.put("athom", JSON.stringify(tok));
  }
  return tok.access;
}

async function homeySession(env, force) {
  if (!force) {
    const c = JSON.parse((await env.KV.get("homey")) || "null");
    if (c && Date.now() < c.exp) return c;
  }
  const access = await athomAccess(env);
  const me = await (await fetch(ATHOM + "/user/me", { headers: { Authorization: "Bearer " + access } })).json();
  const h = (me.homeys || [])[0];
  if (!h || !h.remoteUrl) throw new Error("Hittade ingen Homey med fjärradress.");
  const deleg = await (await fetch(ATHOM + "/delegation/token?audience=homey", { method: "POST", headers: { Authorization: "Bearer " + access } })).json();
  const lr = await fetch(h.remoteUrl + "/api/manager/users/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token: deleg }),
  });
  if (!lr.ok) throw new Error("Homey-inloggning " + lr.status);
  const s = { remote: h.remoteUrl, token: await lr.json(), exp: Date.now() + 50 * 60 * 1000 };
  await env.KV.put("homey", JSON.stringify(s));
  return s;
}

async function proxy(req, url, env, cors) {
  const body = req.method === "GET" ? undefined : await req.text();
  const call = async (s) =>
    fetch(s.remote + url.pathname + url.search, {
      method: req.method,
      headers: { Authorization: "Bearer " + s.token, "Content-Type": "application/json" },
      body,
    });
  let r = await call(await homeySession(env, false));
  if (r.status === 401) r = await call(await homeySession(env, true));
  return new Response(r.body, { status: r.status, headers: { "Content-Type": r.headers.get("Content-Type") || "application/json", ...cors } });
}
