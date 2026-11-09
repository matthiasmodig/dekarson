/* Dekarson energicentral: inloggning mot Homey via Athom-molnet och säker proxy.
   Hemligheter (Cloudflare secrets): CLIENT_ID, CLIENT_SECRET, ALLOWED_EMAIL, USERS
   USERS = JSON med användare till inloggningssidan: {"matthias":"pbkdf2$100000$salt$hash","anna":"..."}; skapa varje värde med: node worker/hash.js "lösenord"
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
  ["GET", /^\/api\/image\/[0-9a-zA-Z-]{8,64}$/],
  ["GET", /^\/api\/manager\/images\/image\/?$/],
  ["POST", /^\/api\/manager\/flow\/flowcardaction\/homey(:|%3A)device(:|%3A)[0-9a-f-]{36}\/(homey(:|%3A)device(:|%3A)[0-9a-f-]{36}(:|%3A))?action_CMD_SNAPSHOT\/run$/],
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
      if (url.pathname === "/auth" && req.method === "POST") return await auth(req, env, cors);
      if (url.pathname === "/login") return await login(url, env);
      if (url.pathname === "/callback") return await callback(url, env, req);
      if (url.pathname === "/logout") {
        const s = bearer(req);
        if (s) { SESS.delete(s); await env.KV.delete("sess:" + s); }
        return json({ ok: true }, 200, cors);
      }
      if (url.pathname === "/me") {
        const ok = await sessionOk(req, env);
        return json({ ok }, ok ? 200 : 401, cors);
      }
      if (url.pathname === "/cal" && req.method === "POST") {
        if (!(await sessionOk(req, env))) return json({ error: "Inte inloggad" }, 401, cors);
        let target;
        try { target = new URL((await req.json()).url); } catch (e) { return json({ error: "Ogiltig adress" }, 400, cors); }
        if (target.protocol !== "https:" || target.hostname !== "calendar.google.com" || !/\.ics$/.test(target.pathname))
          return json({ error: "Bara iCal-adresser från calendar.google.com tillåts" }, 403, cors);
        const r = await fetch(target.toString(), { cf: { cacheTtl: 300, cacheEverything: true } });
        return new Response(await r.text(), { status: r.status, headers: { "Content-Type": "text/calendar; charset=utf-8", ...cors } });
      }
      if (url.pathname === "/sport" && req.method === "GET") {
        if (!(await sessionOk(req, env))) return json({ error: "Inte inloggad" }, 401, cors);
        try { return json(await sportData(env, url.searchParams.get("k") || ""), 200, cors); }
        catch (e) { return json({ error: e.message }, 502, cors); }
      }
      if (url.pathname === "/tibber" && req.method === "GET") {
        if (!(await sessionOk(req, env))) return json({ error: "Inte inloggad" }, 401, cors);
        if (url.searchParams.get("history")) {
          const hit = await env.KV.get("tp:hist", "json");
          if (hit && Date.now() - hit.at < 10 * 60e3) return json(hit, 200, cors);
          const ks = (await env.KV.list({ prefix: "tp:day:" })).keys.map((k) => k.name).sort().slice(-400);
          const days = [];
          for (const k of ks) {
            const d = await env.KV.get(k, "json");
            if (!d || !d.intervals || !d.intervals.length) continue;
            const t = d.intervals.map((x) => x.t);
            days.push({ day: d.day, n: t.length, avg: t.reduce((a, b) => a + b, 0) / t.length, min: Math.min(...t), max: Math.max(...t) });
          }
          const out = { at: Date.now(), days };
          await env.KV.put("tp:hist", JSON.stringify(out), { expirationTtl: 3600 });
          return json(out, 200, cors);
        }
        const day = url.searchParams.get("day");
        if (day) {
          if (!/^\d{4}-\d{2}-\d{2}$/.test(day)) return json({ error: "Ogiltigt datum" }, 400, cors);
          return json((await env.KV.get("tp:day:" + day, "json")) || { day, intervals: [] }, 200, cors);
        }
        return json(await tibberCurrent(env, false), 200, cors);
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
  async scheduled(event, env, ctx) {
    ctx.waitUntil(tibberCurrent(env, true).catch(() => {}));
  },
};

/* ---------- Tibber elpriser (Dekarsön 235), 15-minutersupplösning ----------
   Secrets: TIBBER_API_TOKEN (obligatorisk), TIBBER_HOME_ID (krävs om kontot har fler än ett hem).
   Priserna sparas permanent per dag i KV (tp:day:YYYY-MM-DD), nyckel = startsAt, så inga dubbletter uppstår.
   Token skickas aldrig till webbläsaren och ingår aldrig i svar. */
const TIBBER_Q = `query GetTibberPrices { viewer { homes { id appNickname timeZone currentSubscription { priceInfo(resolution: QUARTER_HOURLY) {
  current { startsAt energy tax total currency level } today { startsAt energy tax total currency level } tomorrow { startsAt energy tax total currency level } } } } } }`;
const stockholmDay = (iso) => new Intl.DateTimeFormat("sv-SE", { timeZone: "Europe/Stockholm", year: "numeric", month: "2-digit", day: "2-digit" }).format(new Date(iso));
const stockholmHour = () => +new Intl.DateTimeFormat("en-GB", { timeZone: "Europe/Stockholm", hour: "numeric", hourCycle: "h23" }).format(new Date());

async function tibberCurrent(env, fromCron) {
  const cached = (await env.KV.get("tp:cur", "json")) || null;
  const now = Date.now(), today = stockholmDay(new Date()), age = cached ? now - cached.fetchedAt : Infinity;
  const hasTomorrow = !!(cached && cached.intervals.some((x) => stockholmDay(x.s) > today));
  const wantTomorrow = stockholmHour() >= 13 && !hasTomorrow;
  const dayChanged = cached && cached.today !== today;
  const stale = !cached || dayChanged || age > 6 * 3600e3 || (wantTomorrow && age > 60e3);
  if (!stale) return { ...cached, cached: true };
  const lastTry = +(await env.KV.get("tp:lastTry")) || 0;
  if (now - lastTry < (wantTomorrow ? 60e3 : 5 * 60e3) && cached) return { ...cached, cached: true };
  await env.KV.put("tp:lastTry", String(now), { expirationTtl: 3600 });
  try {
    if (!env.TIBBER_API_TOKEN) throw new Error("TIBBER_API_TOKEN saknas som secret i Cloudflare-workern dekarson-api.");
    const r = await fetch("https://api.tibber.com/v1-beta/gql", {
      method: "POST",
      headers: { Authorization: "Bearer " + env.TIBBER_API_TOKEN, "Content-Type": "application/json" },
      body: JSON.stringify({ query: TIBBER_Q }),
    });
    if (!r.ok) throw new Error("Tibber svarade " + r.status);
    const j = await r.json();
    if (j.errors) throw new Error("Tibber: " + String(j.errors[0] && j.errors[0].message).slice(0, 120));
    const homes = (j.data && j.data.viewer && j.data.viewer.homes) || [];
    const home = env.TIBBER_HOME_ID ? homes.find((h) => h.id === env.TIBBER_HOME_ID) : homes.length === 1 ? homes[0] : null;
    if (!home) throw new Error(env.TIBBER_HOME_ID ? "Hittade inte hemmet TIBBER_HOME_ID hos Tibber." : "Kontot har flera hem. Sätt secret TIBBER_HOME_ID till rätt id: " + homes.map((h) => h.id + " (" + h.appNickname + ")").join(", "));
    const pi = home.currentSubscription && home.currentSubscription.priceInfo;
    if (!pi) throw new Error("Hemmet saknar prisinformation.");
    const map = new Map();
    for (const x of [...(pi.today || []), ...(pi.tomorrow || [])]) map.set(x.startsAt, { s: x.startsAt, e: x.energy, x: x.tax, t: x.total, l: x.level, c: x.currency });
    const intervals = [...map.values()].sort((a, b) => (a.s < b.s ? -1 : 1));
    const cur = pi.current ? { s: pi.current.startsAt, e: pi.current.energy, x: pi.current.tax, t: pi.current.total } : null;
    const byDay = {};
    for (const x of intervals) (byDay[stockholmDay(x.s)] = byDay[stockholmDay(x.s)] || []).push(x);
    for (const [d, arr] of Object.entries(byDay)) {
      const old = (await env.KV.get("tp:day:" + d, "json")) || { day: d, intervals: [] };
      const m = new Map(old.intervals.map((x) => [x.s, x]));
      arr.forEach((x) => m.set(x.s, x));
      await env.KV.put("tp:day:" + d, JSON.stringify({ day: d, intervals: [...m.values()].sort((a, b) => (a.s < b.s ? -1 : 1)) }));
    }
    const out = { fetchedAt: now, today, homeId: home.id, tz: home.timeZone, resolution: "QUARTER_HOURLY", current: cur, intervals };
    await env.KV.put("tp:cur", JSON.stringify(out));
    return { ...out, cached: false };
  } catch (e) {
    if (fromCron) throw e;
    if (cached) return { ...cached, cached: true, error: String(e.message || e) };
    return { error: String(e.message || e), intervals: [] };
  }
}

const json = (o, status = 200, headers = {}) =>
  new Response(JSON.stringify(o), { status, headers: { "Content-Type": "application/json", ...headers } });
const bearer = (req) => (req.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "") || null;
const rand = () => [...crypto.getRandomValues(new Uint8Array(32))].map((b) => b.toString(16).padStart(2, "0")).join("");

/* Minnescache i workern (per instans) så varje anrop inte kostar KV-läsningar: sessioner 5 min, Homey-inloggning till dess den går ut. */
const SESS = new Map();
let HS = null;
async function sessionOk(req, env) {
  const s = bearer(req);
  if (!(s && s.length === 64)) return false;
  const c = SESS.get(s);
  if (c && c > Date.now()) return true;
  const ok = !!(await env.KV.get("sess:" + s));
  if (ok) SESS.set(s, Date.now() + 5 * 60 * 1000);
  return ok;
}

const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
const unhex = (s) => new Uint8Array((s.match(/../g) || []).map((h) => parseInt(h, 16)));
async function verifyPw(pw, rec) {
  const [kind, it, salt, hash] = String(rec).split("$");
  if (kind !== "pbkdf2" || !salt || !hash) return false;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(pw), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: unhex(salt), iterations: Math.min(100000, +it || 100000) }, key, 256);
  const got = hex(bits);
  let d = got.length ^ hash.length;
  for (let i = 0; i < got.length; i++) d |= got.charCodeAt(i) ^ (hash.charCodeAt(i) || 0);
  return d === 0;
}
/* Inloggningssidan: användarnamn + lösenord mot USERS. Max 8 felförsök per IP och 15 minuter. */
async function auth(req, env, cors) {
  const ip = req.headers.get("CF-Connecting-IP") || "x", rk = "rl:" + ip;
  const n = +(await env.KV.get(rk)) || 0;
  if (n >= 8) return json({ error: "För många försök. Vänta 15 minuter." }, 429, cors);
  let b;
  try { b = await req.json(); } catch (e) { return json({ error: "Ogiltig begäran" }, 400, cors); }
  let users = {};
  try { users = JSON.parse(env.USERS || "{}"); } catch (e) { return json({ error: "USERS är inte giltig JSON i Cloudflare." }, 500, cors); }
  const name = String(b.user || "").trim().toLowerCase(), rec = Object.prototype.hasOwnProperty.call(users, name) ? users[name] : null;
  const ok = rec ? await verifyPw(String(b.pass || ""), rec) : (await verifyPw("x", "pbkdf2$100000$00$00"), false);
  if (!ok) {
    await env.KV.put(rk, String(n + 1), { expirationTtl: 900 });
    return json({ error: "Fel användarnamn eller lösenord." }, 401, cors);
  }
  await env.KV.delete(rk);
  const sess = rand();
  await env.KV.put("sess:" + sess, name, { expirationTtl: SESSION_TTL });
  return json({ session: sess, user: name }, 200, cors);
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
    if (HS && Date.now() < HS.exp) return HS;
    const c = JSON.parse((await env.KV.get("homey")) || "null");
    if (c && Date.now() < c.exp) { HS = c; return c; }
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
  HS = s;
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


/* ---- Idrott: tabeller och spelschema via API-Sports (api-football / api-hockey) ----
   Secret: APISPORTS_KEY (gratiskonto på api-sports.io räcker; samma nyckel för fotboll och hockey).
   Svaren cachas i KV (1 h) och återanvänds vid fel, så gratisgränsen (100 anrop/dygn) räcker. */
const SPORT = {
  ishockey: { host: "v1.hockey.api-sports.io", hockey: true, name: /hockeyallsvenskan/i, team: /modo/i },
  allsvenskan: { host: "v3.football.api-sports.io", name: /^allsvenskan$/i },
  superettan: { host: "v3.football.api-sports.io", name: /^superettan$/i },
  "ettan-norra": { host: "v3.football.api-sports.io", name: /^ettan.*norra/i },
  "ettan-sodra": { host: "v3.football.api-sports.io", name: /^ettan.*s(ö|o)dra/i },
  damallsvenskan: { host: "v3.football.api-sports.io", name: /^(obos )?damallsvenskan$/i },
  elitettan: { host: "v3.football.api-sports.io", name: /^elitettan$/i },
};
async function apis(env, host, path) {
  if (!env.APISPORTS_KEY) throw new Error("APISPORTS_KEY saknas som secret i Cloudflare-workern dekarson-api.");
  const r = await fetch("https://" + host + path, { headers: { "x-apisports-key": env.APISPORTS_KEY } });
  if (!r.ok) throw new Error("API-Sports svarade " + r.status);
  const j = await r.json();
  const er = j.errors && (Array.isArray(j.errors) ? j.errors[0] : Object.values(j.errors)[0]);
  if (er) throw new Error("API-Sports: " + String(er).slice(0, 140));
  return j.response || [];
}
async function sportData(env, k) {
  const cfg = SPORT[k];
  if (!cfg) throw new Error("Okänd serie");
  const ck = "sp:" + k, now = Date.now();
  const hit = await env.KV.get(ck, "json");
  if (hit && now - hit.at < 3600e3) return { ...hit, cached: true };
  if (hit && now - (hit.tried || 0) < 120e3) return { ...hit, cached: true };
  try {
    const d = new Date(), y = d.getUTCFullYear(), m = d.getUTCMonth() + 1;
    const season = cfg.hockey ? (m >= 7 ? y : y - 1) : y;
    const lgs = (await env.KV.get("sp:lg:" + cfg.host + ":" + season, "json")) || [];
    let lg = lgs.find((x) => cfg.name.test(x.name));
    if (!lg) {
      const all = await apis(env, cfg.host, "/leagues?country=Sweden&season=" + season);
      const list = all.map((x) => ({ id: x.league ? x.league.id : x.id, name: x.league ? x.league.name : x.name }));
      await env.KV.put("sp:lg:" + cfg.host + ":" + season, JSON.stringify(list), { expirationTtl: 7 * 86400 });
      lg = list.find((x) => cfg.name.test(x.name));
    }
    if (!lg) throw new Error("Hittade inte serien hos API-Sports för säsongen " + season);
    let out;
    if (cfg.hockey) {
      const st = await apis(env, cfg.host, "/standings?league=" + lg.id + "&season=" + season);
      /* En serie kan ha flera steg/grupper (grundserie, slutspel ...): ta första gruppen i grundserien och inga dubbletter. */
      let rows = st.flat();
      const stages = [...new Set(rows.map((r) => r.stage || ""))];
      const stg = stages.find((x) => /regular|grund|season/i.test(x)) ?? stages[0];
      rows = rows.filter((r) => (r.stage || "") === stg);
      const g0 = rows[0] && rows[0].group && rows[0].group.name;
      rows = rows.filter((r) => !g0 || (r.group && r.group.name) === g0);
      const seen = new Set();
      rows = rows.filter((r) => (seen.has(r.team.id) ? false : seen.add(r.team.id)));
      const table = rows.map((r) => ({
        pos: r.position, id: r.team.id, team: r.team.name, p: r.games.played,
        w: (r.games.win && r.games.win.total) || 0, otw: (r.games.win_overtime && r.games.win_overtime.total) || 0,
        otl: (r.games.lose_overtime && r.games.lose_overtime.total) || 0, l: (r.games.lose && r.games.lose.total) || 0,
        gf: r.goals && r.goals.for, ga: r.goals && r.goals.against, pts: r.points,
      })).sort((a, b) => a.pos - b.pos);
      const modo = table.find((t) => cfg.team.test(t.team));
      let games = [];
      if (modo) {
        games = (await apis(env, cfg.host, "/games?league=" + lg.id + "&season=" + season + "&team=" + modo.id)).map((g) => ({
          id: g.id, ts: g.timestamp * 1000, home: g.teams.home.name, away: g.teams.away.name,
          hs: g.scores.home, as: g.scores.away, st: g.status && g.status.short,
        }));
      }
      out = { league: lg.name, season, table, games, team: modo ? modo.team : "MODO Hockey" };
    } else {
      const st = await apis(env, cfg.host, "/standings?league=" + lg.id + "&season=" + season);
      const grp = st[0] && st[0].league && st[0].league.standings && st[0].league.standings[0] || [];
      const table = grp.map((r) => ({
        pos: r.rank, id: r.team.id, team: r.team.name, p: r.all.played, w: r.all.win, d: r.all.draw, l: r.all.lose,
        gf: r.all.goals.for, ga: r.all.goals.against, pts: r.points, form: r.form || "",
      }));
      const games = (await apis(env, cfg.host, "/fixtures?league=" + lg.id + "&season=" + season)).map((g) => ({
        id: g.fixture.id, ts: g.fixture.timestamp * 1000, home: g.teams.home.name, away: g.teams.away.name,
        hs: g.goals.home, as: g.goals.away, st: g.fixture.status && g.fixture.status.short,
      })).sort((a, b) => a.ts - b.ts);
      out = { league: lg.name, season, table, games };
    }
    out.at = now;
    await env.KV.put(ck, JSON.stringify(out));
    return { ...out, cached: false };
  } catch (e) {
    if (hit) { await env.KV.put(ck, JSON.stringify({ ...hit, tried: now })); return { ...hit, cached: true, stale: true, error: e.message }; }
    throw e;
  }
}
