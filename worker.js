// =====================================================================
// EARNING APP - standalone web app (no Telegram, no crypto, no mining)
// Single-file Cloudflare Worker (frontend + backend) + D1 database
// Binding: D1 "DB" | Variable: ADMIN_EMAIL (the email that gets the Admin tab)
// Features: email login, farming, daily check-in, tasks (timer enforced on server),
// referral bonus, withdraw by bKash / Nagad / PayPal (manual admin payout), admin panel
// =====================================================================
const DEF = { name: "EarnBD", cur: "৳", farm_h: 6, farm_r: 0.5, ci: "0.2,0.3,0.4,0.5,0.6,0.8,2", ref: 5, secs: 20, minw: 100, wd: 1, notice: "" };
const NUM = ["farm_h", "farm_r", "ref", "secs", "minw", "wd"];
const J = (d, s = 200) => new Response(JSON.stringify(d), { status: s, headers: { "content-type": "application/json", "cache-control": "no-store" } });
const r2 = n => Math.round(n * 100) / 100;
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, "0")).join("");
const rnd = n => hex(crypto.getRandomValues(new Uint8Array(n)));
const day = t => Math.floor((t + 216e5) / 864e5); // day number in Bangladesh time (UTC+6)
const EM = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
async function hash(p, salt) {
  const k = await crypto.subtle.importKey("raw", new TextEncoder().encode(p), "PBKDF2", false, ["deriveBits"]);
  return hex(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: new TextEncoder().encode(salt), iterations: 100000 }, k, 256));
}
const ch = async st => (await st.run()).meta.changes;
const credit = (db, u, amt, k) => [
  db.prepare("UPDATE users SET bal=ROUND(bal+?,2) WHERE id=?").bind(amt, u),
  db.prepare("INSERT INTO hist(u,k,amt,ts) VALUES(?,?,?,?)").bind(u, k, amt, Date.now())];

let READY = false;
async function init(db) {
  if (READY) return;
  await db.batch([
    "CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,email TEXT UNIQUE,name TEXT,pw TEXT,salt TEXT,bal REAL DEFAULT 0,code TEXT UNIQUE,refby INTEGER DEFAULT 0,refok INTEGER DEFAULT 0,banned INTEGER DEFAULT 0,created INTEGER,lci INTEGER DEFAULT 0,streak INTEGER DEFAULT 0)",
    "CREATE TABLE IF NOT EXISTS sess(t TEXT PRIMARY KEY,u INTEGER,exp INTEGER)",
    "CREATE TABLE IF NOT EXISTS farm(u INTEGER PRIMARY KEY,s INTEGER DEFAULT 0)",
    "CREATE TABLE IF NOT EXISTS tasks(id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT,url TEXT,rw REAL,on1 INTEGER DEFAULT 1)",
    "CREATE TABLE IF NOT EXISTS tdone(u INTEGER,t INTEGER,s INTEGER,d INTEGER DEFAULT 0,PRIMARY KEY(u,t))",
    "CREATE TABLE IF NOT EXISTS hist(id INTEGER PRIMARY KEY AUTOINCREMENT,u INTEGER,k TEXT,amt REAL,ts INTEGER)",
    "CREATE INDEX IF NOT EXISTS hu ON hist(u,id)",
    "CREATE TABLE IF NOT EXISTS wd(id INTEGER PRIMARY KEY AUTOINCREMENT,u INTEGER,m TEXT,a TEXT,amt REAL,st TEXT DEFAULT 'p',ts INTEGER)",
    "CREATE TABLE IF NOT EXISTS cfg(k TEXT PRIMARY KEY,v TEXT)"].map(s => db.prepare(s)));
  READY = true;
}
async function getCfg(db) {
  const o = { ...DEF };
  (await db.prepare("SELECT k,v FROM cfg").all()).results.forEach(r => { if (r.k in DEF) o[r.k] = NUM.includes(r.k) ? Number(r.v) : r.v });
  return o;
}
async function mkSess(db, u) {
  const t = rnd(24);
  await db.prepare("INSERT INTO sess(t,u,exp) VALUES(?,?,?)").bind(t, u, Date.now() + 30 * 864e5).run();
  await db.prepare("DELETE FROM sess WHERE exp<?").bind(Date.now()).run();
  return t;
}

// ---------------------------------------------------------------- API
async function api(req, env) {
  const db = env.DB; await init(db);
  let b; try { b = await req.json() } catch (e) { return J({ e: "Bad request" }, 400) }
  const a = String(b.a || ""), now = Date.now(), c = await getCfg(db);

  if (a === "reg") {
    const em = String(b.email || "").trim().toLowerCase(), nm = String(b.name || "").trim().slice(0, 30), pw = String(b.pass || "");
    if (!EM.test(em) || em.length > 100) return J({ e: "Invalid email" }, 400);
    if (!nm) return J({ e: "Enter your name" }, 400);
    if (pw.length < 6 || pw.length > 100) return J({ e: "Password must be 6+ characters" }, 400);
    const salt = rnd(8), code = rnd(4);
    const rf = b.ref ? await db.prepare("SELECT id FROM users WHERE code=?").bind(String(b.ref).slice(0, 12)).first() : null;
    try { await db.prepare("INSERT INTO users(email,name,pw,salt,code,refby,created) VALUES(?,?,?,?,?,?,?)").bind(em, nm, await hash(pw, salt), salt, code, rf ? rf.id : 0, now).run() }
    catch (e) { return J({ e: "Email already registered" }, 400) }
    const u = await db.prepare("SELECT id FROM users WHERE email=?").bind(em).first();
    return J({ t: await mkSess(db, u.id) });
  }
  if (a === "login") {
    const em = String(b.email || "").trim().toLowerCase();
    const u = await db.prepare("SELECT id,pw,salt,banned FROM users WHERE email=?").bind(em).first();
    if (!u || u.pw !== await hash(String(b.pass || ""), u.salt)) return J({ e: "Wrong email or password" }, 400);
    if (u.banned) return J({ e: "Account blocked" }, 403);
    return J({ t: await mkSess(db, u.id) });
  }

  const s = await db.prepare("SELECT u FROM sess WHERE t=? AND exp>?").bind((req.headers.get("authorization") || "").slice(7), now).first();
  if (!s) return J({ e: "auth" }, 401);
  const u = await db.prepare("SELECT * FROM users WHERE id=?").bind(s.u).first();
  if (!u || u.banned) return J({ e: "Account blocked" }, 403);
  const adm = !!env.ADMIN_EMAIL && u.email === env.ADMIN_EMAIL.trim().toLowerCase();
  if (a.startsWith("ad") && !adm) return J({ e: "No access" }, 403);

  if (a === "me") {
    const f = await db.prepare("SELECT s FROM farm WHERE u=?").bind(u.id).first();
    const tk = (await db.prepare("SELECT t.id,t.title,t.url,t.rw,d.s,d.d FROM tasks t LEFT JOIN tdone d ON d.t=t.id AND d.u=? WHERE t.on1=1 ORDER BY t.id DESC").bind(u.id).all()).results;
    const h = (await db.prepare("SELECT k,amt,ts FROM hist WHERE u=? ORDER BY id DESC LIMIT 30").bind(u.id).all()).results;
    const w = (await db.prepare("SELECT id,m,a,amt,st,ts FROM wd WHERE u=? ORDER BY id DESC LIMIT 15").bind(u.id).all()).results;
    const rc = await db.prepare("SELECT COUNT(*) n,COALESCE(SUM(refok),0) k FROM users WHERE refby=?").bind(u.id).first();
    const dn = day(now);
    return J({ u: { id: u.id, name: u.name, email: u.email, bal: u.bal, code: u.code, n: u.lci === dn || u.lci === dn - 1 ? u.streak : 0, ci: u.lci === dn }, fs: f ? f.s : 0, now, c, tk, h, w, rc, adm });
  }
  if (a === "fs") {
    await db.prepare("INSERT OR IGNORE INTO farm(u,s) VALUES(?,0)").bind(u.id).run();
    if (!await ch(db.prepare("UPDATE farm SET s=? WHERE u=? AND s=0").bind(now, u.id))) return J({ e: "Already farming" }, 400);
    return J({ msg: "Farming started 🌱" });
  }
  if (a === "fh") {
    if (!await ch(db.prepare("UPDATE farm SET s=0 WHERE u=? AND s>0 AND s<=?").bind(u.id, now - c.farm_h * 36e5))) return J({ e: "Not ready yet" }, 400);
    await db.batch(credit(db, u.id, c.farm_r, "farm"));
    // referral bonus: paid once, when the invited user finishes the first harvest
    if (u.refby && !u.refok && await ch(db.prepare("UPDATE users SET refok=1 WHERE id=? AND refok=0").bind(u.id)))
      await db.batch(credit(db, u.refby, c.ref, "ref"));
    return J({ msg: "Harvested +" + c.cur + c.farm_r });
  }
  if (a === "ci") {
    const d = day(now), st = u.lci === d - 1 ? u.streak + 1 : 1, arr = c.ci.split(",").map(Number), rw = r2(arr[(st - 1) % arr.length] || 0);
    if (!await ch(db.prepare("UPDATE users SET lci=?,streak=? WHERE id=? AND lci<?").bind(d, st, u.id, d))) return J({ e: "Already checked in today" }, 400);
    await db.batch(credit(db, u.id, rw, "ci"));
    return J({ msg: "Check-in +" + c.cur + rw });
  }
  if (a === "ts") {
    const id = Number(b.id);
    if (!await db.prepare("SELECT id FROM tasks WHERE id=? AND on1=1").bind(id).first()) return J({ e: "Task not found" }, 400);
    await db.prepare("INSERT OR IGNORE INTO tdone(u,t,s) VALUES(?,?,?)").bind(u.id, id, now).run();
    return J({});
  }
  if (a === "tc") {
    const id = Number(b.id), t = await db.prepare("SELECT rw FROM tasks WHERE id=? AND on1=1").bind(id).first();
    if (!t) return J({ e: "Task not found" }, 400);
    if (!await ch(db.prepare("UPDATE tdone SET d=1 WHERE u=? AND t=? AND d=0 AND s<=?").bind(u.id, id, now - c.secs * 1000))) return J({ e: "Please wait for the timer" }, 400);
    await db.batch(credit(db, u.id, t.rw, "task"));
    return J({ msg: "Task done +" + c.cur + t.rw });
  }
  if (a === "wr") {
    const m = String(b.m), ac = String(b.ac || "").trim(), amt = r2(Number(b.amt));
    if (!c.wd) return J({ e: "Withdraw is closed right now" }, 400);
    if (!["bkash", "nagad", "paypal"].includes(m)) return J({ e: "Choose a method" }, 400);
    if (m === "paypal" ? !EM.test(ac) : !/^01[3-9][0-9]{8}$/.test(ac)) return J({ e: m === "paypal" ? "Enter your PayPal email" : "Enter a valid 11-digit number" }, 400);
    if (!(amt >= c.minw)) return J({ e: "Minimum withdraw is " + c.cur + c.minw }, 400);
    if ((await db.prepare("SELECT COUNT(*) n FROM wd WHERE u=? AND st='p'").bind(u.id).first()).n >= 1) return J({ e: "You already have a pending request" }, 400);
    if (!await ch(db.prepare("UPDATE users SET bal=ROUND(bal-?,2) WHERE id=? AND bal>=?").bind(amt, u.id, amt))) return J({ e: "Not enough balance" }, 400);
    await db.batch([db.prepare("INSERT INTO wd(u,m,a,amt,ts) VALUES(?,?,?,?,?)").bind(u.id, m, ac, amt, now),
      db.prepare("INSERT INTO hist(u,k,amt,ts) VALUES(?,?,?,?)").bind(u.id, "wd", -amt, now)]);
    return J({ msg: "Withdraw request sent ✓" });
  }

  // ------------------------------------------------------------ admin
  if (a === "ad") {
    const q = "%" + String(b.q || "").trim().toLowerCase() + "%";
    const st = await db.prepare("SELECT COUNT(*) n,COALESCE(SUM(bal),0) b FROM users").first();
    const w = (await db.prepare("SELECT w.id,w.m,w.a,w.amt,u.email FROM wd w JOIN users u ON u.id=w.u WHERE w.st='p' ORDER BY w.id LIMIT 50").all()).results;
    const t = (await db.prepare("SELECT id,title,url,rw FROM tasks WHERE on1=1 ORDER BY id DESC").all()).results;
    const us = b.q ? (await db.prepare("SELECT id,email,name,bal,banned FROM users WHERE email LIKE ? OR name LIKE ? LIMIT 10").bind(q, q).all()).results : [];
    return J({ st, w, t, us });
  }
  if (a === "adw") {
    const id = Number(b.id), w = await db.prepare("SELECT u,amt FROM wd WHERE id=? AND st='p'").bind(id).first();
    if (!w) return J({ e: "Already handled" }, 400);
    if (b.ok) { await db.prepare("UPDATE wd SET st='d' WHERE id=? AND st='p'").bind(id).run(); return J({ msg: "Marked as paid" }) }
    if (await ch(db.prepare("UPDATE wd SET st='r' WHERE id=? AND st='p'").bind(id))) await db.batch(credit(db, w.u, w.amt, "refund"));
    return J({ msg: "Rejected and refunded" });
  }
  if (a === "adj") {
    const amt = r2(Number(b.amt)); if (!amt) return J({ e: "Enter an amount" }, 400);
    await db.batch(credit(db, Number(b.id), amt, "admin")); return J({ msg: "Balance adjusted" });
  }
  if (a === "adb") { await db.prepare("UPDATE users SET banned=? WHERE id=? AND email<>?").bind(b.on ? 1 : 0, Number(b.id), u.email).run(); return J({ msg: "Done" }) }
  if (a === "adt") {
    const rw = r2(Number(b.rw)), t = String(b.title || "").trim().slice(0, 80), url = String(b.url || "").trim();
    if (!t || !/^https?:\/\//.test(url) || !(rw > 0)) return J({ e: "Title, a full link (https://) and reward are needed" }, 400);
    await db.prepare("INSERT INTO tasks(title,url,rw) VALUES(?,?,?)").bind(t, url, rw).run(); return J({ msg: "Task added" });
  }
  if (a === "adx") { await db.prepare("UPDATE tasks SET on1=0 WHERE id=?").bind(Number(b.id)).run(); return J({ msg: "Task removed" }) }
  if (a === "adcfg") {
    for (const k of Object.keys(DEF)) {
      if (b[k] === undefined) continue;
      let v = String(b[k]).slice(0, 200);
      if (NUM.includes(k)) { v = Number(v); if (!isFinite(v) || v < 0) return J({ e: "Invalid " + k }, 400) }
      await db.prepare("INSERT INTO cfg(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").bind(k, String(v)).run();
    }
    return J({ msg: "Settings saved" });
  }
  return J({ e: "Unknown action" }, 400);
}

export default {
  async fetch(req, env) {
    try {
      if (new URL(req.url).pathname === "/api" && req.method === "POST") return await api(req, env);
      return new Response(HTML, { headers: { "content-type": "text/html;charset=utf-8", "cache-control": "no-store" } });
    } catch (e) { return J({ e: "Server error" }, 500) }
  }
};

// ---------------------------------------------------------------- Frontend
const HTML = String.raw`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,viewport-fit=cover"><title>Earn</title>
<style>
:root{--a:#2dffa0;--bg:#030a06;--ln:#143826;--mu:#7aa88f;--rd:#ff5470;--gd:#f0d27a}
*{box-sizing:border-box;margin:0;-webkit-tap-highlight-color:transparent}
html{background:var(--bg)}
body{font:14px/1.4 system-ui,sans-serif;color:#e8fff2;padding:0 12px 96px;min-height:100vh;max-width:480px;margin:0 auto;background:repeating-conic-gradient(from 0deg at 50% 0,rgba(45,255,160,.035) 0 1deg,transparent 1deg 14deg),repeating-radial-gradient(circle at 50% 0,rgba(45,255,160,.035) 0 1px,transparent 1px 44px),radial-gradient(120% 55% at 50% -8%,#0c4a2c 0,transparent 62%),var(--bg);background-attachment:fixed}
.g{display:grid;gap:10px;grid-template-columns:repeat(auto-fit,minmax(145px,1fr))}
.c{background:linear-gradient(160deg,#0a1a12,#060f0a);border:1px solid var(--ln);border-radius:16px;padding:14px;margin-bottom:10px;box-shadow:0 6px 24px rgba(0,0,0,.35)}
.b{width:100%;padding:12px;border:1px solid rgba(110,230,170,.28);border-radius:12px;background:linear-gradient(135deg,#0f7a50,#094a31);color:#eafff3;font-weight:800;font-size:15px;margin-top:4px;transition:transform .1s;box-shadow:0 4px 14px rgba(0,0,0,.45);text-shadow:0 1px 0 rgba(0,0,0,.35)}
.b:active{transform:scale(.97)}.b:disabled{background:#12281c;color:var(--mu);box-shadow:none}
.b.x{background:var(--rd);color:#fff;box-shadow:none;border-color:transparent}.b.gd{background:linear-gradient(135deg,#f6dc8d,#c79a3b);color:#2a1d02;box-shadow:0 4px 16px rgba(240,210,122,.22);border-color:rgba(255,230,150,.5);text-shadow:none}
.b.s{width:auto;padding:8px 14px;margin:0;font-size:13px}.b.l{background:none;border:0;box-shadow:none;color:var(--mu);font-weight:500}
input,select{width:100%;padding:12px;margin:5px 0;border-radius:12px;border:1px solid var(--ln);background:#040c07;color:#e8fff2;font-size:16px}
nav{position:fixed;bottom:0;left:50%;transform:translateX(-50%);width:100%;max-width:480px;display:grid;grid-auto-flow:column;grid-auto-columns:1fr;background:rgba(5,14,9,.92);backdrop-filter:blur(10px);border-top:1px solid var(--ln);padding:6px 2px calc(6px + env(safe-area-inset-bottom))}
nav a{display:flex;flex-direction:column;align-items:center;gap:3px;padding:7px 0;font-size:11px;color:var(--mu)}nav a.on{color:var(--a)}
.big{font-size:clamp(28px,9vw,42px);font-weight:800;color:var(--a);font-variant-numeric:tabular-nums;letter-spacing:1px;margin:6px 0;text-shadow:0 0 18px rgba(45,255,160,.4)}
.m{color:var(--mu);font-size:12px}h3{margin:14px 0 8px}
header{position:sticky;top:0;z-index:5;display:flex;align-items:center;gap:10px;height:58px;margin:0 -12px;padding:0 12px;background:rgba(3,10,6,.94);backdrop-filter:blur(8px);border-bottom:1px solid var(--ln)}
.av{flex:none;width:40px;height:40px;border-radius:50%;background:linear-gradient(135deg,#2dffa0,#0a8a52);color:#02140a;display:grid;place-items:center;font-weight:800;border:2px solid var(--gd)}
.tt{flex:1;min-width:0;display:flex;flex-direction:column}.tt b{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.tt span{font-size:12px;color:var(--mu)}
.pill{padding:6px 12px;border:1px solid var(--gd);border-radius:18px;font-weight:700;flex:none;font-variant-numeric:tabular-nums;color:var(--gd)}.pg{padding-top:12px}
.pl{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--a);animation:pl 1.2s infinite}@keyframes pl{50%{opacity:.25;transform:scale(1.6)}}
.fi{animation:fi .22s}@keyframes fi{from{opacity:0;transform:translateY(8px)}}
#ts{position:fixed;top:66px;left:50%;transform:translate(-50%,-16px);background:#0d2418;border:1px solid var(--a);padding:10px 16px;border-radius:20px;opacity:0;transition:.25s;pointer-events:none;z-index:9;font-weight:700;max-width:92%;text-align:center}#ts.on{opacity:1;transform:translate(-50%,0)}
.r{display:flex;justify-content:space-between;gap:8px;align-items:center;word-break:break-all;padding:6px 0}.r .b{width:auto;padding:8px 12px;font-size:13px;margin:0}
.mine{text-align:center;padding:18px 14px;background:radial-gradient(90% 60% at 50% 0,rgba(45,255,160,.15),transparent 70%),linear-gradient(160deg,#0a1f15,#050e09)}
.st{display:inline-flex;align-items:center;gap:6px;padding:4px 12px;border-radius:20px;font-size:11px;font-weight:800;letter-spacing:1.5px;border:1px solid var(--ln);color:var(--mu)}
.st.on{color:var(--a);border-color:rgba(45,255,160,.5);box-shadow:0 0 14px rgba(45,255,160,.25)}
.ringw{position:relative;width:min(76vw,290px);aspect-ratio:1;margin:14px auto}
.ring{width:100%;height:100%;transform:rotate(-90deg)}
.rb{fill:none;stroke:#0f2a1d;stroke-width:10}
.rf{fill:none;stroke:url(#gr);stroke-width:10;stroke-linecap:round;stroke-dasharray:553;stroke-dashoffset:553;transition:stroke-dashoffset .3s;filter:drop-shadow(0 0 6px rgba(45,255,160,.7))}
.rin{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}.rin .big{font-size:clamp(22px,7vw,30px);margin:4px 0}
.stat3{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin:6px 0 12px;text-align:center}.stat3>div{background:#06120b;border:1px solid var(--ln);border-radius:12px;padding:9px 4px}.stat3 span{display:block;color:var(--mu);font-size:10px;letter-spacing:1px;text-transform:uppercase}.stat3 b{font-size:15px}
.vcard{position:relative;overflow:hidden;border-radius:20px;padding:18px;aspect-ratio:1.586/1;min-height:200px;color:#eafff3;background:radial-gradient(120% 120% at 100% 0,#16c47a 0,transparent 55%),linear-gradient(135deg,#052e1c 0,#0a5a37 45%,#031a10 100%);border:1px solid rgba(240,210,122,.4);box-shadow:0 14px 40px rgba(0,0,0,.6),0 0 30px rgba(45,255,160,.12);display:flex;flex-direction:column;justify-content:space-between;margin-bottom:10px}
.vcard::before{content:"";position:absolute;inset:0;background:repeating-conic-gradient(from 0deg at 100% 0,rgba(255,255,255,.05) 0 1deg,transparent 1deg 12deg),repeating-radial-gradient(circle at 100% 0,rgba(255,255,255,.05) 0 1px,transparent 1px 30px)}
.sh{position:absolute;inset:0;background:linear-gradient(115deg,transparent 40%,rgba(255,255,255,.15) 50%,transparent 60%);transform:translateX(-100%);animation:sh 5s infinite}@keyframes sh{60%,100%{transform:translateX(100%)}}
.vr{display:flex;justify-content:space-between;align-items:center;position:relative}.vcard>div{position:relative}
.vbrand{font-weight:800;letter-spacing:3px;font-size:13px;color:var(--gd)}.vl{font-size:9px;letter-spacing:1.5px;color:#9fd6b8}
.vn{font-size:13px;font-weight:700;letter-spacing:1px;text-transform:uppercase;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.vamt{font-size:clamp(24px,8vw,32px);font-weight:800;text-shadow:0 2px 10px rgba(0,0,0,.45);font-variant-numeric:tabular-nums}
.vno{font-family:ui-monospace,Menlo,monospace;letter-spacing:2.5px;font-size:15px;color:#d9fbe9}
.sg{display:grid;grid-auto-flow:column;grid-auto-columns:1fr;gap:4px;background:#06120b;border:1px solid var(--ln);border-radius:14px;padding:4px;margin-bottom:10px}
.sg a{padding:10px 0;text-align:center;border-radius:10px;color:var(--mu);font-weight:700;font-size:13px}.sg a.on{background:linear-gradient(135deg,#0f7a50,#094a31);color:#eafff3;box-shadow:inset 0 0 0 1px rgba(110,230,170,.35)}
.chp{display:inline-block;padding:2px 9px;border-radius:12px;font-size:10px;font-weight:800;letter-spacing:.5px}.chp.a{background:rgba(61,220,151,.15);color:#3ddc97}.chp.p{background:rgba(240,210,122,.15);color:var(--gd)}.chp.x{background:rgba(255,84,112,.15);color:var(--rd)}
.dep{display:flex;gap:8px;align-items:center;background:#040c07;border:1px dashed #2e6b4c;border-radius:12px;padding:8px 8px 8px 12px;margin:6px 0}
@media(prefers-reduced-motion:reduce){*{animation:none!important}}
</style></head><body><div id="app"><p class="m" style="padding:40px;text-align:center">Loading…</p></div><div id="ts"></div><nav id="nav"></nav>
<script>
const $=id=>document.getElementById(id);
const esc=s=>String(s==null?"":s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
let TK=localStorage.getItem("t"),S=null,tab="h",wsub="w",off=0,AD=null,AQ="",mode="login";
const money=n=>S.c.cur+(+n).toFixed(2);
const fmt=ms=>{const s=Math.max(0,Math.floor(ms/1e3));return Math.floor(s/3600)+"h "+Math.floor(s%3600/60)+"m "+s%60+"s"};
const ic=p=>'<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">'+p+'</svg>';
const IC={h:'<path d="M3 11l9-8 9 8v10a1 1 0 0 1-1 1h-5v-7H9v7H4a1 1 0 0 1-1-1z"/>',t:'<rect x="4" y="3" width="16" height="18" rx="2"/><path d="M8 12l3 3 5-6"/>',r:'<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20c0-3.6 2.9-6 6.5-6s6.5 2.4 6.5 6"/><circle cx="17.5" cy="9" r="2.5"/><path d="M17 14c2.6.2 4.5 2 4.5 5"/>',w:'<rect x="3" y="6" width="18" height="14" rx="3"/><path d="M3 10h18M16 15h2"/>',a:'<circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M4.9 19.1L7 17M17 7l2.1-2.1"/>'};
function toast(m){const e=$("ts");e.textContent=m;e.className="on";clearTimeout(toast.t);toast.t=setTimeout(()=>{e.className=""},2600)}
async function api(a,d){const r=await fetch("/api",{method:"POST",headers:{authorization:"Bearer "+(TK||"")},body:JSON.stringify(Object.assign({a:a},d||{}))});const j=await r.json();
 if(r.status===401&&a!=="login"&&a!=="reg"){TK=null;localStorage.removeItem("t");S=null;render();throw 0}return j}
async function load(){S=await api("me");off=S.now-Date.now();if(S.adm&&tab=="a")await adload();render()}
async function adload(q){if(q!==undefined)AQ=q;AD=await api("ad",{q:AQ})}
async function act(a,d){try{const j=await api(a,d);if(j.e){toast(j.e);return}if(j.t){TK=j.t;localStorage.setItem("t",TK)}if(j.msg)toast(j.msg);await load()}catch(e){}}
function auth(){const rg=mode=="reg";return '<div style="text-align:center;padding:46px 0 14px"><div style="font-size:46px">🕷</div><div class="big" style="font-size:30px">EARN</div><div class="m">Farm. Complete tasks. Get paid.</div></div><div class="c fi" data-f><b>'+(rg?'Create account':'Login')+'</b>'+(rg?'<input name="name" placeholder="Your name">':'')+'<input name="email" type="email" placeholder="Email"><input name="pass" type="password" placeholder="Password">'+
 '<button class="b" data-a="'+(rg?'reg':'login')+'">'+(rg?'Register':'Login')+'</button><button class="b l" data-a="mode" data-m="'+(rg?'login':'reg')+'">'+(rg?'Have an account? Login':'New here? Register')+'</button></div>'}
function head(){const u=S.u;return '<header><div class="av">'+esc((u.name||"?").charAt(0).toUpperCase())+'</div><div class="tt"><b>'+esc(u.name)+'</b><span>'+esc(S.c.name)+'</span></div><div class="pill">'+money(u.bal)+'</div></header><div class="pg fi">'}
function home(){const u=S.u,c=S.c,tot=c.farm_h*36e5,l=S.fs?S.fs+tot-(Date.now()+off):0,ready=S.fs&&l<=0,go=S.fs&&l>0;
 const o=!S.fs?553:ready?0:553*(l/tot);
 const mid=!S.fs?'<div style="font-size:40px">🌱</div><div class="m">Ready to plant</div><div class="big">+'+money(c.farm_r)+'</div>':go?'<div class="m">Growing</div><div class="big" id="ft">'+fmt(l)+'</div><div class="m">+'+money(c.farm_r)+' at harvest</div>':'<div style="font-size:40px">🌾</div><div class="big">+'+money(c.farm_r)+'</div><div class="m">Ready to harvest</div>';
 const bt=!S.fs?'<button class="b" data-a="fs">🌱 Start farming</button>':go?'<button class="b" disabled>Farming…</button>':'<button class="b gd" data-a="fh">🌾 Harvest '+money(c.farm_r)+'</button>';
 return (c.notice?'<div class="c" style="border-color:var(--gd);text-align:center">📢 '+esc(c.notice)+'</div>':'')+
 '<div class="c mine"><span class="st'+(go||ready?' on':'')+'">'+(go?'<i class="pl"></i>FARMING':ready?'● READY':'● IDLE')+'</span><div class="ringw"><svg class="ring" viewBox="0 0 200 200"><defs><linearGradient id="gr" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#2dffa0"/><stop offset="1" stop-color="#f0d27a"/></linearGradient></defs><circle class="rb" cx="100" cy="100" r="88"/><circle class="rf" id="rf" cx="100" cy="100" r="88" style="stroke-dashoffset:'+o+'"/></svg><div class="rin">'+mid+'</div></div>'+bt+'</div>'+
 '<div class="stat3"><div><span>Streak</span><b>'+u.n+' d</b></div><div><span>Invited</span><b>'+S.rc.k+'</b></div><div><span>Min withdraw</span><b>'+money(c.minw)+'</b></div></div>'}
function checkin(){const u=S.u,arr=S.c.ci.split(",").map(Number),L=arr.length,done=u.ci,cnt=done?((u.n-1)%L)+1:u.n%L;
 const g=arr.map((v,i)=>{const dn=i<cnt,cur=!done&&i==cnt;return '<div style="border:1px solid '+(cur?'var(--gd)':'var(--ln)')+';border-radius:12px;padding:8px 4px;text-align:center;background:'+(dn?'rgba(45,255,160,.12)':'transparent')+'"><div class="m">Day '+(i+1)+'</div><b style="color:'+(dn?'var(--a)':'var(--gd)')+'">'+money(v)+'</b><div class="m">'+(dn?'✓':cur?'Today':'🔒')+'</div></div>'}).join("");
 return '<div class="c"><b>Daily Check-in</b><p class="m">Streak: '+u.n+' day'+(u.n==1?'':'s')+'. Miss a day and it starts again.</p><div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(64px,1fr));gap:6px;margin:8px 0">'+g+'</div>'+(done?'<button class="b" disabled>Checked in today ✓</button>':'<button class="b" data-a="ci">Claim Day '+(cnt+1)+' · +'+money(arr[cnt]||0)+'</button>')+'</div>'}
function tasks(){return checkin()+'<h3>Tasks</h3><p class="m" style="margin:-4px 0 8px">Open the link, wait '+S.c.secs+' seconds, then claim.</p>'+(S.tk.length?'<div class="g">'+S.tk.map(k=>{const l=k.s?k.s+S.c.secs*1e3-(Date.now()+off):0;
 const bt=k.d?'<button class="b" disabled>Done ✓</button>':!k.s?'<button class="b" data-a="ts" data-id="'+k.id+'" data-url="'+esc(k.url)+'">Visit</button>':l>0?'<button class="b" disabled>⏳ '+Math.ceil(l/1e3)+'s</button>':'<button class="b gd" data-a="tc" data-id="'+k.id+'">Claim</button>';
 return '<div class="c"><span class="m">Task</span><div style="margin:4px 0;word-break:break-word">'+esc(k.title)+'</div><b style="color:var(--a)">+'+money(k.rw)+'</b><br>'+bt+'</div>'}).join("")+'</div>':'<div class="c m">No tasks yet. Come back soon.</div>')}
function refer(){const l=location.origin+"/?ref="+S.u.code,c=S.c;
 return '<div class="c"><b>👥 Earn '+money(c.ref)+' per successful referral</b><input readonly value="'+esc(l)+'"><div class="g"><button class="b" data-a="cp" data-l="'+esc(l)+'">Copy link</button><button class="b" data-a="sh" data-l="'+esc(l)+'">Share</button></div></div>'+
 '<div class="c"><div class="stat3"><div><span>Total</span><b>'+S.rc.n+'</b></div><div><span>Pending</span><b>'+(S.rc.n-S.rc.k)+'</b></div><div><span>Successful</span><b>'+S.rc.k+'</b></div></div><div class="r"><span class="m">Referral earnings</span><b>'+money(S.rc.k*c.ref)+'</b></div></div>'+
 '<div class="c"><b>How it works</b><p class="m">1. Share your link. 2. Your friend registers. 3. Your friend finishes their first harvest. Then the referral is Successful and you get '+money(c.ref)+' once. Until then it stays Pending. Fake or self-referral accounts get nothing.</p></div>'}
const KN={farm:"Farm",ci:"Check-in",task:"Task",ref:"Referral",wd:"Withdraw",refund:"Refund",admin:"Admin"};
const WS={p:'<span class="chp p">PENDING</span>',d:'<span class="chp a">PAID</span>',r:'<span class="chp x">REJECTED</span>'};
function wallet(){const u=S.u;let x='<div class="vcard"><div class="sh"></div><div class="vr"><span class="vbrand">'+esc(S.c.name).toUpperCase()+'</span><span class="vl">MEMBER</span></div><div><div class="vl">BALANCE</div><div class="vamt">'+money(u.bal)+'</div></div><div class="vr"><div class="vn">'+esc(u.name)+'</div></div></div>'+
 '<div class="sg">'+[["w","Withdraw"],["h","History"]].map(t=>'<a data-a="ws" data-s="'+t[0]+'" class="'+(wsub==t[0]?'on':'')+'">'+t[1]+'</a>').join("")+'</div>';
 if(wsub=="w"){x+=(S.c.wd?'<div class="c" data-f><b>Withdraw</b><p class="m">Minimum '+money(S.c.minw)+'. Requests are reviewed and paid manually by an admin.</p><select name="m"><option value="bkash">bKash</option><option value="nagad">Nagad</option><option value="paypal">PayPal</option></select><input name="ac" placeholder="bKash/Nagad number or PayPal email"><input name="amt" type="number" step="any" placeholder="Amount"><button class="b gd" data-a="wr">Request withdraw</button></div>':'<div class="c" style="text-align:center;padding:30px 14px"><b>Withdraw is closed</b><p class="m">Please check back later.</p></div>')+
 (S.w.length?'<div class="c"><b>Withdraw requests</b>'+S.w.map(w=>'<div class="r" style="border-top:1px solid var(--ln)"><span>'+w.m+' · '+esc(w.a)+'<br><span class="m">'+new Date(w.ts).toLocaleDateString()+'</span></span><span style="text-align:right"><b>'+money(w.amt)+'</b><br>'+WS[w.st]+'</span></div>').join("")+'</div>':'')}
 else x+='<div class="c"><b>Wallet history</b>'+(S.h.map(h=>'<div class="r" style="border-top:1px solid var(--ln)"><span>'+(KN[h.k]||h.k)+'<br><span class="m">'+new Date(h.ts).toLocaleString()+'</span></span><b style="color:'+(h.amt<0?'var(--rd)':'var(--a)')+'">'+(h.amt>=0?'+':'')+money(h.amt)+'</b></div>').join("")||'<p class="m">Nothing yet.</p>')+'</div>';
 return x+'<button class="b l" data-a="out">Log out</button>'}
const CF=[["name","Site name"],["cur","Currency symbol"],["farm_h","Farm hours"],["farm_r","Farm reward"],["ci","Check-in rewards (comma separated)"],["ref","Referral bonus"],["secs","Task timer (seconds)"],["minw","Minimum withdraw"],["wd","Withdraw open (1 = yes, 0 = no)"],["notice","Notice on home page"]];
function admin(){if(!AD)return"";let x='<div class="c"><b>🛠 Admin</b><p class="m">Users: '+AD.st.n+' · Total user balance: '+money(AD.st.b)+'</p></div>';
 x+='<div class="c"><b>Withdraw requests</b>'+(AD.w.map(w=>'<div class="r" style="border-top:1px solid var(--ln)"><span>'+esc(w.email)+'<br><span class="m">'+w.m+' · '+esc(w.a)+' · '+money(w.amt)+'</span></span><span style="display:flex;gap:6px"><button class="b gd" data-a="adw" data-id="'+w.id+'" data-ok="1">Paid</button><button class="b x" data-a="adw" data-id="'+w.id+'" data-ok="">✕</button></span></div>').join("")||'<p class="m">None</p>')+'</div>';
 x+='<div class="c" data-f><b>Add task</b><input name="title" placeholder="Title"><input name="url" placeholder="https://link"><input name="rw" type="number" step="any" placeholder="Reward"><button class="b" data-a="adt">Add</button></div>';
 x+='<div class="c"><b>Active tasks</b>'+AD.t.map(t=>'<div class="r" style="border-top:1px solid var(--ln)"><span>'+esc(t.title)+' · '+money(t.rw)+'</span><button class="b x" data-a="adx" data-id="'+t.id+'">✕</button></div>').join("")+'</div>';
 x+='<div class="c" data-f><b>Find user</b><input name="q" value="'+esc(AQ)+'" placeholder="email or name"><button class="b" data-a="ads">Search</button></div>';
 x+=AD.us.map(z=>'<div class="c" data-f><b>'+esc(z.name)+'</b> · '+esc(z.email)+'<br><span class="m">Balance '+money(z.bal)+(z.banned?' · BLOCKED':'')+'</span><input name="amt" type="number" step="any" placeholder="+ add / - deduct"><div class="g"><button class="b" data-a="adj" data-id="'+z.id+'">Adjust</button><button class="b x" data-a="adb" data-id="'+z.id+'" data-on="'+(z.banned?'':'1')+'">'+(z.banned?'Unblock':'Block')+'</button></div></div>').join("");
 x+='<div class="c" data-f><b>Settings</b>'+CF.map(f=>'<span class="m">'+f[1]+'</span><input name="'+f[0]+'" value="'+esc(S.c[f[0]])+'">').join("")+'<button class="b" data-a="adcfg">Save settings</button></div>';return x}
function render(){if(!S){$("app").innerHTML=auth();$("nav").innerHTML="";return}
 $("app").innerHTML=head()+({h:home,t:tasks,r:refer,w:wallet,a:admin})[tab]()+'</div>';
 const tb=[["h","Home"],["t","Tasks"],["r","Refer"],["w","Wallet"]];if(S.adm)tb.push(["a","Admin"]);
 $("nav").innerHTML=tb.map(t=>'<a data-a="tab" data-t="'+t[0]+'" class="'+(tab==t[0]?'on':'')+'">'+ic(IC[t[0]])+t[1]+'</a>').join("")}
document.onclick=async e=>{const b=e.target.closest("[data-a]");if(!b)return;const d=Object.assign({},b.dataset),a=d.a,F=b.closest("[data-f]");
 if(F)F.querySelectorAll("input,select").forEach(i=>{if(i.name)d[i.name]=i.value});
 if(a=="tab"){tab=d.t;if(tab=="a"&&S.adm)await adload();render();scrollTo(0,0)}
 else if(a=="ws"){wsub=d.s;render()}
 else if(a=="mode"){mode=d.m;render()}
 else if(a=="out"){TK=null;localStorage.removeItem("t");S=null;render()}
 else if(a=="cp"){try{await navigator.clipboard.writeText(d.l);toast("Copied ✓")}catch(x){toast(d.l)}}
 else if(a=="sh"){if(navigator.share)navigator.share({text:"Join and earn: "+d.l}).catch(()=>{});else{try{await navigator.clipboard.writeText(d.l);toast("Copied ✓")}catch(x){toast(d.l)}}}
 else if(a=="ts"){window.open(d.url,"_blank","noopener");act("ts",{id:d.id})}
 else if(a=="ads"){await adload(d.q);render()}
 else{if(a=="reg")d.ref=new URLSearchParams(location.search).get("ref")||"";act(a,d)}};
setInterval(()=>{if(!S)return;const n=Date.now()+off,c=S.c;
 if(tab=="h"&&S.fs){const tot=c.farm_h*36e5,l=S.fs+tot-n,ft=$("ft");if(l<=0&&ft){render();return}if(ft){ft.textContent=fmt(l);$("rf").style.strokeDashoffset=553*(l/tot)}}
 if(tab=="t"&&S.tk.some(k=>k.s&&!k.d&&n-k.s<c.secs*1e3+1e3))render()},1000);
if(TK)load().catch(()=>render());else render();
</script></body></html>`;

// =====================================================================
// DEPLOYMENT
// 1. D1:       wrangler d1 create earn-db
//              wrangler.toml:  [[d1_databases]] binding="DB" database_name="earn-db" database_id="<id>"
//              Tables are created automatically on the first request.
// 2. Admin:    wrangler.toml:  [vars] ADMIN_EMAIL = "you@example.com"
//              Register on the site with that email to get the Admin tab.
// 3. Deploy:   wrangler deploy   -> open https://NAME.SUBDOMAIN.workers.dev
// NOTE: Withdrawals are NOT sent automatically. Admin pays manually from his own
//       bKash/Nagad/PayPal and presses "Paid". Reject refunds the balance.
// =====================================================================
