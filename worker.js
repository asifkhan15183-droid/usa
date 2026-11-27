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
const HTML = String.raw`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="theme-color" content="#1A1F2E"><title>Earn</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0;-webkit-tap-highlight-color:transparent}
html{scroll-behavior:smooth}body{background:#1A1F2E;color:#E4E8F0;font-family:'Inter',Arial,sans-serif;overflow-x:hidden}
:root{--bg:#1A1F2E;--bg-soft:#1F2637;--card:#242B3D;--card-hover:#2A3248;--border:rgba(255,255,255,.07);--border-strong:rgba(255,255,255,.12);--blue:#4F82FF;--blue-soft:#6BA6FF;--blue-glow:rgba(79,130,255,.25);--text:#E4E8F0;--text-dim:#8B95AD;--text-soft:#B4BCCF;--success:#4ADE80;--warning:#FBBF24;--danger:#F87171;
--a:#4ADE80;--gd:#FBBF24;--ln:rgba(255,255,255,.12);--mu:#8B95AD;--rd:#F87171}
.bg-glow{position:fixed;inset:0;overflow:hidden;pointer-events:none;z-index:0}.glow{position:absolute;border-radius:50%;filter:blur(90px);opacity:.15}
.glow1{width:300px;height:300px;background:#4F82FF;top:-100px;left:-100px;animation:gf 20s ease-in-out infinite}.glow2{width:240px;height:240px;background:#6BA6FF;top:40%;right:-120px;animation:gf 24s ease-in-out infinite reverse}.glow3{width:280px;height:280px;background:#3A63CC;bottom:0;left:-100px;animation:gf 22s ease-in-out infinite}
@keyframes gf{0%,100%{transform:translate(0,0) scale(1)}50%{transform:translate(30px,-40px) scale(1.15)}}
#app{width:100%;max-width:520px;margin:auto;min-height:100vh;padding:14px 16px calc(110px + env(safe-area-inset-bottom));position:relative;z-index:1}
.fade-in{animation:fi .5s cubic-bezier(.2,.8,.2,1) both}@keyframes fi{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:none}}
header{display:flex;align-items:center;justify-content:space-between;padding:10px 0 16px}.brand{display:flex;align-items:center;gap:12px}
.spider-logo{width:52px;height:52px;border-radius:16px;display:grid;place-items:center;background:linear-gradient(145deg,#4F82FF,#3A63CC);box-shadow:0 4px 20px rgba(79,130,255,.35)}.spider-logo svg{width:28px;height:28px;color:#fff}
.brand-name{font-size:20px;font-weight:900;letter-spacing:1px;line-height:1;background:linear-gradient(135deg,#E4E8F0,#6BA6FF);-webkit-background-clip:text;background-clip:text;color:transparent}.brand-sub{font-size:12px;color:var(--text-dim);font-weight:600;margin-top:5px}
.profile{display:flex;align-items:center;gap:7px;border:1px solid var(--border);border-radius:24px;background:var(--card);padding:6px 12px 6px 6px;font-size:12px;font-weight:700;cursor:pointer;max-width:140px}.profile span{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.avatar{width:28px;height:28px;border-radius:50%;background:linear-gradient(135deg,#4F82FF,#6BA6FF);display:grid;place-items:center;font-size:12px;color:#fff;font-weight:800;flex:none}
.hero{min-height:200px;border-radius:24px;padding:22px 18px;margin-bottom:14px;background:linear-gradient(135deg,#2D3A5C,#1E2942);overflow:hidden;position:relative;box-shadow:0 8px 30px rgba(0,0,0,.25);border:1px solid var(--border-strong)}
.hero::before{content:"";position:absolute;top:-50%;right:-20%;width:300px;height:300px;border-radius:50%;background:radial-gradient(circle,rgba(79,130,255,.2),transparent 70%)}
.hero-copy{position:relative;z-index:2;width:62%}.hero h1{font-size:30px;line-height:1;font-weight:900;letter-spacing:-1px;color:#F0F3F9;word-break:break-word}
.hero h1 span{background:linear-gradient(90deg,#6BA6FF,#A8C4FF);-webkit-background-clip:text;background-clip:text;color:transparent}
.hero h2{font-size:19px;line-height:1.15;font-weight:800;margin:8px 0 10px}.hero p{font-size:11px;color:var(--text-soft);margin-bottom:16px;line-height:1.5}
.cta{border:none;border-radius:26px;padding:13px 20px;background:linear-gradient(135deg,#4F82FF,#3A63CC);color:#fff;font-size:12.5px;font-weight:800;font-family:inherit;cursor:pointer;box-shadow:0 4px 16px rgba(79,130,255,.4)}.cta:active{transform:scale(.95)}
.hero-art{position:absolute;right:-10px;top:0;width:52%;height:100%;display:grid;place-items:center}
.web{position:absolute;width:180px;height:180px;border-radius:50%;border:1px solid rgba(107,166,255,.2);animation:spin 25s linear infinite}
.web::before,.web::after{content:"";position:absolute;inset:18px;border:1px solid rgba(107,166,255,.18);border-radius:50%;transform:rotate(35deg) scaleX(.55)}.web::after{transform:rotate(-35deg) scaleX(.55)}
.spider-art{color:#6BA6FF;z-index:1;filter:drop-shadow(0 4px 12px rgba(79,130,255,.4));animation:fl 3s ease-in-out infinite;text-align:center}.spider-art svg{width:62px;height:62px}
@keyframes spin{to{transform:rotate(360deg)}}@keyframes fl{0%,100%{transform:translateY(0)}50%{transform:translateY(-6px)}}@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.6;transform:scale(1.05)}}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:14px}.stat{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:11px 8px;text-align:center}
.stat-val{font-size:16px;font-weight:900;line-height:1;font-variant-numeric:tabular-nums}.stat-val.blue{color:var(--blue-soft)}.stat-val.green{color:var(--success)}.stat-lbl{font-size:9.5px;color:var(--text-dim);font-weight:600;margin-top:4px}
.balance{border-radius:24px;padding:20px;background:var(--card);border:1px solid var(--border-strong);box-shadow:0 6px 24px rgba(0,0,0,.2);margin-bottom:14px;position:relative;overflow:hidden}
.balance::before{content:"";position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,#4F82FF,transparent)}
.bal-top small{font-size:11.5px;color:var(--text-dim);font-weight:600}.amount{font-size:clamp(26px,6.5vw,32px);font-weight:900;letter-spacing:-1px;line-height:1.1;margin:8px 0 6px;font-variant-numeric:tabular-nums}
.usd{font-size:11px;color:var(--text-dim);font-weight:500;margin-bottom:16px}.bal-actions{display:flex;gap:9px}
.bal-actions button{flex:1;border:1px solid var(--border-strong);border-radius:14px;padding:12px 8px;background:var(--bg-soft);color:var(--text);font-weight:700;font-size:12px;font-family:inherit;cursor:pointer}
.bal-actions button.primary{background:linear-gradient(135deg,#4F82FF,#3A63CC);border-color:transparent;color:#fff;box-shadow:0 4px 14px rgba(79,130,255,.35)}.bal-actions button:active{transform:scale(.96)}
.streak{display:flex;align-items:center;gap:12px;background:linear-gradient(135deg,rgba(251,191,36,.15),rgba(251,191,36,.08));border-radius:16px;padding:12px 14px;margin-bottom:14px;border:1px solid rgba(251,191,36,.25)}
.streak-icon{width:38px;height:38px;border-radius:50%;background:rgba(251,191,36,.15);display:grid;place-items:center;font-size:22px;flex:none}.streak-text{flex:1;min-width:0}.streak-text b{font-size:12.5px;color:#FCD34D;display:block;font-weight:800}.streak-text small{font-size:10.5px;color:var(--text-soft);display:block;margin-top:2px}
.streak-cta{background:linear-gradient(135deg,#FBBF24,#F59E0B);color:#1A1F2E;border:none;border-radius:20px;padding:8px 14px;font-size:11px;font-weight:800;font-family:inherit;cursor:pointer;flex:none}.streak-cta:disabled{opacity:.5}
.tiles{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:14px}.tile{border:1px solid var(--border);border-radius:18px;background:var(--card);display:flex;align-items:center;justify-content:center;flex-direction:column;text-align:center;gap:7px;padding:14px 4px;cursor:pointer;position:relative}
.tile:active{transform:scale(.95)}.tile-icon{width:38px;height:38px;border-radius:12px;display:grid;place-items:center;background:rgba(79,130,255,.15);color:var(--blue-soft)}.tile-icon svg{width:19px;height:19px}
.tile strong{font-size:11px;font-weight:700}.tile small{font-size:9.5px;color:var(--text-dim)}.badge-dot{position:absolute;top:9px;right:9px;width:7px;height:7px;border-radius:50%;background:var(--success);box-shadow:0 0 6px var(--success);animation:pulse 1.5s infinite}
.tasks{border:1px solid var(--border);border-radius:22px;background:var(--card);overflow:hidden;margin-bottom:14px}.section-head{padding:15px 18px;background:rgba(79,130,255,.06);border-bottom:1px solid var(--border)}.section-head h3{font-size:15px;font-weight:800;margin:0}
.task{display:flex;align-items:center;gap:11px;padding:15px 18px;border-bottom:1px solid var(--border)}.task:last-child{border-bottom:none}
.task-icon{width:44px;height:44px;border-radius:14px;display:grid;place-items:center;flex:none;background:rgba(79,130,255,.12);font-size:20px}.task-text{flex:1;min-width:0}
.task-text b{font-size:13px;display:block;font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.task-text small{font-size:11px;color:var(--text-dim);display:block;margin-top:3px}
.task-right{display:flex;flex-direction:column;align-items:flex-end;gap:6px;flex:none}.reward{font-size:11px;color:var(--blue-soft);font-weight:800}
.start{border:none;border-radius:20px;padding:9px 16px;background:linear-gradient(135deg,#4F82FF,#3A63CC);color:#fff;font-size:11px;font-weight:800;font-family:inherit;cursor:pointer;white-space:nowrap;box-shadow:0 3px 10px rgba(79,130,255,.3)}
.start.gold{background:linear-gradient(135deg,#FBBF24,#F59E0B);color:#1A1F2E}.start:active{transform:scale(.94)}.start:disabled{background:rgba(74,222,128,.15);color:var(--success);box-shadow:none}
.progress-wrap{height:4px;background:rgba(79,130,255,.12);border-radius:4px;margin-top:7px;overflow:hidden}.progress-bar{height:100%;background:linear-gradient(90deg,#4F82FF,#6BA6FF);border-radius:4px;transition:width .3s linear}
.promos{display:grid;grid-template-columns:1fr 1fr;gap:11px;margin-bottom:14px}.promo{border:1px solid var(--border);border-radius:18px;background:var(--card);display:flex;align-items:center;gap:10px;padding:14px;cursor:pointer}.promo:active{transform:scale(.97)}
.promo .emoji{width:44px;height:44px;border-radius:13px;background:rgba(79,130,255,.12);display:grid;place-items:center;flex:none;font-size:22px}.promo b{font-size:12px;display:block;margin-bottom:4px}.promo small{font-size:10px;color:var(--text-dim)}
nav{position:fixed;bottom:0;left:50%;transform:translateX(-50%);width:100%;max-width:520px;height:calc(74px + env(safe-area-inset-bottom));padding-bottom:env(safe-area-inset-bottom);background:rgba(26,31,46,.96);backdrop-filter:blur(20px);border-top:1px solid var(--border-strong);display:flex;justify-content:space-around;align-items:center;z-index:10}
.navitem{font-size:10px;color:var(--text-dim);text-align:center;min-width:52px;font-weight:600;display:flex;flex-direction:column;align-items:center;gap:4px;padding:6px 0;position:relative;cursor:pointer}.navitem svg{width:22px;height:22px}
.navitem.active{color:var(--blue-soft)}.navitem.active::before{content:"";position:absolute;top:-6px;left:50%;transform:translateX(-50%);width:24px;height:3px;border-radius:0 0 3px 3px;background:var(--blue)}
.nav-spider{width:58px;height:58px;border-radius:50%;display:grid;place-items:center;background:linear-gradient(145deg,#4F82FF,#3A63CC);box-shadow:0 4px 16px rgba(79,130,255,.4);margin-top:-26px;cursor:pointer}.nav-spider svg{width:26px;height:26px;color:#fff}.nav-spider:active{transform:scale(.92)}
#ts{position:fixed;bottom:calc(96px + env(safe-area-inset-bottom));left:50%;transform:translateX(-50%) translateY(20px);background:#2D3A5C;padding:12px 20px;border-radius:22px;font-size:12px;font-weight:600;z-index:20;opacity:0;pointer-events:none;transition:.35s;border:1px solid var(--border-strong);box-shadow:0 8px 24px rgba(0,0,0,.4);max-width:92%;text-align:center}#ts.on{opacity:1;transform:translateX(-50%)}
.confetti{position:fixed;width:8px;height:8px;z-index:30;pointer-events:none;border-radius:2px}
.c{background:var(--card);border:1px solid var(--border);border-radius:18px;padding:16px;margin-bottom:12px}.g{display:grid;gap:10px;grid-template-columns:repeat(auto-fit,minmax(130px,1fr))}
.b{width:100%;padding:12px;border:0;border-radius:14px;background:linear-gradient(135deg,#4F82FF,#3A63CC);color:#fff;font-weight:800;font-size:14px;font-family:inherit;margin-top:6px;box-shadow:0 4px 14px rgba(79,130,255,.3);cursor:pointer}.b:active{transform:scale(.97)}.b:disabled{background:rgba(74,222,128,.12);color:var(--success);box-shadow:none}
.b.x{background:var(--danger);color:#fff;box-shadow:none}.b.gd{background:linear-gradient(135deg,#FBBF24,#F59E0B);color:#1A1F2E}.b.l{background:none;box-shadow:none;color:var(--text-dim);font-weight:500}
.r .b{width:auto;padding:8px 12px;font-size:13px;margin:0}.r{display:flex;justify-content:space-between;gap:8px;align-items:center;word-break:break-all;padding:8px 0}
input,select{width:100%;padding:12px;margin:5px 0;border-radius:12px;border:1px solid var(--border-strong);background:var(--bg-soft);color:var(--text);font-size:16px;font-family:inherit}
.m{color:var(--text-dim);font-size:12px}h3{margin:14px 0 8px}.big{font-size:34px;font-weight:900;color:var(--blue-soft)}
.stat3{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin:6px 0 12px;text-align:center}.stat3>div{background:var(--bg-soft);border:1px solid var(--border);border-radius:12px;padding:9px 4px}.stat3 span{display:block;color:var(--text-dim);font-size:10px;text-transform:uppercase}.stat3 b{font-size:15px}
.sg{display:grid;grid-auto-flow:column;grid-auto-columns:1fr;gap:4px;background:var(--bg-soft);border:1px solid var(--border);border-radius:14px;padding:4px;margin-bottom:12px}.sg a{padding:10px 0;text-align:center;border-radius:10px;color:var(--text-dim);font-weight:700;font-size:13px;cursor:pointer}.sg a.on{background:linear-gradient(135deg,#4F82FF,#3A63CC);color:#fff}
.chp{display:inline-block;padding:2px 9px;border-radius:12px;font-size:10px;font-weight:800}.chp.a{background:rgba(74,222,128,.15);color:var(--success)}.chp.p{background:rgba(251,191,36,.15);color:var(--warning)}.chp.x{background:rgba(248,113,113,.15);color:var(--danger)}
@media(max-width:390px){.hero h1{font-size:26px}.hero-copy{width:66%}.spider-art svg{width:48px;height:48px}.tile strong{font-size:10px}}
</style></head><body><div class="bg-glow"><div class="glow glow1"></div><div class="glow glow2"></div><div class="glow glow3"></div></div><div id="app"><p class="m" style="padding:40px;text-align:center">Loading…</p></div><div id="ts"></div><nav id="nav"></nav>
<script>
const $=id=>document.getElementById(id);
const esc=s=>String(s==null?"":s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
let TK=localStorage.getItem("t"),S=null,tab="h",wsub="w",off=0,AD=null,AQ="",mode="login";
const money=n=>S.c.cur+(+n).toFixed(2);
const fmt=ms=>{const s=Math.max(0,Math.floor(ms/1e3));return Math.floor(s/3600)+"h "+Math.floor(s%3600/60)+"m "+s%60+"s"};
const sv=(p,w)=>'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="'+(w||2)+'" stroke-linecap="round" stroke-linejoin="round">'+p+'</svg>';
const SPD=sv('<circle cx="12" cy="12" r="2.5"/><path d="M12 9.5V4M9 10l-4-3M15 10l4-3M9.5 12H4M14.5 12H20M9 14l-4 3M15 14l4 3M12 14.5V20"/>',1.8);
const IC={h:'<path d="M3 10l9-7 9 7v10a2 2 0 01-2 2H5a2 2 0 01-2-2V10z"/>',t:'<rect x="3" y="4" width="18" height="18" rx="3"/><path d="M8 10h8M8 14h5"/>',w:'<rect x="2" y="6" width="20" height="14" rx="3"/><path d="M2 10h20M16 14h2"/>',p:'<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 4-7 8-7s8 3 8 7"/>',
 cal:'<rect x="3" y="4" width="18" height="18" rx="3"/><path d="M3 10h18M8 2v4M16 2v4"/>',us:'<circle cx="9" cy="8" r="3"/><path d="M3 20c0-3 3-5 6-5s6 2 6 5M17 11a3 3 0 100-6M21 20c0-2-1.5-3.5-4-4"/>',ck:'<path d="M9 11l3 3 8-8"/><path d="M20 12v6a2 2 0 01-2 2H6a2 2 0 01-2-2V6a2 2 0 012-2h9"/>'};
function toast(m){const e=$("ts");e.textContent=m;e.className="on";clearTimeout(toast.t);toast.t=setTimeout(()=>{e.className=""},2600)}
function confetti(el){if(!el)return;const r=el.getBoundingClientRect(),cl=["#4F82FF","#6BA6FF","#4ADE80","#FBBF24","#A8C4FF"];
 for(let i=0;i<22;i++){const c=document.createElement("div");c.className="confetti";c.style.background=cl[i%5];c.style.left=r.left+r.width/2+"px";c.style.top=r.top+r.height/2+"px";document.body.appendChild(c);
  const an=Math.random()*6.28,v=70+Math.random()*140,dx=Math.cos(an)*v,dy=Math.sin(an)*v-90;
  c.animate([{transform:"translate(0,0) rotate(0)",opacity:1},{transform:"translate("+dx+"px,"+(dy+200)+"px) rotate("+Math.random()*720+"deg)",opacity:0}],{duration:1000+Math.random()*400,easing:"cubic-bezier(.2,.7,.3,1)"}).onfinish=()=>c.remove()}}
async function api(a,d){const r=await fetch("/api",{method:"POST",headers:{authorization:"Bearer "+(TK||"")},body:JSON.stringify(Object.assign({a:a},d||{}))});const j=await r.json();
 if(r.status===401&&a!=="login"&&a!=="reg"){TK=null;localStorage.removeItem("t");S=null;render();throw 0}return j}
async function load(){S=await api("me");off=S.now-Date.now();if(S.adm&&tab=="a")await adload();render()}
async function adload(q){if(q!==undefined)AQ=q;AD=await api("ad",{q:AQ})}
async function act(a,d,el){try{const j=await api(a,d);if(j.e){toast(j.e);return}if(j.t){TK=j.t;localStorage.setItem("t",TK)}if(j.msg){toast(j.msg);if(["fh","ci","tc"].indexOf(a)>-1)confetti(el)}await load()}catch(e){}}
function auth(){const rg=mode=="reg";return '<div class="fade-in" style="text-align:center;padding:40px 0 18px"><div class="spider-logo" style="margin:0 auto 12px">'+SPD+'</div><div class="brand-name" style="font-size:26px">EARN</div><div class="m" style="margin-top:6px">Farm. Complete tasks. Get paid.</div></div><div class="c fade-in" data-f><b>'+(rg?'Create account':'Login')+'</b>'+(rg?'<input name="name" placeholder="Your name">':'')+'<input name="email" type="email" placeholder="Email"><input name="pass" type="password" placeholder="Password">'+
 '<button class="b" data-a="'+(rg?'reg':'login')+'">'+(rg?'Register':'Login')+'</button><button class="b l" data-a="mode" data-m="'+(rg?'login':'reg')+'">'+(rg?'Have an account? Login':'New here? Register')+'</button></div>'}
function head(){const u=S.u;return '<header class="fade-in"><div class="brand"><div class="spider-logo">'+SPD+'</div><div><div class="brand-name">'+esc(S.c.name.toUpperCase())+'</div><div class="brand-sub">Task Earn</div></div></div><div class="profile" data-a="tab" data-t="p"><div class="avatar">'+esc((u.name||"?").charAt(0).toUpperCase())+'</div><span>'+esc(u.name.split(" ")[0])+'</span></div></header>'}
function ci(){const u=S.u,arr=S.c.ci.split(",").map(Number),L=arr.length,cnt=u.ci?((u.n-1)%L)+1:u.n%L;return{arr:arr,cnt:cnt,done:u.ci}}
function home(){const u=S.u,c=S.c,tot=c.farm_h*36e5,l=S.fs?S.fs+tot-(Date.now()+off):0,go=S.fs&&l>0,ready=S.fs&&l<=0,k=ci(),pct=!S.fs?0:ready?100:Math.min(100,(tot-l)/tot*100);
 const fb=!S.fs?'<button class="start" data-a="fs">Start</button>':go?'<button class="start" disabled>Growing</button>':'<button class="start gold" data-a="fh">Harvest</button>';
 const done=S.tk.filter(t=>t.d).length;
 return (c.notice?'<div class="c" style="border-color:rgba(251,191,36,.4);text-align:center">📢 '+esc(c.notice)+'</div>':'')+
 '<section class="hero fade-in"><div class="hero-copy"><h1>'+esc(c.name)+'</h1><h2>Task Earning App</h2><p>Farm • Complete Tasks • Get Paid</p><button class="cta" data-a="tab" data-t="t">Start Earning →</button></div><div class="hero-art"><div class="web"></div><div class="spider-art">'+sv('<circle cx="12" cy="12" r="2.8"/><path d="M12 9.2V4M9.2 10L5 7M14.8 10L19 7M9.5 12H4M14.5 12H20M9.2 14L5 17M14.8 14L19 17M12 14.8V20" stroke-width="1.6"/>')+'</div></div></section>'+
 '<section class="stats fade-in"><div class="stat"><div class="stat-val blue">'+done+'</div><div class="stat-lbl">Tasks Done</div></div><div class="stat"><div class="stat-val">'+u.n+' d</div><div class="stat-lbl">Streak</div></div><div class="stat"><div class="stat-val green">'+S.rc.k+'</div><div class="stat-lbl">Invited</div></div></section>'+
 '<section class="balance fade-in"><div class="bal-top"><small>Your Balance</small></div><div class="amount">'+money(u.bal)+'</div><div class="usd">Minimum withdraw '+money(c.minw)+' · bKash · Nagad · PayPal</div><div class="bal-actions"><button class="primary" data-a="tab" data-t="w">Withdraw</button><button data-a="tab" data-t="r">Invite & Earn</button></div></section>'+
 '<section class="streak fade-in"><div class="streak-icon">🔥</div><div class="streak-text"><b>'+u.n+'-Day Streak!</b><small>'+(k.done?'Come back tomorrow for more':'Claim today bonus +'+money(k.arr[k.cnt]||0))+'</small></div><button class="streak-cta" data-a="ci"'+(k.done?' disabled':'')+'>'+(k.done?'✓ Done':'Claim')+'</button></section>'+
 '<section class="tiles fade-in"><div class="tile" data-a="tab" data-t="t"><div class="tile-icon">'+sv(IC.cal)+'</div><strong>Tasks</strong><small>'+S.tk.filter(t=>!t.d).length+' open</small></div><div class="tile" data-a="tab" data-t="r"><div class="tile-icon">'+sv(IC.us)+'</div><strong>Refer</strong><small>+'+money(c.ref)+'</small></div><div class="tile" data-a="tab" data-t="t">'+(k.done?'':'<div class="badge-dot"></div>')+'<div class="tile-icon">'+sv(IC.ck)+'</div><strong>Check-in</strong><small>'+(k.done?'Done ✓':'Claim')+'</small></div><div class="tile" data-a="tab" data-t="w"><div class="tile-icon">'+sv(IC.w)+'</div><strong>Wallet</strong><small>Withdraw</small></div></section>'+
 '<section class="tasks fade-in"><div class="section-head"><h3>🌱 Farming</h3></div><div class="task"><div class="task-icon">'+(ready?'🌾':'🌱')+'</div><div class="task-text"><b>Farm</b><small id="ft">'+(!S.fs?'Plant and harvest every '+c.farm_h+' hours':go?fmt(l)+' left':'Ready to harvest!')+'</small><div class="progress-wrap"><div class="progress-bar" id="fb" style="width:'+pct+'%"></div></div></div><div class="task-right"><div class="reward">+'+money(c.farm_r)+'</div>'+fb+'</div></div></section>'}
function checkin(){const u=S.u,k=ci(),arr=k.arr,cnt=k.cnt,done=k.done;
 const g=arr.map((v,i)=>{const dn=i<cnt,cur=!done&&i==cnt;return '<div style="border:1px solid '+(cur?'var(--gd)':'var(--ln)')+';border-radius:12px;padding:8px 4px;text-align:center;background:'+(dn?'rgba(74,222,128,.12)':'transparent')+'"><div class="m">Day '+(i+1)+'</div><b style="color:'+(dn?'var(--a)':'var(--gd)')+'">'+money(v)+'</b><div class="m">'+(dn?'✓':cur?'Today':'🔒')+'</div></div>'}).join("");
 return '<div class="c"><b>Daily Check-in</b><p class="m">Streak: '+u.n+' day'+(u.n==1?'':'s')+'. Miss a day and it starts again.</p><div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(64px,1fr));gap:6px;margin:10px 0">'+g+'</div>'+(done?'<button class="b" disabled>Checked in today ✓</button>':'<button class="b" data-a="ci">Claim Day '+(cnt+1)+' · +'+money(arr[cnt]||0)+'</button>')+'</div>'}
function tasks(){const now=Date.now()+off,T=S.c.secs*1e3;
 return checkin()+'<section class="tasks"><div class="section-head"><h3>⚡ Tasks</h3></div>'+(S.tk.length?S.tk.map(k=>{const l=k.s?k.s+T-now:0,pr=k.d?100:!k.s?0:Math.min(100,(1-l/T)*100);
 const bt=k.d?'<button class="start" disabled>✓ Done</button>':!k.s?'<button class="start" data-a="ts" data-id="'+k.id+'" data-url="'+esc(k.url)+'">Start</button>':l>0?'<button class="start" disabled>'+Math.ceil(l/1e3)+'s</button>':'<button class="start gold" data-a="tc" data-id="'+k.id+'">Claim</button>';
 return '<div class="task"><div class="task-icon">🔗</div><div class="task-text"><b>'+esc(k.title)+'</b><small>Open the link, wait '+S.c.secs+'s</small><div class="progress-wrap"><div class="progress-bar" style="width:'+pr+'%"></div></div></div><div class="task-right"><div class="reward">+'+money(k.rw)+'</div>'+bt+'</div></div>'}).join(""):'<div class="task m">No tasks yet. Come back soon.</div>')+'</section>'}
function refer(){const l=location.origin+"/?ref="+S.u.code,c=S.c;
 return '<div class="c"><b>👥 Earn '+money(c.ref)+' per successful referral</b><input readonly value="'+esc(l)+'"><div class="g"><button class="b" data-a="cp" data-l="'+esc(l)+'">Copy link</button><button class="b" data-a="sh" data-l="'+esc(l)+'">Share</button></div></div>'+
 '<div class="c"><div class="stat3"><div><span>Total</span><b>'+S.rc.n+'</b></div><div><span>Pending</span><b>'+(S.rc.n-S.rc.k)+'</b></div><div><span>Successful</span><b>'+S.rc.k+'</b></div></div><div class="r"><span class="m">Referral earnings</span><b>'+money(S.rc.k*c.ref)+'</b></div></div>'+
 '<div class="c"><b>How it works</b><p class="m" style="margin-top:6px">1. Share your link. 2. Your friend registers. 3. Your friend finishes their first harvest. Then the referral is Successful and you get '+money(c.ref)+' once. Until then it stays Pending. Fake or self-referral accounts get nothing.</p></div>'}
const KN={farm:"Farm",ci:"Check-in",task:"Task",ref:"Referral",wd:"Withdraw",refund:"Refund",admin:"Admin"};
const WS={p:'<span class="chp p">PENDING</span>',d:'<span class="chp a">PAID</span>',r:'<span class="chp x">REJECTED</span>'};
function wallet(){const u=S.u;let x='<section class="balance"><div class="bal-top"><small>Your Balance</small></div><div class="amount">'+money(u.bal)+'</div><div class="usd">'+esc(u.name)+' · minimum withdraw '+money(S.c.minw)+'</div></section>'+
 '<div class="sg">'+[["w","Withdraw"],["h","History"]].map(t=>'<a data-a="ws" data-s="'+t[0]+'" class="'+(wsub==t[0]?'on':'')+'">'+t[1]+'</a>').join("")+'</div>';
 if(wsub=="w"){x+=(S.c.wd?'<div class="c" data-f><b>Withdraw</b><p class="m">Requests are reviewed and paid manually by an admin.</p><select name="m"><option value="bkash">bKash</option><option value="nagad">Nagad</option><option value="paypal">PayPal</option></select><input name="ac" placeholder="bKash/Nagad number or PayPal email"><input name="amt" type="number" step="any" placeholder="Amount"><button class="b gd" data-a="wr">Request withdraw</button></div>':'<div class="c" style="text-align:center;padding:30px 14px"><b>Withdraw is closed</b><p class="m">Please check back later.</p></div>')+
 (S.w.length?'<div class="c"><b>Withdraw requests</b>'+S.w.map(w=>'<div class="r" style="border-top:1px solid var(--ln)"><span>'+w.m+' · '+esc(w.a)+'<br><span class="m">'+new Date(w.ts).toLocaleDateString()+'</span></span><span style="text-align:right"><b>'+money(w.amt)+'</b><br>'+WS[w.st]+'</span></div>').join("")+'</div>':'')}
 else x+='<div class="c"><b>Wallet history</b>'+(S.h.map(h=>'<div class="r" style="border-top:1px solid var(--ln)"><span>'+(KN[h.k]||h.k)+'<br><span class="m">'+new Date(h.ts).toLocaleString()+'</span></span><b style="color:'+(h.amt<0?'var(--rd)':'var(--a)')+'">'+(h.amt>=0?'+':'')+money(h.amt)+'</b></div>').join("")||'<p class="m">Nothing yet.</p>')+'</div>';
 return x}
function profile(){const u=S.u;return '<div class="c" style="text-align:center"><div class="avatar" style="width:64px;height:64px;font-size:26px;margin:0 auto 10px">'+esc((u.name||"?").charAt(0).toUpperCase())+'</div><b style="font-size:18px">'+esc(u.name)+'</b><div class="m">'+esc(u.email)+'</div></div>'+
 '<div class="stat3"><div><span>Balance</span><b>'+money(u.bal)+'</b></div><div><span>Streak</span><b>'+u.n+' d</b></div><div><span>Invited</span><b>'+S.rc.k+'</b></div></div>'+(S.adm?'<button class="b" data-a="tab" data-t="a">🛠 Admin panel</button>':'')+'<button class="b l" data-a="out">Log out</button>'}
const CF=[["name","Site name"],["cur","Currency symbol"],["farm_h","Farm hours"],["farm_r","Farm reward"],["ci","Check-in rewards (comma separated)"],["ref","Referral bonus"],["secs","Task timer (seconds)"],["minw","Minimum withdraw"],["wd","Withdraw open (1 = yes, 0 = no)"],["notice","Notice on home page"]];
function admin(){if(!AD)return"";let x='<div class="c"><b>🛠 Admin</b><p class="m">Users: '+AD.st.n+' · Total user balance: '+money(AD.st.b)+'</p></div>';
 x+='<div class="c"><b>Withdraw requests</b>'+(AD.w.map(w=>'<div class="r" style="border-top:1px solid var(--ln)"><span>'+esc(w.email)+'<br><span class="m">'+w.m+' · '+esc(w.a)+' · '+money(w.amt)+'</span></span><span style="display:flex;gap:6px"><button class="b gd" data-a="adw" data-id="'+w.id+'" data-ok="1">Paid</button><button class="b x" data-a="adw" data-id="'+w.id+'" data-ok="">✕</button></span></div>').join("")||'<p class="m">None</p>')+'</div>';
 x+='<div class="c" data-f><b>Add task</b><input name="title" placeholder="Title"><input name="url" placeholder="https://link"><input name="rw" type="number" step="any" placeholder="Reward"><button class="b" data-a="adt">Add</button></div>';
 x+='<div class="c"><b>Active tasks</b>'+AD.t.map(t=>'<div class="r" style="border-top:1px solid var(--ln)"><span>'+esc(t.title)+' · '+money(t.rw)+'</span><button class="b x" data-a="adx" data-id="'+t.id+'">✕</button></div>').join("")+'</div>';
 x+='<div class="c" data-f><b>Find user</b><input name="q" value="'+esc(AQ)+'" placeholder="email or name"><button class="b" data-a="ads">Search</button></div>';
 x+=AD.us.map(z=>'<div class="c" data-f><b>'+esc(z.name)+'</b> · '+esc(z.email)+'<br><span class="m">Balance '+money(z.bal)+(z.banned?' · BLOCKED':'')+'</span><input name="amt" type="number" step="any" placeholder="+ add / - deduct"><div class="g"><button class="b" data-a="adj" data-id="'+z.id+'">Adjust</button><button class="b x" data-a="adb" data-id="'+z.id+'" data-on="'+(z.banned?'':'1')+'">'+(z.banned?'Unblock':'Block')+'</button></div></div>').join("");
 x+='<div class="c" data-f><b>Settings</b>'+CF.map(f=>'<span class="m">'+f[1]+'</span><input name="'+f[0]+'" value="'+esc(S.c[f[0]])+'">').join("")+'<button class="b" data-a="adcfg">Save settings</button></div>';return x+'<button class="b l" data-a="tab" data-t="p">← Back</button>'}
function render(){if(!S){$("app").innerHTML=auth();$("nav").innerHTML="";return}
 $("app").innerHTML=head()+({h:home,t:tasks,r:refer,w:wallet,p:profile,a:admin})[tab]();
 const ni=(t,n)=>'<div class="navitem'+((tab==t||(t=="p"&&tab=="a"))?' active':'')+'" data-a="tab" data-t="'+t+'">'+sv(IC[t])+n+'</div>';
 $("nav").innerHTML=ni("h","Home")+ni("t","Tasks")+'<div class="nav-spider" data-a="tab" data-t="r">'+sv('<circle cx="12" cy="12" r="2.8"/><path d="M12 9.2V4M9.2 10L5 7M14.8 10L19 7M9.5 12H4M14.5 12H20M9.2 14L5 17M14.8 14L19 17M12 14.8V20" stroke-width="1.6"/>')+'</div>'+ni("w","Wallet")+ni("p","Profile")}
document.onclick=async e=>{const b=e.target.closest("[data-a]");if(!b)return;const d=Object.assign({},b.dataset),a=d.a,F=b.closest("[data-f]");
 if(F)F.querySelectorAll("input,select").forEach(i=>{if(i.name)d[i.name]=i.value});
 if(a=="tab"){tab=d.t;if(tab=="a"&&S.adm)await adload();render();scrollTo(0,0)}
 else if(a=="ws"){wsub=d.s;render()}
 else if(a=="mode"){mode=d.m;render()}
 else if(a=="out"){TK=null;localStorage.removeItem("t");S=null;tab="h";render()}
 else if(a=="cp"){try{await navigator.clipboard.writeText(d.l);toast("Copied ✓")}catch(x){toast(d.l)}}
 else if(a=="sh"){if(navigator.share)navigator.share({text:"Join and earn: "+d.l}).catch(()=>{});else{try{await navigator.clipboard.writeText(d.l);toast("Copied ✓")}catch(x){toast(d.l)}}}
 else if(a=="ts"){window.open(d.url,"_blank","noopener");act("ts",{id:d.id})}
 else if(a=="ads"){await adload(d.q);render()}
 else{if(a=="reg")d.ref=new URLSearchParams(location.search).get("ref")||"";act(a,d,b)}};
setInterval(()=>{if(!S)return;const n=Date.now()+off,c=S.c;
 if(tab=="h"&&S.fs){const tot=c.farm_h*36e5,l=S.fs+tot-n,ft=$("ft");if(l<=0&&ft&&ft.textContent.indexOf("Ready")<0){render();return}if(l>0&&ft){ft.textContent=fmt(l)+" left";$("fb").style.width=Math.min(100,(tot-l)/tot*100)+"%"}}
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
