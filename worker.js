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
    return J({ u: { name: u.name, email: u.email, bal: u.bal, code: u.code, streak: u.streak, ci: u.lci === day(now) }, fs: f ? f.s : 0, now, c, tk, h, w, rc, adm });
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
const HTML = String.raw`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><title>Earn</title>
<style>
:root{--bg:#0d1512;--cd:#16211c;--ln:#24352d;--tx:#e8f3ec;--mu:#8fa89a;--g:#2ecc71;--y:#f1c40f;--r:#e74c3c}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font:15px system-ui,sans-serif;padding-bottom:76px}
.w{max-width:520px;margin:0 auto;padding:14px}.c{background:var(--cd);border:1px solid var(--ln);border-radius:14px;padding:14px;margin-bottom:12px}
.r{display:flex;justify-content:space-between;align-items:center;gap:10px}.m{color:var(--mu);font-size:13px}h1{margin:6px 0 14px;font-size:22px}
.big{font-size:34px;font-weight:700;margin:4px 0}input,select{width:100%;padding:11px;margin:5px 0;border-radius:10px;border:1px solid var(--ln);background:#0f1a15;color:var(--tx);font:inherit}
.b{background:var(--g);color:#06210f;border:0;border-radius:10px;padding:11px 16px;font:inherit;font-weight:600;width:100%;margin-top:6px}.b.s{width:auto;padding:8px 14px;margin:0}
.b.gd{background:var(--y)}.b.x{background:var(--r);color:#fff}.b.l{background:none;color:var(--mu);font-weight:400}
.bar{height:10px;background:#0f1a15;border-radius:6px;overflow:hidden;margin:10px 0}.bar i{display:block;height:100%;background:var(--g)}
nav{position:fixed;bottom:0;left:0;right:0;background:var(--cd);border-top:1px solid var(--ln);display:flex;padding-bottom:env(safe-area-inset-bottom)}
nav a{flex:1;text-align:center;padding:12px 0;color:var(--mu);font-size:12px}nav a.on{color:var(--g)}
#to{position:fixed;top:14px;left:50%;transform:translateX(-50%);background:#fff;color:#000;padding:10px 16px;border-radius:10px;display:none;z-index:9;max-width:90%}
.pl{color:var(--g)}.mi{color:var(--r)}
</style></head><body><div class="w" id="app"></div><nav id="nav"></nav><div id="to"></div>
<script>
const $=id=>document.getElementById(id);
const esc=s=>String(s==null?"":s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
let TK=localStorage.getItem("t"),S=null,tab="h",off=0,AD=null,AQ="",mode="login",tt;
const money=n=>S.c.cur+(+n).toFixed(2);
const fmt=ms=>{const s=Math.max(0,Math.floor(ms/1e3));return Math.floor(s/3600)+"h "+Math.floor(s%3600/60)+"m "+s%60+"s"};
function toast(m){const t=$("to");t.textContent=m;t.style.display="block";clearTimeout(tt);tt=setTimeout(()=>t.style.display="none",2500)}
async function api(a,d){const r=await fetch("/api",{method:"POST",headers:{authorization:"Bearer "+(TK||"")},body:JSON.stringify(Object.assign({a:a},d||{}))});const j=await r.json();
 if(r.status===401&&a!=="login"&&a!=="reg"){TK=null;localStorage.removeItem("t");S=null;render();throw 0}return j}
async function load(){S=await api("me");off=S.now-Date.now();if(S.adm&&tab=="a")await adload();render()}
async function adload(q){if(q!==undefined)AQ=q;AD=await api("ad",{q:AQ})}
async function act(a,d){try{const j=await api(a,d);if(j.e){toast(j.e);return}if(j.t){TK=j.t;localStorage.setItem("t",TK)}if(j.msg)toast(j.msg);await load()}catch(e){}}
function auth(){const rg=mode=="reg";return '<h1>🌾 Earn</h1><div class="c" data-f><b>'+(rg?'Create account':'Login')+'</b>'+(rg?'<input name="name" placeholder="Your name">':'')+'<input name="email" type="email" placeholder="Email"><input name="pass" type="password" placeholder="Password">'+
 '<button class="b" data-a="'+(rg?'reg':'login')+'">'+(rg?'Register':'Login')+'</button><button class="b l" data-a="mode" data-m="'+(rg?'login':'reg')+'">'+(rg?'Have an account? Login':'New here? Register')+'</button></div>'}
function home(){const u=S.u,c=S.c,tot=c.farm_h*36e5,l=S.fs?S.fs+tot-(Date.now()+off):0;
 const fm=!S.fs?'<button class="b" data-a="fs">🌱 Start farming</button>':l>0?'<div class="bar"><i id="fb" style="width:'+Math.min(100,(tot-l)/tot*100)+'%"></i></div><p class="m" id="ft">'+fmt(l)+' left</p>':'<button class="b gd" data-a="fh">🌾 Harvest '+money(c.farm_r)+'</button>';
 return (c.notice?'<div class="c">📢 '+esc(c.notice)+'</div>':'')+'<div class="c"><span class="m">Hi '+esc(u.name)+', your balance</span><div class="big">'+money(u.bal)+'</div></div>'+
 '<div class="c"><b>Farm</b><p class="m">Harvest '+money(c.farm_r)+' every '+c.farm_h+' hours.</p>'+fm+'</div>'+
 '<div class="c"><b>Daily check-in</b><p class="m">Streak: '+u.streak+' day(s). Reward grows every day.</p>'+(u.ci?'<button class="b" disabled>Checked in ✓</button>':'<button class="b" data-a="ci">Check in</button>')+'</div>'}
function tasks(){return '<div class="c"><b>Tasks</b><p class="m">Open the link, wait '+S.c.secs+' seconds, then claim.</p></div>'+(S.tk.map(k=>{const l=k.s?k.s+S.c.secs*1e3-(Date.now()+off):0;
 const bt=k.d?'<span class="m">Done ✓</span>':!k.s?'<button class="b s" data-a="ts" data-id="'+k.id+'" data-url="'+esc(k.url)+'">Start</button>':l>0?'<span class="m">'+Math.ceil(l/1e3)+'s</span>':'<button class="b gd s" data-a="tc" data-id="'+k.id+'">Claim</button>';
 return '<div class="c r"><span>'+esc(k.title)+'<br><span class="m">+'+money(k.rw)+'</span></span>'+bt+'</div>'}).join("")||'<div class="c m">No tasks right now. Check back later.</div>')}
function refer(){const l=location.origin+"/?ref="+S.u.code;return '<div class="c"><b>Invite friends</b><p class="m">You get '+money(S.c.ref)+' when a friend you invite finishes their first harvest.</p><input readonly value="'+esc(l)+'"><button class="b" data-a="cp" data-l="'+esc(l)+'">Copy link</button></div>'+
 '<div class="c"><b>Your referrals</b><p>Joined: '+S.rc.n+' · Successful: '+S.rc.k+'</p></div>'}
const KN={farm:"Farm",ci:"Check-in",task:"Task",ref:"Referral",wd:"Withdraw",refund:"Refund",admin:"Admin"};
const WS={p:"Pending",d:"Paid ✓",r:"Rejected"};
function wallet(){return '<div class="c"><span class="m">Balance</span><div class="big">'+money(S.u.bal)+'</div></div>'+
 '<div class="c" data-f><b>Withdraw</b><p class="m">Minimum '+money(S.c.minw)+'. Paid manually by admin.</p><select name="m"><option value="bkash">bKash</option><option value="nagad">Nagad</option><option value="paypal">PayPal</option></select>'+
 '<input name="ac" placeholder="bKash/Nagad number or PayPal email"><input name="amt" type="number" step="any" placeholder="Amount"><button class="b gd" data-a="wr">Request withdraw</button></div>'+
 (S.w.length?'<div class="c"><b>Withdraw requests</b>'+S.w.map(w=>'<div class="r"><span>'+w.m+' · '+esc(w.a)+'</span><span>'+money(w.amt)+' · '+WS[w.st]+'</span></div>').join("")+'</div>':'')+
 '<div class="c"><b>History</b>'+(S.h.map(h=>'<div class="r"><span>'+(KN[h.k]||h.k)+'<br><span class="m">'+new Date(h.ts).toLocaleString()+'</span></span><b class="'+(h.amt>=0?'pl':'mi')+'">'+(h.amt>=0?'+':'')+money(h.amt)+'</b></div>').join("")||'<p class="m">Nothing yet.</p>')+'</div>'+
 '<button class="b l" data-a="out">Log out</button>'}
const CF=[["name","Site name"],["cur","Currency symbol"],["farm_h","Farm hours"],["farm_r","Farm reward"],["ci","Check-in rewards (7 values, comma)"],["ref","Referral bonus"],["secs","Task timer (seconds)"],["minw","Minimum withdraw"],["wd","Withdraw open (1 = yes, 0 = no)"],["notice","Notice on home page"]];
function admin(){if(!AD)return"";let x='<div class="c"><b>Stats</b><p>Users: '+AD.st.n+' · Total user balance: '+money(AD.st.b)+'</p></div>';
 x+='<div class="c"><b>Withdraw requests</b>'+(AD.w.map(w=>'<div class="r" style="margin:8px 0"><span>'+esc(w.email)+'<br><span class="m">'+w.m+' · '+esc(w.a)+' · '+money(w.amt)+'</span></span><span><button class="b gd s" data-a="adw" data-id="'+w.id+'" data-ok="1">Paid</button> <button class="b x s" data-a="adw" data-id="'+w.id+'" data-ok="">✕</button></span></div>').join("")||'<p class="m">None</p>')+'</div>';
 x+='<div class="c" data-f><b>Add task</b><input name="title" placeholder="Title"><input name="url" placeholder="https://link"><input name="rw" type="number" step="any" placeholder="Reward"><button class="b" data-a="adt">Add</button></div>';
 x+='<div class="c"><b>Active tasks</b>'+AD.t.map(t=>'<div class="r" style="margin:8px 0"><span>'+esc(t.title)+' · '+money(t.rw)+'</span><button class="b x s" data-a="adx" data-id="'+t.id+'">✕</button></div>').join("")+'</div>';
 x+='<div class="c" data-f><b>Find user</b><input name="q" value="'+esc(AQ)+'" placeholder="email or name"><button class="b" data-a="ads">Search</button></div>';
 x+=AD.us.map(z=>'<div class="c" data-f><b>'+esc(z.name)+'</b> · '+esc(z.email)+'<br>Balance '+money(z.bal)+(z.banned?' · BLOCKED':'')+'<input name="amt" type="number" step="any" placeholder="+ add / - deduct"><button class="b s" data-a="adj" data-id="'+z.id+'">Adjust</button> <button class="b x s" data-a="adb" data-id="'+z.id+'" data-on="'+(z.banned?'':'1')+'">'+(z.banned?'Unblock':'Block')+'</button></div>').join("");
 x+='<div class="c" data-f><b>Settings</b>'+CF.map(f=>'<label class="m">'+f[1]+'</label><input name="'+f[0]+'" value="'+esc(S.c[f[0]])+'">').join("")+'<button class="b" data-a="adcfg">Save settings</button></div>';return x}
function render(){if(!S){$("app").innerHTML=auth();$("nav").innerHTML="";return}
 $("app").innerHTML=({h:home,t:tasks,r:refer,w:wallet,a:admin})[tab]();
 const tb=[["h","🏠","Home"],["t","✅","Tasks"],["r","👥","Refer"],["w","💰","Wallet"]];if(S.adm)tb.push(["a","⚙️","Admin"]);
 $("nav").innerHTML=tb.map(t=>'<a data-a="tab" data-t="'+t[0]+'" class="'+(tab==t[0]?'on':'')+'">'+t[1]+'<br>'+t[2]+'</a>').join("")}
document.onclick=async e=>{const b=e.target.closest("[data-a]");if(!b)return;const d=Object.assign({},b.dataset),a=d.a,F=b.closest("[data-f]");
 if(F)F.querySelectorAll("input,select").forEach(i=>{if(i.name)d[i.name]=i.value});
 if(a=="tab"){tab=d.t;if(tab=="a"&&S.adm)await adload();render()}
 else if(a=="mode"){mode=d.m;render()}
 else if(a=="out"){TK=null;localStorage.removeItem("t");S=null;render()}
 else if(a=="cp"){try{await navigator.clipboard.writeText(d.l);toast("Copied ✓")}catch(x){toast(d.l)}}
 else if(a=="ts"){window.open(d.url,"_blank","noopener");act("ts",{id:d.id})}
 else if(a=="ads"){await adload(d.q);render()}
 else{if(a=="reg")d.ref=new URLSearchParams(location.search).get("ref")||"";act(a,d)}};
setInterval(()=>{if(!S)return;const n=Date.now()+off,c=S.c;
 if(tab=="h"&&S.fs){const tot=c.farm_h*36e5,l=S.fs+tot-n,ft=$("ft");if(l<=0&&ft){render();return}if(ft){ft.textContent=fmt(l)+" left";$("fb").style.width=Math.min(100,(tot-l)/tot*100)+"%"}}
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
