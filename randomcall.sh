#!/usr/bin/env bash
set -euo pipefail

# ===== PROMPTS =====
if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root: sudo bash $0"; exit 1
fi

read -rp "Let's Encrypt email (TLS certs): " LE_EMAIL
while [[ -z "${LE_EMAIL}" ]]; do read -rp "Email cannot be empty: " LE_EMAIL; done

read -rp "Site domain (e.g. randomcall.mydomain.xyz): " SITE_DOMAIN
while [[ -z "${SITE_DOMAIN}" ]]; do read -rp "Domain cannot be empty: " SITE_DOMAIN; done

read -rp "TURN domain or IP (Enter to use server IP): " TURN_HOST
SERVER_IP="$(curl -fsS https://api.ipify.org || true)"
if [[ -z "${TURN_HOST}" ]]; then
  TURN_HOST="${SERVER_IP}"
  echo "Using server IP for TURN: ${TURN_HOST}"
fi

read -rp "Google OAuth WEB client ID: " GOOGLE_CLIENT_ID
while [[ -z "${GOOGLE_CLIENT_ID}" ]]; do read -rp "Client ID cannot be empty: " GOOGLE_CLIENT_ID; done

read -rp "Admin username for /admin: " ADMIN_USER
while [[ -z "${ADMIN_USER}" ]]; do read -rp "Admin username cannot be empty: " ADMIN_USER; done
read -rsp "Admin password for /admin: " ADMIN_PASS; echo
while [[ -z "${ADMIN_PASS}" ]]; do read -rsp "Admin password cannot be empty: " ADMIN_PASS; echo; done

# ===== PACKAGES =====
apt-get update
apt-get install -y ca-certificates curl gnupg ufw

# Docker
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg
. /etc/os-release
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
  > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

systemctl enable docker
systemctl start docker

APP_DIR="/opt/random-call"
mkdir -p "$APP_DIR"
cd "$APP_DIR"

# ===== SECRETS (reuse if present) =====
if [[ -f .env ]]; then set -a; source ./.env; set +a || true; fi

DB_PASS="${DB_PASS:-$(openssl rand -hex 16)}"
REDIS_PASS="${REDIS_PASS:-$(openssl rand -hex 16)}"
JWT_SECRET="${JWT_SECRET:-$(openssl rand -hex 32)}"
TURN_USER="${TURN_USER:-webrtc$(openssl rand -hex 2)}"
TURN_PASS="${TURN_PASS:-$(openssl rand -hex 16)}"

mkdir -p data/postgres data/redis server admin caddy

# ===== DOCKER COMPOSE (Caddy reverse proxy) =====
cat > docker-compose.yml <<'YML'
services:
  caddy:
    image: caddy:2-alpine
    container_name: rc-caddy
    restart: unless-stopped
    ports: ["80:80","443:443"]
    environment:
      - ACME_AGREE=true
    volumes:
      - ./caddy/Caddyfile:/etc/caddy/Caddyfile
      - ./caddy/data:/data
      - ./caddy/config:/config

  postgres:
    image: postgres:16-alpine
    container_name: rc-postgres
    restart: unless-stopped
    environment:
      POSTGRES_PASSWORD: ${DB_PASS}
      POSTGRES_USER: rcuser
      POSTGRES_DB: rcdb
    volumes:
      - ./data/postgres:/var/lib/postgresql/data
      - ./server/init.sql:/docker-entrypoint-initdb.d/01_init.sql
    healthcheck:
      test: ["CMD-SHELL","pg_isready -U rcuser -d rcdb"]
      interval: 10s
      timeout: 5s
      retries: 10

  redis:
    image: redis:7-alpine
    container_name: rc-redis
    restart: unless-stopped
    command: ["redis-server","--requirepass","${REDIS_PASS}"]
    volumes:
      - ./data/redis:/data
    healthcheck:
      test: ["CMD","redis-cli","-a","${REDIS_PASS}","ping"]
      interval: 10s
      timeout: 5s
      retries: 10

  api:
    build:
      context: ./server
      dockerfile: Dockerfile
    container_name: rc-api
    restart: unless-stopped
    depends_on:
      - postgres
      - redis
    environment:
      NODE_ENV: production
      PORT: 3000
      DATABASE_URL: postgres://rcuser:${DB_PASS}@postgres:5432/rcdb
      REDIS_URL: redis://default:${REDIS_PASS}@redis:6379
      JWT_SECRET: ${JWT_SECRET}
      GOOGLE_CLIENT_ID: ${GOOGLE_CLIENT_ID}
      ADMIN_USER: ${ADMIN_USER}
      ADMIN_PASS: ${ADMIN_PASS}
      TURN_HOST: ${TURN_HOST}
      TURN_USERNAME: ${TURN_USER}
      TURN_PASSWORD: ${TURN_PASS}
      TURN_PORT: 3478
    healthcheck:
      test: ["CMD","node","/usr/src/app/healthcheck.js"]
      interval: 20s
      timeout: 5s
      retries: 10

  coturn:
    image: instrumentisto/coturn
    container_name: rc-turn
    restart: unless-stopped
    network_mode: "host"
    command:
      - /bin/sh
      - -c
      - |
        cat >/etc/turnserver.conf <<EOF
        listening-port=3478
        realm=${SITE_DOMAIN}
        fingerprint
        lt-cred-mech
        user=${TURN_USER}:${TURN_PASS}
        no-stdout-log
        no-cli
        min-port=49152
        max-port=65535
        EOF
        turnserver -c /etc/turnserver.conf -v
YML

# ===== CADDYFILE =====
cat > caddy/Caddyfile <<CADDY
{
  email ${LE_EMAIL}
}

${SITE_DOMAIN} {
  encode zstd gzip

  @api path /socket.io* /health /v1/* /admin* /v1/admin/* 
  reverse_proxy api:3000

  handle {
    reverse_proxy api:3000
  }
}
CADDY

# ===== SERVER Dockerfile & code =====
cat > server/Dockerfile <<'DOCKER'
FROM node:20-alpine
WORKDIR /usr/src/app
COPY package*.json ./
RUN npm install --omit=dev
COPY . .
EXPOSE 3000
CMD ["node","server.js"]
DOCKER

cat > server/package.json <<'PKG'
{
  "name": "random-call-backend",
  "version": "1.2.0",
  "type": "module",
  "main": "server.js",
  "scripts": { "start": "node server.js" },
  "dependencies": {
    "cors": "2.8.5",
    "dockerode": "4.0.4",
    "express": "4.19.2",
    "google-auth-library": "9.14.2",
    "jsonwebtoken": "9.0.2",
    "pg": "8.11.5",
    "redis": "4.7.0",
    "socket.io": "4.7.5",
    "uuid": "9.0.1"
  }
}
PKG

cat > server/init.sql <<'SQL'
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  display_name TEXT,
  avatar_url TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS wallets (
  user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  coins BIGINT NOT NULL DEFAULT 0,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname='call_kind') THEN
    CREATE TYPE call_kind AS ENUM ('audio','video');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname='call_status') THEN
    CREATE TYPE call_status AS ENUM ('active','ended');
  END IF;
END$$;

CREATE TABLE IF NOT EXISTS calls (
  id UUID PRIMARY KEY,
  caller_id UUID REFERENCES users(id),
  callee_id UUID REFERENCES users(id),
  kind call_kind NOT NULL,
  status call_status NOT NULL DEFAULT 'active',
  started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  ended_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS calls_started_idx ON calls(started_at DESC);

CREATE TABLE IF NOT EXISTS messages (
  id UUID PRIMARY KEY,
  room TEXT NOT NULL,
  sender_id UUID REFERENCES users(id),
  receiver_id UUID REFERENCES users(id),
  body TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
SQL

cat > server/healthcheck.js <<'HC'
import http from "http";
const req = http.get("http://127.0.0.1:3000/health", res => process.exit(res.statusCode === 200 ? 0 : 1));
req.on("error", () => process.exit(1));
HC

# --- admin static (copied into image) ---
mkdir -p admin
cat > admin/index.html <<'HTML'
<!doctype html><html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>RandomCall Admin</title>
<style>
body{font-family:system-ui,Arial;margin:24px}.card{border:1px solid #ddd;border-radius:12px;padding:16px;margin-bottom:16px}
input,button{padding:8px;margin:4px}table{border-collapse:collapse;width:100%}th,td{padding:8px;border-bottom:1px solid #eee;text-align:left}
.ok{color:#0a7}.bad{color:#d33}.hidden{display:none}
</style></head><body>
<h2>RandomCall Admin</h2>
<div id="login" class="card"><h3>Login</h3><input id="u" placeholder="Admin username"/><input id="p" type="password" placeholder="Admin password"/>
<button onclick="login()">Login</button><div id="loginStatus"></div></div>
<div id="panel" class="hidden">
  <div class="card"><h3>Service Status</h3><div id="services"></div></div>
  <div class="card"><h3>Users</h3><input id="q" placeholder="Search email or name"/><button onclick="loadUsers()">Search</button>
    <table id="usersTbl"><thead><tr><th>Email</th><th>Name</th><th>Coins</th><th>Actions</th></tr></thead><tbody></tbody></table></div>
  <div class="card"><h3>Recent Calls</h3>
    <table id="callsTbl"><thead><tr><th>ID</th><th>Kind</th><th>Status</th><th>Start</th><th>End</th></tr></thead><tbody></tbody></table></div>
</div>
<script>
const base=location.origin;let token=localStorage.getItem("admintoken")||"";function setVisible(id,show){document.getElementById(id).classList.toggle("hidden",!show)}
async function login(){const username=document.getElementById("u").value.trim();const password=document.getElementById("p").value;
 const r=await fetch(base+"/v1/admin/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username,password})});
 if(!r.ok){document.getElementById("loginStatus").innerText="Login failed";return}const j=await r.json();token=j.token;localStorage.setItem("admintoken",token);
 setVisible("login",false);setVisible("panel",true);refreshAll()}
async function refreshAll(){loadServices();loadUsers();loadCalls()}function authHeaders(){return{"Authorization":"Bearer "+token}}
async function loadServices(){const r=await fetch(base+"/v1/admin/services",{headers:authHeaders()});if(!r.ok)return;const list=await r.json();const el=document.getElementById("services");el.innerHTML="";
 list.forEach(s=>{const d=document.createElement("div");d.innerHTML=`<strong>${s.name}</strong> : <span class="${s.running?"ok":"bad"}">${s.state}</span> <button onclick="restartSvc('${s.name}')">Restart</button>`;el.appendChild(d)});}
async function restartSvc(name){await fetch(base+"/v1/admin/services/"+name+"/restart",{method:"POST",headers:authHeaders()});loadServices()}
async function loadUsers(){const q=document.getElementById("q").value.trim();const r=await fetch(base+"/v1/admin/users"+(q?("?q="+encodeURIComponent(q)):""),{headers:authHeaders()});if(!r.ok)return;
 const users=await r.json();const tb=document.querySelector("#usersTbl tbody");tb.innerHTML="";users.forEach(u=>{const tr=document.createElement("tr");
 tr.innerHTML=`<td>${u.email}</td><td>${u.display_name||""}</td><td>${u.coins}</td><td>
 <button onclick="coinAdd('${u.id}',10)">+10</button><button onclick="coinAdd('${u.id}',100)">+100</button>
 <button onclick="coinAdd('${u.id}',-10)">-10</button><button onclick="coinSetPrompt('${u.id}')">Set…</button></td>`;tb.appendChild(tr);});}
async function coinAdd(id,delta){await fetch(base+"/v1/admin/users/"+id+"/coins/add",{method:"POST",headers:{...authHeaders(),"Content-Type":"application/json"},body:JSON.stringify({delta})});loadUsers()}
async function coinSetPrompt(id){const v=prompt("Set new coin balance:");if(v===null)return;const amount=parseInt(v,10);if(isNaN(amount))return alert("Invalid number");
 await fetch(base+"/v1/admin/users/"+id+"/coins/set",{method:"POST",headers:{...authHeaders(),"Content-Type":"application/json"},body:JSON.stringify({amount})});loadUsers()}
async function loadCalls(){const r=await fetch(base+"/v1/admin/calls",{headers:authHeaders()});if(!r.ok)return;const rows=await r.json();const tb=document.querySelector("#callsTbl tbody");tb.innerHTML="";
 rows.forEach(c=>{const tr=document.createElement("tr");tr.innerHTML=`<td>${c.id}</td><td>${c.kind}</td><td>${c.status}</td><td>${c.started_at}</td><td>${c.ended_at||""}</td>`;tb.appendChild(tr);});}
if(token){setVisible("login",false);setVisible("panel",true);refreshAll()}
</script></body></html>
HTML

# copy admin into server so it’s inside the image
cp -r admin server/admin

cat > server/server.js <<'SRV'
import express from "express";
import http from "http";
import { Server as SocketIOServer } from "socket.io";
import cors from "cors";
import jwt from "jsonwebtoken";
import { OAuth2Client } from "google-auth-library";
import pkg from "pg";
import { createClient as createRedisClient } from "redis";
import { v4 as uuidv4 } from "uuid";
import Docker from "dockerode";
import path from "path";

const {
  PORT = 3000,
  DATABASE_URL,
  REDIS_URL,
  JWT_SECRET,
  GOOGLE_CLIENT_ID,
  ADMIN_USER,
  ADMIN_PASS,
  TURN_HOST,
  TURN_USERNAME,
  TURN_PASSWORD,
  TURN_PORT = 3478
} = process.env;

const app = express();
app.use(cors());
app.use(express.json());
const server = http.createServer(app);
const io = new SocketIOServer(server, { cors: { origin: "*" }, path: "/socket.io" });

const { Pool } = pkg;
const db = new Pool({ connectionString: DATABASE_URL });
const redis = createRedisClient({ url: REDIS_URL });
await redis.connect();

const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// ---- helpers
async function ensureUser(email, name, avatarUrl){
  const ex = await db.query("SELECT id FROM users WHERE email=$1", [email]);
  if (ex.rowCount>0) return ex.rows[0].id;
  const id = uuidv4();
  await db.query("INSERT INTO users (id,email,display_name,avatar_url) VALUES ($1,$2,$3,$4)", [id,email,name||"",avatarUrl||""]);
  await db.query("INSERT INTO wallets (user_id,coins) VALUES ($1,500)", [id]); // welcome coins
  return id;
}
async function getCoins(uid){
  const r = await db.query("SELECT coins FROM wallets WHERE user_id=$1", [uid]);
  return r.rowCount ? Number(r.rows[0].coins) : 0;
}
async function addCoins(uid, delta){
  await db.query("INSERT INTO wallets (user_id, coins) VALUES ($1,0) ON CONFLICT (user_id) DO NOTHING", [uid]);
  await db.query("UPDATE wallets SET coins=coins+$1, updated_at=NOW() WHERE user_id=$2", [delta, uid]);
}
async function setCoins(uid, amount){
  await db.query("INSERT INTO wallets (user_id, coins) VALUES ($1,0) ON CONFLICT (user_id) DO NOTHING", [uid]);
  await db.query("UPDATE wallets SET coins=$1, updated_at=NOW() WHERE user_id=$2", [amount, uid]);
}

function adminAuth(req,res,next){
  const h = req.headers.authorization||""; const t = h.startsWith("Bearer ")?h.slice(7):null;
  if(!t) return res.status(401).json({error:"Missing token"});
  try{ const p = jwt.verify(t, JWT_SECRET); if(p.role!=="admin") return res.status(403).json({error:"Forbidden"}); req.admin=p; next(); }
  catch{ return res.status(401).json({error:"Invalid token"}); }
}

app.get("/health", (_req,res)=>res.json({ok:true}));

// Google login (app sends idToken from Android client)
app.post("/v1/auth/google", async (req,res)=>{
  const { idToken } = req.body||{};
  if(!idToken) return res.status(400).json({error:"idToken required"});
  try{
    const ticket = await googleClient.verifyIdToken({idToken, audience: GOOGLE_CLIENT_ID});
    const p = ticket.getPayload();
    const uid = await ensureUser(p.email, p.name, p.picture);
    const appJwt = jwt.sign({userId: uid, email: p.email}, JWT_SECRET, {expiresIn:"30d"});
    const coins = await getCoins(uid);
    return res.json({ token: appJwt, userId: uid, email: p.email, coins,
      turn:{
        urls:[`stun:stun.l.google.com:19302`, `turn:${TURN_HOST}:${TURN_PORT}`],
        username: TURN_USERNAME, credential: TURN_PASSWORD
      }});
  }catch{ return res.status(401).json({error:"Invalid Google token"}); }
});

// admin auth
app.post("/v1/admin/login",(req,res)=>{
  const {username,password} = req.body||{};
  if(username===ADMIN_USER && password===ADMIN_PASS){
    const tok = jwt.sign({role:"admin",name:username}, JWT_SECRET, {expiresIn:"12h"});
    return res.json({token: tok});
  }
  return res.status(401).json({error:"Invalid admin credentials"});
});

// admin api
import Dockerode from "dockerode";
const docker = new Dockerode({socketPath:"/var/run/docker.sock"});
const SERVICES = ["rc-caddy","rc-api","rc-postgres","rc-redis","rc-turn"];
app.get("/v1/admin/services", adminAuth, async (_req,res)=>{
  const list=[];
  for(const n of SERVICES){
    try{ const c = docker.getContainer(n); const d = await c.inspect();
      list.push({name:n, state:d?.State?.Status||"unknown", running:!!d?.State?.Running, restartCount:d?.State?.RestartCount||0});
    }catch{ list.push({name:n, state:"not_found", running:false, restartCount:0}); }
  }
  res.json(list);
});
app.post("/v1/admin/services/:name/restart", adminAuth, async (req,res)=>{
  const n=req.params.name; if(!SERVICES.includes(n)) return res.status(400).json({error:"Unknown service"});
  try{ await docker.getContainer(n).restart(); res.json({ok:true}); }catch(e){ res.status(500).json({error:"Failed to restart", detail:String(e)}); }
});

app.get("/v1/admin/users", adminAuth, async (req,res)=>{
  const q = req.query.q ? `%${req.query.q}%` : null;
  const sql = q
   ? `SELECT u.id,u.email,u.display_name,COALESCE(w.coins,0) coins,u.created_at
      FROM users u LEFT JOIN wallets w ON w.user_id=u.id
      WHERE u.email ILIKE $1 OR u.display_name ILIKE $1 ORDER BY u.created_at DESC LIMIT 200`
   : `SELECT u.id,u.email,u.display_name,COALESCE(w.coins,0) coins,u.created_at
      FROM users u LEFT JOIN wallets w ON w.user_id=u.id ORDER BY u.created_at DESC LIMIT 200`;
  const r = await db.query(sql, q?[q]:[]);
  res.json(r.rows);
});
app.post("/v1/admin/users/:id/coins/add", adminAuth, async (req,res)=>{
  await addCoins(req.params.id, Number((req.body||{}).delta||0));
  res.json({ok:true, coins: await getCoins(req.params.id)});
});
app.post("/v1/admin/users/:id/coins/set", adminAuth, async (req,res)=>{
  await setCoins(req.params.id, Number((req.body||{}).amount||0));
  res.json({ok:true, coins: await getCoins(req.params.id)});
});
app.get("/v1/admin/calls", adminAuth, async (_req,res)=>{
  const r = await db.query("SELECT id,caller_id,callee_id,kind,status,started_at,ended_at FROM calls ORDER BY started_at DESC LIMIT 200");
  res.json(r.rows);
});

// Socket.IO: matchmaking + signaling + charging
const COST = {audio:10, video:50};
const userToSocket = new Map(); const socketToUser = new Map();

io.use((socket,next)=>{
  try{ const t = socket.handshake.auth?.token; if(!t) return next(new Error("Auth token required"));
    socket.data.user = jwt.verify(t, JWT_SECRET); next(); }catch{ next(new Error("Invalid token")); }
});

io.on("connection",(socket)=>{
  const { userId } = socket.data.user;
  userToSocket.set(userId, socket.id); socketToUser.set(socket.id, {userId});

  socket.on("joinQueue", async ({kind})=>{
    if(!["audio","video"].includes(kind)) return;
    socket.join(`queue:${kind}`);
    const peers = (await io.in(`queue:${kind}`).fetchSockets()).filter(s=>s.id!==socket.id);
    if(peers.length>0){
      const peer = peers[Math.floor(Math.random()*peers.length)];
      const callId = uuidv4();
      await db.query("INSERT INTO calls (id,caller_id,callee_id,kind,status) VALUES ($1,$2,$3,$4,'active')",
        [callId, userId, (socketToUser.get(peer.id)||{}).userId, kind]);
      const room = `call:${callId}`;
      socket.join(room); peer.join(room);
      socket.leave(`queue:${kind}`); peer.leave(`queue:${kind}`);
      await redis.hSet(`call:${callId}`, {kind, status:"active", ts: Date.now().toString()});
      io.to(room).emit("matchFound", {callId, room, kind, coinRate: COST[kind]});
    }
  });

  socket.on("signal", ({room,type,payload})=>{
    io.to(room).emit("signal", {from: socket.id, type, payload});
  });

  socket.on("endCall", async ({callId})=>{
    await endCall(callId);
  });

  socket.on("disconnect", ()=>{ userToSocket.delete(userId); socketToUser.delete(socket.id); });
});

async function endCall(callId){
  const r = await db.query("UPDATE calls SET status='ended', ended_at=NOW() WHERE id=$1 RETURNING *", [callId]);
  if(!r.rowCount) return;
  await redis.hSet(`call:${callId}`, {status:"ended"});
  const room=`call:${callId}`; io.to(room).emit("callEnded",{callId});
  const sockets = await io.in(room).fetchSockets(); sockets.forEach(s=>s.leave(room));
}

setInterval(async ()=>{
  const keys = await redis.keys("call:*");
  for(const k of keys){
    const meta = await redis.hGetAll(k);
    if(!meta || meta.status!=="active") continue;
    const callId = k.split(":")[1];
    const r = await db.query("SELECT * FROM calls WHERE id=$1 AND status='active'", [callId]);
    if(!r.rowCount){ await redis.hSet(k,{status:"ended"}); continue; }
    const { caller_id, callee_id, kind } = r.rows[0];
    const cost = COST[kind]||10;
    const [a,b] = await Promise.all([getCoins(caller_id), getCoins(callee_id)]);
    if(a<cost || b<cost){ await endCall(callId); continue; }
    await addCoins(caller_id, -cost); await addCoins(callee_id, -cost);
    const sa=userToSocket.get(caller_id), sb=userToSocket.get(callee_id);
    if(sa) io.to(sa).emit("wallet:update",{coins:await getCoins(caller_id)});
    if(sb) io.to(sb).emit("wallet:update",{coins:await getCoins(callee_id)});
  }
}, 60_000);

// serve admin static
import { fileURLToPath } from "url";
import { dirname } from "path";
const __dirname = dirname(fileURLToPath(import.meta.url));
app.use("/admin", express.static(path.join(__dirname,"admin")));

server.listen(PORT, ()=>console.log(`API listening on :${PORT}`));
SRV

# ===== .env =====
cat > .env <<EOF
LE_EMAIL=${LE_EMAIL}
SITE_DOMAIN=${SITE_DOMAIN}
DB_PASS=${DB_PASS}
REDIS_PASS=${REDIS_PASS}
JWT_SECRET=${JWT_SECRET}
GOOGLE_CLIENT_ID=${GOOGLE_CLIENT_ID}
ADMIN_USER=${ADMIN_USER}
ADMIN_PASS=${ADMIN_PASS}
TURN_HOST=${TURN_HOST}
TURN_USER=${TURN_USER}
TURN_PASS=${TURN_PASS}
EOF

# ===== FIREWALL =====
ufw allow 22/tcp || true
ufw allow 80,443/tcp || true
ufw allow 3478/tcp || true
ufw allow 3478/udp || true
ufw allow 49152:65535/udp || true
echo "y" | ufw enable || true

# ===== BUILD & START =====
docker compose build --no-cache
docker compose up -d

# ===== UNINSTALL HELPER =====
cat > "${APP_DIR}/uninstall.sh" <<'UN'
#!/usr/bin/env bash
set -euo pipefail
cd /opt/random-call || exit 1
docker compose down
if [[ "${1:-}" == "--full-wipe" ]]; then
  rm -rf data/postgres data/redis caddy/data caddy/config
  echo "Full wipe completed (DB removed)."
else
  echo "Stack stopped. Data preserved."
fi
UN
chmod +x "${APP_DIR}/uninstall.sh"

echo
echo "==============================================="
echo "Install complete."
echo "Domain:              https://${SITE_DOMAIN}"
echo "Health:              https://${SITE_DOMAIN}/health"
echo "Admin Panel:         https://${SITE_DOMAIN}/admin"
echo "TURN server:         turn:${TURN_HOST}:3478"
echo "TURN username:       ${TURN_USER}"
echo "TURN password:       ${TURN_PASS}"
echo "Reinstall/upgrade:   re-run this script (users kept)."
echo "Uninstall (keep DB): sudo bash /opt/random-call/uninstall.sh"
echo "Full wipe (drop DB): sudo bash /opt/random-call/uninstall.sh --full-wipe"
echo "==============================================="
