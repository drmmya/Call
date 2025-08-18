#!/usr/bin/env bash
set -euo pipefail

# ===========================
# RandomCall Stack (with Admin)
# ===========================
# Services (Docker Compose):
# - nginx-proxy + acme-companion (auto TLS)
# - rc-api (Node.js: auth, wallet, matchmaking, signaling, admin panel)
# - rc-postgres (persistent users, coins, calls)
# - rc-redis
# - rc-turn (coturn; host network for proper UDP)
#
# Control Panel (/admin):
# - Admin login (username/password you set now)
# - Users list, coin edit (add/sub/set)
# - Recent calls table
# - Service status (running/stopped) + restart buttons
#
# Redeploy/upgrade:
# - Re-running this script will rebuild & up containers, keeping the DB volume
# - Uninstall helper: `sudo bash /opt/random-call/uninstall.sh` (keeps DB by default)

[[ $(id -u) -eq 0 ]] || { echo "Run as root: sudo bash $0"; exit 1; }

read -rp "Let's Encrypt email (for TLS certs): " LE_EMAIL
while [[ -z "${LE_EMAIL}" ]]; do read -rp "Email cannot be empty. Enter Let's Encrypt email: " LE_EMAIL; done

read -rp "API domain (e.g. api.example.com): " API_DOMAIN
while [[ -z "${API_DOMAIN}" ]]; do read -rp "Domain cannot be empty. Enter API domain: " API_DOMAIN; done

read -rp "TURN domain or IP (press Enter to use server IP): " TURN_HOST
SERVER_IP="$(curl -fsS https://api.ipify.org || true)"
if [[ -z "${TURN_HOST}" ]]; then
  TURN_HOST="${SERVER_IP}"
  echo "Using server IP for TURN: ${TURN_HOST}"
fi

read -rp "Google OAuth WEB client ID: " GOOGLE_CLIENT_ID
while [[ -z "${GOOGLE_CLIENT_ID}" ]]; do read -rp "Client ID cannot be empty. Enter Google OAuth Client ID: " GOOGLE_CLIENT_ID; done

read -rp "Admin username for /admin: " ADMIN_USER
while [[ -z "${ADMIN_USER}" ]]; do read -rp "Admin username cannot be empty: " ADMIN_USER; done
read -rsp "Admin password for /admin: " ADMIN_PASS; echo
while [[ -z "${ADMIN_PASS}" ]]; do read -rsp "Admin password cannot be empty: " ADMIN_PASS; echo; done

apt-get update
apt-get install -y ca-certificates curl gnupg ufw git

# Docker engine + compose plugin
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg
. /etc/os-release
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

systemctl enable docker
systemctl start docker

APP_DIR="/opt/random-call"
mkdir -p "${APP_DIR}"
cd "${APP_DIR}"

# If re-running, keep existing .env values where possible (DB/Redis/JWT/TURN creds)
if [[ -f .env ]]; then
  # shellcheck disable=SC1091
  set -a; source ./.env; set +a || true
fi

DB_PASS="${DB_PASS:-$(openssl rand -hex 16)}"
JWT_SECRET="${JWT_SECRET:-$(openssl rand -hex 32)}"
REDIS_PASS="${REDIS_PASS:-$(openssl rand -hex 16)}"
TURN_USER="${TURN_USER:-webrtc$(openssl rand -hex 2)}"
TURN_PASS="${TURN_PASS:-$(openssl rand -hex 16)}"

mkdir -p data/postgres data/redis nginx/certs server admin

# -----------------------
# docker-compose.yml
# -----------------------
cat > docker-compose.yml <<'YML'
version: "3.9"
services:
  nginx-proxy:
    image: nginxproxy/nginx-proxy:latest
    container_name: nginx-proxy
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/certs:/etc/nginx/certs:ro
      - /etc/nginx/vhost.d
      - /usr/share/nginx/html
      - /var/run/docker.sock:/tmp/docker.sock:ro
    healthcheck:
      test: ["CMD-SHELL", "nginx -t"]
      interval: 30s
      timeout: 5s
      retries: 5

  acme-companion:
    image: nginxproxy/acme-companion:latest
    container_name: nginx-proxy-acme
    restart: unless-stopped
    environment:
      DEFAULT_EMAIL: ${LE_EMAIL}
    volumes:
      - ./nginx/certs:/etc/nginx/certs
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - /etc/acme.sh

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
      test: ["CMD-SHELL", "pg_isready -U rcuser -d rcdb"]
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
      VIRTUAL_HOST: ${API_DOMAIN}
      LETSENCRYPT_HOST: ${API_DOMAIN}
      VIRTUAL_PORT: 3000

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
    volumes:
      - ./server:/usr/src/app
      - /var/run/docker.sock:/var/run/docker.sock  # for status/restart via Docker API
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
    environment:
      - REALM=${API_DOMAIN}
    command:
      - /bin/sh
      - -c
      - |
        cat >/etc/turnserver.conf <<EOF
        listening-port=3478
        realm=${API_DOMAIN}
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

# -----------------------
# Backend package files
# -----------------------
cat > server/Dockerfile <<'DOCKER'
FROM node:20-alpine
WORKDIR /usr/src/app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
EXPOSE 3000
CMD ["node","server.js"]
DOCKER

cat > server/package.json <<'PKG'
{
  "name": "random-call-backend",
  "version": "1.1.0",
  "type": "module",
  "main": "server.js",
  "scripts": { "start": "node server.js" },
  "dependencies": {
    "bcryptjs": "2.4.3",
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

# -----------------------
# Database schema
# -----------------------
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
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'call_kind') THEN
    CREATE TYPE call_kind AS ENUM ('audio','video');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'call_status') THEN
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

# -----------------------
# Server app (API + Admin UI)
# -----------------------
cat > server/healthcheck.js <<'HC'
import http from "http";
const req = http.get("http://127.0.0.1:3000/health", res => process.exit(res.statusCode === 200 ? 0 : 1));
req.on("error", () => process.exit(1));
HC

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
import fs from "fs";

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

// ---- Helpers ----
async function ensureUser(email, displayName, avatarUrl) {
  const existing = await db.query("SELECT id FROM users WHERE email=$1", [email]);
  if (existing.rowCount > 0) return existing.rows[0].id;
  const id = uuidv4();
  await db.query("INSERT INTO users (id,email,display_name,avatar_url) VALUES ($1,$2,$3,$4)", [id, email, displayName, avatarUrl]);
  await db.query("INSERT INTO wallets (user_id, coins) VALUES ($1, 500)", [id]); // 500 welcome coins
  return id;
}
async function getCoins(userId) {
  const r = await db.query("SELECT coins FROM wallets WHERE user_id=$1", [userId]);
  return r.rowCount ? Number(r.rows[0].coins) : 0;
}
async function addCoins(userId, delta) {
  await db.query("INSERT INTO wallets (user_id, coins) VALUES ($1, 0) ON CONFLICT (user_id) DO NOTHING", [userId]);
  await db.query("UPDATE wallets SET coins = coins + $1, updated_at=NOW() WHERE user_id=$2", [delta, userId]);
}
async function setCoins(userId, amount) {
  await db.query("INSERT INTO wallets (user_id, coins) VALUES ($1, 0) ON CONFLICT (user_id) DO NOTHING", [userId]);
  await db.query("UPDATE wallets SET coins = $1, updated_at=NOW() WHERE user_id=$2", [amount, userId]);
}

function authMiddleware(req, _res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return next("Unauthorized");
  try { req.user = jwt.verify(token, JWT_SECRET); next(); } catch { next("Unauthorized"); }
}
function adminMiddleware(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing token" });
  try {
    const p = jwt.verify(token, JWT_SECRET);
    if (p.role !== "admin") return res.status(403).json({ error: "Forbidden" });
    req.admin = p; next();
  } catch { return res.status(401).json({ error: "Invalid token" }); }
}

// ---- Public: health ----
app.get("/health", (_req, res) => res.json({ ok: true }));

// ---- Auth ----
app.post("/v1/auth/google", async (req, res) => {
  const { idToken } = req.body || {};
  if (!idToken) return res.status(400).json({ error: "idToken required" });
  try {
    const ticket = await googleClient.verifyIdToken({ idToken, audience: GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    const email = payload.email, name = payload.name || "", pic = payload.picture || "";
    const userId = await ensureUser(email, name, pic);
    const token = jwt.sign({ userId, email }, JWT_SECRET, { expiresIn: "30d" });
    const coins = await getCoins(userId);
    return res.json({
      token, userId, email, coins,
      turn: {
        urls: [`stun:stun.l.google.com:19302`, `turn:${TURN_HOST}:${TURN_PORT}`],
        username: TURN_USERNAME,
        credential: TURN_PASSWORD
      }
    });
  } catch {
    return res.status(401).json({ error: "Invalid Google token" });
  }
});

// ---- Admin auth ----
app.post("/v1/admin/login", (req, res) => {
  const { username, password } = req.body || {};
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    const token = jwt.sign({ role: "admin", name: username }, JWT_SECRET, { expiresIn: "12h" });
    return res.json({ token });
  }
  return res.status(401).json({ error: "Invalid admin credentials" });
});

// ---- Admin: users & wallet ----
app.get("/v1/admin/users", adminMiddleware, async (req, res) => {
  const q = req.query.q ? `%${req.query.q}%` : null;
  const sql = q
    ? `SELECT u.id, u.email, u.display_name, COALESCE(w.coins,0) coins, u.created_at
       FROM users u LEFT JOIN wallets w ON w.user_id=u.id
       WHERE u.email ILIKE $1 OR u.display_name ILIKE $1
       ORDER BY u.created_at DESC LIMIT 200`
    : `SELECT u.id, u.email, u.display_name, COALESCE(w.coins,0) coins, u.created_at
       FROM users u LEFT JOIN wallets w ON w.user_id=u.id
       ORDER BY u.created_at DESC LIMIT 200`;
  const r = await db.query(sql, q ? [q] : []);
  res.json(r.rows);
});
app.post("/v1/admin/users/:id/coins/add", adminMiddleware, async (req, res) => {
  const { id } = req.params; const { delta } = req.body || {};
  await addCoins(id, Number(delta || 0));
  res.json({ ok: true, coins: await getCoins(id) });
});
app.post("/v1/admin/users/:id/coins/set", adminMiddleware, async (req, res) => {
  const { id } = req.params; const { amount } = req.body || {};
  await setCoins(id, Number(amount || 0));
  res.json({ ok: true, coins: await getCoins(id) });
});
app.get("/v1/admin/calls", adminMiddleware, async (_req, res) => {
  const r = await db.query(`SELECT id, caller_id, callee_id, kind, status, started_at, ended_at
                            FROM calls ORDER BY started_at DESC LIMIT 200`);
  res.json(r.rows);
});

// ---- Admin: service status + restart ----
const docker = new Docker({ socketPath: "/var/run/docker.sock" });
const SERVICE_NAMES = ["nginx-proxy","nginx-proxy-acme","rc-api","rc-postgres","rc-redis","rc-turn"];

app.get("/v1/admin/services", adminMiddleware, async (_req, res) => {
  const list = [];
  for (const name of SERVICE_NAMES) {
    try {
      const c = docker.getContainer(name);
      const data = await c.inspect();
      list.push({
        name,
        state: data?.State?.Status || "unknown",
        running: !!data?.State?.Running,
        restartCount: data?.State?.RestartCount || 0
      });
    } catch {
      list.push({ name, state: "not_found", running: false, restartCount: 0 });
    }
  }
  res.json(list);
});

app.post("/v1/admin/services/:name/restart", adminMiddleware, async (req, res) => {
  const name = req.params.name;
  if (!SERVICE_NAMES.includes(name)) return res.status(400).json({ error: "Unknown service" });
  try {
    const c = docker.getContainer(name);
    await c.restart();
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: "Failed to restart", detail: String(e) });
  }
});

// ---- Socket.IO: matchmaking + signaling + charging ----
const COST = { audio: 10, video: 50 };
const userToSocket = new Map(); // userId -> socketId
const socketToUser = new Map(); // socketId -> { userId }

io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) return next(new Error("Auth token required"));
  try { socket.data.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { next(new Error("Invalid token")); }
});

io.on("connection", (socket) => {
  const { userId } = socket.data.user;
  userToSocket.set(userId, socket.id);
  socketToUser.set(socket.id, { userId });

  socket.on("joinQueue", async ({ kind }) => {
    if (!["audio","video"].includes(kind)) return;
    socket.join(`queue:${kind}`);

    const peers = (await io.in(`queue:${kind}`).fetchSockets()).filter(s => s.id !== socket.id);
    if (peers.length > 0) {
      const peer = peers[Math.floor(Math.random()*peers.length)];
      const callId = uuidv4();
      await db.query("INSERT INTO calls (id, caller_id, callee_id, kind, status) VALUES ($1,$2,$3,$4,'active')",
        [callId, socket.data.user.userId, socketToUser.get(peer.id).userId, kind]);

      const room = `call:${callId}`;
      socket.join(room); peer.join(room);
      socket.leave(`queue:${kind}`); peer.leave(`queue:${kind}`);

      await redis.hSet(`call:${callId}`, { kind, status: "active", ts: Date.now().toString() });
      io.to(room).emit("matchFound", { callId, room, kind, coinRate: COST[kind] });
    }
  });

  socket.on("signal", ({ room, type, payload }) => {
    io.to(room).emit("signal", { from: socket.id, type, payload });
  });

  socket.on("endCall", async ({ callId }) => {
    await endCall(callId);
  });

  socket.on("disconnect", async () => {
    userToSocket.delete(userId);
    socketToUser.delete(socket.id);
  });
});

async function endCall(callId) {
  const r = await db.query("UPDATE calls SET status='ended', ended_at=NOW() WHERE id=$1 RETURNING *", [callId]);
  if (!r.rowCount) return;
  await redis.hSet(`call:${callId}`, { status: "ended" });
  const room = `call:${callId}`;
  io.to(room).emit("callEnded", { callId });
  const sockets = await io.in(room).fetchSockets();
  for (const s of sockets) s.leave(room);
}

// Per-minute charging (both parties pay). Change to caller-only if you want.
setInterval(async () => {
  const keys = await redis.keys("call:*");
  for (const k of keys) {
    const meta = await redis.hGetAll(k);
    if (!meta || meta.status !== "active") continue;
    const callId = k.split(":")[1];
    const r = await db.query("SELECT * FROM calls WHERE id=$1 AND status='active'", [callId]);
    if (!r.rowCount) { await redis.hSet(k, { status: "ended" }); continue; }

    const { caller_id, callee_id, kind } = r.rows[0];
    const cost = COST[kind] || 10;
    const [a,b] = await Promise.all([getCoins(caller_id), getCoins(callee_id)]);
    if (a < cost || b < cost) { await endCall(callId); continue; }
    await addCoins(caller_id, -cost); await addCoins(callee_id, -cost);

    const sa = userToSocket.get(caller_id), sb = userToSocket.get(callee_id);
    if (sa) io.to(sa).emit("wallet:update", { coins: await getCoins(caller_id) });
    if (sb) io.to(sb).emit("wallet:update", { coins: await getCoins(callee_id) });
  }
}, 60_000);

// ---- Admin UI (static) ----
const adminDir = path.join(process.cwd(), "admin");
app.use("/admin", express.static(adminDir));

// ---- Start ----
server.listen(PORT, () => console.log(`API listening on :${PORT}`));
SRV

# -----------------------
# Admin frontend (vanilla HTML+JS)
# -----------------------
cat > admin/index.html <<'HTML'
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>RandomCall Admin</title>
  <style>
    body { font-family: system-ui, Arial; margin: 24px; }
    .card { border:1px solid #ddd; border-radius:12px; padding:16px; margin-bottom:16px; }
    input, button, select { padding:8px; margin:4px; }
    table { border-collapse: collapse; width:100%; }
    th, td { padding:8px; border-bottom:1px solid #eee; text-align:left; }
    .row { display:flex; gap:12px; flex-wrap:wrap; }
    .ok { color: #0a7; } .bad { color: #d33; }
    .hidden { display:none; }
  </style>
</head>
<body>
  <h2>RandomCall Admin</h2>

  <div id="login" class="card">
    <h3>Login</h3>
    <input id="u" placeholder="Admin username"/>
    <input id="p" type="password" placeholder="Admin password"/>
    <button onclick="login()">Login</button>
    <div id="loginStatus"></div>
  </div>

  <div id="panel" class="hidden">
    <div class="card">
      <h3>Service Status</h3>
      <div id="services"></div>
    </div>

    <div class="card">
      <h3>Users</h3>
      <input id="q" placeholder="Search email or name"/>
      <button onclick="loadUsers()">Search</button>
      <table id="usersTbl">
        <thead><tr><th>Email</th><th>Name</th><th>Coins</th><th>Actions</th></tr></thead>
        <tbody></tbody>
      </table>
    </div>

    <div class="card">
      <h3>Recent Calls</h3>
      <table id="callsTbl">
        <thead><tr><th>ID</th><th>Kind</th><th>Status</th><th>Start</th><th>End</th></tr></thead>
        <tbody></tbody>
      </table>
    </div>
  </div>

  <script>
    const base = location.origin;
    let token = localStorage.getItem("admintoken") || "";

    function setVisible(id, show){ document.getElementById(id).classList.toggle('hidden', !show); }

    async function login(){
      const username = document.getElementById('u').value.trim();
      const password = document.getElementById('p').value;
      const r = await fetch(base + '/v1/admin/login', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ username, password })
      });
      if(!r.ok){ document.getElementById('loginStatus').innerText = 'Login failed'; return; }
      const j = await r.json(); token = j.token; localStorage.setItem('admintoken', token);
      setVisible('login', false); setVisible('panel', true);
      refreshAll();
    }

    async function refreshAll(){ loadServices(); loadUsers(); loadCalls(); }
    function authHeaders(){ return { 'Authorization':'Bearer ' + token }; }

    async function loadServices(){
      const r = await fetch(base + '/v1/admin/services', { headers: authHeaders() });
      if(!r.ok) return;
      const list = await r.json();
      const el = document.getElementById('services');
      el.innerHTML = "";
      list.forEach(s => {
        const div = document.createElement('div');
        div.innerHTML = \`
          <strong>\${s.name}</strong> :
          <span class="\${s.running ? 'ok':'bad'}">\${s.state}</span>
          <button onclick="restartSvc('\${s.name}')">Restart</button>
        \`;
        el.appendChild(div);
      });
    }
    async function restartSvc(name){
      await fetch(base + '/v1/admin/services/' + name + '/restart', { method:'POST', headers: authHeaders() });
      loadServices();
    }

    async function loadUsers(){
      const q = document.getElementById('q').value.trim();
      const r = await fetch(base + '/v1/admin/users' + (q?('?q='+encodeURIComponent(q)):""), { headers: authHeaders() });
      if(!r.ok) return;
      const users = await r.json();
      const tb = document.querySelector('#usersTbl tbody'); tb.innerHTML = "";
      users.forEach(u => {
        const tr = document.createElement('tr');
        tr.innerHTML = \`
          <td>\${u.email}</td>
          <td>\${u.display_name || ''}</td>
          <td>\${u.coins}</td>
          <td>
            <button onclick="coinAdd('\${u.id}',10)">+10</button>
            <button onclick="coinAdd('\${u.id}',100)">+100</button>
            <button onclick="coinAdd('\${u.id}',-10)">-10</button>
            <button onclick="coinSetPrompt('\${u.id}')">Set…</button>
          </td>\`;
        tb.appendChild(tr);
      });
    }
    async function coinAdd(id, delta){
      await fetch(base + '/v1/admin/users/'+id+'/coins/add', {
        method:'POST', headers:{...authHeaders(),'Content-Type':'application/json'},
        body: JSON.stringify({ delta })
      });
      loadUsers();
    }
    async function coinSetPrompt(id){
      const v = prompt("Set new coin balance:");
      if(v===null) return;
      const amount = parseInt(v,10);
      if(isNaN(amount)) return alert("Invalid number");
      await fetch(base + '/v1/admin/users/'+id+'/coins/set', {
        method:'POST', headers:{...authHeaders(),'Content-Type':'application/json'},
        body: JSON.stringify({ amount })
      });
      loadUsers();
    }

    async function loadCalls(){
      const r = await fetch(base + '/v1/admin/calls', { headers: authHeaders() });
      if(!r.ok) return;
      const rows = await r.json();
      const tb = document.querySelector('#callsTbl tbody'); tb.innerHTML = "";
      rows.forEach(c => {
        const tr = document.createElement('tr');
        tr.innerHTML = \`
          <td>\${c.id}</td>
          <td>\${c.kind}</td>
          <td>\${c.status}</td>
          <td>\${c.started_at}</td>
          <td>\${c.ended_at || ''}</td>\`;
        tb.appendChild(tr);
      });
    }

    // Auto-show panel if token already saved
    if(token){ setVisible('login', false); setVisible('panel', true); refreshAll(); }
  </script>
</body>
</html>
HTML

# -----------------------
# .env (persist secrets & config)
# -----------------------
cat > .env <<EOF
LE_EMAIL=${LE_EMAIL}
API_DOMAIN=${API_DOMAIN}
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

# -----------------------
# Firewall
# -----------------------
ufw allow 22/tcp || true
ufw allow 80,443/tcp || true
ufw allow 3478/tcp || true
ufw allow 3478/udp || true
ufw allow 49152:65535/udp || true
echo "y" | ufw enable || true

# -----------------------
# Build & start (idempotent)
# -----------------------
docker compose build
docker compose up -d

# -----------------------
# Uninstall helper (keeps DB by default)
# -----------------------
cat > "${APP_DIR}/uninstall.sh" <<'UN'
#!/usr/bin/env bash
set -euo pipefail
cd /opt/random-call || exit 1
echo "Stopping containers..."
docker compose down
if [[ "${1:-}" == "--full-wipe" ]]; then
  echo "FULL WIPE: removing volumes (DB, Redis). THIS DELETES USERS/COINS."
  rm -rf data/postgres data/redis
else
  echo "Keeping data volumes (users & coins preserved)."
fi
echo "Removing images (optional)"; docker image prune -f || true
echo "Done."
UN
chmod +x "${APP_DIR}/uninstall.sh"

echo
echo "======================================================"
echo "Install complete."
echo " Admin Panel:        https://${API_DOMAIN}/admin"
echo "  -> Log in with the admin username/password you set"
echo " API base URL:       https://${API_DOMAIN}"
echo " Socket.IO (WSS):    wss://${API_DOMAIN}/socket.io"
echo " TURN server:        turn:${TURN_HOST}:3478"
echo " TURN username:      ${TURN_USER}"
echo " TURN password:      ${TURN_PASS}"
echo
echo "Re-run this script any time to upgrade/redeploy (users kept)."
echo "Uninstall (keep DB): sudo bash ${APP_DIR}/uninstall.sh"
echo "Uninstall FULL WIPE: sudo bash ${APP_DIR}/uninstall.sh --full-wipe"
echo "======================================================"
