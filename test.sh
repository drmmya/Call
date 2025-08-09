#!/usr/bin/env bash
set -e

INSTALL_DIR="/opt/webrtc-one2one-ports"
WEB_PORT=8081
WS_PORT=8082
TURN_USER="webrtcuser"
TURN_PASS="$(head -c 12 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c16)"
PUBLIC_IP=$(curl -s https://api.ipify.org || curl -s ifconfig.me || echo "YOUR_PUBLIC_IP")

echo "Public IP: $PUBLIC_IP"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# -------- Docker ----------
if ! command -v docker >/dev/null 2>&1; then
  apt-get update
  apt-get install -y ca-certificates curl gnupg
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  systemctl enable docker
  systemctl start docker
fi

mkdir -p signal web coturn

# -------- Signaling server (Node + ws on WS_PORT) --------
cat > signal/server.js <<'JS'
const WebSocket = require('ws');
const PORT = process.env.PORT || 8082;
const wss = new WebSocket.Server({ port: PORT });
const peers = new Map(); // id -> ws

function safeSend(ws, obj) { try { ws.send(JSON.stringify(obj)); } catch(e) {} }

wss.on('connection', (ws) => {
  let myId = null;
  ws.on('message', (buf) => {
    let msg; try { msg = JSON.parse(buf.toString()); } catch(e) { return; }

    if (msg.type === 'join' && typeof msg.id === 'string') {
      myId = msg.id;
      peers.set(myId, ws);
      const roster = Array.from(peers.keys());
      peers.forEach(cli => safeSend(cli, { type:'roster', roster }));
      return;
    }
    if (msg.to && peers.has(msg.to)) {
      const peer = peers.get(msg.to);
      safeSend(peer, { from: myId, type: msg.type, payload: msg.payload });
    }
  });
  ws.on('close', () => {
    if (myId) {
      peers.delete(myId);
      const roster = Array.from(peers.keys());
      peers.forEach(cli => safeSend(cli, { type:'roster', roster }));
    }
  });
});

console.log('Signaling server on :' + PORT);
JS

cat > signal/package.json <<'JSON'
{
  "name": "webrtc-signal",
  "version": "1.0.0",
  "main": "server.js",
  "license": "MIT",
  "dependencies": { "ws": "^8.18.0" }
}
JSON

cat > signal/Dockerfile <<'DOCKER'
FROM node:20-alpine
WORKDIR /app
COPY package.json ./
RUN npm install --production
COPY server.js ./
ENV PORT=8082
EXPOSE 8082
CMD ["node", "server.js"]
DOCKER

# -------- Web UI (serves on WEB_PORT) --------
cat > web/index.html <<'HTML'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>One-to-One Call</title>
<style>
  body{font-family:system-ui,Arial,sans-serif;margin:0;padding:16px;background:#0b1220;color:#e8eefc}
  .card{background:#121a2b;border:1px solid #1f2b46;border-radius:16px;padding:16px;max-width:980px;margin:0 auto 16px}
  input,button{padding:10px;border-radius:12px;border:1px solid #2b3a5e;background:#0f172a;color:#e8eefc}
  button{cursor:pointer}
  .row{display:flex;gap:12px;flex-wrap:wrap;align-items:center}
  .grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
  video{width:100%;background:#000;border-radius:12px}
  .roster{display:flex;gap:8px;flex-wrap:wrap}
  .pill{padding:6px 10px;border:1px solid #334;border-radius:999px}
  .pill button{margin-left:8px}
  small{opacity:.7}
</style>
</head>
<body>
<div class="card">
  <h2>One-to-One WebRTC Call</h2>
  <div class="row">
    <input id="name" placeholder="Your name"/>
    <button id="joinBtn">Join</button>
    <small id="status">Disconnected</small>
  </div>
  <div><small>Open this page on two devices → join with two different names → click Call.</small></div>
</div>

<div class="card">
  <h3>Online Users</h3>
  <div id="roster" class="roster"></div>
</div>

<div class="card">
  <h3>Call</h3>
  <div class="row">
    <input id="peer" placeholder="Peer name"/>
    <button id="callBtn">Call</button>
    <button id="hangBtn">Hang Up</button>
  </div>
</div>

<div class="card grid">
  <div>
    <h4>Local</h4>
    <video id="local" autoplay playsinline muted></video>
  </div>
  <div>
    <h4>Remote</h4>
    <video id="remote" autoplay playsinline></video>
  </div>
</div>

<script src="app.js"></script>
</body>
</html>
HTML

cat > web/app.js <<'JS'
const host = location.hostname;
const WS_URL = `ws://${host}:8082/ws`;      // fixed to :8082
const STUN_URL = `stun:${host}:3478`;
const TURN_URL = `turn:${host}:3478`;
const TURN_USER = 'WEBSERVER_REPL_TURN_USER';
const TURN_PASS = 'WEBSERVER_REPL_TURN_PASS';

const nameEl = document.getElementById('name');
const joinBtn = document.getElementById('joinBtn');
const peerEl = document.getElementById('peer');
const callBtn = document.getElementById('callBtn');
const hangBtn = document.getElementById('hangBtn');
const rosterEl = document.getElementById('roster');
const statusEl = document.getElementById('status');
const vLocal = document.getElementById('local');
const vRemote = document.getElementById('remote');

let ws, pc, localStream, myName=null;

function log(s){ console.log(s); statusEl.textContent=s; }

function renderRoster(list){
  rosterEl.innerHTML = '';
  list.filter(n => n !== myName).forEach(n=>{
    const div = document.createElement('div');
    div.className='pill';
    div.textContent = n;
    const b = document.createElement('button');
    b.textContent='Call';
    b.onclick = ()=>{ peerEl.value=n; startCall(); };
    div.appendChild(b);
    rosterEl.appendChild(div);
  });
}

joinBtn.onclick = async () => {
  myName = (nameEl.value||'').trim();
  if(!myName){ alert('Enter your name'); return; }

  ws = new WebSocket(WS_URL);
  ws.onopen = ()=>{
    log('Connected');
    ws.send(JSON.stringify({type:'join', id: myName}));
  };
  ws.onmessage = (ev)=>{
    const msg = JSON.parse(ev.data);
    if(msg.type==='roster'){ renderRoster(msg.roster); }
    if(msg.type==='offer'){ onOffer(msg); }
    if(msg.type==='answer'){ onAnswer(msg); }
    if(msg.type==='ice'){ if(pc) pc.addIceCandidate(msg.payload).catch(()=>{}); }
  };
  ws.onclose = ()=> log('Disconnected');
};

async function ensureMediaAndPC() {
  if(!localStream){
    localStream = await navigator.mediaDevices.getUserMedia({video:true, audio:true});
    vLocal.srcObject = localStream;
  }
  if(!pc){
    pc = new RTCPeerConnection({
      iceServers: [
        { urls: [STUN_URL] },
        { urls: [TURN_URL], username: TURN_USER, credential: TURN_PASS }
      ]
    });
    localStream.getTracks().forEach(t=>pc.addTrack(t, localStream));
    pc.ontrack = (ev)=>{ vRemote.srcObject = ev.streams[0]; };
    pc.onicecandidate = (ev)=>{
      if(ev.candidate) send({type:'ice', to: peerEl.value, payload: ev.candidate});
    };
  }
}

function send(obj){ ws && ws.readyState===1 && ws.send(JSON.stringify(obj)); }

async function startCall(){
  const to = (peerEl.value||'').trim();
  if(!to){ alert('Enter peer name'); return; }
  await ensureMediaAndPC();
  const offer = await pc.createOffer({offerToReceiveAudio:true, offerToReceiveVideo:true});
  await pc.setLocalDescription(offer);
  send({type:'offer', to, payload: offer});
}

async function onOffer(msg){
  peerEl.value = msg.from;
  await ensureMediaAndPC();
  await pc.setRemoteDescription(msg.payload);
  const answer = await pc.createAnswer();
  await pc.setLocalDescription(answer);
  send({type:'answer', to: msg.from, payload: answer});
}

async function onAnswer(msg){
  await pc.setRemoteDescription(msg.payload);
}

hangBtn.onclick = ()=>{
  if(pc){ pc.getSenders().forEach(s=>s.track && s.track.stop()); pc.close(); pc=null; }
  if(localStream){ localStream.getTracks().forEach(t=>t.stop()); localStream=null; vLocal.srcObject=null; vRemote.srcObject=null; }
};
JS

# Inject TURN creds
sed -i "s/WEBSERVER_REPL_TURN_USER/${TURN_USER}/g" web/app.js
sed -i "s/WEBSERVER_REPL_TURN_PASS/${TURN_PASS}/g" web/app.js

# -------- coturn (host networking for UDP) --------
cat > coturn/turnserver.conf <<CONF
listening-port=3478
tls-listening-port=5349
external-ip=${PUBLIC_IP}
realm=webrtc.local
fingerprint
lt-cred-mech
user=${TURN_USER}:${TURN_PASS}
no-cli
no-loopback-peers
no-multicast-peers
# (Optional TLS later) cert=/etc/ssl/turn/fullchain.pem
# (Optional TLS later) pkey=/etc/ssl/turn/privkey.pem
CONF

# -------- docker-compose --------
cat > docker-compose.yml <<YML
services:
  web:
    image: nginx:alpine
    restart: unless-stopped
    ports:
      - "${WEB_PORT}:80"
    volumes:
      - ./web:/usr/share/nginx/html:ro

  signal:
    build: ./signal
    restart: unless-stopped
    ports:
      - "${WS_PORT}:8082"

  coturn:
    image: coturn/coturn:latest
    restart: unless-stopped
    network_mode: host
    volumes:
      - ./coturn/turnserver.conf:/etc/turnserver.conf
YML

# -------- firewall (if UFW present) --------
if command -v ufw >/dev/null 2>&1; then
  ufw allow ${WEB_PORT}/tcp || true
  ufw allow ${WS_PORT}/tcp || true
  ufw allow 3478/tcp || true
  ufw allow 3478/udp || true
  ufw allow 5349/tcp || true
  ufw allow 5349/udp || true
fi

docker compose build
docker compose up -d

echo
echo "====================== DONE ======================"
echo "Open this on two devices/browsers:"
echo "Web UI:              http://${PUBLIC_IP}:${WEB_PORT}"
echo "Signaling (WS):      ws://${PUBLIC_IP}:${WS_PORT}/ws"
echo "TURN/STUN:           stun:${PUBLIC_IP}:3478 , turn:${PUBLIC_IP}:3478"
echo
echo "TURN username:       ${TURN_USER}"
echo "TURN password:       ${TURN_PASS}"
echo "Project dir:         ${INSTALL_DIR}"
echo "Logs:                docker compose logs -f"
echo "=================================================="
