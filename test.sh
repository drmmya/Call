#!/usr/bin/env bash
set -e

# ====== User inputs ======
read -p "Enter your domain (e.g. call.example.com): " DOMAIN
if [ -z "$DOMAIN" ]; then
  echo "Domain is required for HTTPS on 8443. Exiting."
  exit 1
fi

echo
echo "If your DNS provider is Cloudflare, I can auto-issue SSL via DNS-01."
echo "Otherwise, leave the next two prompts empty and I'll show manual TXT steps."
read -p "Cloudflare Email (optional): " CF_EMAIL
read -s -p "Cloudflare Global API Key (optional): " CF_KEY
echo

# ====== Vars ======
INSTALL_DIR="/opt/webrtc-one2one-https8443"
WEB_PORT=8443                 # HTTPS port (won't touch 443)
WS_INTERNAL=8082              # internal signaling
WEB_STATIC_INTERNAL=80        # static web container
PUBLIC_IP=$(curl -s https://api.ipify.org || curl -s ifconfig.me || echo "YOUR_PUBLIC_IP")

TURN_USER="webrtcuser"
TURN_PASS="$(head -c 12 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c16)"

mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

echo "Public IP: $PUBLIC_IP"
echo "Install dir: $INSTALL_DIR"

# ====== Docker ======
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

# ====== Layout ======
mkdir -p signal web coturn certs

# -------- Signaling (Node + ws) --------
cat > signal/server.js <<'JS'
const WebSocket = require('ws');
const PORT = process.env.PORT || 8082;
const wss = new WebSocket.Server({ port: PORT });
const peers = new Map(); // id -> ws

function safeSend(ws, obj){ try{ ws.send(JSON.stringify(obj)); }catch(e){} }

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

# -------- Web UI (static) --------
cat > web/index.html <<'HTML'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>One-to-One Call (HTTPS 8443)</title>
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
  <h2>One-to-One WebRTC Call (Secure)</h2>
  <div class="row">
    <input id="name" placeholder="Your name"/>
    <button id="joinBtn">Join</button>
    <small id="status">Disconnected</small>
  </div>
  <div><small>Open on two devices → join with two different names → click Call.</small></div>
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
const WS_URL = `wss://${host}:8443/ws`;   // secure websocket via reverse proxy on 8443
const STUN_URL = `stun:${host}:3478`;
const TURN_URL = `turn:${host}:3478`;     // also enabling 5349 (TLS) server-side; you may add 'turns:' with :5349
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
  try{
    if(!localStream){
      localStream = await navigator.mediaDevices.getUserMedia({video:true, audio:true});
      vLocal.srcObject = localStream;
    }
    if(!pc){
      pc = new RTCPeerConnection({
        iceServers: [
          { urls: [STUN_URL] },
          { urls: [TURN_URL], username: TURN_USER, credential: TURN_PASS },
          { urls: [`turns:${host}:5349`], username: TURN_USER, credential: TURN_PASS } // optional TLS TURN
        ]
      });
      localStream.getTracks().forEach(t=>pc.addTrack(t, localStream));
      pc.ontrack = (ev)=>{ vRemote.srcObject = ev.streams[0]; };
      pc.onicecandidate = (ev)=>{
        if(ev.candidate) send({type:'ice', to: peerEl.value, payload: ev.candidate});
      };
    }
  }catch(e){
    console.error('Media error:', e);
    alert('Camera/Mic access failed. Ensure HTTPS and grant permissions.');
    throw e;
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

# -------- coturn (host networking) with optional TLS on 5349 --------
mkdir -p coturn/certs
cat > coturn/turnserver.conf <<CONF
listening-port=3478
tls-listening-port=5349
external-ip=${PUBLIC_IP}
realm=${DOMAIN}
fingerprint
lt-cred-mech
user=${TURN_USER}:${TURN_PASS}
no-cli
no-loopback-peers
no-multicast-peers
# TLS certs will be mounted to /etc/ssl/turn/
cert=/etc/ssl/turn/fullchain.cer
pkey=/etc/ssl/turn/domain.key
cipher-list=HIGH
dh-file=/etc/ssl/turn/dhparam.pem
no-udp-relay
# Enable both TCP and TLS relays (good for restrictive networks)
# remove 'no-udp-relay' if you want UDP too (recommended for performance).
CONF

# Create dhparam for coturn TLS
openssl dhparam -out coturn/certs/dhparam.pem 2048 >/dev/null 2>&1 || true

# -------- Caddy (TLS on 8443, static + /ws reverse_proxy) --------
cat > Caddyfile <<CADDY
:8443 {
	tls /certs/fullchain.cer /certs/domain.key

	@ws path /ws
	handle @ws {
		reverse_proxy signal:8082
	}

	handle {
		root * /srv
		file_server
	}
}
CADDY

# -------- docker-compose --------
cat > docker-compose.yml <<YML
services:
  web:
    image: nginx:alpine
    restart: unless-stopped
    volumes:
      - ./web:/usr/share/nginx/html:ro

  signal:
    build: ./signal
    restart: unless-stopped
    ports:
      - "${WS_INTERNAL}:8082"

  caddy:
    image: caddy:2
    restart: unless-stopped
    ports:
      - "8443:8443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - ./web:/srv:ro
      - ./certs:/certs:ro
    depends_on:
      - web
      - signal

  coturn:
    image: coturn/coturn:latest
    restart: unless-stopped
    network_mode: host
    volumes:
      - ./coturn/turnserver.conf:/etc/turnserver.conf
      - ./certs:/etc/ssl/turn:ro
YML

# ====== ACME (Let's Encrypt via DNS-01) ======
echo
echo "==> Installing acme.sh (Let's Encrypt client)..."
if [ ! -d "$HOME/.acme.sh" ]; then
  curl https://get.acme.sh | sh -s email=admin@$DOMAIN >/dev/null 2>&1
fi
source "$HOME/.acme.sh/acme.sh.env"

mkdir -p certs

ISSUED=0
if [ -n "$CF_EMAIL" ] && [ -n "$CF_KEY" ]; then
  echo "Attempting Cloudflare auto DNS-01 issuance..."
  export CF_Email="$CF_EMAIL"
  export CF_Key="$CF_KEY"
  ~/.acme.sh/acme.sh --issue --dns dns_cf -d "$DOMAIN" --keylength ec-256 || true
  if [ -f "$HOME/.acme.sh/${DOMAIN}_ecc/${DOMAIN}.cer" ]; then
    ~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" \
      --ecc \
      --fullchain-file "$PWD/certs/fullchain.cer" \
      --key-file "$PWD/certs/domain.key"
    ISSUED=1
  fi
fi

if [ "$ISSUED" -eq 0 ]; then
  echo
  echo "Cloudflare auto-mode not used or failed."
  echo "Manual DNS-01 steps:"
  echo "1) Create a TXT record:"
  echo "   _acme-challenge.${DOMAIN}  TXT  <value>"
  echo "2) I'll now start a manual issuance to show you the required TXT value."
  echo "   Keep this shell open, create the TXT record in your DNS panel, then press Enter."
  ~/.acme.sh/acme.sh --issue --dns --yes-I-know-dns-manual-mode-enough-go-ahead-please -d "$DOMAIN" || true
  echo
  read -p "Add the shown TXT record in your DNS panel. Wait 1-2 mins, then press Enter to continue..."
  ~/.acme.sh/acme.sh --renew -d "$DOMAIN" --yes-I-know-dns-manual-mode-enough-go-ahead-please || true

  if [ -f "$HOME/.acme.sh/${DOMAIN}/${DOMAIN}.cer" ]; then
    cp "$HOME/.acme.sh/${DOMAIN}/${DOMAIN}.cer" certs/fullchain.cer
    cp "$HOME/.acme.sh/${DOMAIN}/${DOMAIN}.key" certs/domain.key
    ISSUED=1
  elif [ -f "$HOME/.acme.sh/${DOMAIN}_ecc/${DOMAIN}.cer" ]; then
    cp "$HOME/.acme.sh/${DOMAIN}_ecc/${DOMAIN}.cer" certs/fullchain.cer
    cp "$HOME/.acme.sh/${DOMAIN}_ecc/${DOMAIN}.key" certs/domain.key
    ISSUED=1
  fi
fi

if [ "$ISSUED" -ne 1 ]; then
  echo "ERROR: SSL issuing failed. You can retry later with acme.sh; continuing so that non-TLS pieces are ready."
fi

# Copy certs to coturn path, too
if [ -f certs/fullchain.cer ] && [ -f certs/domain.key ]; then
  cp certs/fullchain.cer coturn/certs/fullchain.cer || true
  cp certs/domain.key coturn/certs/domain.key || true
fi

# ====== Firewall (UFW) ======
if command -v ufw >/dev/null 2>&1; then
  ufw allow 8443/tcp || true
  ufw allow 3478/tcp || true
  ufw allow 3478/udp || true
  ufw allow 5349/tcp || true
  ufw allow 5349/udp || true
  ufw allow ${WS_INTERNAL}/tcp || true
fi

# ====== Bring up stack ======
docker compose build
docker compose up -d

echo
echo "================== SETUP DONE =================="
echo "Open:  https://${DOMAIN}:8443"
echo "Signal: wss://${DOMAIN}:8443/ws"
echo "TURN:  stun:${PUBLIC_IP}:3478 , turn:${PUBLIC_IP}:3478 , turns:${DOMAIN}:5349"
echo
echo "TURN username: ${TURN_USER}"
echo "TURN password: ${TURN_PASS}"
echo "Project dir:   ${INSTALL_DIR}"
echo "Logs:          docker compose logs -f"
echo "================================================"
