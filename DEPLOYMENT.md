# NIRVEX — Seamless Online Multiplayer Deployment & Operations Guide

## 1. Zero-Friction Player Experience
When deployed to any cloud host (Render, Fly.io, Railway, VPS, or Docker), players simply open the game URL in their browser:
- **No terminal commands or manual server URLs required**: The client (`nirma_strike.html`) automatically discovers its hosted same-origin HTTP + WebSocket endpoint (`window.location.origin` -> `ws:` / `wss:` at `/ws`), or reads `<meta name="nirvex-backend-url">` / `window.NIRVEX_CONFIG.backendUrl` when hosted on a static CDN.
- **Persistent Accounts & Guest Play**: Players can create a password-protected account (`scrypt` hashed), sign in to an existing account, or play immediately as a Guest with automatic session restoration (`sessionToken`).
- **Live Friends, Presence, Parties & Custom Rooms**: Players can add friends by Callsign, Player ID, or Friend Code (`NV-XXXX`), see live online presence (`Online — In Lobby`, `In Party`, `In Queue`, `In Custom Room`, `In Match`, `Offline`), form parties (`1–5` players), share Custom Room codes (`NRVX-XXXX-XXXX`) or 1-click `?room=CODE` invite links, and launch synchronized matches across all 7 modes.

## 2. Cloud Deployment Options

### Option A: Render (`render.yaml` - Free Tier Default)
1. Push this repository to GitHub: `https://github.com/udaydomadiya08/nirvex`.
2. In the Render Dashboard ([dashboard.render.com](https://dashboard.render.com)):
   - Click **New +** -> **Blueprint**.
   - Connect your GitHub repository `udaydomadiya08/nirvex`.
   - Render automatically reads `render.yaml` and deploys the `nirvex` Web Service on the Free plan.
   - Alternatively, create a **Web Service** directly:
     - Runtime: `Node`
     - Build Command: `echo 'Zero external dependencies required'`
     - Start Command: `node server/multiplayer_server.js`
     - Health Check Path: `/healthz`
     - Plan: `Free`
3. Once deployed, Render provides your public URL (e.g., `https://nirvex.onrender.com` or `https://nirvex-xxxx.onrender.com`).
4. Share that single URL with any player. The browser loads the game over HTTPS and establishes secure WebSockets (`wss://`) automatically.

> **Free Tier vs. Persistent Disk Storage Note**:
> - The default `render.yaml` is set to `plan: free` with local ephemeral storage at `./server/data/nirvex_db.json`. While running, accounts, match stats, and rooms persist in memory and atomic file storage.
> - Note that Render Free instances spin down after 15 minutes of inactivity. When spun down, ephemeral file storage resets.
> - To enable durable disk persistence across server restarts on Render:
>   1. Upgrade service to `plan: starter` ($7/month).
>   2. Add a persistent disk in Render Dashboard or `render.yaml` (`mountPath: /var/data`, `sizeGB: 1`).
>   3. Set `NIRVEX_DB_PATH=/var/data/nirvex_db.json`.

### Option B: Fly.io (`fly.toml`)
```bash
fly volumes create nirvex_data --region bom --size 1
fly deploy
```

### Option C: Docker (`Dockerfile`)
```bash
docker build -t nirvex-multiplayer .
docker run -d -p 8787:8787 -v nirvex_data:/app/server/data --name nirvex nirvex-multiplayer
```

### Option D: Standalone Node.js (`>= 18.0.0`, Zero External Dependencies)
```bash
npm start
# Health check: curl http://127.0.0.1:8787/healthz
# Config check: curl http://127.0.0.1:8787/api/config
```

## 3. Environment Variables (`.env.example`)
| Variable | Default | Description |
|---|---|---|
| `PORT` / `NIRVEX_PORT` | `process.env.PORT` \|\| `8787` | HTTP + WebSocket listening port (Render assigns `PORT` dynamically) |
| `NIRVEX_HOST` | `0.0.0.0` | Bind interface |
| `NIRVEX_DB_PATH` | `./server/data/nirvex_db.json` | Atomic JSON persistence path (with `.bak` auto-recovery) |
| `NIRVEX_RECONNECT_GRACE_MS` | `120000` | In-match disconnect reconnect grace window (ms) |
| `NIRVEX_CORS_ORIGIN` | `*` | Allowed CORS origin header |
| `NIRVEX_MAX_BODY_BYTES` | `65536` | Maximum HTTP/WS payload size |
