# NIRVEX / Velorant — Production Deployment & Operations Guide

## 1. Architecture Overview
- **Single Self-Hosted Node.js Service (`server/multiplayer_server.js`)**:
  - Serves the game client (`/` and `/nirma_strike.html`), shared multiplayer core (`/server/multiplayer_core.js`), and 3D GLB assets (`/assets/*`).
  - Exposes REST APIs (`/api/modes`, `/api/auth/*`, `/api/profile`, `/api/party/*`, `/api/queue/*`, `/api/rooms/*`, `/api/matches/*`) and Health/Readiness probes (`/healthz`, `/readyz`, `/api/health`).
  - Runs an RFC 6455 WebSocket server (`ws://HOST:PORT/ws`) speaking **Protocol v2.0.0** with sequence numbers (`seq`), server timestamps, scoped per-room/per-match pub/sub channels, ping/pong heartbeats, and a 20Hz (`50ms`) authoritative match loop.
- **Transactional Atomic Persistence**:
  - Account profiles, password hashes (`scrypt`), session tokens, competitive MMR & rank tiers, processed match IDs (idempotency guard), and security audit logs are persisted atomically to `NIRVEX_DB_PATH` (`server/data/nirvex_db.json`) via write-to-temp + atomic rename (`fs.renameSync`) with automatic `.bak` backup recovery.

## 2. Local & LAN Multi-Device Quickstart
```bash
# 1. Start the authoritative server (listens on 0.0.0.0:8787 by default)
npm start

# 2. Verify health probe
curl http://127.0.0.1:8787/healthz

# 3. Open in two different browsers or devices on the network:
#    Player A (Host):  http://<SERVER_IP>:8787/nirma_strike.html?player=PlayerA&name=AaravHost
#    Player B (Guest): http://<SERVER_IP>:8787/nirma_strike.html?player=PlayerB&name=MeeraGuest
```

## 3. Cloud Deployment (Docker / Render / Fly.io)
- **Docker**:
  ```bash
  docker build -t nirvex-multiplayer .
  docker run -d -p 8787:8787 -v nirvex_data:/app/server/data --name nirvex nirvex-multiplayer
  ```
- **Render.com**: Connect repository with `render.yaml`; Render automatically provisions the web service, mounts the persistent disk at `/var/data`, and monitors `/healthz`.
- **Fly.io**: Run `fly volumes create nirvex_data --region bom --size 1` followed by `fly deploy`.

## 4. Backup, Recovery & Rollback Procedure
- **Backup**: Copy `server/data/nirvex_db.json` and `server/data/nirvex_db.json.bak` to external storage.
- **Automatic Corruption Recovery**: On startup, `loadPersistedDb()` validates `nirvex_db.json` and automatically falls back to `nirvex_db.json.bak` if the primary file was interrupted.
- **Rollback**: Redeploy the previous container image while preserving the `/app/server/data` volume; `importPersistedState()` maintains backward compatibility across schema versions v1 and v2.
