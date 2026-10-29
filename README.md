# NIRVEX — YOUR CAMPUS, YOUR BATTLEFIELD

[![Node.js Version](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)](https://nodejs.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zero External Dependencies](https://img.shields.io/badge/dependencies-0-success.svg)](package.json)

**NIRVEX** is a production-grade, authoritative online multiplayer tactical FPS built for the web. Experience fast-paced campus tactical combat directly in your browser with zero client installs.

---

## 🎮 Features & Architecture

- **Authoritative 20Hz Simulation Loop**: Zero client-side authority over positions, hits, or economy. Full server-side anti-cheat and movement verification.
- **Pure Node.js Architecture**: Zero external npm dependencies. Pure standard library implementation of HTTP/1.1 and RFC 6455 WebSockets.
- **7 Complete Game Modes**:
  1. **Unrated**: Standard 5v5 bomb defusal tactical FPS with economy round buy phases (13 rounds to win).
  2. **Competitive**: Ranked 5v5 with Elo/MMR rating calculations and rank tier progression (Bronze to Radiant).
  3. **Swiftplay**: Fast-paced 5v5 bomb defusal (first to 5 rounds) with accelerated economy.
  4. **Custom**: Private room lobbies with 8-character codes (`NRVX-XXXX-XXXX`), 1-click invite links, team switching, and host controls.
  5. **Team Deathmatch (TDM)**: 5v5 continuous respawns, safe spawn point selection avoiding enemy line-of-sight, 40-kill score limit.
  6. **Spike Rush**: High-tempo 5v5 defusal, round-randomized identical loadouts for all 10 players, and power-up orbs.
  7. **Free-for-All (FFA)**: 10 solo players, no teammates, 20-kill win condition, and full 1st–10th podium rankings.
- **Social & Party Systems**:
  - Live friends list and real-time presence (`Online — In Lobby`, `In Party`, `In Queue`, `In Custom Room`, `In Match`, `Offline`).
  - 1–5 player parties with leader controls and party matchmaking.
  - Automatic party member placement on the same team during 5v5 matchmaking.
- **Security & Persistence**:
  - `crypto.scrypt` password hashing and salt generation.
  - 64-character cryptographically secure session tokens.
  - Actor ownership validation on all REST endpoints and WebSocket events (impersonation rejection).
  - Atomic transactional JSON persistence (`savePersistedDbAtomic`) with staging and `.bak` recovery.
  - Sliding-window rate limiter protecting HTTP and WebSocket connections.

---

## 🚀 Quick Start (Local)

Requires Node.js >= 18.0.0.

```bash
# Clone the repository
git clone https://github.com/udaydomadiya08/nirvex.git
cd nirvex

# Start server (zero dependencies required)
npm start

# Run tests
npm test
```

Open `http://localhost:8787` in any modern web browser to play.

---

## ☁️ Deployment

### Render (Recommended)

1. Connect your repository to Render via Blueprint (`render.yaml`).
2. Render automatically sets up the Node.js web service on the **Free** plan with health checking on `/healthz`.
3. The client connects securely via HTTPS and WSS using the same public origin.

For full deployment guides including Docker and Fly.io, refer to [DEPLOYMENT.md](DEPLOYMENT.md).

---

## 🧪 Testing

The repository includes a comprehensive 18-suite automated test matrix covering:
- Mode rules, scoring, and economy
- Party formation, invites, and queue states
- Custom room lifecycle and team switching
- Scrypt auth security and actor validation
- Multi-client RFC 6455 WebSocket end-to-end sync
- 1,000-tick performance benchmark (< 0.5ms/tick)

```bash
npm test
```

---

## 📄 License

MIT

