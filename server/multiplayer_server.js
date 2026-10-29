/**
 * NIRVEX / VELORANT — AUTHORITATIVE MULTIPLAYER HTTP + WEBSOCKET SERVER
 * (`server/multiplayer_server.js`)
 *
 * Production-grade zero-dependency Node.js server implementing:
 *   - Static client & 3D asset serving (`/`, `/nirma_strike.html`, `/assets/*`)
 *   - Health & Readiness probes (`/healthz`, `/readyz`, `/api/health`)
 *   - REST API (`/api/modes`, `/api/auth/*`, `/api/profile/*`, `/api/party/*`, `/api/queue/*`, `/api/rooms/*`, `/api/matches/*`)
 *   - Session token authentication, scrypt password hashing, actor ownership verification, rate limiting & audit logging
 *   - RFC 6455 WebSocket Server (`ws://HOST:PORT/ws`) with Protocol v2.0.0, sequence numbers,
 *     scoped per-room/per-match subscriptions, ping/pong heartbeats, and 120s reconnect grace window
 *   - Authoritative 20Hz match simulation tick loop & transactional atomic JSON persistence with backup recovery
 */
'use strict';

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const url = require('url');

const Core = require('./multiplayer_core.js');

const DEFAULT_PORT = Number(process.env.PORT || process.env.NIRVEX_PORT || 8787);
const DEFAULT_HOST = process.env.NIRVEX_HOST || '0.0.0.0';
const DEFAULT_DB_PATH = process.env.NIRVEX_DB_PATH || path.join(__dirname, 'data', 'nirvex_db.json');
const RECONNECT_GRACE_MS = Number(process.env.NIRVEX_RECONNECT_GRACE_MS || 120000);
const MAX_BODY_BYTES = Number(process.env.NIRVEX_MAX_BODY_BYTES || 65536);
const ALLOWED_ORIGIN = process.env.NIRVEX_CORS_ORIGIN || '*';

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.glb': 'model/gltf-binary',
  '.mp3': 'audio/mpeg',
  '.wav': 'audio/wav'
};

// ============================================================================
// 1. ATOMIC TRANSACTIONAL PERSISTENCE WITH BACKUP RECOVERY
// ============================================================================
function loadPersistedDb(dbPath) {
  const candidates = [dbPath, `${dbPath}.bak`];
  for (const candidate of candidates) {
    try {
      if (fs.existsSync(candidate)) {
        const raw = fs.readFileSync(candidate, 'utf8');
        const parsed = JSON.parse(raw);
        if (parsed && typeof parsed === 'object') {
          return parsed;
        }
      }
    } catch (e) {
      // If primary file is corrupted, loop automatically attempts `.bak` recovery
    }
  }
  return null;
}

function savePersistedDbAtomic(dbPath, stateObj) {
  try {
    const dir = path.dirname(dbPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    const serialized = JSON.stringify(stateObj, null, 2);
    const tmpPath = `${dbPath}.tmp.${process.pid}.${Date.now()}`;
    fs.writeFileSync(tmpPath, serialized, 'utf8');
    if (fs.existsSync(dbPath)) {
      try {
        fs.copyFileSync(dbPath, `${dbPath}.bak`);
      } catch (e) {}
    }
    fs.renameSync(tmpPath, dbPath);
    return true;
  } catch (e) {
    try {
      fs.writeFileSync(dbPath, JSON.stringify(stateObj, null, 2), 'utf8');
      return true;
    } catch (err) {
      return false;
    }
  }
}

// ============================================================================
// 2. RFC 6455 WEBSOCKET FRAME ENCODER & DECODER (TEXT, CLOSE, PING, PONG)
// ============================================================================
function encodeWsFrame(payloadObj, opcode = 0x01) {
  let data;
  if (opcode === 0x01) {
    const jsonStr = typeof payloadObj === 'string' ? payloadObj : JSON.stringify(payloadObj);
    data = Buffer.from(jsonStr, 'utf8');
  } else if (Buffer.isBuffer(payloadObj)) {
    data = payloadObj;
  } else {
    data = Buffer.alloc(0);
  }

  const len = data.length;
  let header;
  if (len < 126) {
    header = Buffer.alloc(2);
    header[0] = 0x80 | (opcode & 0x0f);
    header[1] = len;
  } else if (len < 65536) {
    header = Buffer.alloc(4);
    header[0] = 0x80 | (opcode & 0x0f);
    header[1] = 126;
    header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x80 | (opcode & 0x0f);
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(len), 2);
  }
  return Buffer.concat([header, data]);
}

function decodeWsFrames(buffer) {
  const messages = [];
  const controlFrames = [];
  let offset = 0;
  while (offset + 2 <= buffer.length) {
    const firstByte = buffer[offset];
    const secondByte = buffer[offset + 1];
    const opcode = firstByte & 0x0f;
    const isMasked = Boolean(secondByte & 0x80);
    let payloadLen = secondByte & 0x7f;
    let headerLen = 2;

    if (opcode === 0x08) {
      return { messages, controlFrames, rest: Buffer.alloc(0), closed: true };
    }

    if (payloadLen === 126) {
      if (offset + 4 > buffer.length) break;
      payloadLen = buffer.readUInt16BE(offset + 2);
      headerLen = 4;
    } else if (payloadLen === 127) {
      if (offset + 10 > buffer.length) break;
      payloadLen = Number(buffer.readBigUInt64BE(offset + 2));
      headerLen = 10;
    }

    if (payloadLen > MAX_BODY_BYTES) {
      return { messages, controlFrames, rest: Buffer.alloc(0), closed: true, error: 'WS_FRAME_TOO_LARGE' };
    }

    const maskLen = isMasked ? 4 : 0;
    if (offset + headerLen + maskLen + payloadLen > buffer.length) break;

    const payloadStart = offset + headerLen + maskLen;
    const payload = Buffer.alloc(payloadLen);
    if (isMasked) {
      const mask = buffer.slice(offset + headerLen, offset + headerLen + 4);
      for (let i = 0; i < payloadLen; i++) {
        payload[i] = buffer[payloadStart + i] ^ mask[i % 4];
      }
    } else {
      buffer.copy(payload, 0, payloadStart, payloadStart + payloadLen);
    }

    if (opcode === 0x01) {
      try {
        messages.push(JSON.parse(payload.toString('utf8')));
      } catch (e) {}
    } else if (opcode === 0x09 || opcode === 0x0a) {
      controlFrames.push({ opcode, payload });
    }
    offset = payloadStart + payloadLen;
  }
  return { messages, controlFrames, rest: buffer.slice(offset), closed: false };
}

// ============================================================================
// 3. SLIDING-WINDOW RATE LIMITER
// ============================================================================
class SlidingWindowRateLimiter {
  constructor(windowMs = 10000, maxRequests = 400) {
    this.windowMs = windowMs;
    this.maxRequests = maxRequests;
    this.buckets = new Map();
  }

  allow(key, cost = 1) {
    const now = Date.now();
    let entry = this.buckets.get(key);
    if (!entry || (now - entry.windowStart) >= this.windowMs) {
      entry = { windowStart: now, count: 0 };
      this.buckets.set(key, entry);
    }
    entry.count += cost;
    if (this.buckets.size > 5000) {
      for (const [k, v] of this.buckets.entries()) {
        if (now - v.windowStart >= this.windowMs) this.buckets.delete(k);
      }
    }
    return entry.count <= this.maxRequests;
  }
}

// ============================================================================
// 4. AUTHORITATIVE SERVER FACTORY
// ============================================================================
function createNirvexServer(options = {}) {
  const dbPath = options.dbPath || DEFAULT_DB_PATH;
  const projectRoot = options.projectRoot || path.resolve(__dirname, '..');
  const requireSessionAuth = Boolean(options.requireSessionAuth || process.env.NIRVEX_REQUIRE_AUTH === 'true');
  const initialDb = loadPersistedDb(dbPath);
  const wsClients = new Map(); // socket -> ClientMeta
  const rateLimiter = new SlidingWindowRateLimiter(
    options.rateLimitWindowMs || 10000,
    options.rateLimitMax || 500
  );

  let serverSeq = 0;
  let startedAt = Date.now();
  let lastTickDurationMs = 0;
  let totalTicks = 0;

  function sendToSocket(socket, payloadObj) {
    if (!socket || socket.destroyed) return false;
    try {
      const enriched = {
        protocolVersion: Core.PROTOCOL_VERSION,
        seq: ++serverSeq,
        timestamp: Date.now(),
        ...payloadObj
      };
      socket.write(encodeWsFrame(enriched, 0x01));
      return true;
    } catch (e) {
      return false;
    }
  }

  function broadcastScopedEvent(eventType, detail = {}) {
    const targetRoomCode = detail?.room?.code || detail?.roomCode || null;
    const targetMatchId = detail?.match?.id || detail?.matchId || detail?.results?.matchId || null;
    const targetPartyId = detail?.party?.id || detail?.partyId || null;

    for (const [socket, meta] of wsClients.entries()) {
      if (socket.destroyed) continue;
      if (meta.playerId && hub && hub.players.has(meta.playerId)) {
        const prof = hub.players.get(meta.playerId);
        if (prof.roomCode) meta.subscribedRoomCode = prof.roomCode;
        if (prof.partyId) meta.subscribedPartyId = prof.partyId;
        if (prof.activeMatchId) meta.subscribedMatchId = prof.activeMatchId;
      }
      // If event is match-specific and socket is subscribed to a DIFFERENT match, skip
      if (targetMatchId && meta.subscribedMatchId && meta.subscribedMatchId !== targetMatchId) {
        if (!['match_starting', 'custom_room_match_started', 'match_completed'].includes(eventType)) {
          continue;
        }
      }
      // If event is room-specific and socket is subscribed to a DIFFERENT room, skip
      if (targetRoomCode && meta.subscribedRoomCode && meta.subscribedRoomCode !== targetRoomCode) {
        const inRoomRoster = detail?.room?.members && detail.room.members.some(m => m.id === meta.playerId);
        if (!inRoomRoster && detail?.targetPlayerId !== meta.playerId && detail?.leftPlayerId !== meta.playerId) {
          continue;
        }
      }
      if (targetPartyId && meta.subscribedPartyId && meta.subscribedPartyId !== targetPartyId) {
        const inPartyRoster = detail?.party?.members && detail.party.members.some(m => m.id === meta.playerId);
        const isInviteTarget = detail?.invite?.targetId === meta.playerId || detail?.kickedPlayerId === meta.playerId || detail?.leftPlayerId === meta.playerId;
        if (!inPartyRoster && !isInviteTarget && !['party_invite_sent', 'party_member_kicked', 'party_dissolved'].includes(eventType)) {
          continue;
        }
      }
      sendToSocket(socket, { type: eventType, detail });
    }
  }

  const hub = new Core.NirvexAuthoritativeHub({
    reconnectGraceMs: options.reconnectGraceMs || RECONNECT_GRACE_MS,
    initialState: initialDb,
    onStateChanged: (eventType, detail) => {
      savePersistedDbAtomic(dbPath, hub.exportPersistedState());
      broadcastScopedEvent(eventType, detail);
    }
  });

  // Ensure initial DB exists on disk immediately when players are registered or initialized
  savePersistedDbAtomic(dbPath, hub.exportPersistedState());

  function extractSessionToken(req, body = {}) {
    const authHeader = req.headers['authorization'];
    if (authHeader && authHeader.startsWith('Bearer ')) {
      return authHeader.slice(7).trim();
    }
    if (req.headers['x-session-token']) {
      return String(req.headers['x-session-token']).trim();
    }
    if (body && body.sessionToken) {
      return String(body.sessionToken).trim();
    }
    return null;
  }

  function verifyRequestActor(req, res, body, actorId) {
    const token = extractSessionToken(req, body);
    const targetProfile = actorId ? hub.players.get(actorId) : null;
    const mustRequireToken = requireSessionAuth || Boolean(targetProfile && targetProfile.hasPassword);
    const check = hub.verifySessionActor(token, actorId, mustRequireToken);
    if (!check.ok) {
      sendJson(res, check.statusCode || 401, {
        ok: false,
        code: check.code,
        message: check.message
      });
      return null;
    }
    return check;
  }

  function sendJson(res, statusCode, body) {
    const payload = JSON.stringify(body);
    res.writeHead(statusCode, {
      'Content-Type': 'application/json; charset=utf-8',
      'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Session-Token',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'SAMEORIGIN'
    });
    res.end(payload);
  }

  function readJsonBody(req) {
    return new Promise((resolve, reject) => {
      let raw = '';
      let byteCount = 0;
      req.on('data', chunk => {
        byteCount += chunk.length;
        if (byteCount > MAX_BODY_BYTES) {
          req.destroy();
          reject(new Error('PAYLOAD_TOO_LARGE'));
          return;
        }
        raw += chunk.toString('utf8');
      });
      req.on('end', () => {
        if (!raw) return resolve({});
        try {
          resolve(JSON.parse(raw));
        } catch (e) {
          resolve({});
        }
      });
      req.on('error', reject);
    });
  }

  function tryServeStaticFile(reqPath, res) {
    let relPath = reqPath === '/' || reqPath === '/index.html' ? '/nirma_strike.html' : reqPath;
    const normalized = path.normalize(relPath).replace(/^(\.\.[\/\\])+/, '');
    const candidatePaths = [
      path.join(projectRoot, normalized),
      path.join(projectRoot, 'artifacts', 'file_generation', 'ttl=63d', 'output', path.basename(normalized))
    ];

    for (const fullPath of candidatePaths) {
      if (fs.existsSync(fullPath) && fs.statSync(fullPath).isFile()) {
        const ext = path.extname(fullPath).toLowerCase();
        const contentType = MIME_TYPES[ext] || 'application/octet-stream';
        res.writeHead(200, {
          'Content-Type': contentType,
          'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
          'Cache-Control': 'no-cache'
        });
        fs.createReadStream(fullPath).pipe(res);
        return true;
      }
    }
    return false;
  }

  const server = http.createServer(async (req, res) => {
    if (req.method === 'OPTIONS') {
      return sendJson(res, 200, { ok: true });
    }

    const clientIp = req.socket.remoteAddress || '127.0.0.1';
    if (!rateLimiter.allow(clientIp, 1)) {
      hub.recordAuditEvent('HTTP_RATE_LIMIT_EXCEEDED', null, { ip: clientIp, url: req.url });
      return sendJson(res, 429, { ok: false, code: 'RATE_LIMITED', message: 'Too many requests. Please slow down.' });
    }

    const parsedUrl = url.parse(req.url, true);
    const pathname = parsedUrl.pathname;

    // Health & Readiness Probes
    if (req.method === 'GET' && (pathname === '/api/health' || pathname === '/healthz' || pathname === '/readyz')) {
      return sendJson(res, 200, {
        ok: true,
        status: 'healthy',
        service: 'NIRVEX Authoritative Multiplayer Server',
        protocolVersion: Core.PROTOCOL_VERSION,
        uptimeSeconds: Math.round((Date.now() - startedAt) / 1000),
        modesCount: Object.keys(Core.MODE_CONFIG_REGISTRY).length,
        playersRegistered: hub.players.size,
        connectedSockets: wsClients.size,
        activeParties: hub.parties.size,
        activeQueues: hub.queueTickets.size,
        activeRooms: hub.customRooms.size,
        activeMatches: hub.matches.size,
        tickMetrics: {
          totalTicks,
          lastTickDurationMs: Number(lastTickDurationMs.toFixed(3))
        }
      });
    }

    // Serve Game Client (`nirma_strike.html`), Core Engine & 3D Assets
    if (req.method === 'GET' && (
      pathname === '/' ||
      pathname === '/index.html' ||
      pathname === '/nirma_strike.html' ||
      pathname === '/server/multiplayer_core.js' ||
      pathname.startsWith('/assets/')
    )) {
      if (tryServeStaticFile(pathname, res)) return;
    }

    if (req.method === 'GET' && pathname === '/api/config') {
      const hostHdr = req.headers['host'] || `127.0.0.1:${DEFAULT_PORT}`;
      const isTls = Boolean(req.headers['x-forwarded-proto'] === 'https' || req.socket.encrypted);
      const httpProto = isTls ? 'https' : 'http';
      const wsProto = isTls ? 'wss' : 'ws';
      return sendJson(res, 200, {
        ok: true,
        protocolVersion: Core.PROTOCOL_VERSION,
        httpUrl: `${httpProto}://${hostHdr}`,
        wsUrl: `${wsProto}://${hostHdr}/ws`,
        modes: Object.keys(Core.MODE_CONFIG_REGISTRY),
        features: {
          accounts: true,
          friends: true,
          presence: true,
          parties: true,
          customRooms: true,
          matchmaking: true
        }
      });
    }

    if (req.method === 'GET' && pathname === '/api/modes') {
      return sendJson(res, 200, {
        ok: true,
        protocolVersion: Core.PROTOCOL_VERSION,
        modes: Core.MODE_CONFIG_REGISTRY,
        rankTiers: Core.RANK_TIERS,
        weapons: Core.WEAPON_STATS_REGISTRY
      });
    }

    let body = {};
    if (req.method === 'POST') {
      try {
        body = await readJsonBody(req);
      } catch (err) {
        if (err && err.message === 'PAYLOAD_TOO_LARGE') {
          return sendJson(res, 413, { ok: false, code: 'PAYLOAD_TOO_LARGE', message: 'Request payload exceeds size limit.' });
        }
        return sendJson(res, 400, { ok: false, code: 'BAD_REQUEST' });
      }
    }

    // Account Registration & Login
    if (req.method === 'POST' && (pathname === '/api/profile/register' || pathname === '/api/auth/register')) {
      if (pathname === '/api/auth/register' && body.password) {
        const regRes = hub.registerAccount(body);
        if (!regRes.ok) return sendJson(res, 400, regRes);
        savePersistedDbAtomic(dbPath, hub.exportPersistedState());
        return sendJson(res, 200, regRes);
      }
      const profile = hub.registerOrGetPlayer(body);
      savePersistedDbAtomic(dbPath, hub.exportPersistedState());
      return sendJson(res, 200, { ok: true, profile, sessionToken: profile.sessionToken });
    }

    if (req.method === 'POST' && pathname === '/api/auth/login') {
      const loginRes = hub.loginAccount(body);
      if (!loginRes.ok) return sendJson(res, 401, loginRes);
      savePersistedDbAtomic(dbPath, hub.exportPersistedState());
      return sendJson(res, 200, loginRes);
    }

    if (req.method === 'POST' && pathname === '/api/auth/guest') {
      const guestId = body.id || Core.generateSecureCode('GST', 4, 2);
      const guestName = body.name || `GUEST_${guestId.slice(-4)}`;
      const profile = hub.registerOrGetPlayer({ id: guestId, name: guestName, heroId: body.heroId || 'vajra' });
      savePersistedDbAtomic(dbPath, hub.exportPersistedState());
      return sendJson(res, 200, { ok: true, profile, sessionToken: profile.sessionToken });
    }

    if (req.method === 'POST' && pathname === '/api/auth/session') {
      const token = extractSessionToken(req, body);
      const profile = hub.authenticateSession(token);
      if (!profile) return sendJson(res, 401, { ok: false, code: 'INVALID_SESSION_TOKEN', message: 'Session token invalid or expired.' });
      return sendJson(res, 200, { ok: true, profile, sessionToken: profile.sessionToken });
    }

    if (req.method === 'GET' && pathname === '/api/profile') {
      const playerId = parsedUrl.query.playerId;
      const p = hub.players.get(playerId);
      if (!p) return sendJson(res, 404, { ok: false, code: 'PLAYER_NOT_FOUND' });
      const reqToken = extractSessionToken(req, {});
      const isSelf = !reqToken || reqToken === p.sessionToken;
      const safeProfile = isSelf ? p : { ...p, sessionToken: undefined };
      return sendJson(res, 200, { ok: true, profile: safeProfile });
    }

    // Social, Friends & Presence Endpoints
    if (req.method === 'GET' && pathname === '/api/social/state') {
      const playerId = parsedUrl.query.playerId;
      if (!playerId) return sendJson(res, 400, { ok: false, code: 'MISSING_PLAYER_ID' });
      return sendJson(res, 200, hub.getSocialState(playerId));
    }

    if (req.method === 'GET' && pathname === '/api/friends/search') {
      const q = parsedUrl.query.q || '';
      const viewerId = parsedUrl.query.viewerId || null;
      return sendJson(res, 200, { ok: true, results: hub.searchPlayers(q, viewerId) });
    }

    if (req.method === 'POST' && pathname === '/api/friends/request') {
      if (!verifyRequestActor(req, res, body, body.senderId)) return;
      const resReq = hub.sendFriendRequest(body.senderId, body.targetQuery || body.targetId);
      savePersistedDbAtomic(dbPath, hub.exportPersistedState());
      return sendJson(res, resReq.ok ? 200 : 400, resReq);
    }

    if (req.method === 'POST' && pathname === '/api/friends/respond') {
      if (!verifyRequestActor(req, res, body, body.playerId)) return;
      const resResp = hub.respondFriendRequest(body.playerId, body.requestId, body.accept !== false);
      savePersistedDbAtomic(dbPath, hub.exportPersistedState());
      return sendJson(res, resResp.ok ? 200 : 400, resResp);
    }

    if (req.method === 'POST' && pathname === '/api/friends/remove') {
      if (!verifyRequestActor(req, res, body, body.playerId)) return;
      const resRem = hub.removeFriend(body.playerId, body.friendId);
      savePersistedDbAtomic(dbPath, hub.exportPersistedState());
      return sendJson(res, resRem.ok ? 200 : 400, resRem);
    }

    // Party Endpoints
    if (req.method === 'POST' && pathname === '/api/party/create') {
      if (!verifyRequestActor(req, res, body, body.leaderId)) return;
      return sendJson(res, 200, hub.createParty(body.leaderId));
    }

    if (req.method === 'POST' && pathname === '/api/party/invite') {
      if (!verifyRequestActor(req, res, body, body.inviterId)) return;
      return sendJson(res, 200, hub.inviteToParty(body.inviterId, body.targetIdOrCode));
    }

    if (req.method === 'POST' && pathname === '/api/party/respond') {
      if (!verifyRequestActor(req, res, body, body.playerId)) return;
      return sendJson(res, 200, hub.respondToPartyInvite(body.playerId, body.inviteId, body.accept !== false));
    }

    if (req.method === 'POST' && pathname === '/api/party/join-code') {
      if (!verifyRequestActor(req, res, body, body.playerId)) return;
      return sendJson(res, 200, hub.joinPartyByCode(body.playerId, body.inviteCode));
    }

    if (req.method === 'POST' && pathname === '/api/party/leave') {
      if (!verifyRequestActor(req, res, body, body.playerId)) return;
      return sendJson(res, 200, hub.leaveParty(body.playerId));
    }

    if (req.method === 'POST' && pathname === '/api/party/ready') {
      if (!verifyRequestActor(req, res, body, body.playerId)) return;
      return sendJson(res, 200, hub.setPartyMemberReady(body.playerId, body.ready));
    }

    if (req.method === 'POST' && pathname === '/api/party/kick') {
      if (!verifyRequestActor(req, res, body, body.leaderId)) return;
      const resKick = hub.kickPartyMember(body.leaderId, body.targetMemberId);
      return sendJson(res, resKick.ok ? 200 : 403, resKick);
    }

    if (req.method === 'POST' && pathname === '/api/party/promote') {
      if (!verifyRequestActor(req, res, body, body.leaderId)) return;
      const resProm = hub.promotePartyLeader(body.leaderId, body.newLeaderId);
      return sendJson(res, resProm.ok ? 200 : 403, resProm);
    }

    if (req.method === 'POST' && pathname === '/api/party/mode') {
      if (!verifyRequestActor(req, res, body, body.requesterId || body.playerId)) return;
      const resMode = hub.setPartyMode(body.requesterId || body.playerId, body.modeId);
      return sendJson(res, resMode.ok ? 200 : 403, resMode);
    }

    // Matchmaking Queue Endpoints
    if (req.method === 'POST' && pathname === '/api/queue/enter') {
      if (!verifyRequestActor(req, res, body, body.playerId)) return;
      return sendJson(res, 200, hub.enterQueue(body.playerId, body.modeId, body.options || {}));
    }

    if (req.method === 'POST' && pathname === '/api/queue/cancel') {
      if (!verifyRequestActor(req, res, body, body.playerId)) return;
      return sendJson(res, 200, hub.cancelQueue(body.playerId, body.reason));
    }

    if (req.method === 'POST' && pathname === '/api/queue/tick') {
      const match = hub.processMatchmakingTick(body.modeId, body.options || {});
      return sendJson(res, 200, { ok: true, match: match ? match.getPublicSummary() : null });
    }

    // Custom Room Endpoints
    if (req.method === 'GET' && pathname === '/api/rooms/state') {
      const roomCode = String(parsedUrl.query.roomCode || '').trim().toUpperCase();
      const room = hub.customRooms.get(roomCode);
      if (!room) return sendJson(res, 404, { ok: false, code: 'ROOM_NOT_FOUND' });
      const activeMatch = room.activeMatchId ? hub.matches.get(room.activeMatchId) : null;
      return sendJson(res, 200, {
        ok: true,
        room,
        match: activeMatch ? activeMatch.getPublicSummary() : null
      });
    }

    if (req.method === 'POST' && pathname === '/api/rooms/create') {
      if (!verifyRequestActor(req, res, body, body.hostId)) return;
      return sendJson(res, 200, hub.createCustomRoom(body.hostId, body.settings || {}));
    }

    if (req.method === 'POST' && pathname === '/api/rooms/join') {
      if (!verifyRequestActor(req, res, body, body.playerId)) return;
      return sendJson(res, 200, hub.joinCustomRoom(body.playerId, body.roomCode));
    }

    if (req.method === 'POST' && pathname === '/api/rooms/switch-team') {
      if (!verifyRequestActor(req, res, body, body.playerId)) return;
      return sendJson(res, 200, hub.switchCustomRoomTeam(body.playerId, body.roomCode, body.targetTeam));
    }

    if (req.method === 'POST' && pathname === '/api/rooms/ready') {
      if (!verifyRequestActor(req, res, body, body.playerId)) return;
      return sendJson(res, 200, hub.setCustomRoomReady(body.playerId, body.roomCode, body.ready));
    }

    if (req.method === 'POST' && pathname === '/api/rooms/settings') {
      if (!verifyRequestActor(req, res, body, body.requesterId)) return;
      const resSettings = hub.updateCustomRoomSettings(body.requesterId, body.roomCode, body.settings || {});
      return sendJson(res, resSettings.ok ? 200 : 403, resSettings);
    }

    if (req.method === 'POST' && pathname === '/api/rooms/kick') {
      if (!verifyRequestActor(req, res, body, body.requesterId)) return;
      const resKick = hub.kickFromCustomRoom(body.requesterId, body.roomCode, body.targetPlayerId);
      return sendJson(res, resKick.ok ? 200 : 403, resKick);
    }

    if (req.method === 'POST' && pathname === '/api/rooms/transfer-host') {
      if (!verifyRequestActor(req, res, body, body.requesterId)) return;
      const resTrans = hub.transferCustomRoomHost(body.requesterId, body.roomCode, body.newHostId);
      return sendJson(res, resTrans.ok ? 200 : 403, resTrans);
    }

    if (req.method === 'POST' && pathname === '/api/rooms/leave') {
      if (!verifyRequestActor(req, res, body, body.playerId)) return;
      return sendJson(res, 200, hub.leaveCustomRoom(body.playerId, body.roomCode));
    }

    if (req.method === 'POST' && pathname === '/api/rooms/start') {
      if (!verifyRequestActor(req, res, body, body.requesterId)) return;
      const resStart = hub.startCustomRoomMatch(body.requesterId, body.roomCode);
      if (!resStart.ok) return sendJson(res, 403, resStart);
      return sendJson(res, 200, { ok: true, room: resStart.room, match: resStart.match.getPublicSummary() });
    }

    // Authoritative Match State & Action Endpoints
    if (req.method === 'GET' && pathname === '/api/matches/state') {
      const matchId = parsedUrl.query.matchId;
      const viewerId = parsedUrl.query.viewerId;
      const includeAll = parsedUrl.query.includeAll === '1';
      const match = hub.matches.get(matchId);
      if (!match) return sendJson(res, 404, { ok: false, code: 'MATCH_NOT_FOUND' });
      return sendJson(res, 200, {
        ok: true,
        state: match.getFilteredStateForViewer(viewerId, [], null, includeAll),
        summary: match.getPublicSummary()
      });
    }

    if (req.method === 'POST' && pathname === '/api/matches/move') {
      if (!verifyRequestActor(req, res, body, body.playerId)) return;
      const match = hub.matches.get(body.matchId);
      if (!match) return sendJson(res, 404, { ok: false, code: 'MATCH_NOT_FOUND' });
      const moveRes = match.updatePlayerState(body.playerId, body);
      if (moveRes.ok) {
        broadcastScopedEvent('player_moved', {
          matchId: match.id,
          playerId: body.playerId,
          position: moveRes.position,
          yaw: moveRes.yaw,
          pitch: moveRes.pitch,
          weaponId: body.weaponId
        });
      }
      return sendJson(res, 200, moveRes);
    }

    if (req.method === 'POST' && pathname === '/api/matches/hit') {
      if (!verifyRequestActor(req, res, body, body.attackerId)) return;
      const match = hub.matches.get(body.matchId);
      if (!match) return sendJson(res, 404, { ok: false, code: 'MATCH_NOT_FOUND' });
      const hitRes = match.processCombatHit(body);
      if (hitRes.ok) {
        broadcastScopedEvent('combat_hit', {
          matchId: match.id,
          ...hitRes
        });
        // Auto-schedule respawn if mode has continuous respawn and victim was eliminated
        if (hitRes.eliminated && match.modeCfg.respawnEnabled && match.phase === 'LIVE') {
          const delayMs = Math.round((match.modeCfg.respawnDelay || 1.8) * 1000);
          setTimeout(() => {
            if (match.phase === 'LIVE') {
              const resp = match.respawnParticipant(body.victimId);
              if (resp.ok) {
                broadcastScopedEvent('player_respawned', {
                  matchId: match.id,
                  playerId: body.victimId,
                  spawnPoint: resp.spawnPoint,
                  spawnProtectionUntil: resp.spawnProtectionUntil
                });
              }
            }
          }, delayMs);
        }
      }
      return sendJson(res, 200, hitRes);
    }

    if (req.method === 'POST' && pathname === '/api/matches/plant') {
      if (!verifyRequestActor(req, res, body, body.playerId)) return;
      const match = hub.matches.get(body.matchId);
      if (!match) return sendJson(res, 404, { ok: false, code: 'MATCH_NOT_FOUND' });
      return sendJson(res, 200, match.plantSpike(body.playerId, body));
    }

    if (req.method === 'POST' && pathname === '/api/matches/defuse') {
      if (!verifyRequestActor(req, res, body, body.playerId)) return;
      const match = hub.matches.get(body.matchId);
      if (!match) return sendJson(res, 404, { ok: false, code: 'MATCH_NOT_FOUND' });
      return sendJson(res, 200, match.defuseSpike(body.playerId));
    }

    if (req.method === 'POST' && pathname === '/api/matches/buy') {
      if (!verifyRequestActor(req, res, body, body.playerId)) return;
      const match = hub.matches.get(body.matchId);
      if (!match) return sendJson(res, 404, { ok: false, code: 'MATCH_NOT_FOUND' });
      return sendJson(res, 200, match.buyEquipment(body.playerId, body));
    }

    if (req.method === 'POST' && pathname === '/api/matches/orb') {
      if (!verifyRequestActor(req, res, body, body.playerId)) return;
      const match = hub.matches.get(body.matchId);
      if (!match) return sendJson(res, 404, { ok: false, code: 'MATCH_NOT_FOUND' });
      const orbRes = match.pickupPowerOrb(body.playerId, body.orbId);
      if (orbRes.ok) {
        broadcastScopedEvent('orb_picked_up', { matchId: match.id, playerId: body.playerId, orbId: body.orbId, orb: orbRes.orb });
      }
      return sendJson(res, 200, orbRes);
    }

    if (req.method === 'POST' && pathname === '/api/matches/complete') {
      if (body.requesterId && !verifyRequestActor(req, res, body, body.requesterId)) return;
      const match = hub.matches.get(body.matchId);
      if (!match) return sendJson(res, 404, { ok: false, code: 'MATCH_NOT_FOUND' });
      // If requesterId is provided, verify they are a participant in this match
      if (body.requesterId && !match.participants.has(body.requesterId)) {
        hub.recordAuditEvent('FORBIDDEN_MATCH_COMPLETE', body.requesterId, { matchId: body.matchId });
        return sendJson(res, 403, { ok: false, code: 'NOT_MATCH_PARTICIPANT' });
      }
      const results = match.completeMatch(body.winner, body.reason);
      savePersistedDbAtomic(dbPath, hub.exportPersistedState());
      return sendJson(res, 200, { ok: true, results });
    }

    if (req.method === 'POST' && pathname === '/api/matches/reconnect') {
      const match = hub.matches.get(body.matchId);
      if (!match) return sendJson(res, 404, { ok: false, code: 'MATCH_NOT_FOUND' });
      return sendJson(res, 200, match.reconnectPlayer(body.playerId, body.sessionToken));
    }

    if (req.method === 'GET' && pathname === '/api/security/audit') {
      return sendJson(res, 200, { ok: true, auditLog: hub.auditLog.slice(-50) });
    }

    return sendJson(res, 404, { ok: false, code: 'ENDPOINT_NOT_FOUND', path: pathname });
  });

  // ==========================================================================
  // 5. RFC 6455 WEBSOCKET UPGRADE & REAL-TIME ACTION DISPATCHER
  // ==========================================================================
  server.on('upgrade', (req, socket) => {
    const key = req.headers['sec-websocket-key'];
    if (!key) {
      socket.destroy();
      return;
    }
    const acceptKey = crypto
      .createHash('sha1')
      .update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
      .digest('base64');

    socket.write(
      'HTTP/1.1 101 Switching Protocols\r\n' +
      'Upgrade: websocket\r\n' +
      'Connection: Upgrade\r\n' +
      `Sec-WebSocket-Accept: ${acceptKey}\r\n\r\n`
    );

    const clientMeta = {
      clientId: Core.generateSecureCode('WS', 4, 2),
      playerId: null,
      sessionToken: null,
      subscribedRoomCode: null,
      subscribedMatchId: null,
      subscribedPartyId: null,
      connectedAt: Date.now(),
      lastPongAt: Date.now()
    };
    wsClients.set(socket, clientMeta);
    let recvBuffer = Buffer.alloc(0);

    sendToSocket(socket, {
      type: 'welcome',
      clientId: clientMeta.clientId,
      protocolVersion: Core.PROTOCOL_VERSION,
      modes: Object.keys(Core.MODE_CONFIG_REGISTRY)
    });

    socket.on('data', (chunk) => {
      const ipKey = `ws_${clientMeta.clientId}`;
      if (!rateLimiter.allow(ipKey, 1)) {
        sendToSocket(socket, { type: 'error', code: 'WS_RATE_LIMITED', message: 'Rate limit exceeded.' });
        return;
      }

      recvBuffer = Buffer.concat([recvBuffer, chunk]);
      const decoded = decodeWsFrames(recvBuffer);
      recvBuffer = decoded.rest;

      if (decoded.closed) {
        handleSocketDisconnect(socket);
        socket.end();
        return;
      }

      for (const ctrl of decoded.controlFrames) {
        if (ctrl.opcode === 0x09) {
          // Ping -> reply Pong
          try { socket.write(encodeWsFrame(ctrl.payload, 0x0a)); } catch (e) {}
        } else if (ctrl.opcode === 0x0a) {
          clientMeta.lastPongAt = Date.now();
        }
      }

      for (const msg of decoded.messages) {
        clientMeta.lastPongAt = Date.now();
        handleWsMessage(socket, clientMeta, msg);
      }
    });

    socket.on('close', () => handleSocketDisconnect(socket));
    socket.on('error', () => handleSocketDisconnect(socket));
  });

  function handleSocketDisconnect(socket) {
    const meta = wsClients.get(socket);
    wsClients.delete(socket);
    if (!meta || !meta.playerId) return;

    let hasOtherSocket = false;
    for (const [, otherMeta] of wsClients.entries()) {
      if (otherMeta.playerId === meta.playerId) {
        hasOtherSocket = true;
        break;
      }
    }

    const p = hub.players.get(meta.playerId);
    if (p) {
      p.lastSeenAt = Date.now();
      if (!hasOtherSocket && !p.isPeerBot) {
        p.online = false;
        broadcastScopedEvent('presence_updated', {
          playerId: p.id,
          online: false,
          presenceStatus: hub.getDynamicPresenceStatus(p)
        });
      }
    }
    if (meta.subscribedMatchId && hub.matches.has(meta.subscribedMatchId)) {
      const match = hub.matches.get(meta.subscribedMatchId);
      match.disconnectPlayer(meta.playerId);
      broadcastScopedEvent('player_disconnected', {
        matchId: match.id,
        playerId: meta.playerId,
        reconnectGraceMs: hub.reconnectGraceMs
      });
    }
  }

  function verifyWsActor(socket, meta, msg, requestedPlayerId) {
    const token = msg.sessionToken || meta.sessionToken;
    const actorId = requestedPlayerId || meta.playerId;
    if (token) {
      const check = hub.verifySessionActor(token, actorId, false);
      if (!check.ok) {
        sendToSocket(socket, {
          type: 'error',
          reqId: msg.reqId || null,
          code: check.code,
          message: check.message
        });
        return null;
      }
      meta.playerId = check.player ? check.player.id : actorId;
      meta.sessionToken = token;
      return meta.playerId;
    }
    if (requireSessionAuth) {
      sendToSocket(socket, {
        type: 'error',
        reqId: msg.reqId || null,
        code: 'UNAUTHORIZED_WS',
        message: 'Session token required for WebSocket actions.'
      });
      return null;
    }
    return actorId;
  }

  function handleWsMessage(socket, meta, msg) {
    if (!msg || typeof msg !== 'object') return;
    const action = msg.action || msg.type;
    const reqId = msg.reqId || null;

    if (action === 'ping') {
      sendToSocket(socket, { type: 'pong', reqId, clientTimestamp: msg.timestamp || null });
      return;
    }

    if (action === 'register_player' || action === 'auth' || action === 'restore_session' || action === 'auth_guest') {
      const payload = msg.payload || msg;
      let profile = null;
      if (payload.sessionToken) {
        profile = hub.authenticateSession(payload.sessionToken);
      }
      if (!profile) {
        profile = hub.registerOrGetPlayer(payload);
      }
      profile.online = true;
      profile.lastSeenAt = Date.now();
      meta.playerId = profile.id;
      meta.sessionToken = profile.sessionToken;
      if (profile.roomCode) meta.subscribedRoomCode = profile.roomCode;
      if (profile.activeMatchId) meta.subscribedMatchId = profile.activeMatchId;
      if (profile.partyId) meta.subscribedPartyId = profile.partyId;

      savePersistedDbAtomic(dbPath, hub.exportPersistedState());
      sendToSocket(socket, {
        type: 'profile_registered',
        reqId,
        profile,
        sessionToken: profile.sessionToken,
        social: hub.getSocialState(profile.id)
      });
      broadcastScopedEvent('presence_updated', {
        playerId: profile.id,
        online: true,
        presenceStatus: hub.getDynamicPresenceStatus(profile)
      });
      return;
    }

    if (action === 'auth_signup') {
      const payload = msg.payload || msg;
      const res = hub.registerAccount(payload);
      if (res.ok && res.profile) {
        meta.playerId = res.profile.id;
        meta.sessionToken = res.sessionToken;
        if (res.profile.partyId) meta.subscribedPartyId = res.profile.partyId;
        savePersistedDbAtomic(dbPath, hub.exportPersistedState());
      }
      sendToSocket(socket, { type: 'auth_response', reqId, result: res });
      return;
    }

    if (action === 'auth_login') {
      const payload = msg.payload || msg;
      const res = hub.loginAccount(payload);
      if (res.ok && res.profile) {
        meta.playerId = res.profile.id;
        meta.sessionToken = res.sessionToken;
        if (res.profile.partyId) meta.subscribedPartyId = res.profile.partyId;
        if (res.profile.roomCode) meta.subscribedRoomCode = res.profile.roomCode;
        savePersistedDbAtomic(dbPath, hub.exportPersistedState());
      }
      sendToSocket(socket, { type: 'auth_response', reqId, result: res });
      return;
    }

    if (action === 'get_social_state') {
      const pid = msg.playerId || meta.playerId;
      if (!pid) return;
      sendToSocket(socket, { type: 'social_state', reqId, result: hub.getSocialState(pid) });
      return;
    }

    if (action === 'friend_search') {
      sendToSocket(socket, {
        type: 'friend_search_results',
        reqId,
        results: hub.searchPlayers(msg.q || '', msg.viewerId || meta.playerId)
      });
      return;
    }

    if (action === 'friend_request') {
      const actorId = verifyWsActor(socket, meta, msg, msg.senderId || msg.playerId);
      if (!actorId) return;
      const res = hub.sendFriendRequest(actorId, msg.targetQuery || msg.targetId);
      savePersistedDbAtomic(dbPath, hub.exportPersistedState());
      sendToSocket(socket, { type: 'friend_response', reqId, result: res });
      return;
    }

    if (action === 'friend_respond') {
      const actorId = verifyWsActor(socket, meta, msg, msg.playerId);
      if (!actorId) return;
      const res = hub.respondFriendRequest(actorId, msg.requestId, msg.accept !== false);
      savePersistedDbAtomic(dbPath, hub.exportPersistedState());
      sendToSocket(socket, { type: 'friend_response', reqId, result: res });
      return;
    }

    if (action === 'friend_remove') {
      const actorId = verifyWsActor(socket, meta, msg, msg.playerId);
      if (!actorId) return;
      const res = hub.removeFriend(actorId, msg.friendId);
      savePersistedDbAtomic(dbPath, hub.exportPersistedState());
      sendToSocket(socket, { type: 'friend_response', reqId, result: res });
      return;
    }

    if (action === 'party_create') {
      const actorId = verifyWsActor(socket, meta, msg, msg.leaderId || msg.playerId);
      if (!actorId) return;
      const res = hub.createParty(actorId);
      if (res.ok && res.party) meta.subscribedPartyId = res.party.id;
      sendToSocket(socket, { type: 'party_response', reqId, result: res });
      return;
    }

    if (action === 'party_invite') {
      const actorId = verifyWsActor(socket, meta, msg, msg.inviterId || msg.playerId);
      if (!actorId) return;
      const res = hub.inviteToParty(actorId, msg.targetIdOrCode);
      if (res.ok && res.party) meta.subscribedPartyId = res.party.id;
      sendToSocket(socket, { type: 'party_response', reqId, result: res });
      return;
    }

    if (action === 'party_respond') {
      const actorId = verifyWsActor(socket, meta, msg, msg.playerId);
      if (!actorId) return;
      const res = hub.respondToPartyInvite(actorId, msg.inviteId, msg.accept !== false);
      if (res.ok && res.party) meta.subscribedPartyId = res.party.id;
      sendToSocket(socket, { type: 'party_response', reqId, result: res });
      return;
    }

    if (action === 'party_join_code') {
      const actorId = verifyWsActor(socket, meta, msg, msg.playerId);
      if (!actorId) return;
      const res = hub.joinPartyByCode(actorId, msg.inviteCode);
      if (res.ok && res.party) meta.subscribedPartyId = res.party.id;
      sendToSocket(socket, { type: 'party_response', reqId, result: res });
      return;
    }

    if (action === 'party_leave') {
      const actorId = verifyWsActor(socket, meta, msg, msg.playerId);
      if (!actorId) return;
      const res = hub.leaveParty(actorId);
      const newPty = hub.createParty(actorId);
      meta.subscribedPartyId = newPty.ok && newPty.party ? newPty.party.id : null;
      sendToSocket(socket, { type: 'party_response', reqId, result: newPty.ok ? newPty : res });
      return;
    }

    if (action === 'party_ready') {
      const actorId = verifyWsActor(socket, meta, msg, msg.playerId);
      if (!actorId) return;
      const res = hub.setPartyMemberReady(actorId, msg.ready);
      sendToSocket(socket, { type: 'party_response', reqId, result: res });
      return;
    }

    if (action === 'party_kick') {
      const actorId = verifyWsActor(socket, meta, msg, msg.leaderId || msg.playerId);
      if (!actorId) return;
      const res = hub.kickPartyMember(actorId, msg.targetMemberId);
      sendToSocket(socket, { type: 'party_response', reqId, result: res });
      return;
    }

    if (action === 'party_promote') {
      const actorId = verifyWsActor(socket, meta, msg, msg.leaderId || msg.playerId);
      if (!actorId) return;
      const res = hub.promotePartyLeader(actorId, msg.newLeaderId);
      sendToSocket(socket, { type: 'party_response', reqId, result: res });
      return;
    }

    if (action === 'party_mode') {
      const actorId = verifyWsActor(socket, meta, msg, msg.requesterId || msg.playerId);
      if (!actorId) return;
      const res = hub.setPartyMode(actorId, msg.modeId);
      sendToSocket(socket, { type: 'party_response', reqId, result: res });
      return;
    }

    if (action === 'subscribe') {
      if (msg.roomCode !== undefined) meta.subscribedRoomCode = msg.roomCode ? String(msg.roomCode).toUpperCase() : null;
      if (msg.matchId !== undefined) meta.subscribedMatchId = msg.matchId || null;
      if (msg.partyId !== undefined) meta.subscribedPartyId = msg.partyId || null;
      sendToSocket(socket, {
        type: 'subscribed',
        reqId,
        roomCode: meta.subscribedRoomCode,
        matchId: meta.subscribedMatchId,
        partyId: meta.subscribedPartyId
      });
      return;
    }

    if (action === 'enter_queue') {
      const actorId = verifyWsActor(socket, meta, msg, msg.playerId);
      if (!actorId) return;
      const res = hub.enterQueue(actorId, msg.modeId, msg.options || {});
      sendToSocket(socket, { type: 'queue_response', reqId, result: res });
      return;
    }

    if (action === 'cancel_queue') {
      const actorId = verifyWsActor(socket, meta, msg, msg.playerId);
      if (!actorId) return;
      const res = hub.cancelQueue(actorId, msg.reason);
      sendToSocket(socket, { type: 'queue_cancelled_ack', reqId, result: res });
      return;
    }

    if (action === 'queue_tick') {
      const match = hub.processMatchmakingTick(msg.modeId, msg.options || {});
      if (match) {
        for (const [, cMeta] of wsClients.entries()) {
          if (cMeta.playerId && match.participants.has(cMeta.playerId)) {
            cMeta.subscribedMatchId = match.id;
          }
        }
      }
      sendToSocket(socket, {
        type: 'queue_tick_response',
        reqId,
        match: match ? match.getPublicSummary() : null
      });
      return;
    }

    if (action === 'leave_room') {
      const actorId = verifyWsActor(socket, meta, msg, msg.playerId);
      if (!actorId) return;
      const res = hub.leaveCustomRoom(actorId, msg.roomCode);
      meta.subscribedRoomCode = null;
      sendToSocket(socket, { type: 'room_response', reqId, result: res });
      return;
    }

    if (action === 'kick_from_room') {
      const actorId = verifyWsActor(socket, meta, msg, msg.requesterId || msg.playerId);
      if (!actorId) return;
      const res = hub.kickFromCustomRoom(actorId, msg.roomCode, msg.targetPlayerId);
      sendToSocket(socket, { type: 'room_response', reqId, result: res });
      return;
    }

    if (action === 'transfer_room_host') {
      const actorId = verifyWsActor(socket, meta, msg, msg.requesterId || msg.playerId);
      if (!actorId) return;
      const res = hub.transferCustomRoomHost(actorId, msg.roomCode, msg.newHostId);
      sendToSocket(socket, { type: 'room_response', reqId, result: res });
      return;
    }

    if (action === 'create_room') {
      const actorId = verifyWsActor(socket, meta, msg, msg.hostId || msg.playerId);
      if (!actorId) return;
      const res = hub.createCustomRoom(actorId, msg.settings || {});
      if (res.ok) meta.subscribedRoomCode = res.room.code;
      sendToSocket(socket, { type: 'room_response', reqId, result: res });
      return;
    }

    if (action === 'join_room') {
      const actorId = verifyWsActor(socket, meta, msg, msg.playerId);
      if (!actorId) return;
      const res = hub.joinCustomRoom(actorId, msg.roomCode);
      if (res.ok) meta.subscribedRoomCode = res.room.code;
      sendToSocket(socket, { type: 'room_response', reqId, result: res });
      return;
    }

    if (action === 'switch_room_team') {
      const actorId = verifyWsActor(socket, meta, msg, msg.playerId);
      if (!actorId) return;
      const res = hub.switchCustomRoomTeam(actorId, msg.roomCode, msg.targetTeam);
      sendToSocket(socket, { type: 'room_response', reqId, result: res });
      return;
    }

    if (action === 'room_ready') {
      const actorId = verifyWsActor(socket, meta, msg, msg.playerId);
      if (!actorId) return;
      const res = hub.setCustomRoomReady(actorId, msg.roomCode, msg.ready);
      sendToSocket(socket, { type: 'room_response', reqId, result: res });
      return;
    }

    if (action === 'update_room_settings') {
      const actorId = verifyWsActor(socket, meta, msg, msg.requesterId || msg.playerId);
      if (!actorId) return;
      const res = hub.updateCustomRoomSettings(actorId, msg.roomCode, msg.settings || {});
      sendToSocket(socket, { type: 'room_response', reqId, result: res });
      return;
    }

    if (action === 'start_room_match') {
      const actorId = verifyWsActor(socket, meta, msg, msg.requesterId || msg.playerId);
      if (!actorId) return;
      const res = hub.startCustomRoomMatch(actorId, msg.roomCode);
      if (res.ok) {
        meta.subscribedMatchId = res.match.id;
        // Subscribe all connected members of this room to the new matchId automatically
        for (const [, cMeta] of wsClients.entries()) {
          if (cMeta.subscribedRoomCode === res.room.code) {
            cMeta.subscribedMatchId = res.match.id;
          }
        }
      }
      sendToSocket(socket, {
        type: 'room_match_start_response',
        reqId,
        result: res.ok ? { ok: true, room: res.room, match: res.match.getPublicSummary() } : res
      });
      return;
    }

    if (action === 'join_match') {
      const actorId = verifyWsActor(socket, meta, msg, msg.playerId);
      if (!actorId) return;
      const match = hub.matches.get(msg.matchId);
      if (!match) {
        sendToSocket(socket, { type: 'error', reqId, code: 'MATCH_NOT_FOUND' });
        return;
      }
      meta.subscribedMatchId = match.id;
      sendToSocket(socket, {
        type: 'match_joined',
        reqId,
        match: match.getPublicSummary(),
        state: match.getFilteredStateForViewer(actorId, [], null, true)
      });
      return;
    }

    if (action === 'player_input' || action === 'player_move') {
      const actorId = verifyWsActor(socket, meta, msg, msg.playerId);
      if (!actorId) return;
      const matchId = msg.matchId || meta.subscribedMatchId;
      const match = hub.matches.get(matchId);
      if (!match) return;
      meta.subscribedMatchId = match.id;
      const moveRes = match.updatePlayerState(actorId, msg);
      if (moveRes.ok) {
        for (const [peerSock, peerMeta] of wsClients.entries()) {
          if (peerSock !== socket && peerMeta.subscribedMatchId === match.id) {
            sendToSocket(peerSock, {
              type: 'player_moved',
              matchId: match.id,
              playerId: actorId,
              position: moveRes.position,
              yaw: moveRes.yaw,
              pitch: moveRes.pitch,
              crouching: Boolean(msg.crouching),
              weaponId: msg.weaponId
            });
          }
        }
      }
      return;
    }

    if (action === 'weapon_fire') {
      const actorId = verifyWsActor(socket, meta, msg, msg.playerId);
      if (!actorId) return;
      const matchId = msg.matchId || meta.subscribedMatchId;
      const match = hub.matches.get(matchId);
      if (!match) return;
      for (const [peerSock, peerMeta] of wsClients.entries()) {
        if (peerSock !== socket && peerMeta.subscribedMatchId === match.id) {
          sendToSocket(peerSock, {
            type: 'weapon_fired',
            matchId: match.id,
            playerId: actorId,
            weaponId: msg.weaponId || 'vanguard_ar',
            origin: msg.origin || null,
            dir: msg.dir || null,
            hitPoint: msg.hitPoint || null
          });
        }
      }
      return;
    }

    if (action === 'combat_hit') {
      const actorId = verifyWsActor(socket, meta, msg, msg.attackerId || msg.playerId);
      if (!actorId) return;
      const matchId = msg.matchId || meta.subscribedMatchId;
      const match = hub.matches.get(matchId);
      if (!match) return;
      const hitRes = match.processCombatHit({
        ...msg,
        attackerId: actorId
      });
      sendToSocket(socket, { type: 'combat_hit_ack', reqId, result: hitRes });
      if (hitRes.ok && !hitRes.deduplicated) {
        broadcastScopedEvent('combat_hit', {
          matchId: match.id,
          ...hitRes
        });
        if (hitRes.eliminated && match.modeCfg.respawnEnabled && match.phase === 'LIVE') {
          const delayMs = Math.round((match.modeCfg.respawnDelay || 1.8) * 1000);
          setTimeout(() => {
            if (match.phase === 'LIVE') {
              const resp = match.respawnParticipant(msg.victimId);
              if (resp.ok) {
                broadcastScopedEvent('player_respawned', {
                  matchId: match.id,
                  playerId: msg.victimId,
                  spawnPoint: resp.spawnPoint,
                  spawnProtectionUntil: resp.spawnProtectionUntil
                });
              }
            }
          }, delayMs);
        }
      }
      return;
    }

    if (action === 'reload_weapon') {
      const actorId = verifyWsActor(socket, meta, msg, msg.playerId);
      if (!actorId) return;
      const match = hub.matches.get(msg.matchId || meta.subscribedMatchId);
      if (!match) return;
      const res = match.reloadWeapon(actorId);
      sendToSocket(socket, { type: 'reload_weapon_ack', reqId, result: res });
      return;
    }

    if (action === 'buy_equipment') {
      const actorId = verifyWsActor(socket, meta, msg, msg.playerId);
      if (!actorId) return;
      const match = hub.matches.get(msg.matchId || meta.subscribedMatchId);
      if (!match) return;
      const res = match.buyEquipment(actorId, msg);
      sendToSocket(socket, { type: 'buy_equipment_ack', reqId, result: res });
      return;
    }

    if (action === 'pickup_orb') {
      const actorId = verifyWsActor(socket, meta, msg, msg.playerId);
      if (!actorId) return;
      const match = hub.matches.get(msg.matchId || meta.subscribedMatchId);
      if (!match) return;
      const res = match.pickupPowerOrb(actorId, msg.orbId);
      sendToSocket(socket, { type: 'pickup_orb_ack', reqId, result: res });
      if (res.ok) {
        broadcastScopedEvent('orb_picked_up', { matchId: match.id, playerId: actorId, orbId: msg.orbId, orb: res.orb });
      }
      return;
    }

    if (action === 'plant_spike') {
      const actorId = verifyWsActor(socket, meta, msg, msg.playerId);
      if (!actorId) return;
      const match = hub.matches.get(msg.matchId || meta.subscribedMatchId);
      if (!match) return;
      const res = match.plantSpike(actorId, msg);
      sendToSocket(socket, { type: 'plant_spike_ack', reqId, result: res });
      return;
    }

    if (action === 'defuse_spike') {
      const actorId = verifyWsActor(socket, meta, msg, msg.playerId);
      if (!actorId) return;
      const match = hub.matches.get(msg.matchId || meta.subscribedMatchId);
      if (!match) return;
      const res = match.defuseSpike(actorId);
      sendToSocket(socket, { type: 'defuse_spike_ack', reqId, result: res });
      return;
    }

    if (action === 'reconnect_match') {
      const match = hub.matches.get(msg.matchId);
      if (!match) {
        sendToSocket(socket, { type: 'error', reqId, code: 'MATCH_NOT_FOUND' });
        return;
      }
      const res = match.reconnectPlayer(msg.playerId, msg.sessionToken || meta.sessionToken);
      if (res.ok) {
        meta.playerId = msg.playerId;
        meta.subscribedMatchId = match.id;
      }
      sendToSocket(socket, { type: 'reconnect_response', reqId, result: res });
    }
  }

  // ==========================================================================
  // 6. AUTHORITATIVE 20HZ MATCH LOOP & HEARTBEAT MONITOR
  // ==========================================================================
  const tickIntervalMs = options.tickIntervalMs || 50; // 20Hz authoritative server tick
  const tickTimer = setInterval(() => {
    const t0 = performance.now();
    const dtSec = tickIntervalMs / 1000;
    totalTicks++;

    // Every 10 ticks (500ms), process authoritative matchmaking queues on the server
    if (totalTicks % 10 === 0 && hub.queueTickets.size > 0) {
      const nowMs = Date.now();
      const modesInQueue = new Set();
      for (const t of hub.queueTickets.values()) {
        if (t.state === Core.QUEUE_STATES.SEARCHING && !t.reservedMatchId) {
          modesInQueue.add(t.modeId);
        }
      }
      for (const mId of modesInQueue) {
        // First attempt pure human match formation
        let formed = hub.processMatchmakingTick(mId, { fillWithBotsIfShort: false, rankedSimulationAllowed: true });
        if (!formed) {
          // Check if any searching ticket in this mode opted into auto-matchmaking and waited >= 1500ms
          const modeTickets = Array.from(hub.queueTickets.values()).filter(t => t.modeId === mId && t.state === Core.QUEUE_STATES.SEARCHING);
          const oldestWaitMs = modeTickets.reduce((maxW, t) => Math.max(maxW, nowMs - (t.enqueuedAt || nowMs)), 0);
          const allowAutoFill = modeTickets.some(t => t.allowPracticeFill !== false);
          if (allowAutoFill && oldestWaitMs >= (options.queueBotFillAfterMs || 1500)) {
            formed = hub.processMatchmakingTick(mId, { fillWithBotsIfShort: true, rankedSimulationAllowed: true });
          }
        }
        if (formed) {
          for (const [, cMeta] of wsClients.entries()) {
            if (cMeta.playerId && formed.participants.has(cMeta.playerId)) {
              cMeta.subscribedMatchId = formed.id;
            }
          }
        }
      }
    }

    for (const match of hub.matches.values()) {
      if (match.phase === 'MATCH_OVER' || match.finalized) continue;
      match.tickMatch(dtSec);

      // Every 4 ticks (200ms), push filtered state snapshots to sockets subscribed to this match
      if (totalTicks % 4 === 0) {
        for (const [sock, meta] of wsClients.entries()) {
          if (meta.subscribedMatchId === match.id && !sock.destroyed) {
            sendToSocket(sock, {
              type: 'match_snapshot',
              matchId: match.id,
              state: match.getFilteredStateForViewer(meta.playerId, [], null, true)
            });
          }
        }
      }
    }

    // Every 200 ticks (~10s), send WebSocket heartbeat ping & prune dead sockets
    if (totalTicks % 200 === 0) {
      const now = Date.now();
      for (const [sock, meta] of wsClients.entries()) {
        if (sock.destroyed || (now - meta.lastPongAt) > 90000) {
          handleSocketDisconnect(sock);
          try { sock.destroy(); } catch (e) {}
        } else {
          try { sock.write(encodeWsFrame(Buffer.from('nirvex_hb'), 0x09)); } catch (e) {}
        }
      }
    }

    lastTickDurationMs = performance.now() - t0;
  }, tickIntervalMs);
  if (typeof tickTimer.unref === 'function') {
    tickTimer.unref();
  }

  server.on('close', () => {
    clearInterval(tickTimer);
    savePersistedDbAtomic(dbPath, hub.exportPersistedState());
  });

  return { server, hub, wsClients, rateLimiter };
}

if (require.main === module) {
  const { server, hub, wsClients } = createNirvexServer();
  server.listen(DEFAULT_PORT, DEFAULT_HOST, () => {
    console.log(`[NIRVEX MULTIPLAYER SERVER v${Core.PROTOCOL_VERSION}] Listening on http://${DEFAULT_HOST}:${DEFAULT_PORT} (WS: ws://${DEFAULT_HOST}:${DEFAULT_PORT}/ws)`);
  });

  const shutdown = () => {
    console.log('[NIRVEX MULTIPLAYER SERVER] Graceful shutdown initiated...');
    savePersistedDbAtomic(DEFAULT_DB_PATH, hub.exportPersistedState());
    for (const [sock] of wsClients.entries()) {
      try { sock.destroy(); } catch (e) {}
    }
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 250).unref();
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

module.exports = { createNirvexServer, encodeWsFrame, decodeWsFrames, loadPersistedDb, savePersistedDbAtomic };
