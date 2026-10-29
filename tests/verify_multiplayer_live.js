#!/usr/bin/env node
/**
 * NIRVEX — LIVE DEPLOYMENT MULTI-PLAYER INTEGRATION & VERIFICATION RUNNER
 * (`tests/verify_multiplayer_live.js`)
 *
 * Verifies live deployment over HTTP/HTTPS and WS/WSS:
 *   1. Root Game Client HTML load (`/`)
 *   2. Health check probe (`/healthz`)
 *   3. Configuration endpoint (`/api/config`)
 *   4. Two concurrent WebSocket connections (Client A & Client B)
 *   5. Player registrations
 *   6. Client A creates Custom Room (receives code `NRVX-XXXX-XXXX`)
 *   7. Client B joins Room by code
 *   8. Team switching & ready synchronization
 *   9. Match start & synchronized matchId
 *  10. Real-time player movement synchronization
 *  11. Authoritative combat hit & damage synchronization
 *  12. Match completion and consistent results
 */
'use strict';

const http = require('http');
const https = require('https');
const net = require('net');
const tls = require('tls');
const crypto = require('crypto');
const url = require('url');

const targetUrlStr = process.argv[2] || process.env.TEST_TARGET_URL || 'http://127.0.0.1:8787';
const parsedTarget = new url.URL(targetUrlStr);
const isSecure = parsedTarget.protocol === 'https:';
const defaultPort = isSecure ? 443 : 80;
const targetPort = parsedTarget.port ? Number(parsedTarget.port) : defaultPort;
const targetHost = parsedTarget.hostname;

console.log(`======================================================================`);
console.log(`NIRVEX — LIVE MULTIPLAYER VERIFICATION`);
console.log(`Target: ${parsedTarget.origin} (${isSecure ? 'TLS/WSS' : 'Plain/WS'})`);
console.log(`======================================================================\n`);

function requestHttp(method, reqPath, body = null) {
  const lib = isSecure ? https : http;
  return new Promise((resolve, reject) => {
    const payload = body ? (typeof body === 'string' ? body : JSON.stringify(body)) : null;
    const req = lib.request({
      protocol: parsedTarget.protocol,
      hostname: targetHost,
      port: targetPort,
      method,
      path: reqPath,
      headers: {
        'Host': parsedTarget.host,
        ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {})
      }
    }, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try {
          resolve({ statusCode: res.statusCode, headers: res.headers, body: JSON.parse(data) });
        } catch (e) {
          resolve({ statusCode: res.statusCode, headers: res.headers, body: data });
        }
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function encodeClientWsFrame(obj) {
  const payload = Buffer.from(JSON.stringify(obj), 'utf8');
  const mask = crypto.randomBytes(4);
  const len = payload.length;
  let header;
  if (len < 126) {
    header = Buffer.alloc(2);
    header[0] = 0x81;
    header[1] = 0x80 | len;
  } else {
    header = Buffer.alloc(4);
    header[0] = 0x81;
    header[1] = 0x80 | 126;
    header.writeUInt16BE(len, 2);
  }
  const masked = Buffer.alloc(len);
  for (let i = 0; i < len; i++) {
    masked[i] = payload[i] ^ mask[i % 4];
  }
  return Buffer.concat([header, mask, masked]);
}

function decodeServerFrames(buffer) {
  const messages = [];
  let offset = 0;
  while (offset + 2 <= buffer.length) {
    const firstByte = buffer[offset];
    const secondByte = buffer[offset + 1];
    const opcode = firstByte & 0x0f;
    let payloadLen = secondByte & 0x7f;
    let headerLen = 2;
    if (payloadLen === 126) {
      if (offset + 4 > buffer.length) break;
      payloadLen = buffer.readUInt16BE(offset + 2);
      headerLen = 4;
    } else if (payloadLen === 127) {
      if (offset + 10 > buffer.length) break;
      payloadLen = Number(buffer.readBigUInt64BE(offset + 2));
      headerLen = 10;
    }
    if (offset + headerLen + payloadLen > buffer.length) break;
    const payload = buffer.slice(offset + headerLen, offset + headerLen + payloadLen);
    if (opcode === 0x01) {
      try {
        messages.push(JSON.parse(payload.toString('utf8')));
      } catch (e) {}
    }
    offset += headerLen + payloadLen;
  }
  return { messages, rest: buffer.slice(offset) };
}

function createLiveWsClient() {
  return new Promise((resolve, reject) => {
    const key = crypto.randomBytes(16).toString('base64');
    const connectFn = isSecure ? tls.connect : net.connect;
    const socket = connectFn({ host: targetHost, port: targetPort, servername: isSecure ? targetHost : undefined }, () => {
      socket.write(
        'GET /ws HTTP/1.1\r\n' +
        `Host: ${parsedTarget.host}\r\n` +
        'Upgrade: websocket\r\n' +
        'Connection: Upgrade\r\n' +
        `Sec-WebSocket-Key: ${key}\r\n` +
        'Sec-WebSocket-Version: 13\r\n\r\n'
      );
    });

    let upgraded = false;
    let recvBuf = Buffer.alloc(0);
    const receivedMessages = [];
    const waiters = [];

    function pushMessage(msg) {
      receivedMessages.push(msg);
      for (let i = waiters.length - 1; i >= 0; i--) {
        if (waiters[i].predicate(msg)) {
          const w = waiters.splice(i, 1)[0];
          clearTimeout(w.timer);
          w.resolve(msg);
        }
      }
    }

    socket.on('data', (chunk) => {
      recvBuf = Buffer.concat([recvBuf, chunk]);
      if (!upgraded) {
        const idx = recvBuf.indexOf('\r\n\r\n');
        if (idx !== -1) {
          upgraded = true;
          recvBuf = recvBuf.slice(idx + 4);
          resolve({
            send(obj) {
              if (!socket.destroyed) socket.write(encodeClientWsFrame(obj));
            },
            waitFor(predicate, timeoutMs = 8000) {
              const existing = receivedMessages.find(predicate);
              if (existing) return Promise.resolve(existing);
              return new Promise((res, rej) => {
                const timer = setTimeout(() => rej(new Error(`Timeout waiting for WS message (${timeoutMs}ms)`)), timeoutMs);
                waiters.push({ predicate, resolve: res, timer });
              });
            },
            close() {
              try { socket.end(); } catch (e) {}
            }
          });
        }
      }
      if (upgraded && recvBuf.length > 0) {
        const decoded = decodeServerFrames(recvBuf);
        recvBuf = decoded.rest;
        for (const msg of decoded.messages) {
          pushMessage(msg);
        }
      }
    });

    socket.on('error', reject);
    setTimeout(() => {
      if (!upgraded) reject(new Error('WebSocket connection timed out'));
    }, 8000);
  });
}

async function runLiveVerification() {
  const steps = [];

  async function step(name, fn) {
    try {
      await fn();
      console.log(`  [OK] ${name}`);
      steps.push({ name, passed: true });
    } catch (err) {
      console.error(`  [FAILED] ${name}: ${err.message}`);
      steps.push({ name, passed: false, error: err.message });
      throw err;
    }
  }

  try {
    // 1. Health check probe
    await step('1. Health check endpoint responds healthy (GET /healthz)', async () => {
      const res = await requestHttp('GET', '/healthz');
      if (res.statusCode !== 200 || !res.body || res.body.status !== 'healthy') {
        throw new Error(`Expected status: healthy, got: ${JSON.stringify(res.body)}`);
      }
      console.log(`       Uptime: ${res.body.uptimeSeconds}s, Registered: ${res.body.playersRegistered}, Modes: ${res.body.modesCount}`);
    });

    // 2. Client HTML serving
    await step('2. Game client HTML served correctly (GET /)', async () => {
      const res = await requestHttp('GET', '/');
      if (res.statusCode !== 200 || typeof res.body !== 'string' || !res.body.includes('NIRVEX')) {
        throw new Error(`Expected HTML containing 'NIRVEX', got status ${res.statusCode}`);
      }
    });

    // 3. API Config
    await step('3. Backend configuration endpoint returns endpoints & modes (GET /api/config)', async () => {
      const res = await requestHttp('GET', '/api/config');
      if (res.statusCode !== 200 || !res.body.ok || !Array.isArray(res.body.modes)) {
        throw new Error(`Expected ok: true with modes array, got ${JSON.stringify(res.body)}`);
      }
      const requiredModes = ['unrated', 'competitive', 'swiftplay', 'custom', 'tdm', 'spikerush', 'ffa'];
      for (const m of requiredModes) {
        if (!res.body.modes.includes(m)) {
          throw new Error(`Required mode "${m}" missing from modes: ${res.body.modes.join(', ')}`);
        }
      }
      console.log(`       Verified modes (${res.body.modes.length}): ${res.body.modes.join(', ')}`);
    });

    // 4. Two concurrent WebSocket connections
    let clientA, clientB;
    await step('4. Establish 2 concurrent WebSocket connections (Client A & B)', async () => {
      clientA = await createLiveWsClient();
      clientB = await createLiveWsClient();
      const welcomeA = await clientA.waitFor(m => m.type === 'welcome');
      const welcomeB = await clientB.waitFor(m => m.type === 'welcome');
      if (!welcomeA.clientId || !welcomeB.clientId) {
        throw new Error('Did not receive valid clientIds in welcome frame');
      }
    });

    // 5. Account Registration
    let regA, regB;
    await step('5. Register Player A & Player B over WebSocket', async () => {
      const idA = `live_player_a_${Date.now().toString().slice(-4)}`;
      const idB = `live_player_b_${Date.now().toString().slice(-4)}`;
      clientA.send({ action: 'register_player', payload: { id: idA, name: 'VajraAlpha' } });
      clientB.send({ action: 'register_player', payload: { id: idB, name: 'KavachBravo' } });
      regA = await clientA.waitFor(m => m.type === 'profile_registered');
      regB = await clientB.waitFor(m => m.type === 'profile_registered');
      if (!regA.sessionToken || !regB.sessionToken) {
        throw new Error('Session tokens missing from registration response');
      }
    });

    // 6. Client A creates Custom Room
    let roomCode;
    await step('6. Player A creates Custom Room and receives room code', async () => {
      clientA.send({
        action: 'create_room',
        hostId: regA.profile.id,
        sessionToken: regA.sessionToken,
        settings: { subMode: 'tdm', scoreLimit: 10, botFill: false }
      });
      const res = await clientA.waitFor(m => m.type === 'room_response' && m.result && m.result.ok);
      roomCode = res.result.room.code;
      if (!/^NRVX-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(roomCode)) {
        throw new Error(`Invalid room code generated: ${roomCode}`);
      }
      console.log(`       Created Room Code: ${roomCode}`);
    });

    // 7. Client B joins Custom Room
    await step('7. Player B joins Room using code and both see updated roster', async () => {
      clientB.send({
        action: 'join_room',
        playerId: regB.profile.id,
        sessionToken: regB.sessionToken,
        roomCode
      });
      const joinAckB = await clientB.waitFor(m => m.type === 'room_response' && m.result && m.result.ok);
      const joinBroadcastA = await clientA.waitFor(m => m.type === 'custom_room_joined');
      if (joinAckB.result.room.members.length !== 2 || joinBroadcastA.detail.room.members.length !== 2) {
        throw new Error('Both clients must observe exactly 2 room members');
      }
    });

    // 8. Player B switches team and toggles ready
    await step('8. Player B switches team to Defenders & toggles Ready', async () => {
      clientB.send({
        action: 'switch_room_team',
        playerId: regB.profile.id,
        sessionToken: regB.sessionToken,
        roomCode,
        targetTeam: 'defenders'
      });
      await clientA.waitFor(m => m.type === 'custom_room_team_switched');
      clientB.send({
        action: 'room_ready',
        playerId: regB.profile.id,
        sessionToken: regB.sessionToken,
        roomCode,
        ready: true
      });
      await clientA.waitFor(m => m.type === 'custom_room_ready_changed');
    });

    // 9. Host starts match
    let matchId;
    await step('9. Host starts match -> both players transition into the SAME matchId', async () => {
      clientA.send({
        action: 'start_room_match',
        requesterId: regA.profile.id,
        sessionToken: regA.sessionToken,
        roomCode
      });
      const startA = await clientA.waitFor(m => m.type === 'custom_room_match_started');
      const startB = await clientB.waitFor(m => m.type === 'custom_room_match_started');
      if (startA.detail.match.id !== startB.detail.match.id) {
        throw new Error(`Match IDs mismatch! Client A: ${startA.detail.match.id}, Client B: ${startB.detail.match.id}`);
      }
      matchId = startA.detail.match.id;
      console.log(`       Active Match ID: ${matchId}`);
    });

    // 10. Movement synchronization
    await step('10. Player A sends movement -> Player B receives position update', async () => {
      clientA.send({
        action: 'player_input',
        matchId,
        playerId: regA.profile.id,
        sessionToken: regA.sessionToken,
        position: { x: -45.0, y: 0.0, z: 85.0 },
        yaw: 1.57
      });
      const moved = await clientB.waitFor(m => m.type === 'player_moved' && m.playerId === regA.profile.id);
      if (!moved || !moved.position || !Number.isFinite(moved.position.x) || !Number.isFinite(moved.position.z)) {
        throw new Error(`Invalid position received: ${JSON.stringify(moved)}`);
      }
      console.log(`       Player B received position: x=${moved.position.x.toFixed(2)}, z=${moved.position.z.toFixed(2)}`);
    });

    // 11. Authoritative combat hit
    await step('11. Player A deals combat damage -> Player B receives damage update', async () => {
      clientA.send({
        action: 'combat_hit',
        matchId,
        attackerId: regA.profile.id,
        victimId: regB.profile.id,
        sessionToken: regA.sessionToken,
        rawDamage: 60,
        isHeadshot: false
      });
      const hit = await clientB.waitFor(m => m.type === 'combat_hit' && m.detail && m.detail.victimId === regB.profile.id);
      if (hit.detail.victimHealth >= 100) {
        throw new Error(`Expected health reduction below 100, got: ${hit.detail.victimHealth}`);
      }
    });

    // 12. Complete match and verify identical results
    await step('12. Complete match and verify both clients receive identical results', async () => {
      await requestHttp('POST', '/api/matches/complete', {
        matchId,
        requesterId: regA.profile.id,
        sessionToken: regA.sessionToken,
        winner: 'attackers',
        reason: 'VERIFICATION_SUCCESS'
      });
      const doneA = await clientA.waitFor(m => m.type === 'match_completed');
      const doneB = await clientB.waitFor(m => m.type === 'match_completed');
      if (doneA.detail.results.matchId !== doneB.detail.results.matchId || doneA.detail.results.winner !== 'attackers') {
        throw new Error('Final match results did not match across clients');
      }
    });

    if (clientA) clientA.close();
    if (clientB) clientB.close();

    console.log(`\n======================================================================`);
    console.log(`VERIFICATION SUMMARY: ALL 12 LIVE MULTIPLAYER PHASES PASSED!`);
    console.log(`======================================================================`);
    process.exit(0);
  } catch (err) {
    console.error(`\nVERIFICATION FAILED: ${err.message}`);
    process.exit(1);
  }
}

runLiveVerification();
