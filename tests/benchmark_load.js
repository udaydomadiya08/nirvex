#!/usr/bin/env node
/**
 * NIRVEX — MULTIPLAYER SERVER CONCURRENCY & TICK PERFORMANCE LOAD BENCHMARK
 * (`tests/benchmark_load.js`)
 */
'use strict';

const { performance } = require('perf_hooks');
const path = require('path');
const fs = require('fs');
const Core = require('../server/multiplayer_core.js');
const { createNirvexServer } = require('../server/multiplayer_server.js');

async function runBenchmark() {
  console.log(`======================================================================`);
  console.log(`NIRVEX — MULTIPLAYER PERFORMANCE & LOAD BENCHMARK`);
  console.log(`======================================================================\n`);

  const mem0 = process.memoryUsage();
  console.log(`[Baseline Memory] RSS: ${(mem0.rss / 1024 / 1024).toFixed(2)} MB, Heap: ${(mem0.heapUsed / 1024 / 1024).toFixed(2)} MB`);

  const tmpDb = path.join(__dirname, 'tmp_bench_db.json');
  if (fs.existsSync(tmpDb)) fs.unlinkSync(tmpDb);

  const { hub } = createNirvexServer({ dbPath: tmpDb });

  const CONCURRENT_PLAYERS = 50;
  const NUM_MATCHES = 5;
  const TICKS = 500;

  console.log(`\nSimulating:`);
  console.log(`- ${CONCURRENT_PLAYERS} concurrent registered players`);
  console.log(`- ${NUM_MATCHES} active simultaneous 5v5 matches (10 players each)`);
  console.log(`- ${TICKS} consecutive authoritative server ticks (20Hz equivalent to 25 seconds of continuous combat)`);

  const tStartSetup = performance.now();
  const playerIds = [];
  for (let i = 1; i <= CONCURRENT_PLAYERS; i++) {
    const pid = `load_p_${i}`;
    playerIds.push(pid);
    hub.registerOrGetPlayer({ id: pid, name: `Operator_${i}` });
  }

  // Create 5 simultaneous active matches with 10 players each
  const activeMatches = [];
  for (let m = 0; m < NUM_MATCHES; m++) {
    const matchPlayers = playerIds.slice(m * 10, (m + 1) * 10);
    const roomRes = hub.createCustomRoom(matchPlayers[0], { subMode: 'tdm', scoreLimit: 40, botFill: false });
    const roomCode = roomRes.room.code;
    for (let j = 1; j < 10; j++) {
      hub.joinCustomRoom(matchPlayers[j], roomCode);
      if (j >= 5) {
        hub.switchCustomRoomTeam(matchPlayers[j], roomCode, 'defenders');
      }
      hub.setCustomRoomReady(matchPlayers[j], roomCode, true);
    }
    const startRes = hub.startCustomRoomMatch(matchPlayers[0], roomCode);
    if (!startRes.ok) {
      throw new Error(`Failed to start match ${m}: ${startRes.message}`);
    }
    activeMatches.push(startRes.match);
  }

  const setupDuration = performance.now() - tStartSetup;
  console.log(`Setup completed in ${setupDuration.toFixed(2)}ms across ${activeMatches.length} active matches.`);

  const tickDurations = [];
  let totalCombatEvents = 0;
  let totalPositionUpdates = 0;

  const tStartSim = performance.now();
  for (let tick = 0; tick < TICKS; tick++) {
    const t0 = performance.now();

    for (const match of activeMatches) {
      // 1. Tick match physics & timers
      match.tickMatch(0.05);

      // 2. Simulate movement inputs for all participants
      for (const [pid, participant] of match.participants.entries()) {
        if (!participant.alive) continue;
        const res = match.updatePlayerState(pid, {
          position: {
            x: participant.position.x + (Math.sin(tick * 0.1) * 0.2),
            y: 0,
            z: participant.position.z + (Math.cos(tick * 0.1) * 0.2)
          },
          yaw: (tick * 0.05) % (Math.PI * 2)
        });
        if (res.ok) totalPositionUpdates++;
      }

      // 3. Simulate periodic combat hits every 5 ticks
      if (tick % 5 === 0) {
        const pArray = Array.from(match.participants.values()).filter(p => p.alive);
        if (pArray.length >= 2) {
          const atk = pArray[0];
          const vic = pArray[1];
          const hitRes = match.processCombatHit({
            attackerId: atk.id,
            victimId: vic.id,
            rawDamage: 25,
            nowMs: Date.now()
          });
          if (hitRes.ok) totalCombatEvents++;
        }
      }

      // 4. Generate filtered state snapshots every 4 ticks
      if (tick % 4 === 0) {
        for (const pid of match.participants.keys()) {
          match.getFilteredStateForViewer(pid, [], null, true);
        }
      }
    }

    const tTick = performance.now() - t0;
    tickDurations.push(tTick);
  }

  const totalSimDuration = performance.now() - tStartSim;
  const memEnd = process.memoryUsage();

  tickDurations.sort((a, b) => a - b);
  const avgTickMs = tickDurations.reduce((a, b) => a + b, 0) / tickDurations.length;
  const medianTickMs = tickDurations[Math.floor(tickDurations.length * 0.5)];
  const p95TickMs = tickDurations[Math.floor(tickDurations.length * 0.95)];
  const maxTickMs = tickDurations[tickDurations.length - 1];

  console.log(`\n----------------------------------------------------------------------`);
  console.log(`BENCHMARK RESULTS:`);
  console.log(`----------------------------------------------------------------------`);
  console.log(`Simulated Matches:            ${activeMatches.length} concurrent 5v5 matches`);
  console.log(`Simulated Players:            ${CONCURRENT_PLAYERS} concurrent players`);
  console.log(`Authoritative Ticks:          ${TICKS} server ticks`);
  console.log(`Total Simulation Time:        ${totalSimDuration.toFixed(2)} ms`);
  console.log(`Average Tick Duration:        ${avgTickMs.toFixed(4)} ms (< 50ms budget for 20Hz)`);
  console.log(`Median Tick Duration:         ${medianTickMs.toFixed(4)} ms`);
  console.log(`95th Percentile Tick:         ${p95TickMs.toFixed(4)} ms`);
  console.log(`Peak Tick Duration:           ${maxTickMs.toFixed(4)} ms`);
  console.log(`Processed Position Updates:   ${totalPositionUpdates}`);
  console.log(`Processed Combat Hits:        ${totalCombatEvents}`);
  console.log(`Heap Used (End):              ${(memEnd.heapUsed / 1024 / 1024).toFixed(2)} MB`);
  console.log(`RSS Memory (End):             ${(memEnd.rss / 1024 / 1024).toFixed(2)} MB`);
  console.log(`Tick Budget Utilization:      ${((avgTickMs / 50) * 100).toFixed(2)}% of 20Hz budget (50ms)`);
  console.log(`----------------------------------------------------------------------\n`);

  if (fs.existsSync(tmpDb)) fs.unlinkSync(tmpDb);
  if (fs.existsSync(`${tmpDb}.bak`)) fs.unlinkSync(`${tmpDb}.bak`);
}

runBenchmark().catch(err => {
  console.error(err);
  process.exit(1);
});
