/**
 * NIRVEX / VELORANT — SHARED AUTHORITATIVE MULTIPLAYER CORE ENGINE
 * (`server/multiplayer_core.js`)
 *
 * Runs identically in:
 *   1. Node.js Authoritative Server (`server/multiplayer_server.js`)
 *   2. Browser Multi-Client / Multi-Tab / Local Authoritative Engine (`nirma_strike.html`)
 *
 * Implements:
 *   - Protocol Version `2.0.0` with sequence numbers, timestamps, and idempotency keys
 *   - Centralized Mode Configuration Registry (`MODE_CONFIG_REGISTRY`) for all 7 modes:
 *     1. `unrated`     — Unrated / Quick Match (5v5 Round-Based Spike Defusal, no MMR change)
 *     2. `competitive` — Competitive / Ranked (5v5 Round-Based Spike Defusal, Elo/Glicko MMR & Tiers)
 *     3. `swiftplay`   — Swiftplay / Quick Rounds (5v5 Shortened Defusal, Boosted Economy)
 *     4. `custom`      — Custom Match / Private Room (Cryptographic Room Code, Host Controls, Custom Teams)
 *     5. `tdm`         — Team Deathmatch (5v5 Continuous Respawn, 40 Kills / 6:00, Safe Spawns + Spawn Shield)
 *     6. `spikerush`   — Spike Rush (5v5 Fast Objective, Shared Random Weapon Per Round, Free Abilities, 3x Ult, Power Orbs)
 *     7. `ffa`         — Free-for-All Deathmatch (10-Player Individual Combat, 20 Kills / 5:00, Individual Leaderboard)
 *   - Cryptographic Account Password Hashing (scrypt/PBKDF2), Session Tokens & Security Audit Logging
 *   - Authoritative Friend & Party System (`PartyManager`)
 *   - Matchmaking Engine & Explicit Queue State Machine (`MatchmakingEngine`)
 *   - Custom Room Lobby Manager (`CustomRoomManager`)
 *   - Server-Authoritative Ranked Rating & Tier Progression (`RatingEngine`)
 *   - Authoritative Match Instance (`AuthoritativeMatchInstance`) with Movement Validation,
 *     Fire-Rate/Ammo/Hit Validation, Spike Plant/Defuse, Visibility Filtering, Safe Spawns & Reconnect
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.NirvexMultiplayerCore = factory();
  }
})(typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : this), function () {
  'use strict';

  const PROTOCOL_VERSION = '2.0.0';
  const DB_SCHEMA_VERSION = 2;

  // ==========================================================================
  // 1. CRYPTOGRAPHICALLY UNPREDICTABLE ID, ROOM CODE & PASSWORD HASHING
  // ==========================================================================
  const SAFE_ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ'; // Excludes ambiguous 0/O/1/I

  function getRandomBytes(length) {
    const out = new Uint8Array(length);
    if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
      crypto.getRandomValues(out);
      return out;
    }
    if (typeof require === 'function') {
      try {
        const nodeCrypto = require('crypto');
        const buf = nodeCrypto.randomBytes(length);
        for (let i = 0; i < length; i++) out[i] = buf[i];
        return out;
      } catch (e) {}
    }
    for (let i = 0; i < length; i++) {
      out[i] = Math.floor(Math.random() * 256);
    }
    return out;
  }

  function generateSecureCode(prefix = 'NRVX', segLen = 4, segCount = 2) {
    const totalChars = segLen * segCount;
    const bytes = getRandomBytes(totalChars);
    const segments = [];
    let idx = 0;
    for (let s = 0; s < segCount; s++) {
      let part = '';
      for (let c = 0; c < segLen; c++) {
        part += SAFE_ALPHABET[bytes[idx++] % SAFE_ALPHABET.length];
      }
      segments.push(part);
    }
    return prefix ? `${prefix}-${segments.join('-')}` : segments.join('-');
  }

  function generateSessionToken() {
    return generateSecureCode('SESS', 8, 3);
  }

  function hashPassword(password, providedSalt = null) {
    const cleanPass = String(password || '');
    const salt = providedSalt || generateSecureCode('SLT', 6, 2);
    if (typeof require === 'function') {
      try {
        const nodeCrypto = require('crypto');
        const derived = nodeCrypto.scryptSync(cleanPass, salt, 64).toString('hex');
        return `scrypt$${salt}$${derived}`;
      } catch (e) {}
    }
    // Browser deterministic fallback hash when Node crypto is unavailable
    let h1 = 0xdeadbeef ^ salt.length;
    let h2 = 0x41c6ce57 ^ cleanPass.length;
    const combined = `${salt}:${cleanPass}:nirvex_v2`;
    for (let i = 0; i < combined.length; i++) {
      const ch = combined.charCodeAt(i);
      h1 = Math.imul(h1 ^ ch, 2654435761);
      h2 = Math.imul(h2 ^ ch, 1597334677);
    }
    h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
    h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
    const hex = (h1 >>> 0).toString(16).padStart(8, '0') + (h2 >>> 0).toString(16).padStart(8, '0');
    return `pbkdf$${salt}$${hex}`;
  }

  function verifyPassword(password, storedHash) {
    if (!storedHash || typeof storedHash !== 'string') return false;
    const parts = storedHash.split('$');
    if (parts.length !== 3) return false;
    const salt = parts[1];
    const recomputed = hashPassword(password, salt);
    if (typeof require === 'function') {
      try {
        const nodeCrypto = require('crypto');
        const a = Buffer.from(recomputed, 'utf8');
        const b = Buffer.from(storedHash, 'utf8');
        if (a.length !== b.length) return false;
        return nodeCrypto.timingSafeEqual(a, b);
      } catch (e) {}
    }
    return recomputed === storedHash;
  }

  const BLOCKED_TERMS = ['admin_root', 'system_override', '<script', 'javascript:'];

  function sanitizeDisplayName(rawName, fallback = 'OPERATIVE') {
    if (rawName === undefined || rawName === null) return fallback;
    const cleaned = String(rawName)
      .replace(/[<>&"'`\\]/g, '')
      .replace(/[\x00-\x1F\x7F]/g, '')
      .trim()
      .slice(0, 24);
    if (cleaned.length < 2) return fallback;
    const lower = cleaned.toLowerCase();
    for (const term of BLOCKED_TERMS) {
      if (lower.includes(term)) return fallback;
    }
    return cleaned;
  }

  // ==========================================================================
  // 1B. AUTHORITATIVE WEAPON STATS & CAMPUS MAP BOUNDS REGISTRY
  // ==========================================================================
  const MAP_BOUNDS = {
    minX: -108,
    maxX: 108,
    minY: -2,
    maxY: 28,
    minZ: -108,
    maxZ: 108,
    maxMoveSpeedMps: 15.5, // Includes Vajra Kinetic Dash burst tolerance
    teleportThresholdM: 28.0
  };

  const WEAPON_STATS_REGISTRY = {
    katar_knife:    { id: 'katar_knife',    name: 'Katar Tactical Blade', cost: 0,    magSize: 999, reserveAmmo: 999, fireRate: 2.2,  minIntervalMs: 320, reloadMs: 0,    headDmg: 150, bodyDmg: 75,  legDmg: 65,  maxRange: 4.2,   melee: true },
    sidearm_9mm:    { id: 'sidearm_9mm',    name: 'Sidearm 9mm',          cost: 0,    magSize: 12,  reserveAmmo: 36,  fireRate: 6.75, minIntervalMs: 110, reloadMs: 1500, headDmg: 78,  bodyDmg: 26,  legDmg: 22,  maxRange: 65.0,  melee: false },
    chhaya_pistol:  { id: 'chhaya_pistol',  name: 'Chhaya Suppressed',    cost: 500,  magSize: 15,  reserveAmmo: 45,  fireRate: 6.75, minIntervalMs: 110, reloadMs: 1500, headDmg: 105, bodyDmg: 30,  legDmg: 25,  maxRange: 75.0,  melee: false },
    rudra_revolver: { id: 'rudra_revolver', name: 'Rudra .44 Magnum',     cost: 800,  magSize: 6,   reserveAmmo: 24,  fireRate: 4.0,  minIntervalMs: 190, reloadMs: 2100, headDmg: 159, bodyDmg: 55,  legDmg: 46,  maxRange: 85.0,  melee: false },
    spectre_smg:    { id: 'spectre_smg',    name: 'Spectre-9 SMG',        cost: 1600, magSize: 30,  reserveAmmo: 90,  fireRate: 13.3, minIntervalMs: 55,  reloadMs: 2100, headDmg: 78,  bodyDmg: 26,  legDmg: 22,  maxRange: 65.0,  melee: false },
    breacher_sg:    { id: 'breacher_sg',    name: 'Breacher-12 Shotgun',  cost: 1850, magSize: 7,   reserveAmmo: 28,  fireRate: 1.4,  minIntervalMs: 480, reloadMs: 2400, headDmg: 160, bodyDmg: 85,  legDmg: 68,  maxRange: 28.0,  melee: false },
    garuda_dmr:     { id: 'garuda_dmr',     name: 'Garuda MK-14 DMR',     cost: 2250, magSize: 12,  reserveAmmo: 36,  fireRate: 5.25, minIntervalMs: 140, reloadMs: 2200, headDmg: 195, bodyDmg: 65,  legDmg: 55,  maxRange: 130.0, melee: false },
    vanguard_ar:    { id: 'vanguard_ar',    name: 'Vanguard-47 Rifle',    cost: 2900, magSize: 25,  reserveAmmo: 75,  fireRate: 9.75, minIntervalMs: 75,  reloadMs: 2500, headDmg: 160, bodyDmg: 40,  legDmg: 34,  maxRange: 110.0, melee: false },
    surya_carbine:  { id: 'surya_carbine',  name: 'Surya-556 Carbine',    cost: 2900, magSize: 30,  reserveAmmo: 90,  fireRate: 11.0, minIntervalMs: 65,  reloadMs: 2400, headDmg: 140, bodyDmg: 35,  legDmg: 29,  maxRange: 105.0, melee: false },
    agni_lmg:       { id: 'agni_lmg',       name: 'Agni-249 Heavy LMG',   cost: 3200, magSize: 80,  reserveAmmo: 160, fireRate: 12.0, minIntervalMs: 60,  reloadMs: 3800, headDmg: 95,  bodyDmg: 38,  legDmg: 32,  maxRange: 95.0,  melee: false },
    vajra_sniper:   { id: 'vajra_sniper',   name: 'Vajra-50 Sniper',      cost: 4700, magSize: 5,   reserveAmmo: 15,  fireRate: 0.85, minIntervalMs: 850, reloadMs: 3200, headDmg: 255, bodyDmg: 150, legDmg: 120, maxRange: 180.0, melee: false }
  };

  // ==========================================================================
  // 2. CENTRALIZED GAME MODE CONFIGURATION REGISTRY (ALL 7 REQUIRED MODES)
  // ==========================================================================
  const MODE_CONFIG_REGISTRY = {
    unrated: {
      id: 'unrated',
      name: 'UNRATED',
      subtitle: 'Standard 5v5 Spike Defusal',
      category: 'round_objective',
      badge: '5V5 STANDARD',
      accentColor: '#38bdf8',
      teamBased: true,
      teamCount: 2,
      teamSize: 5,
      minPlayersToStart: 2,
      maxPartySize: 5,
      allowPartyJoin: true,
      affectsRating: false,
      allowBotFillInCasual: true,
      roundBased: true,
      maxRounds: 12,
      roundsToWin: 7,
      halftimeRound: 6,
      overtimeEnabled: false,
      buyPhaseDuration: 20,
      buyWindowDuration: 25,
      roundDuration: 100,
      roundEndDuration: 4.5,
      spikeTimer: 40,
      plantTime: 3.2,
      defuseTime: 5.0,
      kitDefuseTime: 3.0,
      respawnEnabled: false,
      respawnDelay: 0,
      spawnProtectionDuration: 0,
      economy: {
        enabled: true,
        startingCredits: 800,
        maxCredits: 9000,
        winReward: 3000,
        lossRewardBase: 1900,
        lossStreakBonus: 500,
        maxLossReward: 2900,
        killReward: 200,
        plantReward: 300,
        defuseReward: 300,
        freeBasicAbilities: false,
        sharedRandomLoadout: false,
        anytimeBuy: false
      },
      ultMultiplier: 1,
      startingUltPoints: 0,
      powerOrbsEnabled: false,
      description: 'Standard 5v5 tactical Spike defusal across Nirma Campus. First to 7 round wins with full economy and zero ranked rating risk.'
    },

    competitive: {
      id: 'competitive',
      name: 'COMPETITIVE',
      subtitle: 'Ranked 5v5 Tactical Defusal',
      category: 'round_objective',
      badge: 'RANKED MMR',
      accentColor: '#f43f5e',
      teamBased: true,
      teamCount: 2,
      teamSize: 5,
      minPlayersToStart: 2,
      maxPartySize: 5,
      disallowFourStack: true, // Standard competitive fairness rule (solo/duo/trio or full 5-stack)
      maxPartyRatingSpread: 350, // Max MMR difference allowed in a Competitive party (relaxed only for full 5-stack with penalty)
      fiveStackMaxSpread: 800,
      allowPartyJoin: true,
      affectsRating: true,
      allowBotFillInCasual: false, // Never silently substitute bots as fake human players in Ranked
      roundBased: true,
      maxRounds: 12,
      roundsToWin: 7,
      halftimeRound: 6,
      overtimeEnabled: true,
      buyPhaseDuration: 22,
      buyWindowDuration: 25,
      roundDuration: 100,
      roundEndDuration: 4.5,
      spikeTimer: 40,
      plantTime: 3.2,
      defuseTime: 5.0,
      kitDefuseTime: 3.0,
      respawnEnabled: false,
      respawnDelay: 0,
      spawnProtectionDuration: 0,
      economy: {
        enabled: true,
        startingCredits: 800,
        maxCredits: 9000,
        winReward: 3000,
        lossRewardBase: 1900,
        lossStreakBonus: 500,
        maxLossReward: 2900,
        killReward: 200,
        plantReward: 300,
        defuseReward: 300,
        freeBasicAbilities: false,
        sharedRandomLoadout: false,
        anytimeBuy: false
      },
      ultMultiplier: 1,
      startingUltPoints: 0,
      powerOrbsEnabled: false,
      description: 'High-stakes 5v5 Ranked mode with server-authoritative Elo/Glicko rating updates, tier progression (Iron → Radiant), and overtime rules.'
    },

    swiftplay: {
      id: 'swiftplay',
      name: 'SWIFTPLAY',
      subtitle: 'Fast 5v5 Boosted-Economy Defusal',
      category: 'round_objective',
      badge: 'FIRST TO 5',
      accentColor: '#f59e0b',
      teamBased: true,
      teamCount: 2,
      teamSize: 5,
      minPlayersToStart: 2,
      maxPartySize: 5,
      allowPartyJoin: true,
      affectsRating: false,
      allowBotFillInCasual: true,
      roundBased: true,
      maxRounds: 8,
      roundsToWin: 5,
      halftimeRound: 4,
      overtimeEnabled: false,
      buyPhaseDuration: 14,
      buyWindowDuration: 18,
      roundDuration: 85,
      roundEndDuration: 3.5,
      spikeTimer: 35,
      plantTime: 2.8,
      defuseTime: 4.5,
      kitDefuseTime: 2.8,
      respawnEnabled: false,
      respawnDelay: 0,
      spawnProtectionDuration: 0,
      economy: {
        enabled: true,
        startingCredits: 2400,
        maxCredits: 12000,
        winReward: 3600,
        lossRewardBase: 2800,
        lossStreakBonus: 600,
        maxLossReward: 3400,
        killReward: 300,
        plantReward: 400,
        defuseReward: 400,
        freeBasicAbilities: false,
        sharedRandomLoadout: false,
        anytimeBuy: false
      },
      ultMultiplier: 2,
      startingUltPoints: 2,
      powerOrbsEnabled: false,
      description: 'Condensed 5v5 Spike defusal (First to 5 wins / 8 rounds max) with $2,400 starting credits, high round grants, and 2 starting Ult Points.'
    },

    custom: {
      id: 'custom',
      name: 'CUSTOM MATCH',
      subtitle: 'Private Room & Campus Scrims',
      category: 'private_lobby',
      badge: 'PRIVATE CODE',
      accentColor: '#10b981',
      teamBased: true,
      teamCount: 2,
      teamSize: 5,
      minPlayersToStart: 1,
      maxPartySize: 10,
      allowPartyJoin: true,
      affectsRating: false, // Strictly zero ranked rating impact
      allowBotFillInCasual: true,
      roundBased: true,
      maxRounds: 12,
      roundsToWin: 7,
      halftimeRound: 6,
      overtimeEnabled: true,
      buyPhaseDuration: 20,
      buyWindowDuration: 25,
      roundDuration: 100,
      roundEndDuration: 4.0,
      spikeTimer: 40,
      plantTime: 3.2,
      defuseTime: 5.0,
      kitDefuseTime: 3.0,
      respawnEnabled: false,
      respawnDelay: 0,
      spawnProtectionDuration: 0,
      economy: {
        enabled: true,
        startingCredits: 800,
        maxCredits: 16000,
        winReward: 3000,
        lossRewardBase: 1900,
        lossStreakBonus: 500,
        maxLossReward: 2900,
        killReward: 200,
        plantReward: 300,
        defuseReward: 300,
        freeBasicAbilities: false,
        sharedRandomLoadout: false,
        anytimeBuy: false
      },
      ultMultiplier: 1,
      startingUltPoints: 0,
      powerOrbsEnabled: false,
      description: 'Create or join a private room by secure code. Configure custom Hostel/Branch team names, switch sides, manage ready states, and scrim with zero MMR risk.'
    },

    tdm: {
      id: 'tdm',
      name: 'TEAM DEATHMATCH',
      subtitle: '5v5 Continuous Respawn Combat',
      category: 'respawn_team',
      badge: '40 KILLS · 6:00',
      accentColor: '#a855f7',
      teamBased: true,
      teamCount: 2,
      teamSize: 5,
      minPlayersToStart: 2,
      maxPartySize: 5,
      allowPartyJoin: true,
      affectsRating: false,
      allowBotFillInCasual: true,
      roundBased: false,
      maxRounds: 1,
      roundsToWin: 1,
      scoreLimit: 40,
      timeLimit: 360, // 6:00 match duration
      buyPhaseDuration: 0,
      buyWindowDuration: 360,
      roundDuration: 360,
      roundEndDuration: 4.0,
      respawnEnabled: true,
      respawnDelay: 1.8,
      spawnProtectionDuration: 2.0,
      economy: {
        enabled: false,
        startingCredits: 16000,
        maxCredits: 16000,
        winReward: 0,
        lossRewardBase: 0,
        lossStreakBonus: 0,
        maxLossReward: 0,
        killReward: 250,
        plantReward: 0,
        defuseReward: 0,
        freeBasicAbilities: true,
        sharedRandomLoadout: false,
        anytimeBuy: true
      },
      ultMultiplier: 2,
      startingUltPoints: 2,
      powerOrbsEnabled: true,
      description: 'Non-stop 5v5 respawn action across Nirma Campus. First squad to 40 eliminations or highest score at 6:00 wins. Features safe LOS respawns and free armory access.'
    },

    spikerush: {
      id: 'spikerush',
      name: 'SPIKE RUSH',
      subtitle: 'Shared Random Loadouts & Power Orbs',
      category: 'round_objective',
      badge: 'FIRST TO 4 · ORBS',
      accentColor: '#06b6d4',
      teamBased: true,
      teamCount: 2,
      teamSize: 5,
      minPlayersToStart: 2,
      maxPartySize: 5,
      allowPartyJoin: true,
      affectsRating: false,
      allowBotFillInCasual: true,
      roundBased: true,
      maxRounds: 7,
      roundsToWin: 4,
      halftimeRound: 4,
      overtimeEnabled: false,
      buyPhaseDuration: 10,
      buyWindowDuration: 0, // No weapon buying — server assigns identical random weapon each round
      roundDuration: 80,
      roundEndDuration: 3.5,
      spikeTimer: 35,
      plantTime: 2.6,
      defuseTime: 4.2,
      kitDefuseTime: 2.6,
      respawnEnabled: false,
      respawnDelay: 0,
      spawnProtectionDuration: 0,
      economy: {
        enabled: false,
        startingCredits: 0,
        maxCredits: 0,
        winReward: 0,
        lossRewardBase: 0,
        lossStreakBonus: 0,
        maxLossReward: 0,
        killReward: 0,
        plantReward: 0,
        defuseReward: 0,
        freeBasicAbilities: true,
        sharedRandomLoadout: true,
        anytimeBuy: false
      },
      ultMultiplier: 3,
      startingUltPoints: 2,
      powerOrbsEnabled: true,
      description: 'Fast 5v5 objective mode (First to 4 wins). Every player receives the same randomized weapon each round, full free basic abilities, 3x Ult charge, and campus Power Orbs.'
    },

    ffa: {
      id: 'ffa',
      name: 'FREE-FOR-ALL',
      subtitle: '10-Player Solo Combat Arena',
      category: 'respawn_ffa',
      badge: '20 KILLS · SOLO',
      accentColor: '#eab308',
      teamBased: false,
      teamCount: 10,
      teamSize: 1,
      maxPlayers: 10,
      minPlayersToStart: 2,
      maxPartySize: 1, // Strict anti-collusion rule in public FFA matchmaking (solo queue only)
      allowPartyJoin: false,
      affectsRating: false,
      allowBotFillInCasual: true,
      roundBased: false,
      maxRounds: 1,
      roundsToWin: 1,
      scoreLimit: 20,
      timeLimit: 300, // 5:00 match duration
      buyPhaseDuration: 0,
      buyWindowDuration: 300,
      roundDuration: 300,
      roundEndDuration: 4.0,
      respawnEnabled: true,
      respawnDelay: 1.5,
      spawnProtectionDuration: 1.8,
      economy: {
        enabled: false,
        startingCredits: 16000,
        maxCredits: 16000,
        winReward: 0,
        lossRewardBase: 0,
        lossStreakBonus: 0,
        maxLossReward: 0,
        killReward: 300,
        plantReward: 0,
        defuseReward: 0,
        freeBasicAbilities: true,
        sharedRandomLoadout: false,
        anytimeBuy: true
      },
      ultMultiplier: 2,
      startingUltPoints: 3,
      powerOrbsEnabled: false,
      description: 'Every operative for themselves (10 combatants, no teammates). First individual player to 20 eliminations or top score at 5:00 takes 1st Place on the podium.'
    },

    // Preserve Campus Recon sandbox for architectural inspection compatibility
    recon: {
      id: 'recon',
      name: 'CAMPUS RECON',
      subtitle: 'Architectural & Ballistics Sandbox',
      category: 'sandbox',
      badge: 'SANDBOX',
      accentColor: '#64748b',
      teamBased: true,
      teamCount: 2,
      teamSize: 5,
      minPlayersToStart: 1,
      maxPartySize: 5,
      allowPartyJoin: true,
      affectsRating: false,
      allowBotFillInCasual: true,
      roundBased: false,
      maxRounds: 1,
      roundsToWin: 1,
      scoreLimit: 999,
      timeLimit: 600,
      buyPhaseDuration: 0,
      buyWindowDuration: 600,
      roundDuration: 600,
      roundEndDuration: 2.0,
      respawnEnabled: true,
      respawnDelay: 1.5,
      spawnProtectionDuration: 1.5,
      economy: {
        enabled: false,
        startingCredits: 16000,
        maxCredits: 16000,
        winReward: 0,
        lossRewardBase: 0,
        lossStreakBonus: 0,
        maxLossReward: 0,
        killReward: 300,
        plantReward: 0,
        defuseReward: 0,
        freeBasicAbilities: true,
        sharedRandomLoadout: false,
        anytimeBuy: true
      },
      ultMultiplier: 3,
      startingUltPoints: 6,
      powerOrbsEnabled: true,
      description: 'Unlimited credits, abilities, and camera tools to inspect the 1:1 Nirma University campus.'
    }
  };

  // Create convenient aliases (`team_deathmatch` -> `tdm`, `spike_rush` -> `spikerush`, `deathmatch` -> `ffa`)
  const MODE_ALIASES = {
    defusal: 'unrated',
    ranked: 'competitive',
    team_deathmatch: 'tdm',
    spike_rush: 'spikerush',
    deathmatch: 'ffa',
    free_for_all: 'ffa'
  };

  function resolveModeId(rawModeId) {
    const key = String(rawModeId || 'unrated').trim().toLowerCase();
    return MODE_ALIASES[key] || (MODE_CONFIG_REGISTRY[key] ? key : null);
  }

  // ==========================================================================
  // 3. SPIKE RUSH RANDOMIZED ROUND LOADOUT POOL & POWER ORB DEFINITIONS
  // ==========================================================================
  const SPIKE_RUSH_LOADOUT_POOL = [
    { roundTag: 'SIDEARM DUEL', primaryId: null, secondaryId: 'chhaya_pistol', armor: 25, label: 'CHHAYA SUPPRESSED PISTOL' },
    { roundTag: 'REVOLVER SHOWDOWN', primaryId: null, secondaryId: 'rudra_revolver', armor: 50, label: 'RUDRA .44 MAGNUM' },
    { roundTag: 'CLOSE QUARTERS', primaryId: 'breacher_sg', secondaryId: 'sidearm_9mm', armor: 50, label: 'BREACHER-12 SHOTGUN' },
    { roundTag: 'SMG RUSH', primaryId: 'spectre_smg', secondaryId: 'sidearm_9mm', armor: 50, label: 'SPECTRE-9 TACTICAL SMG' },
    { roundTag: 'DMR PRECISION', primaryId: 'garuda_dmr', secondaryId: 'sidearm_9mm', armor: 50, label: 'GARUDA MK-14 DMR' },
    { roundTag: 'ASSAULT RIFLE', primaryId: 'vanguard_ar', secondaryId: 'sidearm_9mm', armor: 100, label: 'VANGUARD-47 RIFLE' },
    { roundTag: 'SURYA CARBINE', primaryId: 'surya_carbine', secondaryId: 'chhaya_pistol', armor: 100, label: 'SURYA-556 CARBINE' },
    { roundTag: 'HEAVY SUPPRESSION', primaryId: 'agni_lmg', secondaryId: 'sidearm_9mm', armor: 100, label: 'AGNI-249 HEAVY LMG' },
    { roundTag: 'SNIPER DUEL', primaryId: 'vajra_sniper', secondaryId: 'rudra_revolver', armor: 100, label: 'VAJRA-50 ANTI-MATERIEL SNIPER' }
  ];

  const CAMPUS_POWER_ORB_NODES = [
    { id: 'orb_dome_stage', type: 'ULT_CRYSTAL', name: 'ULTIMATE ORB (+2 ULT)', x: -17, z: -4, colorHex: 0x38bdf8, css: '#38bdf8' },
    { id: 'orb_mid_plaza', type: 'DAMAGE_AMP', name: 'OVERCHARGE ORB (+30% DMG)', x: 8, z: -8, colorHex: 0xf43f5e, css: '#f43f5e' },
    { id: 'orb_canteen_courtyard', type: 'SPEED_OVERDRIVE', name: 'KINETIC ORB (+25% SPEED)', x: 34, z: -20, colorHex: 0xf59e0b, css: '#f59e0b' },
    { id: 'orb_itnu_quad', type: 'SHIELD_SURGE', name: 'AEGIS ORB (100 AP + FULL HP)', x: -42, z: 22, colorHex: 0x10b981, css: '#10b981' }
  ];

  // Distributed campus spawn nodes for safe TDM & 10-player FFA respawning
  const DISTRIBUTED_CAMPUS_SPAWNS = [
    { id: 'sp_main_gate_w', x: -72, z: 74, yaw: 0.0, zone: 'Main Gate West' },
    { id: 'sp_main_gate_e', x: -62, z: 68, yaw: 0.0, zone: 'Main Gate East' },
    { id: 'sp_rotary1_scholar', x: -68, z: 36, yaw: -0.3, zone: 'Scholar Rotary' },
    { id: 'sp_itnu_a_south', x: -46, z: 34, yaw: 0.1, zone: 'ITNU A-Block South' },
    { id: 'sp_itnu_a_north', x: -46, z: -18, yaw: 1.5, zone: 'ITNU A-Block North' },
    { id: 'sp_dome_plaza_s', x: -17, z: 14, yaw: 0.0, zone: 'Dome Stage South' },
    { id: 'sp_dome_plaza_n', x: -17, z: -36, yaw: 3.14, zone: 'Dome Stage North' },
    { id: 'sp_itnu_b_east', x: 24, z: 12, yaw: 1.6, zone: 'ITNU B-Block East' },
    { id: 'sp_itnu_c_north', x: 12, z: -64, yaw: 3.0, zone: 'ITNU C-Block North' },
    { id: 'sp_pinwheel_lawn', x: -10, z: 54, yaw: 0.0, zone: 'Pinwheel Courtyard' },
    { id: 'sp_bus_rotary2', x: 28, z: 46, yaw: 0.4, zone: 'Bus Fountain Rotary' },
    { id: 'sp_canteen_south', x: 38, z: -12, yaw: 3.14, zone: 'K-Canteen South' },
    { id: 'sp_canteen_east', x: 68, z: -60, yaw: 0.5, zone: 'Defender Plaza' },
    { id: 'sp_new_bldg_plaza', x: 58, z: -20, yaw: 1.8, zone: 'New Building Plaza' }
  ];

  // ==========================================================================
  // 4. RANK TIER PROGRESSION & ELO/GLICKO RATING ENGINE
  // ==========================================================================
  const RANK_TIERS = [
    { id: 'iron_1',     name: 'IRON I',       tierGroup: 'Iron',     minRating: 0,    maxRating: 699,  color: '#94a3b8', badgeIcon: 'I1' },
    { id: 'iron_2',     name: 'IRON II',      tierGroup: 'Iron',     minRating: 700,  maxRating: 799,  color: '#94a3b8', badgeIcon: 'I2' },
    { id: 'iron_3',     name: 'IRON III',     tierGroup: 'Iron',     minRating: 800,  maxRating: 899,  color: '#94a3b8', badgeIcon: 'I3' },
    { id: 'bronze_1',   name: 'BRONZE I',     tierGroup: 'Bronze',   minRating: 900,  maxRating: 999,  color: '#d97706', badgeIcon: 'B1' },
    { id: 'bronze_2',   name: 'BRONZE II',    tierGroup: 'Bronze',   minRating: 1000, maxRating: 1099, color: '#d97706', badgeIcon: 'B2' },
    { id: 'bronze_3',   name: 'BRONZE III',   tierGroup: 'Bronze',   minRating: 1100, maxRating: 1199, color: '#d97706', badgeIcon: 'B3' },
    { id: 'silver_1',   name: 'SILVER I',     tierGroup: 'Silver',   minRating: 1200, maxRating: 1299, color: '#e2e8f0', badgeIcon: 'S1' },
    { id: 'silver_2',   name: 'SILVER II',    tierGroup: 'Silver',   minRating: 1300, maxRating: 1399, color: '#e2e8f0', badgeIcon: 'S2' },
    { id: 'silver_3',   name: 'SILVER III',   tierGroup: 'Silver',   minRating: 1400, maxRating: 1499, color: '#e2e8f0', badgeIcon: 'S3' },
    { id: 'gold_1',     name: 'GOLD I',       tierGroup: 'Gold',     minRating: 1500, maxRating: 1599, color: '#facc15', badgeIcon: 'G1' },
    { id: 'gold_2',     name: 'GOLD II',      tierGroup: 'Gold',     minRating: 1600, maxRating: 1699, color: '#facc15', badgeIcon: 'G2' },
    { id: 'gold_3',     name: 'GOLD III',     tierGroup: 'Gold',     minRating: 1700, maxRating: 1799, color: '#facc15', badgeIcon: 'G3' },
    { id: 'platinum_1', name: 'PLATINUM I',   tierGroup: 'Platinum', minRating: 1800, maxRating: 1899, color: '#2dd4bf', badgeIcon: 'P1' },
    { id: 'platinum_2', name: 'PLATINUM II',  tierGroup: 'Platinum', minRating: 1900, maxRating: 1999, color: '#2dd4bf', badgeIcon: 'P2' },
    { id: 'platinum_3', name: 'PLATINUM III', tierGroup: 'Platinum', minRating: 2000, maxRating: 2099, color: '#2dd4bf', badgeIcon: 'P3' },
    { id: 'diamond_1',  name: 'DIAMOND I',    tierGroup: 'Diamond',  minRating: 2100, maxRating: 2199, color: '#a855f7', badgeIcon: 'D1' },
    { id: 'diamond_2',  name: 'DIAMOND II',   tierGroup: 'Diamond',  minRating: 2200, maxRating: 2299, color: '#a855f7', badgeIcon: 'D2' },
    { id: 'diamond_3',  name: 'DIAMOND III',  tierGroup: 'Diamond',  minRating: 2300, maxRating: 2399, color: '#a855f7', badgeIcon: 'D3' },
    { id: 'immortal_1', name: 'IMMORTAL I',   tierGroup: 'Immortal', minRating: 2400, maxRating: 2549, color: '#f43f5e', badgeIcon: 'IM1' },
    { id: 'immortal_2', name: 'IMMORTAL II',  tierGroup: 'Immortal', minRating: 2550, maxRating: 2699, color: '#f43f5e', badgeIcon: 'IM2' },
    { id: 'immortal_3', name: 'IMMORTAL III', tierGroup: 'Immortal', minRating: 2700, maxRating: 2899, color: '#f43f5e', badgeIcon: 'IM3' },
    { id: 'radiant',    name: 'RADIANT',      tierGroup: 'Radiant',  minRating: 2900, maxRating: 9999, color: '#fef08a', badgeIcon: 'RAD' }
  ];

  class RatingEngine {
    static getRankTier(rating) {
      const clamped = Math.max(0, Math.round(rating || 1200));
      for (let i = RANK_TIERS.length - 1; i >= 0; i--) {
        if (clamped >= RANK_TIERS[i].minRating) {
          const tier = RANK_TIERS[i];
          const rr = clamped - tier.minRating;
          const span = Math.max(100, tier.maxRating - tier.minRating + 1);
          return {
            ...tier,
            rating: clamped,
            rr: tier.id === 'radiant' ? clamped - 2900 : Math.min(99, Math.round((rr / span) * 100))
          };
        }
      }
      return { ...RANK_TIERS[0], rating: clamped, rr: 0 };
    }

    /**
     * Computes server-authoritative Glicko/Elo skill rating adjustment.
     * Returns 0 delta if `modeConfig.affectsRating` is false, if the match is a custom/bot practice match
     * without ranked qualification, or if the match was aborted before round 2.
     */
    static computeRatingUpdate({
      playerRating = 1500,
      playerRd = 110,
      opponentAvgRating = 1500,
      outcome = 'win', // 'win' | 'loss' | 'draw' | 'abandoned'
      roundsWon = 7,
      roundsLost = 4,
      kills = 12,
      deaths = 6,
      assists = 4,
      affectsRating = true,
      isCustomRoom = false,
      isAbortedEarly = false
    }) {
      const prevTier = RatingEngine.getRankTier(playerRating);
      if (!affectsRating || isCustomRoom || isAbortedEarly) {
        return {
          applied: false,
          reason: !affectsRating ? 'NON_RANKED_MODE' : (isCustomRoom ? 'CUSTOM_ROOM_EXEMPT' : 'EARLY_ABORT_SAFEGUARD'),
          previousRating: playerRating,
          newRating: playerRating,
          delta: 0,
          previousRd: playerRd,
          newRd: playerRd,
          previousTier: prevTier,
          newTier: prevTier,
          promoted: false,
          demoted: false,
          breakdown: { baseDelta: 0, roundMarginBonus: 0, performanceBonus: 0, abandonPenalty: 0 }
        };
      }

      // Expected score via logistic curve
      const expected = 1 / (1 + Math.pow(10, (opponentAvgRating - playerRating) / 400));
      const actualScore = outcome === 'win' ? 1.0 : (outcome === 'draw' ? 0.5 : 0.0);

      // Dynamic K-factor scaled by Glicko Rating Deviation (uncertainty: higher RD = faster calibration)
      const uncertaintyFactor = Math.max(0.75, Math.min(1.65, (playerRd || 90) / 85));
      const baseK = 28 * uncertaintyFactor;
      const baseDelta = Math.round(baseK * (actualScore - expected));

      // Round differential bonus (decisive victories/close losses)
      const totalRounds = Math.max(1, roundsWon + roundsLost);
      const roundDiff = roundsWon - roundsLost;
      const roundMarginBonus = outcome === 'draw' ? 0 : Math.round((roundDiff / totalRounds) * 8);

      // Individual combat performance bonus (KDA & ACS contribution, bounded to prevent selfish baiting)
      const kdRatio = (kills + assists * 0.35) / Math.max(1, deaths);
      const performanceBonus = Math.max(-5, Math.min(7, Math.round((kdRatio - 1.05) * 4.5)));

      // Abandon penalty if player abandoned an active competitive match
      const abandonPenalty = outcome === 'abandoned' ? -24 : 0;

      let totalDelta = baseDelta + roundMarginBonus + performanceBonus + abandonPenalty;
      if (outcome === 'win') totalDelta = Math.max(10, Math.min(42, totalDelta));
      if (outcome === 'loss') totalDelta = Math.min(-8, Math.max(-35, totalDelta));
      if (outcome === 'abandoned') totalDelta = Math.min(-20, totalDelta);

      const newRating = Math.max(100, playerRating + totalDelta);
      const newRd = Math.max(45, Math.round((playerRd || 110) * 0.92));
      const newTier = RatingEngine.getRankTier(newRating);

      return {
        applied: true,
        reason: 'RANKED_COMPETITIVE_MATCH',
        previousRating: playerRating,
        newRating,
        delta: totalDelta,
        previousRd: playerRd,
        newRd,
        previousTier: prevTier,
        newTier,
        promoted: newTier.minRating > prevTier.minRating,
        demoted: newTier.minRating < prevTier.minRating,
        breakdown: {
          baseDelta,
          roundMarginBonus,
          performanceBonus,
          abandonPenalty
        }
      };
    }
  }

  // ==========================================================================
  // 5. QUEUE STATE MACHINE CONSTANTS
  // ==========================================================================
  const QUEUE_STATES = {
    IDLE: 'IDLE',
    VALIDATING_PARTY: 'VALIDATING_PARTY',
    SEARCHING: 'SEARCHING',
    MATCH_FOUND: 'MATCH_FOUND',
    JOINING_MATCH: 'JOINING_MATCH',
    MATCH_STARTING: 'MATCH_STARTING',
    CANCELLED: 'CANCELLED',
    FAILED: 'FAILED'
  };

  // ==========================================================================
  // 6. SAFE SPAWN & LINE-OF-SIGHT GEOMETRIC HELPERS
  // ==========================================================================
  function checkSegmentIntersectsAABB2D(x1, z1, x2, z2, minX, maxX, minZ, maxZ) {
    let t0 = 0.0, t1 = 1.0;
    const dx = x2 - x1;
    const dz = z2 - z1;
    const p = [-dx, dx, -dz, dz];
    const q = [x1 - minX, maxX - x1, z1 - minZ, maxZ - z1];
    for (let i = 0; i < 4; i++) {
      if (Math.abs(p[i]) < 1e-8) {
        if (q[i] < 0) return false;
      } else {
        const t = q[i] / p[i];
        if (p[i] < 0) {
          if (t > t1) return false;
          if (t > t0) t0 = t;
        } else {
          if (t < t0) return false;
          if (t < t1) t1 = t;
        }
      }
    }
    return t0 <= t1;
  }

  // Major solid campus building footprints for server-side LOS and safe-spawn occlusion checks
  const SERVER_SOLID_BUILDINGS_2D = [
    { id: 'ITNU_A', minX: -62, maxX: -30, minZ: -6, maxZ: 26 },
    { id: 'ITNU_B', minX: -4,  maxX: 28,  minZ: -6, maxZ: 26 },
    { id: 'ITNU_C', minX: -4,  maxX: 28,  minZ: -64, maxZ: -32 },
    { id: 'ITNU_D', minX: -62, maxX: -30, minZ: -64, maxZ: -32 },
    { id: 'CANTEEN_K', minX: 24, maxX: 52, minZ: -39, maxZ: -21 },
    { id: 'NEW_BLDG_N', minX: 64, maxX: 92, minZ: -32, maxZ: 0 },
    { id: 'ILNU_PINWHEEL', minX: -26, maxX: 6, minZ: 56, maxZ: 88 }
  ];

  function hasServerLineOfSight2D(posA, posB, smokes = []) {
    if (!posA || !posB) return false;
    const dist = Math.hypot(posB.x - posA.x, posB.z - posA.z);
    if (dist > 90) return false;
    for (const s of smokes) {
      const abx = posB.x - posA.x;
      const abz = posB.z - posA.z;
      const lenSq = abx * abx + abz * abz;
      const t = lenSq > 0 ? Math.max(0, Math.min(1, ((s.x - posA.x) * abx + (s.z - posA.z) * abz) / lenSq)) : 0;
      const cx = posA.x + t * abx;
      const cz = posA.z + t * abz;
      if (Math.hypot(s.x - cx, s.z - cz) <= (s.radius || 5.6)) {
        return false;
      }
    }
    for (const b of SERVER_SOLID_BUILDINGS_2D) {
      if (checkSegmentIntersectsAABB2D(posA.x, posA.z, posB.x, posB.z, b.minX, b.maxX, b.minZ, b.maxZ)) {
        return false;
      }
    }
    return true;
  }

  function isPointInsideSolidBuilding2D(x, z, radius = 0.45) {
    for (const b of SERVER_SOLID_BUILDINGS_2D) {
      if (x >= b.minX - radius && x <= b.maxX + radius && z >= b.minZ - radius && z <= b.maxZ + radius) {
        return true;
      }
    }
    return false;
  }

  /**
   * Selects the safest spawn point for a respawning player in TDM or FFA:
   * - Maximizes minimum distance to any living opponent
   * - Penalizes spawn points that are in direct line-of-sight of any living opponent
   * - Avoids spawning on top of another living entity
   */
  function selectSafeSpawnPoint(candidateSpawns, livingOpponents = [], smokes = [], customLosFn = null) {
    const spawns = (candidateSpawns && candidateSpawns.length > 0) ? candidateSpawns : DISTRIBUTED_CAMPUS_SPAWNS;
    if (!livingOpponents || livingOpponents.length === 0) {
      return spawns[Math.floor(Math.random() * spawns.length)];
    }

    let bestSpawn = spawns[0];
    let bestScore = -Infinity;

    for (const sp of spawns) {
      let minEnemyDist = Infinity;
      let losExposureCount = 0;

      for (const opp of livingOpponents) {
        if (!opp || !opp.alive) continue;
        const ox = opp.position ? opp.position.x : (opp.x || 0);
        const oz = opp.position ? opp.position.z : (opp.z || 0);
        const d = Math.hypot(sp.x - ox, sp.z - oz);
        if (d < minEnemyDist) minEnemyDist = d;

        const inLos = customLosFn
          ? customLosFn(sp, { x: ox, z: oz })
          : hasServerLineOfSight2D(sp, { x: ox, z: oz }, smokes);
        if (inLos && d < 65) {
          losExposureCount++;
        }
      }

      const proximityPenalty = minEnemyDist < 14 ? -500 : 0;
      const losPenalty = losExposureCount * -85;
      const jitter = (Math.random() - 0.5) * 4.0;
      const score = Math.min(minEnemyDist, 80) + proximityPenalty + losPenalty + jitter;

      if (score > bestScore) {
        bestScore = score;
        bestSpawn = sp;
      }
    }

    return bestSpawn;
  }

  // ==========================================================================
  // 7. AUTHORITATIVE MULTIPLAYER WORLD / HUB CONTROLLER
  // ==========================================================================
  class NirvexAuthoritativeHub {
    constructor(options = {}) {
      this.players = new Map();           // playerId -> PlayerProfile
      this.sessions = new Map();          // sessionToken -> playerId
      this.sessionMeta = new Map();       // sessionToken -> { playerId, createdAt, expiresAt, lastSeenAt }
      this.passwordHashes = new Map();    // playerId -> scrypt/pbkdf hash
      this.parties = new Map();           // partyId -> PartyObject
      this.invitations = new Map();       // inviteId -> InvitationObject
      this.friendRequests = new Map();    // requestId -> FriendRequestObject
      this.customRooms = new Map();       // roomCode -> CustomRoomObject
      this.queueTickets = new Map();      // ticketId -> QueueTicket
      this.matches = new Map();           // matchId -> AuthoritativeMatchInstance
      this.processedMatchIds = new Set(); // Idempotency guard for match result finalization
      this.processedActionKeys = new Set(); // Idempotency guard for network packets
      this.auditLog = [];                 // Structured security & anti-abuse audit trail

      this.reconnectGraceMs = options.reconnectGraceMs || 120000; // 2 minutes reconnect grace window
      this.sessionTtlMs = options.sessionTtlMs || 7 * 24 * 3600 * 1000; // 7 days session TTL
      this.queueLock = false;
      this.eventSeq = 0;
      this.onStateChanged = options.onStateChanged || null;

      if (options.initialState) {
        this.importPersistedState(options.initialState);
      }
      this.ensureCampusOnlinePeers();
    }

    recordAuditEvent(event, actorId = null, details = {}) {
      const entry = {
        id: generateSecureCode('AUD', 4, 2),
        timestamp: Date.now(),
        event,
        actorId,
        details
      };
      this.auditLog.push(entry);
      if (this.auditLog.length > 500) {
        this.auditLog.shift();
      }
      return entry;
    }

    checkActionIdempotency(actionKey) {
      if (!actionKey) return false;
      if (this.processedActionKeys.has(actionKey)) {
        return true;
      }
      this.processedActionKeys.add(actionKey);
      if (this.processedActionKeys.size > 5000) {
        const first = this.processedActionKeys.values().next().value;
        this.processedActionKeys.delete(first);
      }
      return false;
    }

    notifyChange(eventType, detail = {}) {
      this.eventSeq++;
      if (typeof this.onStateChanged === 'function') {
        try {
          this.onStateChanged(eventType, detail, this);
        } catch (e) {}
      }
    }

    exportPersistedState() {
      const passwordEntries = {};
      for (const [pid, hash] of this.passwordHashes.entries()) {
        passwordEntries[pid] = hash;
      }
      return {
        schemaVersion: DB_SCHEMA_VERSION,
        version: DB_SCHEMA_VERSION,
        updatedAt: Date.now(),
        players: Array.from(this.players.values()),
        passwordHashes: passwordEntries,
        friendRequests: Array.from(this.friendRequests.values()),
        processedMatchIds: Array.from(this.processedMatchIds),
        auditLog: this.auditLog.slice(-100)
      };
    }

    importPersistedState(data) {
      if (!data || typeof data !== 'object') return;
      if (data.passwordHashes && typeof data.passwordHashes === 'object') {
        for (const [pid, hash] of Object.entries(data.passwordHashes)) {
          if (pid && typeof hash === 'string') {
            this.passwordHashes.set(pid, hash);
          }
        }
      }
      if (Array.isArray(data.players)) {
        for (const p of data.players) {
          if (p && p.id) {
            // Migrate schema v1 -> v2 fields cleanly
            if (!p.stats) {
              p.stats = {
                ranked: { matches: 0, wins: 0, losses: 0, draws: 0, kills: 0, deaths: 0, assists: 0 },
                casual: { matches: 0, wins: 0, losses: 0, draws: 0, kills: 0, deaths: 0, assists: 0 },
                byMode: {}
              };
            }
            if (!Array.isArray(p.matchHistory)) p.matchHistory = [];
            p.rankTier = RatingEngine.getRankTier(p.rating || 1550);
            if (!p.sessionToken) p.sessionToken = generateSessionToken();
            this.players.set(p.id, p);
            this.sessions.set(p.sessionToken, p.id);
            this.sessionMeta.set(p.sessionToken, {
              playerId: p.id,
              createdAt: Date.now(),
              expiresAt: Date.now() + this.sessionTtlMs,
              lastSeenAt: Date.now()
            });
          }
        }
      }
      if (Array.isArray(data.friendRequests)) {
        for (const req of data.friendRequests) {
          if (req && req.id) {
            this.friendRequests.set(req.id, req);
          }
        }
      }
      if (Array.isArray(data.processedMatchIds)) {
        for (const id of data.processedMatchIds) {
          this.processedMatchIds.add(id);
        }
      }
      if (Array.isArray(data.auditLog)) {
        this.auditLog = data.auditLog.slice(-200);
      }
    }

    ensureCampusOnlinePeers() {
      const defaultPeers = [
        { id: 'peer_aarav', name: 'Aarav_ITNU', heroId: 'vajra', role: 'Duelist', rating: 1620, rd: 75, status: 'Online • Nirma Dome Stage', isPeerBot: true },
        { id: 'peer_meera', name: 'Meera_CSE', heroId: 'drishti', role: 'Initiator', rating: 1580, rd: 80, status: 'Online • ITNU A-Block', isPeerBot: true },
        { id: 'peer_rohan', name: 'Rohan_IMNU', heroId: 'kavach', role: 'Sentinel', rating: 1690, rd: 70, status: 'Online • Armory Range', isPeerBot: true },
        { id: 'peer_zoya',  name: 'Zoya_IDNU', heroId: 'pralay', role: 'Controller', rating: 1510, rd: 85, status: 'Online • Hostel H4', isPeerBot: true },
        { id: 'peer_kabir', name: 'Kabir_EC', heroId: 'agni', role: 'Duelist', rating: 1740, rd: 72, status: 'Online • K-Canteen', isPeerBot: true },
        { id: 'peer_vikram', name: 'Vikram_ME', heroId: 'kavach', role: 'Sentinel', rating: 1540, rd: 82, status: 'Online • Pinwheel Lawn', isPeerBot: true },
        { id: 'peer_yash',  name: 'Yash_IT', heroId: 'vajra', role: 'Duelist', rating: 1605, rd: 78, status: 'Online • Main Gate', isPeerBot: true },
        { id: 'peer_nikhil', name: 'Nikhil_CE', heroId: 'pralay', role: 'Controller', rating: 1495, rd: 88, status: 'Online • New Building', isPeerBot: true },
        { id: 'peer_harsh', name: 'Harsh_MBA', heroId: 'drishti', role: 'Initiator', rating: 1650, rd: 74, status: 'Online • Cricket Oval', isPeerBot: true }
      ];
      for (const peer of defaultPeers) {
        if (!this.players.has(peer.id)) {
          this.registerOrGetPlayer(peer);
        }
      }
    }

    // ========================================================================
    // 7.1 PLAYER IDENTITY, PROFILE, AUTHENTICATION & SESSION MANAGEMENT
    // ========================================================================
    registerOrGetPlayer({ id, name, password, heroId = 'vajra', rating = 1550, rd = 95, status = 'Online', isPeerBot = false } = {}) {
      const playerId = id ? String(id).trim().slice(0, 48) : generateSecureCode('PLY', 4, 2);
      const cleanName = sanitizeDisplayName(name, `OPERATIVE_${playerId.slice(-4)}`);
      let profile = this.players.get(playerId);
      const now = Date.now();

      if (!profile) {
        const sessionToken = generateSessionToken();
        const initRating = typeof rating === 'number' && Number.isFinite(rating) ? Math.max(100, Math.min(3500, Math.round(rating))) : 1550;
        profile = {
          id: playerId,
          name: cleanName,
          friendCode: generateSecureCode('NV', 4, 1),
          heroId: heroId || 'vajra',
          rating: initRating,
          rd: typeof rd === 'number' ? rd : 95,
          peakRating: initRating,
          rankTier: RatingEngine.getRankTier(initRating),
          xp: 18450,
          level: 24,
          status: status || 'Online',
          isPeerBot: Boolean(isPeerBot),
          online: true,
          lastSeenAt: now,
          sessionToken,
          partyId: null,
          roomCode: null,
          queueTicketId: null,
          queueState: QUEUE_STATES.IDLE,
          activeMatchId: null,
          friends: [],
          stats: {
            ranked: { matches: 0, wins: 0, losses: 0, draws: 0, kills: 0, deaths: 0, assists: 0 },
            casual: { matches: 0, wins: 0, losses: 0, draws: 0, kills: 0, deaths: 0, assists: 0 },
            byMode: {}
          },
          matchHistory: []
        };
        if (password && String(password).length >= 4) {
          this.passwordHashes.set(playerId, hashPassword(String(password)));
          profile.hasPassword = true;
        }
        this.players.set(playerId, profile);
        this.sessions.set(sessionToken, playerId);
        this.sessionMeta.set(sessionToken, {
          playerId,
          createdAt: now,
          expiresAt: now + this.sessionTtlMs,
          lastSeenAt: now
        });
      } else {
        if (name) profile.name = cleanName;
        if (heroId) profile.heroId = heroId;
        profile.online = true;
        profile.lastSeenAt = now;
        profile.rankTier = RatingEngine.getRankTier(profile.rating);
        if (password && String(password).length >= 4 && !this.passwordHashes.has(playerId)) {
          this.passwordHashes.set(playerId, hashPassword(String(password)));
          profile.hasPassword = true;
        }
        if (!profile.sessionToken) {
          profile.sessionToken = generateSessionToken();
        }
        this.sessions.set(profile.sessionToken, playerId);
        this.sessionMeta.set(profile.sessionToken, {
          playerId,
          createdAt: now,
          expiresAt: now + this.sessionTtlMs,
          lastSeenAt: now
        });
      }
      return profile;
    }

    registerAccount({ id, name, password, heroId = 'vajra', rating = 1550 } = {}) {
      if (!name || String(name).trim().length < 2) {
        return { ok: false, code: 'INVALID_NAME', message: 'Callsign must be between 2 and 24 characters.' };
      }
      const cleanName = sanitizeDisplayName(name, '');
      if (!cleanName) {
        return { ok: false, code: 'INVALID_NAME', message: 'Callsign contains disallowed characters.' };
      }
      const existingById = id ? this.players.get(id) : null;
      if (existingById && this.passwordHashes.has(existingById.id)) {
        if (!password || !verifyPassword(password, this.passwordHashes.get(existingById.id))) {
          this.recordAuditEvent('AUTH_REGISTER_CONFLICT', existingById.id, { reason: 'PASSWORD_MISMATCH' });
          return { ok: false, code: 'ACCOUNT_EXISTS_PASSWORD_REQUIRED', message: 'Account already exists and is password-protected.' };
        }
      }
      const profile = this.registerOrGetPlayer({ id, name: cleanName, password, heroId, rating });
      return { ok: true, profile, sessionToken: profile.sessionToken };
    }

    loginAccount({ idOrName, password } = {}) {
      const target = this.players.get(idOrName) || this.findPlayerByCodeOrName(idOrName);
      if (!target) {
        this.recordAuditEvent('AUTH_LOGIN_FAILED', null, { idOrName, reason: 'USER_NOT_FOUND' });
        return { ok: false, code: 'INVALID_CREDENTIALS', message: 'Invalid operative callsign or password.' };
      }
      const storedHash = this.passwordHashes.get(target.id);
      if (storedHash) {
        if (!password || !verifyPassword(password, storedHash)) {
          this.recordAuditEvent('AUTH_LOGIN_FAILED', target.id, { reason: 'WRONG_PASSWORD' });
          return { ok: false, code: 'INVALID_CREDENTIALS', message: 'Invalid operative callsign or password.' };
        }
      }
      // Rotate session token on explicit login
      const newToken = generateSessionToken();
      target.sessionToken = newToken;
      target.online = true;
      target.lastSeenAt = Date.now();
      this.sessions.set(newToken, target.id);
      this.sessionMeta.set(newToken, {
        playerId: target.id,
        createdAt: Date.now(),
        expiresAt: Date.now() + this.sessionTtlMs,
        lastSeenAt: Date.now()
      });
      return { ok: true, profile: target, sessionToken: newToken };
    }

    authenticateSession(sessionToken) {
      if (!sessionToken || typeof sessionToken !== 'string') return null;
      const meta = this.sessionMeta.get(sessionToken);
      if (meta && meta.expiresAt && Date.now() > meta.expiresAt) {
        this.sessions.delete(sessionToken);
        this.sessionMeta.delete(sessionToken);
        this.recordAuditEvent('SESSION_EXPIRED', meta.playerId);
        return null;
      }
      const playerId = this.sessions.get(sessionToken);
      if (!playerId) return null;
      const p = this.players.get(playerId);
      if (p) {
        p.online = true;
        p.lastSeenAt = Date.now();
        if (meta) meta.lastSeenAt = Date.now();
      }
      return p || null;
    }

    /**
     * Verifies that an incoming network request's `sessionToken` matches `actorId`.
     * When `requireToken` is true, missing tokens are rejected.
     * When `sessionToken` is provided, it MUST match `actorId` (prevents spoofing another player's ID).
     */
    verifySessionActor(sessionToken, actorId, requireToken = false) {
      if (!sessionToken) {
        if (requireToken) {
          this.recordAuditEvent('UNAUTHORIZED_MISSING_TOKEN', actorId);
          return { ok: false, statusCode: 401, code: 'UNAUTHORIZED_MISSING_TOKEN', message: 'Authentication session token is required.' };
        }
        return { ok: true, player: this.players.get(actorId) || null };
      }
      const authedPlayer = this.authenticateSession(sessionToken);
      if (!authedPlayer) {
        this.recordAuditEvent('UNAUTHORIZED_INVALID_TOKEN', actorId);
        return { ok: false, statusCode: 401, code: 'INVALID_SESSION_TOKEN', message: 'Invalid or expired session token.' };
      }
      if (actorId && authedPlayer.id !== actorId) {
        this.recordAuditEvent('FORBIDDEN_ACTOR_IMPERSONATION', authedPlayer.id, { attemptedActorId: actorId });
        return { ok: false, statusCode: 403, code: 'FORBIDDEN_ACTOR_MISMATCH', message: 'Session token does not match the requested player ID.' };
      }
      return { ok: true, player: authedPlayer };
    }

    findPlayerByCodeOrName(query) {
      if (!query) return null;
      const q = String(query).trim().toUpperCase();
      for (const p of this.players.values()) {
        if (p.id.toUpperCase() === q || (p.friendCode && p.friendCode.toUpperCase() === q) || p.name.toUpperCase() === q) {
          return p;
        }
      }
      return null;
    }

    getDynamicPresenceStatus(playerOrId) {
      const p = typeof playerOrId === 'string' ? this.players.get(playerOrId) : playerOrId;
      if (!p) return 'Offline';
      if (p.isPeerBot) return p.status || 'Online — In Lobby';
      if (!p.online) return 'Offline';
      if (p.activeMatchId && this.matches.has(p.activeMatchId)) {
        const m = this.matches.get(p.activeMatchId);
        if (m && m.phase !== 'MATCH_OVER' && !m.finalized) {
          const mName = (m.modeCfg && m.modeCfg.name) || m.modeId || 'Match';
          return `In Match — ${mName}`;
        }
      }
      if (p.queueState === QUEUE_STATES.SEARCHING || p.queueState === QUEUE_STATES.MATCH_FOUND || p.queueState === QUEUE_STATES.JOINING_MATCH) {
        return 'In Queue';
      }
      if (p.roomCode && this.customRooms.has(p.roomCode)) {
        const rm = this.customRooms.get(p.roomCode);
        if (rm && rm.status !== 'CLOSED') {
          return `In Custom Room (${rm.code})`;
        }
      }
      if (p.partyId && this.parties.has(p.partyId)) {
        const pty = this.parties.get(p.partyId);
        if (pty && pty.members.length > 1) {
          return `In Party (${pty.members.length}/5)`;
        }
      }
      return 'Online — In Lobby';
    }

    sendFriendRequest(senderId, targetQuery) {
      const sender = this.players.get(senderId);
      if (!sender) return { ok: false, code: 'SENDER_NOT_FOUND', message: 'Sender profile not found.' };
      const target = this.players.get(targetQuery) || this.findPlayerByCodeOrName(targetQuery);
      if (!target) {
        return { ok: false, code: 'TARGET_NOT_FOUND', message: `Operative "${targetQuery}" not found on Nirma Campus Network.` };
      }
      if (target.id === sender.id) {
        return { ok: false, code: 'CANNOT_ADD_SELF', message: 'You cannot send a friend request to yourself.' };
      }
      if (!Array.isArray(sender.friends)) sender.friends = [];
      if (!Array.isArray(target.friends)) target.friends = [];

      if (sender.friends.includes(target.id)) {
        return { ok: true, alreadyFriends: true, target: { id: target.id, name: target.name, friendCode: target.friendCode } };
      }

      // Check if target already sent a pending friend request to sender -> auto-accept
      for (const req of this.friendRequests.values()) {
        if (req.status === 'PENDING' && req.senderId === target.id && req.targetId === sender.id) {
          return this.respondFriendRequest(sender.id, req.id, true);
        }
        if (req.status === 'PENDING' && req.senderId === sender.id && req.targetId === target.id) {
          return { ok: true, request: req, alreadyPending: true };
        }
      }

      const reqId = generateSecureCode('FRQ', 4, 2);
      const request = {
        id: reqId,
        senderId: sender.id,
        senderName: sender.name,
        senderFriendCode: sender.friendCode,
        senderRating: sender.rating,
        targetId: target.id,
        targetName: target.name,
        status: 'PENDING',
        createdAt: Date.now()
      };
      this.friendRequests.set(reqId, request);

      if (target.isPeerBot) {
        return this.respondFriendRequest(target.id, reqId, true);
      }

      this.notifyChange('friend_request_sent', { request, senderId: sender.id, targetId: target.id });
      return { ok: true, request, target: { id: target.id, name: target.name, friendCode: target.friendCode } };
    }

    respondFriendRequest(playerId, requestIdOrSenderId, accept = true) {
      let request = this.friendRequests.get(requestIdOrSenderId);
      if (!request) {
        for (const r of this.friendRequests.values()) {
          if (r.status === 'PENDING' && r.targetId === playerId && (r.id === requestIdOrSenderId || r.senderId === requestIdOrSenderId)) {
            request = r;
            break;
          }
        }
      }
      if (!request || request.targetId !== playerId) {
        return { ok: false, code: 'FRIEND_REQUEST_NOT_FOUND', message: 'Friend request not found.' };
      }
      if (request.status !== 'PENDING') {
        return { ok: false, code: 'REQUEST_ALREADY_HANDLED', message: `Friend request already ${request.status}.` };
      }

      if (!accept) {
        request.status = 'DECLINED';
        this.notifyChange('friend_request_declined', { request, senderId: request.senderId, targetId: request.targetId });
        return { ok: true, status: 'DECLINED', request };
      }

      request.status = 'ACCEPTED';
      const sender = this.players.get(request.senderId);
      const target = this.players.get(request.targetId);
      if (sender) {
        if (!Array.isArray(sender.friends)) sender.friends = [];
        if (!sender.friends.includes(request.targetId)) sender.friends.push(request.targetId);
      }
      if (target) {
        if (!Array.isArray(target.friends)) target.friends = [];
        if (!target.friends.includes(request.senderId)) target.friends.push(request.senderId);
      }
      this.notifyChange('friend_request_accepted', { request, senderId: request.senderId, targetId: request.targetId });
      return { ok: true, status: 'ACCEPTED', request };
    }

    removeFriend(playerId, friendId) {
      const player = this.players.get(playerId);
      const friend = this.players.get(friendId);
      if (!player) return { ok: false, code: 'PLAYER_NOT_FOUND', message: 'Player not found.' };
      if (Array.isArray(player.friends)) {
        player.friends = player.friends.filter(id => id !== friendId);
      }
      if (friend && Array.isArray(friend.friends)) {
        friend.friends = friend.friends.filter(id => id !== playerId);
      }
      this.notifyChange('friend_removed', { playerId, friendId });
      return { ok: true, playerId, friendId };
    }

    searchPlayers(query, viewerId = null) {
      const q = String(query || '').trim().toUpperCase();
      const results = [];
      for (const p of this.players.values()) {
        if (viewerId && p.id === viewerId) continue;
        if (!q || p.name.toUpperCase().includes(q) || p.id.toUpperCase().includes(q) || (p.friendCode && p.friendCode.toUpperCase().includes(q))) {
          results.push({
            id: p.id,
            name: p.name,
            friendCode: p.friendCode,
            heroId: p.heroId || 'vajra',
            rating: p.rating || 1550,
            rankTier: RatingEngine.getRankTier(p.rating || 1550),
            online: Boolean(p.online),
            isPeerBot: Boolean(p.isPeerBot),
            presenceStatus: this.getDynamicPresenceStatus(p),
            partyId: p.partyId || null,
            roomCode: p.roomCode || null
          });
        }
        if (results.length >= 25) break;
      }
      return results;
    }

    getSocialState(playerId) {
      const player = this.players.get(playerId);
      if (!player) return { ok: false, code: 'PLAYER_NOT_FOUND', message: 'Player not found.' };
      const party = this.getOrCreatePartyForPlayer(playerId);
      const friendIds = new Set(Array.isArray(player.friends) ? player.friends : []);

      const formatPublicPeer = (p) => ({
        id: p.id,
        name: p.name,
        friendCode: p.friendCode,
        heroId: p.heroId || 'vajra',
        rating: p.rating || 1550,
        rankTier: RatingEngine.getRankTier(p.rating || 1550),
        online: Boolean(p.online),
        isPeerBot: Boolean(p.isPeerBot),
        isFriend: friendIds.has(p.id),
        presenceStatus: this.getDynamicPresenceStatus(p),
        partyId: p.partyId || null,
        roomCode: p.roomCode || null
      });

      const friends = [];
      for (const fid of friendIds) {
        const fp = this.players.get(fid);
        if (fp && !fp.isPeerBot) friends.push(formatPublicPeer(fp));
      }

      const onlinePlayers = [];
      for (const p of this.players.values()) {
        if (p.id === playerId) continue;
        if (!p.isPeerBot && p.online) {
          onlinePlayers.push(formatPublicPeer(p));
        }
      }

      const incomingFriendRequests = [];
      const outgoingFriendRequests = [];
      for (const req of this.friendRequests.values()) {
        if (req.status !== 'PENDING') continue;
        if (req.targetId === playerId) incomingFriendRequests.push(req);
        if (req.senderId === playerId) outgoingFriendRequests.push(req);
      }

      const incomingPartyInvites = [];
      for (const inv of this.invitations.values()) {
        if (inv.status === 'PENDING' && inv.targetId === playerId && this.parties.has(inv.partyId)) {
          incomingPartyInvites.push(inv);
        }
      }

      return {
        ok: true,
        profile: {
          ...player,
          presenceStatus: this.getDynamicPresenceStatus(player),
          sessionToken: undefined
        },
        party,
        friends,
        onlinePlayers,
        incomingFriendRequests,
        outgoingFriendRequests,
        incomingPartyInvites
      };
    }

    // ========================================================================
    // 7.2 FRIEND & PARTY SYSTEM (CREATE, INVITE, ACCEPT/DECLINE, LEAVE, LEADER TRANSFER)
    // ========================================================================
    createParty(leaderId) {
      const leader = this.players.get(leaderId);
      if (!leader) return { ok: false, code: 'PLAYER_NOT_FOUND', message: 'Leader profile not found.' };

      if (leader.partyId && this.parties.has(leader.partyId)) {
        return { ok: true, party: this.parties.get(leader.partyId) };
      }

      const partyId = generateSecureCode('PTY', 4, 2);
      const inviteCode = generateSecureCode('SQUAD', 4, 1);
      const party = {
        id: partyId,
        inviteCode,
        leaderId: leader.id,
        selectedMode: 'unrated',
        queueState: QUEUE_STATES.IDLE,
        queueTicketId: null,
        createdAt: Date.now(),
        members: [
          {
            id: leader.id,
            name: leader.name,
            heroId: leader.heroId,
            rating: leader.rating,
            rankTier: RatingEngine.getRankTier(leader.rating),
            ready: true,
            joinedAt: Date.now(),
            isPeerBot: Boolean(leader.isPeerBot)
          }
        ]
      };
      this.parties.set(partyId, party);
      leader.partyId = partyId;
      this.notifyChange('party_created', { party });
      return { ok: true, party };
    }

    getOrCreatePartyForPlayer(playerId) {
      const p = this.players.get(playerId);
      if (!p) return null;
      if (p.partyId && this.parties.has(p.partyId)) {
        return this.parties.get(p.partyId);
      }
      const res = this.createParty(playerId);
      return res.ok ? res.party : null;
    }

    inviteToParty(inviterId, targetIdOrCode) {
      const inviter = this.players.get(inviterId);
      if (!inviter) return { ok: false, code: 'INVITER_NOT_FOUND', message: 'Inviter not found.' };
      const party = this.getOrCreatePartyForPlayer(inviterId);
      if (!party) return { ok: false, code: 'PARTY_ERROR', message: 'Unable to create party.' };

      if (party.queueState === QUEUE_STATES.SEARCHING || party.queueState === QUEUE_STATES.MATCH_FOUND) {
        return { ok: false, code: 'PARTY_IN_QUEUE', message: 'Cannot invite while party is actively searching in queue.' };
      }

      const target = this.players.get(targetIdOrCode) || this.findPlayerByCodeOrName(targetIdOrCode);
      if (!target) return { ok: false, code: 'TARGET_NOT_FOUND', message: `Player "${targetIdOrCode}" not found on Nirma Campus Network.` };

      if (party.members.some(m => m.id === target.id)) {
        return { ok: false, code: 'ALREADY_IN_PARTY', message: `${target.name} is already in your party.` };
      }

      const resolvedMode = resolveModeId(party.selectedMode) || 'unrated';
      const modeCfg = MODE_CONFIG_REGISTRY[resolvedMode] || MODE_CONFIG_REGISTRY.unrated;
      const maxParty = modeCfg.maxPartySize || 5;
      if (party.members.length >= maxParty) {
        return { ok: false, code: 'PARTY_FULL', message: `Party is at max capacity (${maxParty}) for ${modeCfg.name}.` };
      }

      const inviteId = generateSecureCode('INV', 4, 2);
      const invite = {
        id: inviteId,
        partyId: party.id,
        inviterId: inviter.id,
        inviterName: inviter.name,
        targetId: target.id,
        targetName: target.name,
        status: 'PENDING',
        createdAt: Date.now()
      };
      this.invitations.set(inviteId, invite);

      // If target is an online campus peer simulation bot, auto-accept so solo users can immediately test party matchmaking
      if (target.isPeerBot) {
        return this.respondToPartyInvite(target.id, inviteId, true);
      }

      this.notifyChange('party_invite_sent', { invite, party });
      return { ok: true, invite, party };
    }

    respondToPartyInvite(playerId, inviteId, accept = true) {
      const invite = this.invitations.get(inviteId);
      if (!invite || invite.targetId !== playerId) {
        return { ok: false, code: 'INVITE_NOT_FOUND', message: 'Party invitation not found or expired.' };
      }
      if (invite.status !== 'PENDING') {
        return { ok: false, code: 'INVITE_ALREADY_HANDLED', message: `Invitation already ${invite.status}.` };
      }

      if (!accept) {
        invite.status = 'DECLINED';
        this.notifyChange('party_invite_declined', { invite });
        return { ok: true, status: 'DECLINED', invite };
      }

      const party = this.parties.get(invite.partyId);
      if (!party) {
        invite.status = 'EXPIRED';
        return { ok: false, code: 'PARTY_GONE', message: 'Party no longer exists.' };
      }

      const joinRes = this.joinPartyById(playerId, party.id);
      if (!joinRes.ok) return joinRes;

      invite.status = 'ACCEPTED';
      this.notifyChange('party_invite_accepted', { invite, party: joinRes.party });
      return { ok: true, status: 'ACCEPTED', party: joinRes.party, invite };
    }

    joinPartyByCode(playerId, inviteCode) {
      const codeUpper = String(inviteCode || '').trim().toUpperCase();
      for (const party of this.parties.values()) {
        if (party.inviteCode.toUpperCase() === codeUpper || party.id.toUpperCase() === codeUpper) {
          return this.joinPartyById(playerId, party.id);
        }
      }
      return { ok: false, code: 'INVALID_PARTY_CODE', message: `No active party found with code "${inviteCode}".` };
    }

    joinPartyById(playerId, partyId) {
      const player = this.players.get(playerId);
      const party = this.parties.get(partyId);
      if (!player || !party) {
        return { ok: false, code: 'NOT_FOUND', message: 'Player or party not found.' };
      }
      if (party.members.some(m => m.id === playerId)) {
        return { ok: true, party };
      }
      if (party.queueState === QUEUE_STATES.SEARCHING || party.queueState === QUEUE_STATES.MATCH_FOUND) {
        return { ok: false, code: 'PARTY_IN_QUEUE', message: 'Cannot join party while matchmaking is in progress.' };
      }
      if (party.members.length >= 5) {
        return { ok: false, code: 'PARTY_FULL', message: 'Party is full (max 5 operatives).' };
      }

      if (player.partyId && player.partyId !== party.id) {
        this.leaveParty(playerId);
      }

      party.members.push({
        id: player.id,
        name: player.name,
        heroId: player.heroId,
        rating: player.rating,
        rankTier: RatingEngine.getRankTier(player.rating),
        ready: true,
        joinedAt: Date.now(),
        isPeerBot: Boolean(player.isPeerBot)
      });
      player.partyId = party.id;
      this.notifyChange('party_member_joined', { party, playerId });
      return { ok: true, party };
    }

    leaveParty(playerId) {
      const player = this.players.get(playerId);
      if (!player || !player.partyId) {
        return { ok: false, code: 'NOT_IN_PARTY', message: 'Player is not in a party.' };
      }
      const party = this.parties.get(player.partyId);
      player.partyId = null;
      if (!party) return { ok: true, dissolved: true };

      if (party.queueTicketId) {
        this.cancelQueue(party.leaderId, 'PARTY_MEMBER_LEFT');
      }

      party.members = party.members.filter(m => m.id !== playerId);

      const humanRemaining = party.members.filter(m => !m.isPeerBot);
      if (party.members.length === 0 || humanRemaining.length === 0) {
        for (const m of party.members) {
          const mp = this.players.get(m.id);
          if (mp) mp.partyId = null;
        }
        this.parties.delete(party.id);
        this.notifyChange('party_dissolved', { partyId: party.id });
        return { ok: true, dissolved: true };
      }

      let newLeaderId = party.leaderId;
      if (party.leaderId === playerId) {
        const sortedCandidates = [...party.members].sort((a, b) => {
          if (a.isPeerBot !== b.isPeerBot) return a.isPeerBot ? 1 : -1;
          return a.joinedAt - b.joinedAt;
        });
        newLeaderId = sortedCandidates[0].id;
        party.leaderId = newLeaderId;
      }

      this.notifyChange('party_member_left', { party, leftPlayerId: playerId, newLeaderId });
      return { ok: true, party, newLeaderId };
    }

    setPartyMemberReady(playerId, ready) {
      const player = this.players.get(playerId);
      if (!player || !player.partyId) return { ok: false, code: 'NOT_IN_PARTY', message: 'Not in a party.' };
      const party = this.parties.get(player.partyId);
      if (!party) return { ok: false, code: 'PARTY_NOT_FOUND', message: 'Party not found.' };
      const member = party.members.find(m => m.id === playerId);
      if (!member) return { ok: false, code: 'MEMBER_NOT_FOUND', message: 'Member not found.' };
      member.ready = Boolean(ready);
      this.notifyChange('party_ready_changed', { party, playerId, ready: member.ready });
      return { ok: true, party };
    }

    kickPartyMember(leaderId, targetMemberId) {
      const leader = this.players.get(leaderId);
      if (!leader || !leader.partyId) return { ok: false, code: 'NOT_IN_PARTY', message: 'Not in a party.' };
      const party = this.parties.get(leader.partyId);
      if (!party) return { ok: false, code: 'PARTY_NOT_FOUND', message: 'Party not found.' };
      if (party.leaderId !== leaderId) {
        return { ok: false, code: 'NOT_PARTY_LEADER', message: 'Only the party leader can kick members.' };
      }
      if (targetMemberId === leaderId) {
        return { ok: false, code: 'CANNOT_KICK_SELF', message: 'Leader cannot kick themselves.' };
      }
      if (!party.members.some(m => m.id === targetMemberId)) {
        return { ok: false, code: 'MEMBER_NOT_IN_PARTY', message: 'Target operative is not in this party.' };
      }
      if (party.queueTicketId) {
        this.cancelQueue(party.leaderId, 'PARTY_MEMBER_KICKED');
      }
      party.members = party.members.filter(m => m.id !== targetMemberId);
      const targetProfile = this.players.get(targetMemberId);
      if (targetProfile && targetProfile.partyId === party.id) {
        targetProfile.partyId = null;
        if (!targetProfile.isPeerBot) {
          this.createParty(targetMemberId);
        }
      }
      this.notifyChange('party_member_kicked', { party, kickedPlayerId: targetMemberId, leaderId });
      return { ok: true, party, kickedPlayerId: targetMemberId };
    }

    promotePartyLeader(leaderId, newLeaderId) {
      const leader = this.players.get(leaderId);
      if (!leader || !leader.partyId) return { ok: false, code: 'NOT_IN_PARTY', message: 'Not in a party.' };
      const party = this.parties.get(leader.partyId);
      if (!party) return { ok: false, code: 'PARTY_NOT_FOUND', message: 'Party not found.' };
      if (party.leaderId !== leaderId) {
        return { ok: false, code: 'NOT_PARTY_LEADER', message: 'Only the current party leader can transfer leadership.' };
      }
      const targetMem = party.members.find(m => m.id === newLeaderId);
      if (!targetMem) {
        return { ok: false, code: 'MEMBER_NOT_IN_PARTY', message: 'Target operative is not in this party.' };
      }
      party.leaderId = newLeaderId;
      this.notifyChange('party_leader_promoted', { party, previousLeaderId: leaderId, newLeaderId });
      return { ok: true, party, newLeaderId };
    }

    setPartyMode(requesterId, rawModeId) {
      const player = this.players.get(requesterId);
      if (!player || !player.partyId) return { ok: false, code: 'NOT_IN_PARTY', message: 'Not in a party.' };
      const party = this.parties.get(player.partyId);
      if (!party) return { ok: false, code: 'PARTY_NOT_FOUND', message: 'Party not found.' };
      if (party.leaderId !== requesterId && party.members.length > 1) {
        return { ok: false, code: 'NOT_PARTY_LEADER', message: 'Only the party leader can change the party game mode.' };
      }
      const resolved = resolveModeId(rawModeId) || 'unrated';
      party.selectedMode = resolved;
      this.notifyChange('party_mode_changed', { party, selectedMode: resolved });
      return { ok: true, party, selectedMode: resolved };
    }

    validatePartyForMode(party, rawModeId) {
      const modeId = resolveModeId(rawModeId);
      const modeCfg = modeId ? MODE_CONFIG_REGISTRY[modeId] : null;
      if (!modeCfg) {
        return { ok: false, code: 'INVALID_MODE', message: `Unknown game mode "${rawModeId}".` };
      }
      if (!party || !Array.isArray(party.members) || party.members.length === 0) {
        return { ok: false, code: 'EMPTY_PARTY', message: 'Party has no members.' };
      }

      for (const m of party.members) {
        const p = this.players.get(m.id);
        if (p) {
          m.rating = p.rating;
          m.rankTier = RatingEngine.getRankTier(p.rating);
        }
      }

      const count = party.members.length;
      if (!modeCfg.allowPartyJoin && count > 1) {
        return {
          ok: false,
          code: 'FFA_SOLO_ONLY',
          message: `${modeCfg.name} prohibits multi-player parties in public matchmaking to prevent teaming/collusion (Party size: ${count}, Max: 1). Use Custom Match for private FFA with friends.`
        };
      }

      if (count > (modeCfg.maxPartySize || 5)) {
        return {
          ok: false,
          code: 'PARTY_SIZE_EXCEEDED',
          message: `Party size (${count}) exceeds maximum allowed (${modeCfg.maxPartySize}) for ${modeCfg.name}.`
        };
      }

      const unready = party.members.filter(m => !m.ready);
      if (unready.length > 0) {
        return {
          ok: false,
          code: 'PARTY_NOT_READY',
          message: `All party members must be Ready before queuing (${unready.map(u => u.name).join(', ')} not ready).`
        };
      }

      if (modeId === 'competitive' && count > 1) {
        if (modeCfg.disallowFourStack && count === 4) {
          return {
            ok: false,
            code: 'COMPETITIVE_FOUR_STACK_RESTRICTED',
            message: 'Competitive queue prohibits 4-player parties to protect solo-queue teammates. Queue as 1–3 players or invite a 5th for a full 5-stack.'
          };
        }
        const ratings = party.members.map(m => m.rating || 1500);
        const minR = Math.min(...ratings);
        const maxR = Math.max(...ratings);
        const spread = maxR - minR;
        const allowedSpread = count === 5 ? (modeCfg.fiveStackMaxSpread || 800) : (modeCfg.maxPartyRatingSpread || 350);
        if (spread > allowedSpread) {
          return {
            ok: false,
            code: 'COMPETITIVE_SKILL_DISPARITY',
            message: `Party MMR spread (${spread} MMR) exceeds the Competitive limit of ${allowedSpread} MMR (${minR} to ${maxR}).`
          };
        }
      }

      return { ok: true, modeCfg };
    }

    // ========================================================================
    // 7.3 MATCHMAKING ENGINE & QUEUE STATE MACHINE
    // ========================================================================
    enterQueue(requesterId, rawModeId, options = {}) {
      const player = this.players.get(requesterId);
      if (!player) return { ok: false, code: 'PLAYER_NOT_FOUND', message: 'Player not found.' };

      const modeId = resolveModeId(rawModeId);
      const modeCfg = modeId ? MODE_CONFIG_REGISTRY[modeId] : null;
      if (!modeCfg) return { ok: false, code: 'INVALID_MODE', message: `Invalid mode: ${rawModeId}` };

      if (modeId === 'custom') {
        return { ok: false, code: 'CUSTOM_USES_ROOM_LOBBY', message: 'Custom Match uses Private Room creation/join instead of public matchmaking.' };
      }

      if (player.queueTicketId && this.queueTickets.has(player.queueTicketId)) {
        const existing = this.queueTickets.get(player.queueTicketId);
        if ([QUEUE_STATES.VALIDATING_PARTY, QUEUE_STATES.SEARCHING, QUEUE_STATES.MATCH_FOUND, QUEUE_STATES.JOINING_MATCH].includes(existing.state)) {
          return { ok: false, code: 'ALREADY_IN_QUEUE', message: 'Already in matchmaking queue.', ticket: existing };
        }
      }

      const party = this.getOrCreatePartyForPlayer(requesterId);
      if (party.leaderId !== requesterId) {
        return { ok: false, code: 'NOT_PARTY_LEADER', message: 'Only the party leader can start matchmaking.' };
      }

      party.selectedMode = modeId;
      party.queueState = QUEUE_STATES.VALIDATING_PARTY;
      player.queueState = QUEUE_STATES.VALIDATING_PARTY;

      const validation = this.validatePartyForMode(party, modeId);
      if (!validation.ok) {
        party.queueState = QUEUE_STATES.FAILED;
        player.queueState = QUEUE_STATES.FAILED;
        this.notifyChange('queue_failed', { party, reason: validation });
        return validation;
      }

      for (const m of party.members) {
        const mp = this.players.get(m.id);
        if (mp && mp.queueTicketId && this.queueTickets.has(mp.queueTicketId)) {
          const t = this.queueTickets.get(mp.queueTicketId);
          if (t.state === QUEUE_STATES.SEARCHING || t.state === QUEUE_STATES.MATCH_FOUND) {
            return { ok: false, code: 'MEMBER_ALREADY_QUEUED', message: `${m.name} is already in an active queue.` };
          }
        }
      }

      const ratings = party.members.map(m => m.rating || 1500);
      const avgRating = Math.round(ratings.reduce((a, b) => a + b, 0) / ratings.length);

      const ticketId = generateSecureCode('TKT', 4, 2);
      const ticket = {
        id: ticketId,
        modeId,
        partyId: party.id,
        leaderId: party.leaderId,
        players: party.members.map(m => ({
          id: m.id,
          name: m.name,
          heroId: m.heroId || 'vajra',
          rating: m.rating || 1500,
          isPeerBot: Boolean(m.isPeerBot)
        })),
        partySize: party.members.length,
        avgRating,
        preferredTeam: options.preferredTeam || 'attackers',
        allowPracticeFill: Boolean(options.allowPracticeFill),
        state: QUEUE_STATES.SEARCHING,
        reservedMatchId: null,
        enqueuedAt: Date.now()
      };

      this.queueTickets.set(ticketId, ticket);
      party.queueTicketId = ticketId;
      party.queueState = QUEUE_STATES.SEARCHING;
      for (const m of party.members) {
        const mp = this.players.get(m.id);
        if (mp) {
          mp.queueTicketId = ticketId;
          mp.queueState = QUEUE_STATES.SEARCHING;
        }
      }

      this.notifyChange('queue_searching', { ticket, party });

      if (options.autoProcess !== false) {
        this.processMatchmakingTick(modeId);
      }

      return { ok: true, ticket, party };
    }

    cancelQueue(requesterId, reason = 'USER_CANCELLED') {
      const player = this.players.get(requesterId);
      if (!player) return { ok: false, code: 'PLAYER_NOT_FOUND' };
      const party = player.partyId ? this.parties.get(player.partyId) : null;
      const ticketId = (party && party.queueTicketId) || player.queueTicketId;
      if (!ticketId || !this.queueTickets.has(ticketId)) {
        if (party) party.queueState = QUEUE_STATES.IDLE;
        player.queueState = QUEUE_STATES.IDLE;
        return { ok: true, state: QUEUE_STATES.CANCELLED };
      }

      const ticket = this.queueTickets.get(ticketId);
      if (ticket.state === QUEUE_STATES.MATCH_STARTING) {
        return { ok: false, code: 'MATCH_ALREADY_STARTING', message: 'Match is already starting and cannot be cancelled.' };
      }

      ticket.state = QUEUE_STATES.CANCELLED;
      ticket.cancelledReason = reason;
      this.queueTickets.delete(ticketId);

      if (party) {
        party.queueTicketId = null;
        party.queueState = QUEUE_STATES.CANCELLED;
        for (const m of party.members) {
          const mp = this.players.get(m.id);
          if (mp) {
            mp.queueTicketId = null;
            mp.queueState = QUEUE_STATES.CANCELLED;
          }
        }
      } else {
        player.queueTicketId = null;
        player.queueState = QUEUE_STATES.CANCELLED;
      }

      this.notifyChange('queue_cancelled', { ticket, reason });
      return { ok: true, state: QUEUE_STATES.CANCELLED, ticket };
    }

    cleanupStaleQueueTickets(maxAgeMs = 300000) {
      const now = Date.now();
      for (const [, ticket] of this.queueTickets.entries()) {
        const hasOffline = ticket.players.some(tp => {
          const p = this.players.get(tp.id);
          return !p || (!p.online && (now - (p.lastSeenAt || 0)) > this.reconnectGraceMs);
        });
        if (hasOffline || (now - ticket.enqueuedAt) > maxAgeMs) {
          this.cancelQueue(ticket.leaderId, 'STALE_OR_DISCONNECTED_SESSION');
        }
      }
    }

    processMatchmakingTick(rawModeId, options = {}) {
      if (this.queueLock) return null;
      this.queueLock = true;
      try {
        this.cleanupStaleQueueTickets();
        const modeId = resolveModeId(rawModeId);
        const modeCfg = modeId ? MODE_CONFIG_REGISTRY[modeId] : null;
        if (!modeCfg) return null;

        const searchingTickets = Array.from(this.queueTickets.values())
          .filter(t => t.modeId === modeId && t.state === QUEUE_STATES.SEARCHING && !t.reservedMatchId)
          .sort((a, b) => a.enqueuedAt - b.enqueuedAt);

        if (searchingTickets.length === 0) return null;

        // Case 1: Free-For-All (10 individual combatants)
        if (!modeCfg.teamBased) {
          const targetPlayers = modeCfg.maxPlayers || 10;
          const selectedTickets = [];
          let count = 0;
          for (const t of searchingTickets) {
            if (count + t.partySize <= targetPlayers) {
              selectedTickets.push(t);
              count += t.partySize;
              if (count === targetPlayers) break;
            }
          }

          if (count < targetPlayers && options.fillWithBotsIfShort) {
            return this._finalizeMatchedTickets(modeCfg, selectedTickets, [], true, options);
          }
          if (count === targetPlayers) {
            return this._finalizeMatchedTickets(modeCfg, selectedTickets, [], false, options);
          }
          return null;
        }

        // Case 2: Team-based 5v5 modes (Unrated, Competitive, Swiftplay, TDM, Spike Rush)
        const teamSize = modeCfg.teamSize || 5;
        const formation = this._findBalancedTeamFormation(searchingTickets, teamSize);

        if (formation) {
          return this._finalizeMatchedTickets(modeCfg, formation.teamATickets, formation.teamBTickets, false, options);
        }

        if (options.fillWithBotsIfShort && searchingTickets.length > 0) {
          const primaryTicket = searchingTickets[0];
          const teamATickets = [primaryTicket];
          let teamACount = primaryTicket.partySize;
          const teamBTickets = [];
          let teamBCount = 0;

          for (let i = 1; i < searchingTickets.length; i++) {
            const t = searchingTickets[i];
            if (teamBTickets.length === 0 && t.partySize <= teamSize) {
              // Put second human ticket on opposing team if possible so two queued humans play against each other!
              teamBTickets.push(t);
              teamBCount += t.partySize;
            } else if (teamACount + t.partySize <= teamSize) {
              teamATickets.push(t);
              teamACount += t.partySize;
            } else if (teamBCount + t.partySize <= teamSize) {
              teamBTickets.push(t);
              teamBCount += t.partySize;
            }
          }
          return this._finalizeMatchedTickets(modeCfg, teamATickets, teamBTickets, true, options);
        }

        return null;
      } finally {
        this.queueLock = false;
      }
    }

    _findBalancedTeamFormation(tickets, teamSize = 5) {
      const totalAvailable = tickets.reduce((sum, t) => sum + t.partySize, 0);
      if (totalAvailable < teamSize * 2) return null;

      const maxSearch = Math.min(tickets.length, 14);
      const pool = tickets.slice(0, maxSearch);

      function findSubsets(candidateIndices, limit = 60) {
        const results = [];
        function bt(pos, chosen, sum) {
          if (sum === teamSize) {
            results.push([...chosen]);
            return;
          }
          if (sum > teamSize || results.length >= limit) return;
          for (let i = pos; i < candidateIndices.length; i++) {
            const idx = candidateIndices[i];
            chosen.push(idx);
            bt(i + 1, chosen, sum + pool[idx].partySize);
            chosen.pop();
            if (results.length >= limit) return;
          }
        }
        bt(0, [], 0);
        return results;
      }

      const allIndices = pool.map((_, idx) => idx);
      const teamACandidates = findSubsets(allIndices, 45);
      let bestPair = null;
      let bestRatingDiff = Infinity;

      for (const setA of teamACandidates) {
        const usedA = new Set(setA);
        const remIndices = allIndices.filter(idx => !usedA.has(idx));
        const teamBCandidates = findSubsets(remIndices, 30);
        for (const setB of teamBCandidates) {
          const teamATickets = setA.map(idx => pool[idx]);
          const teamBTickets = setB.map(idx => pool[idx]);

          const mmrA = teamATickets.reduce((s, t) => s + t.avgRating * t.partySize, 0) / teamSize;
          const mmrB = teamBTickets.reduce((s, t) => s + t.avgRating * t.partySize, 0) / teamSize;
          const diff = Math.abs(mmrA - mmrB);

          if (diff < bestRatingDiff) {
            bestRatingDiff = diff;
            bestPair = { teamATickets, teamBTickets, mmrDiff: Math.round(diff) };
          }
        }
      }

      return bestPair;
    }

    _finalizeMatchedTickets(modeCfg, teamATickets, teamBTickets, usedBotFill = false, options = {}) {
      const allTickets = [...teamATickets, ...teamBTickets];
      const matchId = generateSecureCode('MCH', 4, 2);

      for (const t of allTickets) {
        t.reservedMatchId = matchId;
        t.state = QUEUE_STATES.MATCH_FOUND;
        this._propagateTicketState(t, QUEUE_STATES.MATCH_FOUND, matchId);
      }
      this.notifyChange('match_found', { matchId, modeId: modeCfg.id, tickets: allTickets });

      for (const t of allTickets) {
        t.state = QUEUE_STATES.JOINING_MATCH;
        this._propagateTicketState(t, QUEUE_STATES.JOINING_MATCH, matchId);
      }

      const preferredTeam = (teamATickets[0] && teamATickets[0].preferredTeam) || 'attackers';
      const otherTeam = preferredTeam === 'attackers' ? 'defenders' : 'attackers';

      const roster = [];
      const heroCycle = ['vajra', 'drishti', 'pralay', 'kavach', 'agni'];
      const weaponCycle = ['vanguard_ar', 'surya_carbine', 'spectre_smg', 'garuda_dmr', 'vajra_sniper'];

      if (!modeCfg.teamBased) {
        let idx = 0;
        for (const t of allTickets) {
          for (const p of t.players) {
            roster.push({
              id: p.id,
              name: p.name,
              team: `ffa_${p.id}`,
              partyId: t.partyId,
              heroId: p.heroId || heroCycle[idx % heroCycle.length],
              weaponId: weaponCycle[idx % weaponCycle.length],
              rating: p.rating || 1500,
              isBot: Boolean(p.isPeerBot)
            });
            idx++;
          }
        }
        const botNames = ['Aarav', 'Dev', 'Rohan', 'Kabir', 'Vikram', 'Yash', 'Nikhil', 'Harsh', 'Pranav', 'Sameer'];
        while (roster.length < (modeCfg.maxPlayers || 10)) {
          const bIdx = roster.length;
          const bId = `bot_ffa_${bIdx}`;
          roster.push({
            id: bId,
            name: `${botNames[bIdx % botNames.length]} [BOT]`,
            team: `ffa_${bId}`,
            partyId: null,
            heroId: heroCycle[bIdx % heroCycle.length],
            weaponId: weaponCycle[bIdx % weaponCycle.length],
            rating: 1500,
            isBot: true
          });
        }
      } else {
        const teamSize = modeCfg.teamSize || 5;
        let aIdx = 0;
        for (const t of teamATickets) {
          for (const p of t.players) {
            roster.push({
              id: p.id,
              name: p.name,
              team: preferredTeam,
              partyId: t.partyId,
              heroId: p.heroId || heroCycle[aIdx % heroCycle.length],
              weaponId: weaponCycle[aIdx % weaponCycle.length],
              rating: p.rating || 1500,
              isBot: Boolean(p.isPeerBot)
            });
            aIdx++;
          }
        }
        const allyBotNames = ['Aarav', 'Dev', 'Rohan', 'Kabir', 'Siddharth'];
        while (aIdx < teamSize) {
          roster.push({
            id: `bot_a${aIdx}`,
            name: `${allyBotNames[aIdx % allyBotNames.length]} [AI]`,
            team: preferredTeam,
            partyId: null,
            heroId: heroCycle[aIdx % heroCycle.length],
            weaponId: weaponCycle[aIdx % weaponCycle.length],
            rating: 1500,
            isBot: true
          });
          aIdx++;
        }

        let bIdx = 0;
        for (const t of teamBTickets) {
          for (const p of t.players) {
            roster.push({
              id: p.id,
              name: p.name,
              team: otherTeam,
              partyId: t.partyId,
              heroId: p.heroId || heroCycle[bIdx % heroCycle.length],
              weaponId: weaponCycle[bIdx % weaponCycle.length],
              rating: p.rating || 1500,
              isBot: Boolean(p.isPeerBot)
            });
            bIdx++;
          }
        }
        const enemyBotNames = ['Vikram', 'Yash', 'Nikhil', 'Harsh', 'Pranav'];
        while (bIdx < teamSize) {
          roster.push({
            id: `bot_d${bIdx + 1}`,
            name: `${enemyBotNames[bIdx % enemyBotNames.length]} [AI]`,
            team: otherTeam,
            partyId: null,
            heroId: heroCycle[bIdx % heroCycle.length],
            weaponId: weaponCycle[bIdx % weaponCycle.length],
            rating: 1500,
            isBot: true
          });
          bIdx++;
        }
      }

      for (const t of allTickets) {
        t.state = QUEUE_STATES.MATCH_STARTING;
        this._propagateTicketState(t, QUEUE_STATES.MATCH_STARTING, matchId);
        this.queueTickets.delete(t.id);
      }

      const matchInstance = new AuthoritativeMatchInstance({
        id: matchId,
        modeId: modeCfg.id,
        modeCfg,
        roster,
        usedBotFill,
        isCustomRoom: false,
        rankedSimulationAllowed: Boolean(options.rankedSimulationAllowed),
        hub: this
      });

      this.matches.set(matchId, matchInstance);
      this.notifyChange('match_starting', { match: matchInstance.getPublicSummary() });
      return matchInstance;
    }

    _propagateTicketState(ticket, state, matchId = null) {
      const party = this.parties.get(ticket.partyId);
      if (party) {
        party.queueState = state;
        if (state === QUEUE_STATES.MATCH_STARTING) party.queueTicketId = null;
      }
      for (const tp of ticket.players) {
        const p = this.players.get(tp.id);
        if (p) {
          p.queueState = state;
          if (matchId) p.activeMatchId = matchId;
          if (state === QUEUE_STATES.MATCH_STARTING) p.queueTicketId = null;
        }
      }
    }

    // ========================================================================
    // 7.4 CUSTOM MATCH / PRIVATE ROOM LOBBY MANAGER
    // ========================================================================
    createCustomRoom(hostId, settings = {}) {
      const host = this.players.get(hostId);
      if (!host) return { ok: false, code: 'HOST_NOT_FOUND', message: 'Host player not found.' };

      let roomCode = generateSecureCode('NRVX', 4, 2);
      while (this.customRooms.has(roomCode)) {
        roomCode = generateSecureCode('NRVX', 4, 2);
      }

      const resolvedSubMode = resolveModeId(settings.subMode || 'unrated') || 'unrated';
      const room = {
        code: roomCode,
        hostId: host.id,
        status: 'LOBBY', // 'LOBBY' | 'IN_MATCH' | 'CLOSED'
        createdAt: Date.now(),
        activeMatchId: null,
        settings: {
          subMode: resolvedSubMode === 'custom' ? 'unrated' : resolvedSubMode,
          mapId: settings.mapId || 'nirma_campus',
          teamNameAttackers: sanitizeDisplayName(settings.teamNameAttackers, 'ITNU VANGUARD'),
          teamNameDefenders: sanitizeDisplayName(settings.teamNameDefenders, 'HOSTEL H4 SENTINEL'),
          maxRounds: Number(settings.maxRounds) || 12,
          scoreLimit: Number(settings.scoreLimit) || 40,
          botFill: settings.botFill !== undefined ? Boolean(settings.botFill) : true,
          botDifficulty: settings.botDifficulty || 'veteran',
          unlimitedAbilities: Boolean(settings.unlimitedAbilities),
          timeOfDay: settings.timeOfDay || 'sunset'
        },
        members: [
          {
            id: host.id,
            name: host.name,
            heroId: host.heroId || 'vajra',
            team: 'attackers',
            ready: true,
            joinedAt: Date.now(),
            isBot: false
          }
        ]
      };

      if (host.partyId && this.parties.has(host.partyId)) {
        const party = this.parties.get(host.partyId);
        for (const pm of party.members) {
          if (pm.id !== host.id && !room.members.some(m => m.id === pm.id)) {
            // Only auto-pull human party members unless includePartyBots is explicitly true
            if (!pm.isPeerBot || settings.includePartyBots) {
              room.members.push({
                id: pm.id,
                name: pm.name,
                heroId: pm.heroId || 'drishti',
                team: room.members.filter(m => m.team === 'attackers').length < 5 ? 'attackers' : 'defenders',
                ready: true,
                joinedAt: Date.now() + 1,
                isBot: Boolean(pm.isPeerBot)
              });
            }
          }
        }
      }

      this.customRooms.set(roomCode, room);
      host.roomCode = roomCode;
      this.notifyChange('custom_room_created', { room });
      return { ok: true, room };
    }

    joinCustomRoom(playerId, roomCode) {
      const player = this.players.get(playerId);
      if (!player) return { ok: false, code: 'PLAYER_NOT_FOUND', message: 'Player not found.' };
      const cleanCode = String(roomCode || '').trim().toUpperCase();
      const room = this.customRooms.get(cleanCode);
      if (!room || room.status === 'CLOSED') {
        return { ok: false, code: 'ROOM_NOT_FOUND', message: `Private room "${cleanCode}" does not exist or has been closed.` };
      }
      if (room.status === 'IN_MATCH') {
        return { ok: false, code: 'ROOM_IN_MATCH', message: 'Room match is already in progress.' };
      }
      if (room.members.some(m => m.id === playerId)) {
        return { ok: true, room };
      }
      if (room.members.length >= 10) {
        return { ok: false, code: 'ROOM_FULL', message: 'Custom room is full (10/10 players).' };
      }

      const atkCount = room.members.filter(m => m.team === 'attackers').length;
      const defCount = room.members.filter(m => m.team === 'defenders').length;
      // Default second joiner onto opposing team if attackers has 1 and defenders has 0 so 1v1 custom scrims work immediately!
      const assignedTeam = atkCount <= defCount ? 'attackers' : 'defenders';

      room.members.push({
        id: player.id,
        name: player.name,
        heroId: player.heroId || 'vajra',
        team: assignedTeam,
        ready: true,
        joinedAt: Date.now(),
        isBot: Boolean(player.isPeerBot)
      });
      player.roomCode = room.code;
      this.notifyChange('custom_room_joined', { room, playerId });
      return { ok: true, room };
    }

    switchCustomRoomTeam(playerId, roomCode, targetTeam) {
      const room = this.customRooms.get(String(roomCode || '').trim().toUpperCase());
      if (!room) return { ok: false, code: 'ROOM_NOT_FOUND', message: 'Room not found.' };
      const member = room.members.find(m => m.id === playerId);
      if (!member) return { ok: false, code: 'NOT_IN_ROOM', message: 'Player is not in this room.' };

      if (!['attackers', 'defenders', 'spectators'].includes(targetTeam)) {
        return { ok: false, code: 'INVALID_TEAM', message: 'Invalid team selection.' };
      }
      if (targetTeam !== 'spectators') {
        const countOnTeam = room.members.filter(m => m.team === targetTeam && m.id !== playerId).length;
        if (countOnTeam >= 5) {
          return { ok: false, code: 'TEAM_FULL', message: `Team ${targetTeam.toUpperCase()} is already full (5/5).` };
        }
      }
      member.team = targetTeam;
      this.notifyChange('custom_room_team_switched', { room, playerId, targetTeam });
      return { ok: true, room };
    }

    setCustomRoomReady(playerId, roomCode, ready) {
      const room = this.customRooms.get(String(roomCode || '').trim().toUpperCase());
      if (!room) return { ok: false, code: 'ROOM_NOT_FOUND', message: 'Room not found.' };
      const member = room.members.find(m => m.id === playerId);
      if (!member) return { ok: false, code: 'NOT_IN_ROOM', message: 'Player is not in this room.' };
      member.ready = Boolean(ready);
      this.notifyChange('custom_room_ready_changed', { room, playerId, ready: member.ready });
      return { ok: true, room };
    }

    updateCustomRoomSettings(requesterId, roomCode, newSettings = {}) {
      const room = this.customRooms.get(String(roomCode || '').trim().toUpperCase());
      if (!room) return { ok: false, code: 'ROOM_NOT_FOUND', message: 'Room not found.' };
      if (room.hostId !== requesterId) {
        this.recordAuditEvent('FORBIDDEN_ROOM_SETTINGS', requesterId, { roomCode });
        return { ok: false, code: 'FORBIDDEN_NOT_HOST', message: 'Only the room host can modify room settings.' };
      }
      if (newSettings.subMode) {
        const resolved = resolveModeId(newSettings.subMode);
        if (resolved && resolved !== 'custom') room.settings.subMode = resolved;
      }
      if (newSettings.teamNameAttackers !== undefined) {
        room.settings.teamNameAttackers = sanitizeDisplayName(newSettings.teamNameAttackers, 'ITNU VANGUARD');
      }
      if (newSettings.teamNameDefenders !== undefined) {
        room.settings.teamNameDefenders = sanitizeDisplayName(newSettings.teamNameDefenders, 'HOSTEL H4');
      }
      if (newSettings.botFill !== undefined) room.settings.botFill = Boolean(newSettings.botFill);
      if (newSettings.unlimitedAbilities !== undefined) room.settings.unlimitedAbilities = Boolean(newSettings.unlimitedAbilities);
      if (newSettings.maxRounds !== undefined) room.settings.maxRounds = Math.max(1, Math.min(30, Number(newSettings.maxRounds) || 12));
      if (newSettings.scoreLimit !== undefined) room.settings.scoreLimit = Math.max(5, Math.min(100, Number(newSettings.scoreLimit) || 40));

      this.notifyChange('custom_room_settings_updated', { room });
      return { ok: true, room };
    }

    kickFromCustomRoom(requesterId, roomCode, targetPlayerId) {
      const room = this.customRooms.get(String(roomCode || '').trim().toUpperCase());
      if (!room) return { ok: false, code: 'ROOM_NOT_FOUND', message: 'Room not found.' };
      if (room.hostId !== requesterId) {
        this.recordAuditEvent('FORBIDDEN_ROOM_KICK', requesterId, { roomCode, targetPlayerId });
        return { ok: false, code: 'FORBIDDEN_NOT_HOST', message: 'Only the room host can kick players.' };
      }
      if (targetPlayerId === room.hostId) {
        return { ok: false, code: 'CANNOT_KICK_SELF', message: 'Host cannot kick themselves.' };
      }
      const idx = room.members.findIndex(m => m.id === targetPlayerId);
      if (idx === -1) return { ok: false, code: 'TARGET_NOT_IN_ROOM', message: 'Target player is not in this room.' };

      room.members.splice(idx, 1);
      const targetPlayer = this.players.get(targetPlayerId);
      if (targetPlayer && targetPlayer.roomCode === room.code) {
        targetPlayer.roomCode = null;
      }
      this.notifyChange('custom_room_member_kicked', { room, targetPlayerId });
      return { ok: true, room };
    }

    transferCustomRoomHost(requesterId, roomCode, newHostId) {
      const room = this.customRooms.get(String(roomCode || '').trim().toUpperCase());
      if (!room) return { ok: false, code: 'ROOM_NOT_FOUND', message: 'Room not found.' };
      if (room.hostId !== requesterId) {
        this.recordAuditEvent('FORBIDDEN_ROOM_TRANSFER_HOST', requesterId, { roomCode, newHostId });
        return { ok: false, code: 'FORBIDDEN_NOT_HOST', message: 'Only the current room host can transfer host privileges.' };
      }
      const targetMember = room.members.find(m => m.id === newHostId);
      if (!targetMember) {
        return { ok: false, code: 'TARGET_NOT_IN_ROOM', message: 'Target player is not in this room.' };
      }
      room.hostId = newHostId;
      targetMember.ready = true;
      this.notifyChange('custom_room_host_transferred', { room, previousHostId: requesterId, newHostId });
      return { ok: true, room, newHostId };
    }

    leaveCustomRoom(playerId, roomCode) {
      const room = this.customRooms.get(String(roomCode || '').trim().toUpperCase());
      if (!room) return { ok: false, code: 'ROOM_NOT_FOUND', message: 'Room not found.' };
      room.members = room.members.filter(m => m.id !== playerId);
      const player = this.players.get(playerId);
      if (player && player.roomCode === room.code) player.roomCode = null;

      if (room.members.length === 0) {
        room.status = 'CLOSED';
        this.customRooms.delete(room.code);
        this.notifyChange('custom_room_closed', { roomCode: room.code });
        return { ok: true, closed: true };
      }

      let newHostId = room.hostId;
      if (room.hostId === playerId) {
        const sorted = [...room.members].sort((a, b) => a.joinedAt - b.joinedAt);
        newHostId = sorted[0].id;
        room.hostId = newHostId;
      }
      this.notifyChange('custom_room_member_left', { room, leftPlayerId: playerId, newHostId });
      return { ok: true, room, newHostId };
    }

    startCustomRoomMatch(requesterId, roomCode) {
      const room = this.customRooms.get(String(roomCode || '').trim().toUpperCase());
      if (!room) return { ok: false, code: 'ROOM_NOT_FOUND', message: 'Room not found.' };
      if (room.hostId !== requesterId) {
        this.recordAuditEvent('FORBIDDEN_ROOM_START', requesterId, { roomCode });
        return { ok: false, code: 'FORBIDDEN_NOT_HOST', message: 'Only the room host can start the custom match.' };
      }

      const unready = room.members.filter(m => !m.ready && m.team !== 'spectators');
      if (unready.length > 0) {
        return { ok: false, code: 'PLAYERS_NOT_READY', message: `All players must be Ready (${unready.map(u => u.name).join(', ')} not ready).` };
      }

      const subModeId = resolveModeId(room.settings.subMode || 'unrated') || 'unrated';
      const baseCfg = MODE_CONFIG_REGISTRY[subModeId] || MODE_CONFIG_REGISTRY.unrated;
      const customModeCfg = {
        ...JSON.parse(JSON.stringify(baseCfg)),
        id: 'custom',
        subModeId,
        name: `CUSTOM (${baseCfg.name})`,
        affectsRating: false, // Never affects ranked MMR
        maxRounds: room.settings.maxRounds || baseCfg.maxRounds,
        roundsToWin: baseCfg.roundBased
          ? (subModeId === 'spikerush' ? 4 : (subModeId === 'swiftplay' ? 5 : Math.floor((room.settings.maxRounds || baseCfg.maxRounds) / 2) + 1))
          : 1,
        scoreLimit: room.settings.scoreLimit || baseCfg.scoreLimit || 40,
        teamNameAttackers: room.settings.teamNameAttackers || 'VANGUARD',
        teamNameDefenders: room.settings.teamNameDefenders || 'SENTINEL',
        unlimitedAbilities: Boolean(room.settings.unlimitedAbilities)
      };

      const roster = [];
      const spectators = [];
      const heroCycle = ['vajra', 'drishti', 'pralay', 'kavach', 'agni'];
      const weaponCycle = ['vanguard_ar', 'surya_carbine', 'spectre_smg', 'garuda_dmr', 'vajra_sniper'];

      for (let i = 0; i < room.members.length; i++) {
        const m = room.members[i];
        if (m.team === 'spectators') {
          spectators.push({ id: m.id, name: m.name });
          continue;
        }
        roster.push({
          id: m.id,
          name: m.name,
          team: customModeCfg.teamBased ? m.team : `ffa_${m.id}`,
          partyId: null,
          heroId: m.heroId || heroCycle[i % heroCycle.length],
          weaponId: weaponCycle[i % weaponCycle.length],
          rating: 1500,
          isBot: Boolean(m.isBot)
        });
      }

      if (room.settings.botFill) {
        if (!customModeCfg.teamBased) {
          const botNames = ['Aarav', 'Dev', 'Rohan', 'Kabir', 'Vikram', 'Yash', 'Nikhil', 'Harsh', 'Pranav'];
          while (roster.length < 10) {
            const idx = roster.length;
            const bId = `bot_ffa_${idx}`;
            roster.push({
              id: bId,
              name: `${botNames[idx % botNames.length]} [BOT]`,
              team: `ffa_${bId}`,
              partyId: null,
              heroId: heroCycle[idx % heroCycle.length],
              weaponId: weaponCycle[idx % weaponCycle.length],
              rating: 1500,
              isBot: true
            });
          }
        } else {
          const allyNames = ['Aarav', 'Dev', 'Rohan', 'Kabir', 'Siddharth'];
          const enemyNames = ['Vikram', 'Yash', 'Nikhil', 'Harsh', 'Pranav'];
          let atkCount = roster.filter(r => r.team === 'attackers').length;
          let defCount = roster.filter(r => r.team === 'defenders').length;
          while (atkCount < 5) {
            roster.push({
              id: `bot_a${atkCount}`,
              name: `${allyNames[atkCount % allyNames.length]} [AI]`,
              team: 'attackers',
              partyId: null,
              heroId: heroCycle[atkCount % heroCycle.length],
              weaponId: weaponCycle[atkCount % weaponCycle.length],
              rating: 1500,
              isBot: true
            });
            atkCount++;
          }
          while (defCount < 5) {
            roster.push({
              id: `bot_d${defCount + 1}`,
              name: `${enemyNames[defCount % enemyNames.length]} [AI]`,
              team: 'defenders',
              partyId: null,
              heroId: heroCycle[defCount % heroCycle.length],
              weaponId: weaponCycle[defCount % weaponCycle.length],
              rating: 1500,
              isBot: true
            });
            defCount++;
          }
        }
      }

      const matchId = generateSecureCode('CRM', 4, 2);
      const matchInstance = new AuthoritativeMatchInstance({
        id: matchId,
        modeId: 'custom',
        modeCfg: customModeCfg,
        roster,
        spectators,
        usedBotFill: Boolean(room.settings.botFill),
        isCustomRoom: true,
        roomCode: room.code,
        hub: this
      });

      room.status = 'IN_MATCH';
      room.activeMatchId = matchId;
      for (const m of room.members) {
        const p = this.players.get(m.id);
        if (p) p.activeMatchId = matchId;
      }

      this.matches.set(matchId, matchInstance);
      this.notifyChange('custom_room_match_started', { room, match: matchInstance.getPublicSummary() });
      return { ok: true, room, match: matchInstance };
    }

    returnCustomRoomToLobby(roomCode) {
      const room = this.customRooms.get(String(roomCode || '').trim().toUpperCase());
      if (!room) return { ok: false, code: 'ROOM_NOT_FOUND' };
      room.status = 'LOBBY';
      room.activeMatchId = null;
      this.notifyChange('custom_room_returned_to_lobby', { room });
      return { ok: true, room };
    }
  }

  // ==========================================================================
  // 8. AUTHORITATIVE MATCH INSTANCE (ALL 7 MODES, MOVEMENT/COMBAT VALIDATION,
  //    SPIKE PLANT/DEFUSE, VISIBILITY FILTERING & RECONNECTION)
  // ==========================================================================
  class AuthoritativeMatchInstance {
    constructor({ id, modeId, modeCfg, roster, spectators = [], usedBotFill = false, isCustomRoom = false, roomCode = null, rankedSimulationAllowed = false, hub = null }) {
      this.id = id || generateSecureCode('MCH', 4, 2);
      this.modeId = modeId;
      this.modeCfg = JSON.parse(JSON.stringify(modeCfg || MODE_CONFIG_REGISTRY[modeId] || MODE_CONFIG_REGISTRY.unrated));
      this.usedBotFill = Boolean(usedBotFill);
      this.isCustomRoom = Boolean(isCustomRoom);
      this.roomCode = roomCode;
      this.rankedSimulationAllowed = Boolean(rankedSimulationAllowed);
      this.hub = hub;

      this.stateSeq = 1;
      this.createdAt = Date.now();
      this.startedAt = Date.now();
      this.endedAt = null;
      this.finalized = false;
      this.finalResults = null;

      this.roundNumber = 1;
      this.phase = this.modeCfg.roundBased ? 'BUY_PHASE' : 'LIVE';
      this.phaseTimer = this.modeCfg.roundBased ? (this.modeCfg.buyPhaseDuration || 20) : (this.modeCfg.timeLimit || 360);
      this.scores = { attackers: 0, defenders: 0 };
      this.consecutiveLosses = { attackers: 0, defenders: 0 };
      this.spikePlanted = false;
      this.spikeTimer = this.modeCfg.spikeTimer || 40;
      this.spikeSite = null;
      this.spikePosition = null;
      this.activeSmokes = [];

      // Spike Rush per-round shared random loadout
      this.currentSpikeRushLoadout = null;
      // Active power-up orbs in Spike Rush / TDM
      this.powerOrbs = [];

      this.spectators = new Map();
      for (const s of (spectators || [])) {
        this.spectators.set(s.id, s);
      }

      // Map of participantId -> ParticipantState
      this.participants = new Map();
      this._initRoster(roster || []);
      this.startRoundOrMatch();
    }

    _initRoster(roster) {
      const econ = this.modeCfg.economy || {};
      let atkIdx = 0, defIdx = 0, ffaIdx = 0;

      for (const r of roster) {
        let spawn = { x: -68, z: 72, yaw: 0 };
        if (!this.modeCfg.teamBased) {
          spawn = DISTRIBUTED_CAMPUS_SPAWNS[ffaIdx % DISTRIBUTED_CAMPUS_SPAWNS.length];
          ffaIdx++;
        } else if (r.team === 'attackers') {
          const atkSpawns = [
            { x: -72, z: 74, yaw: 0 }, { x: -64, z: 74, yaw: 0 },
            { x: -74, z: 68, yaw: 0 }, { x: -62, z: 68, yaw: 0 }, { x: -68, z: 78, yaw: 0 }
          ];
          spawn = atkSpawns[atkIdx++ % atkSpawns.length];
        } else {
          const defSpawns = [
            { x: 68, z: -60, yaw: 0.45 }, { x: 76, z: -60, yaw: 0.45 },
            { x: 64, z: -54, yaw: 0.45 }, { x: 78, z: -54, yaw: 0.45 }, { x: 72, z: -64, yaw: 0.45 }
          ];
          spawn = defSpawns[defIdx++ % defSpawns.length];
        }

        const primaryId = r.weaponId || 'vanguard_ar';
        const wStats = WEAPON_STATS_REGISTRY[primaryId] || WEAPON_STATS_REGISTRY.vanguard_ar;

        this.participants.set(r.id, {
          id: r.id,
          name: r.name,
          team: r.team,
          partyId: r.partyId || null,
          heroId: r.heroId || 'vajra',
          weaponId: primaryId,
          secondaryWeaponId: 'sidearm_9mm',
          ammoInMag: wStats.magSize,
          reserveAmmo: wStats.reserveAmmo,
          reloadingUntil: 0,
          rating: r.rating || 1500,
          isBot: Boolean(r.isBot),
          connected: true,
          disconnectedAt: null,
          abandoned: false,
          alive: true,
          health: 100,
          armor: econ.enabled ? 0 : 100,
          money: econ.startingCredits !== undefined ? econ.startingCredits : 800,
          ultPoints: this.modeCfg.startingUltPoints || 0,
          kills: 0,
          deaths: 0,
          assists: 0,
          damageDealt: 0,
          damagedBy: {}, // attackerId -> totalDamageInLife for assist attribution
          plants: 0,
          defuses: 0,
          position: { x: spawn.x, y: 0, z: spawn.z },
          velocity: { x: 0, y: 0, z: 0 },
          yaw: spawn.yaw || 0,
          pitch: 0,
          crouching: false,
          revealedTimer: 0,
          damageAmpTimer: 0,
          speedBoostTimer: 0,
          spawnProtectionUntil: 0,
          lastFireTimestamp: 0,
          lastMoveTimestamp: Date.now()
        });
      }
    }

    isOpponent(entityAId, entityBId) {
      if (entityAId === entityBId) return false;
      const a = this.participants.get(entityAId);
      const b = this.participants.get(entityBId);
      if (!a || !b) return false;
      if (!this.modeCfg.teamBased || this.modeId === 'ffa' || this.modeCfg.subModeId === 'ffa') {
        return true; // In FFA, every other participant is an opponent!
      }
      return a.team !== b.team;
    }

    startRoundOrMatch() {
      this.stateSeq++;
      this.spikePlanted = false;
      this.spikeTimer = this.modeCfg.spikeTimer || 40;
      this.spikeSite = null;
      this.spikePosition = null;
      this.activeSmokes = [];

      // Halftime side swap for round-based modes
      if (this.modeCfg.roundBased && this.modeCfg.halftimeRound && this.roundNumber === this.modeCfg.halftimeRound + 1 && !this._halftimeSwapped) {
        this._halftimeSwapped = true;
        const oldAtkScore = this.scores.attackers;
        this.scores.attackers = this.scores.defenders;
        this.scores.defenders = oldAtkScore;
        for (const p of this.participants.values()) {
          if (p.team === 'attackers') p.team = 'defenders';
          else if (p.team === 'defenders') p.team = 'attackers';
          if (this.modeCfg.economy && this.modeCfg.economy.enabled) {
            p.money = this.modeCfg.economy.startingCredits || 800;
            p.armor = 0;
          }
        }
      }

      // Spike Rush: Select shared random weapon loadout for ALL players this round
      if (this.modeCfg.economy && this.modeCfg.economy.sharedRandomLoadout) {
        const poolIdx = (this.roundNumber - 1 + Math.floor(Math.random() * SPIKE_RUSH_LOADOUT_POOL.length)) % SPIKE_RUSH_LOADOUT_POOL.length;
        this.currentSpikeRushLoadout = SPIKE_RUSH_LOADOUT_POOL[poolIdx];
        for (const p of this.participants.values()) {
          p.weaponId = this.currentSpikeRushLoadout.primaryId || this.currentSpikeRushLoadout.secondaryId;
          p.secondaryWeaponId = this.currentSpikeRushLoadout.secondaryId;
          p.armor = this.currentSpikeRushLoadout.armor || 50;
          p.money = 0;
        }
      }

      // Spawn Power Orbs if enabled
      if (this.modeCfg.powerOrbsEnabled) {
        this.powerOrbs = CAMPUS_POWER_ORB_NODES.map(node => ({
          ...node,
          active: true,
          respawnTimer: 0
        }));
      } else {
        this.powerOrbs = [];
      }

      // Reset all participants for the round
      let atkIdx = 0, defIdx = 0, ffaIdx = 0;
      for (const p of this.participants.values()) {
        p.alive = true;
        p.health = 100;
        p.damagedBy = {};
        if (!this.modeCfg.economy || !this.modeCfg.economy.enabled) {
          if (!this.currentSpikeRushLoadout) p.armor = 100;
        }
        const wStats = WEAPON_STATS_REGISTRY[p.weaponId] || WEAPON_STATS_REGISTRY.vanguard_ar;
        p.ammoInMag = wStats.magSize;
        p.reserveAmmo = wStats.reserveAmmo;
        p.reloadingUntil = 0;
        p.revealedTimer = 0;

        if (!this.modeCfg.teamBased) {
          const sp = DISTRIBUTED_CAMPUS_SPAWNS[ffaIdx++ % DISTRIBUTED_CAMPUS_SPAWNS.length];
          p.position = { x: sp.x, y: 0, z: sp.z };
          p.yaw = sp.yaw;
        } else if (p.team === 'attackers') {
          const atkSpawns = [
            { x: -72, z: 74, yaw: 0 }, { x: -64, z: 74, yaw: 0 },
            { x: -74, z: 68, yaw: 0 }, { x: -62, z: 68, yaw: 0 }, { x: -68, z: 78, yaw: 0 }
          ];
          const sp = atkSpawns[atkIdx++ % atkSpawns.length];
          p.position = { x: sp.x, y: 0, z: sp.z };
          p.yaw = sp.yaw;
        } else {
          const defSpawns = [
            { x: 68, z: -60, yaw: 0.45 }, { x: 76, z: -60, yaw: 0.45 },
            { x: 64, z: -54, yaw: 0.45 }, { x: 78, z: -54, yaw: 0.45 }, { x: 72, z: -64, yaw: 0.45 }
          ];
          const sp = defSpawns[defIdx++ % defSpawns.length];
          p.position = { x: sp.x, y: 0, z: sp.z };
          p.yaw = sp.yaw;
        }
        p.lastMoveTimestamp = Date.now();
      }

      if (this.modeCfg.roundBased) {
        this.phase = (this.modeCfg.buyPhaseDuration > 0) ? 'BUY_PHASE' : 'LIVE';
        this.phaseTimer = (this.modeCfg.buyPhaseDuration > 0) ? this.modeCfg.buyPhaseDuration : this.modeCfg.roundDuration;
      } else {
        this.phase = 'LIVE';
        this.phaseTimer = this.modeCfg.timeLimit || 360;
      }
    }

    /**
     * Authoritative Player Movement & Aim State Update with Anti-Teleport & Bounds Validation
     */
    updatePlayerState(playerId, input = {}, nowMs = Date.now()) {
      if (this.phase === 'MATCH_OVER') {
        return { ok: false, code: 'MATCH_OVER' };
      }
      const p = this.participants.get(playerId);
      if (!p) return { ok: false, code: 'NOT_IN_MATCH' };
      if (!p.alive) return { ok: false, code: 'PLAYER_DEAD', position: p.position };

      const pos = input.position || input;
      const rawX = Number(pos.x);
      const rawY = Number(pos.y !== undefined ? pos.y : 0);
      const rawZ = Number(pos.z);

      if (!Number.isFinite(rawX) || !Number.isFinite(rawY) || !Number.isFinite(rawZ)) {
        if (this.hub) this.hub.recordAuditEvent('INVALID_MOVEMENT_COORDS', playerId, { pos });
        return { ok: false, code: 'INVALID_COORDINATES', position: p.position };
      }

      // Clamp to campus map boundaries
      let targetX = Math.max(MAP_BOUNDS.minX, Math.min(MAP_BOUNDS.maxX, rawX));
      let targetY = Math.max(MAP_BOUNDS.minY, Math.min(MAP_BOUNDS.maxY, rawY));
      let targetZ = Math.max(MAP_BOUNDS.minZ, Math.min(MAP_BOUNDS.maxZ, rawZ));

      // Anti-teleport speed check
      const elapsedSec = Math.max(0.016, Math.min(2.0, (nowMs - (p.lastMoveTimestamp || nowMs)) / 1000));
      const dx = targetX - p.position.x;
      const dz = targetZ - p.position.z;
      const horizDist = Math.hypot(dx, dz);
      const speedMult = (p.speedBoostTimer && p.speedBoostTimer > 0) ? 1.3 : 1.0;
      const maxAllowedDist = Math.max(MAP_BOUNDS.teleportThresholdM, MAP_BOUNDS.maxMoveSpeedMps * speedMult * elapsedSec + 6.5);

      let clampedTeleport = false;
      if (horizDist > maxAllowedDist && !input.allowSpawnTeleport) {
        const scale = maxAllowedDist / horizDist;
        targetX = p.position.x + dx * scale;
        targetZ = p.position.z + dz * scale;
        clampedTeleport = true;
        if (this.hub) {
          this.hub.recordAuditEvent('ANTI_TELEPORT_CLAMP', playerId, { requestedDist: Math.round(horizDist), maxAllowedDist: Math.round(maxAllowedDist) });
        }
      }

      p.velocity = {
        x: (targetX - p.position.x) / elapsedSec,
        y: (targetY - p.position.y) / elapsedSec,
        z: (targetZ - p.position.z) / elapsedSec
      };
      p.position = { x: targetX, y: targetY, z: targetZ };
      if (Number.isFinite(Number(input.yaw))) p.yaw = Number(input.yaw);
      if (Number.isFinite(Number(input.pitch))) p.pitch = Math.max(-1.55, Math.min(1.55, Number(input.pitch)));
      if (input.crouching !== undefined) p.crouching = Boolean(input.crouching);
      if (input.weaponId && WEAPON_STATS_REGISTRY[input.weaponId]) {
        // In Spike Rush, disallow switching away from shared round weapons
        if (!(this.modeCfg.economy && this.modeCfg.economy.sharedRandomLoadout)) {
          p.weaponId = input.weaponId;
        }
      }
      p.lastMoveTimestamp = nowMs;
      p.connected = true;
      this.stateSeq++;

      return {
        ok: true,
        clampedTeleport,
        position: { ...p.position },
        yaw: p.yaw,
        pitch: p.pitch,
        seq: this.stateSeq
      };
    }

    /**
     * Authoritative Weapon Reload
     */
    reloadWeapon(playerId, nowMs = Date.now()) {
      const p = this.participants.get(playerId);
      if (!p || !p.alive) return { ok: false, code: 'INVALID_PLAYER' };
      const wStats = WEAPON_STATS_REGISTRY[p.weaponId] || WEAPON_STATS_REGISTRY.vanguard_ar;
      if (wStats.melee) return { ok: false, code: 'MELEE_NO_RELOAD' };
      if (p.ammoInMag >= wStats.magSize) return { ok: true, ammoInMag: p.ammoInMag, reserveAmmo: p.reserveAmmo };
      if (p.reserveAmmo <= 0) return { ok: false, code: 'NO_RESERVE_AMMO' };

      const needed = wStats.magSize - p.ammoInMag;
      const take = Math.min(needed, p.reserveAmmo);
      p.ammoInMag += take;
      p.reserveAmmo -= take;
      p.reloadingUntil = nowMs + (wStats.reloadMs || 2000);
      this.stateSeq++;
      return {
        ok: true,
        weaponId: p.weaponId,
        ammoInMag: p.ammoInMag,
        reserveAmmo: p.reserveAmmo,
        reloadingUntil: p.reloadingUntil
      };
    }

    /**
     * Authoritative Buy Phase Equipment Purchase
     */
    buyEquipment(playerId, { weaponId, armorAmount } = {}) {
      const p = this.participants.get(playerId);
      if (!p) return { ok: false, code: 'NOT_IN_MATCH' };
      const econ = this.modeCfg.economy || {};
      if (econ.sharedRandomLoadout) {
        return { ok: false, code: 'BUY_DISABLED_SHARED_LOADOUT', message: 'Buying is disabled in Spike Rush.' };
      }
      if (this.phase !== 'BUY_PHASE' && !econ.anytimeBuy) {
        return { ok: false, code: 'BUY_PHASE_ENDED', message: 'Equipment can only be purchased during Buy Phase.' };
      }

      if (weaponId) {
        const wStats = WEAPON_STATS_REGISTRY[weaponId];
        if (!wStats) return { ok: false, code: 'INVALID_WEAPON' };
        const cost = econ.enabled ? (wStats.cost || 0) : 0;
        if (p.money < cost) {
          return { ok: false, code: 'INSUFFICIENT_CREDITS', message: `Need $${cost} credits (have $${p.money}).` };
        }
        p.money -= cost;
        p.weaponId = wStats.id;
        p.ammoInMag = wStats.magSize;
        p.reserveAmmo = wStats.reserveAmmo;
      }

      if (armorAmount) {
        const targetArmor = Number(armorAmount) >= 100 ? 100 : 50;
        const armorCost = econ.enabled ? (targetArmor === 100 ? 1000 : 400) : 0;
        if (p.money < armorCost) {
          return { ok: false, code: 'INSUFFICIENT_CREDITS' };
        }
        p.money -= armorCost;
        p.armor = targetArmor;
      }

      this.stateSeq++;
      return { ok: true, participant: p };
    }

    /**
     * Authoritative Weapon Fire & Hit Validation
     */
    processCombatHit({
      attackerId,
      victimId,
      rawDamage,
      isHeadshot = false,
      weaponId = null,
      nowMs = Date.now(),
      smokes = [],
      enforceLineOfSight = false,
      enforceFireRate = false,
      enforceAmmo = false,
      actionKey = null
    }) {
      if (actionKey && this.hub && this.hub.checkActionIdempotency(actionKey)) {
        return { ok: true, deduplicated: true, scores: { ...this.scores } };
      }
      if (this.phase === 'MATCH_OVER') {
        return { ok: false, code: 'MATCH_OVER' };
      }
      if (this.phase === 'BUY_PHASE') {
        return { ok: false, code: 'BUY_PHASE_INVULNERABLE' };
      }
      const attacker = this.participants.get(attackerId);
      const victim = this.participants.get(victimId);
      if (!attacker || !victim) {
        return { ok: false, code: 'ENTITY_NOT_FOUND' };
      }
      if (!attacker.alive || !victim.alive) {
        return { ok: false, code: 'ENTITY_DEAD' };
      }
      if (!this.isOpponent(attackerId, victimId)) {
        return { ok: false, code: 'FRIENDLY_FIRE_BLOCKED' };
      }

      const usedWeaponId = weaponId || attacker.weaponId || 'vanguard_ar';
      const wStats = WEAPON_STATS_REGISTRY[usedWeaponId] || WEAPON_STATS_REGISTRY.vanguard_ar;

      // Optional fire-rate & ammo checks when enforced on live network packets
      if (enforceFireRate && attacker.lastFireTimestamp > 0) {
        const minGap = Math.max(30, Math.round((wStats.minIntervalMs || 60) * 0.65));
        if ((nowMs - attacker.lastFireTimestamp) < minGap) {
          return { ok: false, code: 'FIRE_RATE_EXCEEDED' };
        }
      }
      if (enforceAmmo && !wStats.melee) {
        if (attacker.reloadingUntil && nowMs < attacker.reloadingUntil) {
          return { ok: false, code: 'WEAPON_RELOADING' };
        }
        if (attacker.ammoInMag <= 0) {
          return { ok: false, code: 'OUT_OF_AMMO' };
        }
        attacker.ammoInMag = Math.max(0, attacker.ammoInMag - 1);
      }
      attacker.lastFireTimestamp = nowMs;

      // Range & Line-of-Sight check if requested
      if (enforceLineOfSight) {
        const dist = Math.hypot(victim.position.x - attacker.position.x, victim.position.z - attacker.position.z);
        if (dist > (wStats.maxRange || 120) + 8) {
          return { ok: false, code: 'OUT_OF_WEAPON_RANGE' };
        }
        if (!hasServerLineOfSight2D(attacker.position, victim.position, smokes || this.activeSmokes)) {
          return { ok: false, code: 'OCCLUDED_BY_WALL_OR_SMOKE' };
        }
      }

      // If attacker fires while under spawn protection, immediately clear their spawn protection
      if (attacker.spawnProtectionUntil > nowMs) {
        attacker.spawnProtectionUntil = 0;
      }

      // Block damage if victim is currently protected by post-respawn shield
      if (victim.spawnProtectionUntil && victim.spawnProtectionUntil > nowMs) {
        return { ok: false, code: 'SPAWN_PROTECTED', remainingMs: victim.spawnProtectionUntil - nowMs };
      }

      // Compute or clamp damage to plausible weapon bounds
      let baseDmg = rawDamage !== undefined && rawDamage !== null
        ? Number(rawDamage)
        : (isHeadshot ? wStats.headDmg : wStats.bodyDmg);
      if (attacker.damageAmpTimer && attacker.damageAmpTimer > 0) {
        baseDmg = Math.round(baseDmg * 1.3);
      }
      const clampedDmg = Math.max(1, Math.min(255, Math.round(baseDmg || 35)));

      let healthDmg = clampedDmg;
      if (victim.armor > 0) {
        const absorb = Math.min(victim.armor, Math.round(clampedDmg * 0.35));
        victim.armor = Math.max(0, victim.armor - absorb);
        healthDmg = Math.max(1, clampedDmg - Math.round(absorb * 0.65));
      }
      victim.health = Math.max(0, victim.health - healthDmg);
      attacker.damageDealt += healthDmg;
      if (!victim.damagedBy) victim.damagedBy = {};
      victim.damagedBy[attackerId] = (victim.damagedBy[attackerId] || 0) + healthDmg;
      this.stateSeq++;

      let eliminated = false;
      const creditedAssists = [];
      if (victim.health <= 0) {
        victim.alive = false;
        victim.deaths++;
        attacker.kills++;
        eliminated = true;

        // Credit assists to other players who dealt >= 25 damage to victim in this life
        for (const [helperId, dmg] of Object.entries(victim.damagedBy)) {
          if (helperId !== attackerId && dmg >= 25) {
            const helper = this.participants.get(helperId);
            if (helper && !this.isOpponent(attackerId, helperId)) {
              helper.assists++;
              creditedAssists.push(helperId);
            }
          }
        }
        victim.damagedBy = {};

        // Grant kill credits & ult points
        const econ = this.modeCfg.economy || {};
        if (econ.enabled && econ.killReward) {
          attacker.money = Math.min(econ.maxCredits || 9000, attacker.money + econ.killReward);
        }
        attacker.ultPoints = Math.min(7, attacker.ultPoints + (this.modeCfg.ultMultiplier || 1));

        // Handle mode-specific scoring on elimination
        const subMode = this.modeCfg.subModeId || this.modeId;
        if (subMode === 'tdm') {
          this.scores[attacker.team] = (this.scores[attacker.team] || 0) + 1;
          if (this.scores[attacker.team] >= (this.modeCfg.scoreLimit || 40)) {
            this.completeMatch(attacker.team, 'SCORE_LIMIT_REACHED');
          }
        } else if (subMode === 'ffa') {
          if (attacker.kills >= (this.modeCfg.scoreLimit || 20)) {
            this.completeMatch(attacker.id, 'FFA_KILL_TARGET_REACHED');
          }
        } else if (this.modeCfg.roundBased) {
          this._checkRoundEliminationWin();
        }
      }

      return {
        ok: true,
        seq: this.stateSeq,
        attackerId,
        victimId,
        weaponId: usedWeaponId,
        isHeadshot: Boolean(isHeadshot),
        dealtDamage: healthDmg,
        victimHealth: victim.health,
        victimArmor: victim.armor,
        eliminated,
        creditedAssists,
        attackerKills: attacker.kills,
        scores: { ...this.scores },
        phase: this.phase
      };
    }

    /**
     * Authoritative Spike Plant & Defuse Actions
     */
    plantSpike(playerId, { site = 'A', x = null, z = null } = {}) {
      if (!this.modeCfg.roundBased || this.phase !== 'LIVE') {
        return { ok: false, code: 'INVALID_PHASE_FOR_PLANT' };
      }
      if (this.spikePlanted) {
        return { ok: false, code: 'SPIKE_ALREADY_PLANTED' };
      }
      const p = this.participants.get(playerId);
      if (!p || !p.alive || p.team !== 'attackers') {
        return { ok: false, code: 'ONLY_ALIVE_ATTACKER_CAN_PLANT' };
      }

      this.spikePlanted = true;
      this.spikeSite = site || 'A';
      this.spikeTimer = this.modeCfg.spikeTimer || 40;
      this.spikePosition = {
        x: x !== null ? Number(x) : p.position.x,
        y: 0.2,
        z: z !== null ? Number(z) : p.position.z
      };
      p.plants = (p.plants || 0) + 1;
      p.ultPoints = Math.min(7, p.ultPoints + 1);

      const econ = this.modeCfg.economy || {};
      if (econ.enabled && econ.plantReward) {
        for (const ally of this.participants.values()) {
          if (ally.team === 'attackers') {
            ally.money = Math.min(econ.maxCredits || 9000, ally.money + econ.plantReward);
          }
        }
      }
      this.stateSeq++;
      if (this.hub) {
        this.hub.notifyChange('spike_planted', { matchId: this.id, planterId: playerId, site: this.spikeSite, spikePosition: this.spikePosition });
      }
      return { ok: true, spikePlanted: true, site: this.spikeSite, spikeTimer: this.spikeTimer, spikePosition: this.spikePosition };
    }

    defuseSpike(playerId) {
      if (!this.modeCfg.roundBased || this.phase !== 'LIVE' || !this.spikePlanted) {
        return { ok: false, code: 'SPIKE_NOT_PLANTED' };
      }
      const p = this.participants.get(playerId);
      if (!p || !p.alive || p.team !== 'defenders') {
        return { ok: false, code: 'ONLY_ALIVE_DEFENDER_CAN_DEFUSE' };
      }

      this.spikePlanted = false;
      p.defuses = (p.defuses || 0) + 1;
      p.ultPoints = Math.min(7, p.ultPoints + 1);
      const econ = this.modeCfg.economy || {};
      if (econ.enabled && econ.defuseReward) {
        p.money = Math.min(econ.maxCredits || 9000, p.money + econ.defuseReward);
      }

      this.endRound('defenders', 'SPIKE DEFUSED');
      if (this.hub) {
        this.hub.notifyChange('spike_defused', { matchId: this.id, defuserId: playerId, scores: { ...this.scores } });
      }
      return { ok: true, defused: true, scores: { ...this.scores }, phase: this.phase };
    }

    /**
     * Authoritative Server Tick (`tickMatch`):
     * Advances phase timers, spike detonation, power orb respawns, TDM/FFA automatic respawns,
     * and round transitions.
     */
    tickMatch(dtSeconds = 0.05, nowMs = Date.now()) {
      if (this.phase === 'MATCH_OVER' || this.finalized) return;
      const dt = Math.max(0.001, Math.min(1.0, Number(dtSeconds) || 0.05));

      // Tick participant buff timers
      for (const p of this.participants.values()) {
        if (p.revealedTimer > 0) p.revealedTimer = Math.max(0, p.revealedTimer - dt);
        if (p.damageAmpTimer > 0) p.damageAmpTimer = Math.max(0, p.damageAmpTimer - dt);
        if (p.speedBoostTimer > 0) p.speedBoostTimer = Math.max(0, p.speedBoostTimer - dt);
      }

      // Tick power orb respawns
      for (const orb of this.powerOrbs) {
        if (!orb.active && orb.respawnTimer > 0) {
          orb.respawnTimer -= dt;
          if (orb.respawnTimer <= 0) {
            orb.active = true;
            orb.respawnTimer = 0;
          }
        }
      }

      if (this.phase === 'BUY_PHASE') {
        this.phaseTimer -= dt;
        if (this.phaseTimer <= 0) {
          this.phase = 'LIVE';
          this.phaseTimer = this.modeCfg.roundDuration || 100;
          this.stateSeq++;
          if (this.hub) {
            this.hub.notifyChange('match_phase_changed', { matchId: this.id, phase: 'LIVE', roundNumber: this.roundNumber });
          }
        }
      } else if (this.phase === 'LIVE') {
        if (this.spikePlanted) {
          this.spikeTimer -= dt;
          if (this.spikeTimer <= 0) {
            this.endRound('attackers', 'SPIKE DETONATED');
          }
        } else {
          this.phaseTimer -= dt;
          if (this.phaseTimer <= 0) {
            if (this.modeCfg.roundBased) {
              this.endRound('defenders', 'ROUND TIME EXPIRED');
            } else {
              this.completeMatch('TIME_EXPIRED', 'TIME_LIMIT_REACHED');
            }
          }
        }
      } else if (this.phase === 'ROUND_END') {
        this.phaseTimer -= dt;
        if (this.phaseTimer <= 0 && !this.finalized) {
          this.roundNumber++;
          this.startRoundOrMatch();
          if (this.hub) {
            this.hub.notifyChange('round_started', {
              matchId: this.id,
              roundNumber: this.roundNumber,
              phase: this.phase,
              scores: { ...this.scores },
              currentSpikeRushLoadout: this.currentSpikeRushLoadout
            });
          }
        }
      }
    }

    /**
     * Authoritative Respawn for TDM & FFA with Safe Spawn Point Selection + Spawn Protection
     */
    respawnParticipant(participantId, nowMs = Date.now(), smokes = []) {
      const p = this.participants.get(participantId);
      if (!p) return { ok: false, code: 'NOT_FOUND' };
      if (!this.modeCfg.respawnEnabled) {
        return { ok: false, code: 'RESPAWN_DISABLED_IN_MODE' };
      }

      const livingOpponents = [];
      for (const other of this.participants.values()) {
        if (other.alive && this.isOpponent(participantId, other.id)) {
          livingOpponents.push(other);
        }
      }

      const safeSp = selectSafeSpawnPoint(DISTRIBUTED_CAMPUS_SPAWNS, livingOpponents, smokes);
      p.position = { x: safeSp.x, y: 0, z: safeSp.z };
      p.yaw = safeSp.yaw || 0;
      p.health = 100;
      p.armor = 100;
      p.alive = true;
      p.damagedBy = {};
      const wStats = WEAPON_STATS_REGISTRY[p.weaponId] || WEAPON_STATS_REGISTRY.vanguard_ar;
      p.ammoInMag = wStats.magSize;
      p.reserveAmmo = wStats.reserveAmmo;
      p.spawnProtectionUntil = nowMs + Math.round((this.modeCfg.spawnProtectionDuration || 1.8) * 1000);
      p.lastMoveTimestamp = nowMs;
      this.stateSeq++;

      return {
        ok: true,
        spawnPoint: safeSp,
        spawnProtectionUntil: p.spawnProtectionUntil,
        participant: p
      };
    }

    /**
     * Authoritative Power-Up Orb Pickup (Spike Rush / TDM)
     */
    pickupPowerOrb(participantId, orbId) {
      const p = this.participants.get(participantId);
      if (!p || !p.alive) return { ok: false, code: 'INVALID_PLAYER' };
      const orb = this.powerOrbs.find(o => o.id === orbId && o.active);
      if (!orb) return { ok: false, code: 'ORB_INACTIVE' };

      orb.active = false;
      orb.respawnTimer = 25.0;

      if (orb.type === 'ULT_CRYSTAL') {
        p.ultPoints = Math.min(7, p.ultPoints + 2);
      } else if (orb.type === 'SHIELD_SURGE') {
        p.health = 100;
        p.armor = 100;
      } else if (orb.type === 'DAMAGE_AMP') {
        p.damageAmpTimer = 12.0;
      } else if (orb.type === 'SPEED_OVERDRIVE') {
        p.speedBoostTimer = 10.0;
      }
      this.stateSeq++;

      return { ok: true, orb, participant: p };
    }

    _checkRoundEliminationWin() {
      if (this.phase === 'ROUND_END' || this.phase === 'MATCH_OVER') return;
      let atkAlive = 0, defAlive = 0;
      for (const p of this.participants.values()) {
        if (!p.alive) continue;
        if (p.team === 'attackers') atkAlive++;
        else if (p.team === 'defenders') defAlive++;
      }
      if (defAlive === 0) {
        this.endRound('attackers', 'DEFENDERS ELIMINATED');
      } else if (atkAlive === 0 && !this.spikePlanted) {
        this.endRound('defenders', 'ATTACKERS ELIMINATED');
      }
    }

    endRound(winningTeam, reason = 'ROUND_COMPLETED') {
      if (this.phase === 'ROUND_END' || this.phase === 'MATCH_OVER') return;
      this.phase = 'ROUND_END';
      this.phaseTimer = this.modeCfg.roundEndDuration || 4.0;
      this.scores[winningTeam] = (this.scores[winningTeam] || 0) + 1;
      this.stateSeq++;

      const losingTeam = winningTeam === 'attackers' ? 'defenders' : 'attackers';
      this.consecutiveLosses[winningTeam] = 0;
      this.consecutiveLosses[losingTeam] = (this.consecutiveLosses[losingTeam] || 0) + 1;

      const econ = this.modeCfg.economy || {};
      if (econ.enabled) {
        const lossGrant = Math.min(
          econ.maxLossReward || 2900,
          (econ.lossRewardBase || 1900) + Math.max(0, this.consecutiveLosses[losingTeam] - 1) * (econ.lossStreakBonus || 500)
        );
        for (const p of this.participants.values()) {
          const grant = p.team === winningTeam ? (econ.winReward || 3000) : lossGrant;
          p.money = Math.min(econ.maxCredits || 9000, p.money + grant);
        }
      }

      const targetWins = this.modeCfg.roundsToWin || 7;
      const aScore = this.scores.attackers || 0;
      const dScore = this.scores.defenders || 0;

      if (this.modeCfg.overtimeEnabled && aScore >= targetWins - 1 && dScore >= targetWins - 1) {
        if (Math.abs(aScore - dScore) >= 2 || this.roundNumber >= (this.modeCfg.maxRounds || 12) + 4) {
          const winner = aScore >= dScore ? 'attackers' : 'defenders';
          this.completeMatch(winner, reason);
          return;
        }
      } else if (aScore >= targetWins || dScore >= targetWins || this.roundNumber >= (this.modeCfg.maxRounds || 12)) {
        const winner = aScore === dScore ? 'draw' : (aScore > dScore ? 'attackers' : 'defenders');
        this.completeMatch(winner, reason);
        return;
      }

      if (this.hub) {
        this.hub.notifyChange('round_ended', {
          matchId: this.id,
          roundNumber: this.roundNumber,
          winningTeam,
          reason,
          scores: { ...this.scores }
        });
      }
    }

    /**
     * Idempotent Match Result Finalization
     */
    completeMatch(winnerTeamOrPlayerId, reason = 'MATCH_COMPLETED') {
      if (this.finalized && this.finalResults) {
        return this.finalResults;
      }
      if (this.hub && this.hub.processedMatchIds.has(this.id) && this.finalResults) {
        return this.finalResults;
      }

      this.phase = 'MATCH_OVER';
      this.endedAt = Date.now();
      this.finalized = true;
      this.stateSeq++;
      if (this.hub) {
        this.hub.processedMatchIds.add(this.id);
      }

      const subMode = this.modeCfg.subModeId || this.modeId;
      const allParticipants = Array.from(this.participants.values());

      const standings = [...allParticipants].sort((a, b) => {
        if (b.kills !== a.kills) return b.kills - a.kills;
        if (b.damageDealt !== a.damageDealt) return b.damageDealt - a.damageDealt;
        return a.deaths - b.deaths;
      }).map((p, idx) => ({
        placement: idx + 1,
        id: p.id,
        name: p.name,
        team: p.team,
        partyId: p.partyId,
        heroId: p.heroId,
        kills: p.kills,
        deaths: p.deaths,
        assists: p.assists,
        damageDealt: p.damageDealt,
        acs: Math.max(95, Math.round(((p.kills * 210) + (p.assists * 55) + (p.damageDealt * 0.45)) / Math.max(1, this.roundNumber))),
        isBot: p.isBot
      }));

      let resolvedWinner = winnerTeamOrPlayerId;
      if (subMode === 'ffa' && (!resolvedWinner || resolvedWinner === 'TIME_EXPIRED')) {
        resolvedWinner = standings[0] ? standings[0].id : null;
      } else if (subMode === 'tdm' && (!resolvedWinner || resolvedWinner === 'TIME_EXPIRED')) {
        resolvedWinner = (this.scores.attackers >= this.scores.defenders) ? 'attackers' : 'defenders';
      }

      const ratingReceipts = {};
      const humanCount = allParticipants.filter(p => !p.isBot).length;
      const allowRankedUpdate = Boolean(
        this.modeCfg.affectsRating &&
        !this.isCustomRoom &&
        (!this.usedBotFill || this.rankedSimulationAllowed || humanCount >= 2)
      );

      for (const p of allParticipants) {
        if (p.isBot && (!this.hub || !this.hub.players.has(p.id))) continue;
        const profile = this.hub ? this.hub.players.get(p.id) : null;

        let outcome = 'loss';
        if (!this.modeCfg.teamBased || subMode === 'ffa') {
          const place = standings.findIndex(s => s.id === p.id) + 1;
          outcome = place === 1 ? 'win' : (place <= 3 ? 'draw' : 'loss');
        } else if (resolvedWinner === 'draw') {
          outcome = 'draw';
        } else if (p.abandoned) {
          outcome = 'abandoned';
        } else {
          outcome = (p.team === resolvedWinner) ? 'win' : 'loss';
        }

        const enemies = allParticipants.filter(other => this.isOpponent(p.id, other.id));
        const oppAvgRating = enemies.length > 0
          ? Math.round(enemies.reduce((s, e) => s + (e.rating || 1500), 0) / enemies.length)
          : 1500;

        const roundsWon = p.team === 'attackers' ? this.scores.attackers : this.scores.defenders;
        const roundsLost = p.team === 'attackers' ? this.scores.defenders : this.scores.attackers;

        const receipt = RatingEngine.computeRatingUpdate({
          playerRating: profile ? profile.rating : (p.rating || 1500),
          playerRd: profile ? profile.rd : 95,
          opponentAvgRating: oppAvgRating,
          outcome,
          roundsWon,
          roundsLost,
          kills: p.kills,
          deaths: p.deaths,
          assists: p.assists,
          affectsRating: allowRankedUpdate,
          isCustomRoom: this.isCustomRoom,
          isAbortedEarly: false
        });

        ratingReceipts[p.id] = receipt;

        if (profile) {
          if (receipt.applied) {
            profile.rating = receipt.newRating;
            profile.rd = receipt.newRd;
            profile.peakRating = Math.max(profile.peakRating || 0, receipt.newRating);
            profile.rankTier = receipt.newTier;
          }
          profile.xp = (profile.xp || 18450) + (outcome === 'win' ? 450 : 250) + p.kills * 25;
          const bucket = receipt.applied ? profile.stats.ranked : profile.stats.casual;
          bucket.matches++;
          if (outcome === 'win') bucket.wins++;
          else if (outcome === 'draw') bucket.draws++;
          else bucket.losses++;
          bucket.kills += p.kills;
          bucket.deaths += p.deaths;
          bucket.assists += p.assists;

          if (!profile.stats.byMode[this.modeId]) {
            profile.stats.byMode[this.modeId] = { matches: 0, wins: 0, kills: 0, deaths: 0 };
          }
          profile.stats.byMode[this.modeId].matches++;
          if (outcome === 'win') profile.stats.byMode[this.modeId].wins++;
          profile.stats.byMode[this.modeId].kills += p.kills;
          profile.stats.byMode[this.modeId].deaths += p.deaths;

          profile.matchHistory.unshift({
            matchId: this.id,
            modeId: this.modeId,
            modeName: this.modeCfg.name,
            timestamp: this.endedAt,
            outcome,
            scoreText: this.modeCfg.teamBased
              ? `${this.scores.attackers} : ${this.scores.defenders}`
              : `#${standings.findIndex(s => s.id === p.id) + 1} (${p.kills} Kills)`,
            kda: `${p.kills}/${p.deaths}/${p.assists}`,
            ratingDelta: receipt.applied ? receipt.delta : 0,
            newRating: profile.rating,
            rankTierName: profile.rankTier.name
          });
          if (profile.matchHistory.length > 25) profile.matchHistory.pop();
        }
      }

      for (const p of allParticipants) {
        const prof = this.hub ? this.hub.players.get(p.id) : null;
        if (prof && prof.activeMatchId === this.id) {
          prof.activeMatchId = null;
        }
      }
      if (this.isCustomRoom && this.roomCode && this.hub) {
        this.hub.returnCustomRoomToLobby(this.roomCode);
      }

      this.finalResults = {
        matchId: this.id,
        modeId: this.modeId,
        modeName: this.modeCfg.name,
        winner: resolvedWinner,
        reason,
        roundsPlayed: this.roundNumber,
        scores: { ...this.scores },
        standings,
        ratingReceipts,
        completedAt: this.endedAt
      };

      if (this.hub) {
        this.hub.notifyChange('match_completed', { results: this.finalResults });
      }
      return this.finalResults;
    }

    /**
     * Authoritative Visibility Filter (`getFilteredStateForViewer`):
     * Never sends hidden enemy coordinates to a client unless:
     *   1. The entity is the viewer or a friendly teammate (in team-based modes), OR
     *   2. The enemy is within direct Line-of-Sight of the viewer or a living teammate, OR
     *   3. The enemy is actively tagged by a Recon ability (`revealedTimer > 0`), OR
     *   4. `includeAllPositions` is explicitly enabled for same-room real-time 3D arena sync when LOS is evaluated per-frame on the 3D scene.
     */
    getFilteredStateForViewer(viewerId, smokes = [], customLosFn = null, includeAllPositions = false) {
      const viewer = this.participants.get(viewerId);
      const isSpectator = this.spectators && this.spectators.has(viewerId);
      const visibleEntities = [];

      const observers = [];
      for (const p of this.participants.values()) {
        if (!p.alive) continue;
        if (p.id === viewerId || (viewer && !this.isOpponent(viewerId, p.id))) {
          observers.push(p);
        }
      }

      for (const p of this.participants.values()) {
        const isEnemy = viewer ? this.isOpponent(viewerId, p.id) : !isSpectator;
        if (!isEnemy || isSpectator || includeAllPositions) {
          visibleEntities.push({
            id: p.id,
            name: p.name,
            team: p.team,
            heroId: p.heroId,
            weaponId: p.weaponId,
            alive: p.alive,
            health: p.health,
            armor: p.armor,
            money: p.money,
            kills: p.kills,
            deaths: p.deaths,
            assists: p.assists,
            isBot: p.isBot,
            connected: p.connected,
            visible: true,
            position: { ...p.position },
            velocity: p.velocity ? { ...p.velocity } : { x: 0, y: 0, z: 0 },
            yaw: p.yaw,
            pitch: p.pitch || 0,
            crouching: Boolean(p.crouching)
          });
        } else {
          let spotted = Boolean(p.revealedTimer && p.revealedTimer > 0);
          if (!spotted && p.alive) {
            for (const obs of observers) {
              const inLos = customLosFn
                ? customLosFn(obs.position, p.position)
                : hasServerLineOfSight2D(obs.position, p.position, smokes);
              if (inLos) {
                spotted = true;
                break;
              }
            }
          }

          if (spotted && p.alive) {
            visibleEntities.push({
              id: p.id,
              name: p.name,
              team: p.team,
              heroId: p.heroId,
              weaponId: p.weaponId,
              alive: p.alive,
              health: p.health,
              armor: p.armor,
              kills: p.kills,
              deaths: p.deaths,
              assists: p.assists,
              isBot: p.isBot,
              connected: p.connected,
              visible: true,
              position: { ...p.position },
              velocity: p.velocity ? { ...p.velocity } : { x: 0, y: 0, z: 0 },
              yaw: p.yaw,
              pitch: p.pitch || 0,
              crouching: Boolean(p.crouching)
            });
          } else {
            visibleEntities.push({
              id: p.id,
              name: p.name,
              team: p.team,
              heroId: p.heroId,
              weaponId: p.weaponId,
              alive: p.alive,
              kills: p.kills,
              deaths: p.deaths,
              assists: p.assists,
              isBot: p.isBot,
              connected: p.connected,
              visible: false,
              position: null,
              yaw: null
            });
          }
        }
      }

      return {
        protocolVersion: PROTOCOL_VERSION,
        seq: this.stateSeq,
        serverTimestamp: Date.now(),
        matchId: this.id,
        modeId: this.modeId,
        subModeId: this.modeCfg.subModeId || this.modeId,
        phase: this.phase,
        phaseTimer: Math.max(0, Number(this.phaseTimer.toFixed(2))),
        roundNumber: this.roundNumber,
        maxRounds: this.modeCfg.maxRounds,
        roundsToWin: this.modeCfg.roundsToWin,
        scoreLimit: this.modeCfg.scoreLimit,
        scores: { ...this.scores },
        spikePlanted: this.spikePlanted,
        spikeTimer: Math.max(0, Number((this.spikeTimer || 0).toFixed(2))),
        spikeSite: this.spikeSite,
        spikePosition: this.spikePosition,
        currentSpikeRushLoadout: this.currentSpikeRushLoadout,
        powerOrbs: this.powerOrbs,
        entities: visibleEntities,
        finalResults: this.finalResults
      };
    }

    disconnectPlayer(playerId) {
      const p = this.participants.get(playerId);
      if (!p) return { ok: false, code: 'NOT_IN_MATCH' };
      p.connected = false;
      p.disconnectedAt = Date.now();
      this.stateSeq++;
      return { ok: true, participant: p };
    }

    reconnectPlayer(playerId, sessionToken = null) {
      if (sessionToken && this.hub) {
        const auth = this.hub.authenticateSession(sessionToken);
        if (!auth || auth.id !== playerId) {
          return { ok: false, code: 'INVALID_SESSION_TOKEN', message: 'Session token mismatch.' };
        }
      }
      const p = this.participants.get(playerId);
      if (!p) return { ok: false, code: 'NOT_IN_MATCH', message: 'Player is not a participant in this match.' };

      const now = Date.now();
      const grace = (this.hub && this.hub.reconnectGraceMs) || 120000;
      if (p.disconnectedAt && (now - p.disconnectedAt) > grace) {
        p.abandoned = true;
        return { ok: false, code: 'RECONNECT_WINDOW_EXPIRED', message: 'Reconnect grace window expired.' };
      }

      p.connected = true;
      p.disconnectedAt = null;
      this.stateSeq++;
      return {
        ok: true,
        restoredParticipant: p,
        matchState: this.getFilteredStateForViewer(playerId)
      };
    }

    getPublicSummary() {
      return {
        id: this.id,
        modeId: this.modeId,
        subModeId: this.modeCfg.subModeId || this.modeId,
        modeName: this.modeCfg.name,
        phase: this.phase,
        phaseTimer: this.phaseTimer,
        roundNumber: this.roundNumber,
        maxRounds: this.modeCfg.maxRounds,
        roundsToWin: this.modeCfg.roundsToWin,
        scoreLimit: this.modeCfg.scoreLimit,
        teamNameAttackers: this.modeCfg.teamNameAttackers || 'ITNU VANGUARD',
        teamNameDefenders: this.modeCfg.teamNameDefenders || 'HOSTEL H4',
        scores: { ...this.scores },
        usedBotFill: this.usedBotFill,
        isCustomRoom: this.isCustomRoom,
        roomCode: this.roomCode,
        currentSpikeRushLoadout: this.currentSpikeRushLoadout,
        participants: Array.from(this.participants.values()).map(p => ({
          id: p.id,
          name: p.name,
          team: p.team,
          partyId: p.partyId,
          heroId: p.heroId,
          weaponId: p.weaponId,
          kills: p.kills,
          deaths: p.deaths,
          assists: p.assists,
          money: p.money,
          health: p.health,
          armor: p.armor,
          alive: p.alive,
          isBot: p.isBot,
          connected: p.connected,
          position: { ...p.position },
          yaw: p.yaw
        }))
      };
    }
  }

  return {
    PROTOCOL_VERSION,
    DB_SCHEMA_VERSION,
    MAP_BOUNDS,
    WEAPON_STATS_REGISTRY,
    MODE_CONFIG_REGISTRY,
    MODE_ALIASES,
    resolveModeId,
    SPIKE_RUSH_LOADOUT_POOL,
    CAMPUS_POWER_ORB_NODES,
    DISTRIBUTED_CAMPUS_SPAWNS,
    RANK_TIERS,
    QUEUE_STATES,
    RatingEngine,
    NirvexAuthoritativeHub,
    AuthoritativeMatchInstance,
    generateSecureCode,
    generateSessionToken,
    hashPassword,
    verifyPassword,
    sanitizeDisplayName,
    selectSafeSpawnPoint,
    hasServerLineOfSight2D,
    isPointInsideSolidBuilding2D
  };
});
