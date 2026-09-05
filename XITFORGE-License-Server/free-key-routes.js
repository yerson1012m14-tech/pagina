'use strict';

const crypto = require('node:crypto');

const DURATION_SECONDS = 3 * 60 * 60;
const COOLDOWN_MS = 24 * 60 * 60 * 1000;
const ATTEMPT_MS = 45 * 60 * 1000;
const COOKIE = '__Host-xitforge-free';
const HEX64 = /^[a-f0-9]{64}$/i;
const UUID = /^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/i;
const VERIFY_URL = 'https://publisher.linkvertise.com/api/v1/anti_bypassing';

function licenseDurationSeconds(license) {
  const seconds = license.duration_seconds == null
    ? Number(license.duration_days) * 86400
    : Number(license.duration_seconds);
  return Number.isSafeInteger(seconds) && seconds > 0 ? seconds : 0;
}

// Official protocol: POST, token and hash in the query; only literal TRUE succeeds.
// https://publisher.linkvertise.com/documentations/Anti_Bypass_Documentation.pdf
async function verifyLinkvertise(hash, token, fetchImpl = globalThis.fetch) {
  if (!HEX64.test(hash || '') || !HEX64.test(token || '')) return false;
  const url = new URL(VERIFY_URL);
  url.searchParams.set('token', token);
  url.searchParams.set('hash', hash);
  const response = await fetchImpl(url, {
    method: 'POST', redirect: 'error',
    signal: AbortSignal.timeout(4500),
    headers: { Accept: 'application/json, text/plain' }
  });
  if (!response.ok) return false;
  const body = await response.text();
  return /^true$/i.test(body.trim());
}

function makeCodec(secret) {
  const derive = label => crypto.createHmac('sha256', secret).update(label).digest();
  const receiptSecret = derive('xitforge/free-key/receipt/v1');
  const encryptionKey = derive('xitforge/free-key/encryption/v1');
  const identitySecret = derive('xitforge/free-key/identity/v1');
  const digest = value => crypto.createHmac('sha256', identitySecret).update(value).digest('hex');
  const signature = body => crypto.createHmac('sha256', receiptSecret).update(body).digest();
  return {
    digest,
    receipt(claim) {
      const body = Buffer.from(JSON.stringify({
        id: claim.id, exp: new Date(claim.claimed_at).getTime() + COOLDOWN_MS
      })).toString('base64url');
      return `${body}.${signature(body).toString('base64url')}`;
    },
    readReceipt(token, now = Date.now()) {
      if (typeof token !== 'string' || token.length > 512) return null;
      const parts = token.split('.');
      if (parts.length !== 2 || !parts.every(part => /^[A-Za-z0-9_-]+$/.test(part))) return null;
      const [body, sig] = parts;
      const actual = Buffer.from(sig, 'base64url');
      const expected = signature(body);
      if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) return null;
      try {
        const result = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
        if (!UUID.test(result.id || '') || !Number.isSafeInteger(result.exp) || result.exp <= now) return null;
        return result;
      } catch { return null; }
    },
    encrypt(key) {
      const nonce = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, nonce);
      const encrypted = Buffer.concat([cipher.update(key, 'utf8'), cipher.final()]);
      return [nonce, encrypted, cipher.getAuthTag()].map(value => value.toString('base64url')).join('.');
    },
    decrypt(value) {
      const [nonce, encrypted, tag] = String(value).split('.').map(part => Buffer.from(part, 'base64url'));
      const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey, nonce);
      decipher.setAuthTag(tag);
      return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
    }
  };
}

function readConfig(env, secret) {
  let link = null;
  try {
    const candidate = new URL(env.LINKVERTISE_URL || '');
    if (candidate.protocol === 'https:' &&
        ['linkvertise.com', 'www.linkvertise.com'].includes(candidate.hostname) &&
        !candidate.username && !candidate.password && !candidate.port &&
        /^\/\d+\/[^/]+\/?$/.test(candidate.pathname)) link = candidate.href;
  } catch { /* Configuration remains disabled. */ }
  const token = String(env.LINKVERTISE_ANTI_BYPASS_TOKEN || '').trim();
  return {
    link, token,
    enabled: env.FREE_KEYS_ENABLED === 'true' && !!link && HEX64.test(token) && secret.length >= 32
  };
}

function registerFreeKeyRoutes({ app, pool, rateLimit, generateKey, normalizeKey, hashValue,
  secret = '', env = process.env, fetchImpl = globalThis.fetch }) {
  const config = readConfig(env, secret);
  const codec = makeCodec(secret);
  const website = new URL(env.FREE_KEYS_WEBSITE_URL || 'https://jasonxitoficial.com/');
  const server = new URL(env.FREE_KEYS_SERVER_URL || 'https://xitforge-license-server.onrender.com/');
  if (website.protocol !== 'https:' || server.protocol !== 'https:') {
    throw new Error('Free-key public URLs must use HTTPS.');
  }
  const allowedOrigins = new Set([website.origin, 'https://jasonxitoficial.com', 'https://www.jasonxitoficial.com']);

  async function ensureTables() {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS xf_free_visitors (
        visitor_hash TEXT PRIMARY KEY,
        last_claim_at TIMESTAMPTZ,
        pending_id UUID
      );
      CREATE TABLE IF NOT EXISTS xf_free_networks (
        network_hash TEXT PRIMARY KEY,
        last_claim_at TIMESTAMPTZ
      );
      CREATE TABLE IF NOT EXISTS xf_free_claims (
        id UUID PRIMARY KEY,
        visitor_hash TEXT NOT NULL REFERENCES xf_free_visitors(visitor_hash),
        network_hash TEXT NOT NULL REFERENCES xf_free_networks(network_hash),
        started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        claimed_at TIMESTAMPTZ,
        license_id BIGINT REFERENCES licenses(id) ON DELETE SET NULL,
        key_cipher TEXT
      );
    `);
  }

  function baseHeaders(req, res, next) {
    res.set({ 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer',
      'X-Content-Type-Options': 'nosniff' });
    next();
  }
  app.use(['/free-key', '/api/free-key'], baseHeaders);

  function visitor(req, res, create = false) {
    const cookieHeader = String(req.get('cookie') || '');
    let raw = cookieHeader.split(';').map(part => part.trim())
      .find(part => part.startsWith(`${COOKIE}=`))?.slice(COOKIE.length + 1);
    if (!/^[A-Za-z0-9_-]{43}$/.test(raw || '')) {
      if (!create) return null;
      raw = crypto.randomBytes(32).toString('base64url');
      res.cookie(COOKIE, raw, { secure: true, httpOnly: true,
        sameSite: 'lax', path: '/', maxAge: 90 * COOLDOWN_MS });
    }
    return codec.digest(`visitor:${raw}`);
  }
  function network(req) {
    return codec.digest(`network:${req.ip || req.socket.remoteAddress}`);
  }
  function goHome(res, values) {
    const url = new URL(website.href);
    url.hash = `key-gratis?${new URLSearchParams(values)}`;
    return res.redirect(303, url.href);
  }
  function fail(res, code) { return goHome(res, { error: code }); }
  function requireEnabled(req, res, next) {
    if (!config.enabled) return fail(res, 'not_ready');
    next();
  }
  async function transaction(fn) {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const result = await fn(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK').catch(() => {});
      throw error;
    } finally { client.release(); }
  }
  async function lockVisitor(client, visitorHash) {
    await client.query('INSERT INTO xf_free_visitors (visitor_hash) VALUES ($1) ON CONFLICT DO NOTHING', [visitorHash]);
    return (await client.query('SELECT * FROM xf_free_visitors WHERE visitor_hash = $1 FOR UPDATE', [visitorHash])).rows[0];
  }
  async function lockNetwork(client, networkHash) {
    await client.query('INSERT INTO xf_free_networks (network_hash) VALUES ($1) ON CONFLICT DO NOTHING', [networkHash]);
    return (await client.query('SELECT * FROM xf_free_networks WHERE network_hash = $1 FOR UPDATE', [networkHash])).rows[0];
  }
  function remainingUntil(...rows) {
    return Math.max(0, ...rows.map(row => row?.last_claim_at
      ? new Date(row.last_claim_at).getTime() + COOLDOWN_MS : 0));
  }
  function completeResponse(res, result) {
    if (result.claim) return goHome(res, { receipt: codec.receipt(result.claim) });
    if (result.waitUntil) return goHome(res, { waitUntil: String(result.waitUntil) });
    return fail(res, result.error || 'server_error');
  }

  app.get('/api/free-key/config', rateLimit({ windowMs: 60_000, max: 60 }), (req, res) => {
    res.set('Access-Control-Allow-Origin', '*');
    res.json({ ok: true, enabled: config.enabled, durationHours: 3, cooldownHours: 24,
      startsOnFirstUse: true, startUrl: config.enabled ? new URL('/free-key/start', server).href : null });
  });

  app.get('/free-key/start', rateLimit({ windowMs: 60_000, max: 12 }), requireEnabled, async (req, res) => {
    try {
      const visitorHash = visitor(req, res, true);
      const networkHash = network(req);
      const result = await transaction(async client => {
        const v = await lockVisitor(client, visitorHash);
        const n = await lockNetwork(client, networkHash);
        const current = v.pending_id ? (await client.query('SELECT * FROM xf_free_claims WHERE id = $1', [v.pending_id])).rows[0] : null;
        const waitUntil = remainingUntil(v, n);
        if (waitUntil > Date.now()) {
          if (current?.claimed_at && current.key_cipher &&
              new Date(current.claimed_at).getTime() + COOLDOWN_MS > Date.now()) return { claim: current };
          return { waitUntil };
        }
        if (current && !current.claimed_at && Date.now() - new Date(current.started_at).getTime() < ATTEMPT_MS) {
          return { start: true };
        }
        const id = crypto.randomUUID();
        await client.query('INSERT INTO xf_free_claims (id, visitor_hash, network_hash) VALUES ($1, $2, $3)', [id, visitorHash, networkHash]);
        await client.query('UPDATE xf_free_visitors SET pending_id = $1 WHERE visitor_hash = $2', [id, visitorHash]);
        // Receipts expire after 24 hours; discard the recoverable key material then.
        await client.query("UPDATE xf_free_claims SET key_cipher = NULL WHERE claimed_at < NOW() - INTERVAL '24 hours' AND key_cipher IS NOT NULL");
        return { start: true };
      });
      if (result.start) return res.redirect(303, config.link);
      return completeResponse(res, result);
    } catch {
      console.error('Free-key start failed.');
      return fail(res, 'server_error');
    }
  });

  app.get('/free-key/return', rateLimit({ windowMs: 60_000, max: 12 }), requireEnabled, async (req, res) => {
    const visitorHash = visitor(req, res);
    const proof = typeof req.query.hash === 'string' ? req.query.hash : '';
    if (!visitorHash) return fail(res, 'session_missing');
    try {
      const result = await transaction(async client => {
        const v = await lockVisitor(client, visitorHash);
        if (!v.pending_id) return { error: 'session_missing' };
        const claim = (await client.query('SELECT * FROM xf_free_claims WHERE id = $1 FOR UPDATE', [v.pending_id])).rows[0];
        if (!claim) return { error: 'session_missing' };
        if (claim.claimed_at) {
          if (claim.key_cipher && new Date(claim.claimed_at).getTime() + COOLDOWN_MS > Date.now()) return { claim };
          return { error: 'session_expired' };
        }
        if (Date.now() - new Date(claim.started_at).getTime() >= ATTEMPT_MS) return { error: 'session_expired' };
        const n = await lockNetwork(client, claim.network_hash);
        const waitUntil = remainingUntil(v, n);
        if (waitUntil > Date.now()) return { waitUntil };
        // No license or cooldown is written until the provider confirms this proof.
        if (!await verifyLinkvertise(proof, config.token, fetchImpl)) return { error: 'ads_not_verified' };
        const key = normalizeKey(generateKey());
        const license = (await client.query(`
          INSERT INTO licenses (key_hash, key_prefix, key_last4, status,
            expires_at, duration_days, duration_seconds, first_used_at,
            device_limit, note, created_at, updated_at)
          VALUES ($1, $2, $3, 'new', NULL, NULL, $4, NULL, 1,
            'Key gratis Linkvertise - 3 horas desde el primer uso', NOW(), NOW())
          RETURNING id
        `, [hashValue(key), key.slice(0, 9), key.slice(-4), DURATION_SECONDS])).rows[0];
        const completed = (await client.query(`
          UPDATE xf_free_claims SET claimed_at = clock_timestamp(), license_id = $1, key_cipher = $2
          WHERE id = $3 RETURNING *
        `, [license.id, codec.encrypt(key), claim.id])).rows[0];
        await client.query('UPDATE xf_free_visitors SET last_claim_at = $1 WHERE visitor_hash = $2', [completed.claimed_at, visitorHash]);
        await client.query('UPDATE xf_free_networks SET last_claim_at = $1 WHERE network_hash = $2', [completed.claimed_at, claim.network_hash]);
        return { claim: completed };
      });
      return completeResponse(res, result);
    } catch {
      // Do not log the provider URL, token, hash, receipt or generated key.
      console.error('Free-key verification or database operation failed.');
      return fail(res, 'verification_failed');
    }
  });

  function receiptCors(req, res, next) {
    const origin = req.get('origin');
    if (origin && !allowedOrigins.has(origin)) return res.status(403).json({ ok: false });
    if (origin) res.set('Access-Control-Allow-Origin', origin);
    res.vary('Origin');
    res.set({ 'Access-Control-Allow-Headers': 'Authorization', 'Access-Control-Allow-Methods': 'GET, OPTIONS' });
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    next();
  }
  app.options('/api/free-key/receipt', receiptCors);
  app.get('/api/free-key/receipt', receiptCors, rateLimit({ windowMs: 60_000, max: 60 }), async (req, res) => {
    try {
      if (secret.length < 32) return res.status(503).json({ ok: false, error: 'not_ready' });
      const token = String(req.get('authorization') || '').replace(/^Bearer /, '');
      const receipt = codec.readReceipt(token);
      if (!receipt) return res.status(401).json({ ok: false, error: 'receipt_expired' });
      const row = (await pool.query(`
        SELECT c.*, l.status AS license_status, l.expires_at AS license_expires_at,
          l.first_used_at, l.key_hash AS current_key_hash
        FROM xf_free_claims c LEFT JOIN licenses l ON l.id = c.license_id
        WHERE c.id = $1
      `, [receipt.id])).rows[0];
      if (!row?.claimed_at || !row.key_cipher ||
          new Date(row.claimed_at).getTime() + COOLDOWN_MS !== receipt.exp) {
        return res.status(404).json({ ok: false, error: 'receipt_expired' });
      }
      const key = codec.decrypt(row.key_cipher);
      const usable = ['new', 'active'].includes(row.license_status) &&
        row.current_key_hash === hashValue(key) &&
        (!row.license_expires_at || new Date(row.license_expires_at).getTime() > Date.now());
      return res.json({ ok: true, key: usable ? key : null,
        licenseStatus: usable ? row.license_status : 'unavailable',
        expiresAt: row.license_expires_at, firstUsedAt: row.first_used_at,
        nextClaimAt: new Date(receipt.exp).toISOString(), serverNow: new Date().toISOString(),
        durationHours: 3, cooldownHours: 24 });
    } catch {
      console.error('Free-key receipt lookup failed.');
      return res.status(500).json({ ok: false, error: 'server_error' });
    }
  });

  return { ensureTables, enabled: config.enabled };
}

module.exports = { registerFreeKeyRoutes, licenseDurationSeconds,
  verifyLinkvertise, makeCodec, readConfig, DURATION_SECONDS, COOLDOWN_MS };
