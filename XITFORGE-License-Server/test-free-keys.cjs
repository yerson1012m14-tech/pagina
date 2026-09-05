'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const crypto = require('node:crypto');
const express = require('express');
const { PGlite } = require('@electric-sql/pglite');
const { registerFreeKeyRoutes, verifyLinkvertise, makeCodec, readConfig,
  licenseDurationSeconds, COOLDOWN_MS } = require('./free-key-routes');

test('Linkvertise only accepts an explicit successful response', async () => {
  for (const body of ['false', 'FALSE', '"false"', '{"status":true}', 'Invalid token.', '1', '']) {
    assert.equal(await verifyLinkvertise('b'.repeat(64), 'a'.repeat(64), async () => ({ ok: true, text: async () => body })), false);
  }
  assert.equal(await verifyLinkvertise('b'.repeat(64), 'a'.repeat(64), async url => {
    assert.equal(url.origin, 'https://publisher.linkvertise.com');
    assert.equal(url.searchParams.get('hash'), 'b'.repeat(64));
    return { ok: true, text: async () => 'TRUE' };
  }), true);
  assert.equal(await verifyLinkvertise('wrong', 'a'.repeat(64), () => assert.fail('Invalid hash must not be sent')), false);
  await assert.rejects(verifyLinkvertise('b'.repeat(64), 'a'.repeat(64), async () => { throw new Error('Timeout'); }));
});

test('Receipts expire and reject tampering; encryption does not reveal the key', () => {
  const codec = makeCodec('test-secret-with-at-least-32-characters');
  const claim = { id: crypto.randomUUID(), claimed_at: new Date() };
  const token = codec.receipt(claim);
  assert.equal(codec.readReceipt(token).id, claim.id);
  assert.equal(codec.readReceipt(token, claim.claimed_at.getTime() + COOLDOWN_MS), null);
  const [body, signature] = token.split('.');
  assert.equal(codec.readReceipt(body + '.' + (signature[0] === 'a' ? 'b' : 'a') + signature.slice(1)), null);
  const cipher = codec.encrypt('ABCD-EFGH-JKLM-NPQR');
  assert(!cipher.includes('ABCD'));
  assert.equal(codec.decrypt(cipher), 'ABCD-EFGH-JKLM-NPQR');
  assert.notEqual(codec.digest('visitor:identical'), codec.digest('network:identical'));
});

test('Configuration and duration rules fail closed', () => {
  assert.equal(readConfig({}, 'x'.repeat(32)).enabled, false);
  const env = { FREE_KEYS_ENABLED: 'true', LINKVERTISE_URL: 'https://linkvertise.com/12345/xitforge-test', LINKVERTISE_ANTI_BYPASS_TOKEN: 'a'.repeat(64) };
  assert.equal(readConfig(env, 'x'.repeat(32)).enabled, true);
  assert.equal(readConfig({ ...env, LINKVERTISE_URL: 'https://linkvertise.com.evil.invalid/12345/test' }, 'x'.repeat(32)).enabled, false);
  assert.equal(licenseDurationSeconds({ duration_seconds: '10800', duration_days: null }), 10800);
  assert.equal(licenseDurationSeconds({ duration_days: 7 }), 604800);
  assert.equal(licenseDurationSeconds({ duration_seconds: -1, duration_days: 7 }), 0);
});

test('Real PostgreSQL engine and HTTP routes enforce verified, idempotent claims and 24-hour cooldown', async t => {
  const db = new PGlite();
  await db.waitReady;
  // PGlite uses one connection. Serialize transactions like a pool of size one.
  let tail = Promise.resolve();
  async function acquire() {
    const previous = tail;
    let release;
    tail = new Promise(resolve => { release = resolve; });
    await previous;
    return release;
  }
  async function query(sql, params) {
    if (params?.length || !sql.trim().slice(0, -1).includes(';')) return db.query(sql, params);
    const results = await db.exec(sql);
    return results.at(-1) || { rows: [] };
  }
  const pool = {
    async connect() { const release = await acquire(); return { query, release }; },
    async query(sql, params) { const release = await acquire(); try { return await query(sql, params); } finally { release(); } }
  };
  const source = fs.readFileSync(path.join(__dirname, 'server.js'), 'utf8');
  const schema = source.match(/CREATE TABLE IF NOT EXISTS licenses \([\s\S]*?\);/)[0];
  await db.exec(schema);
  await db.exec('ALTER TABLE licenses ADD COLUMN duration_seconds BIGINT NULL;');
  let now = Date.now();
  class ClockDate extends Date {
    constructor(...args) { super(...(args.length ? args : [now])); }
    static now() { return now; }
  }
  const context = { crypto, pool, Date: ClockDate, licenseDurationSeconds };
  vm.createContext(context);
  const helpers = source.slice(source.indexOf('function nowIso()'), source.indexOf('function parseAppVersion'));
  vm.runInContext(helpers, context);
  const queries = source.slice(source.indexOf('async function getLicenseByHash'), source.indexOf('async function getActivationCount'));
  vm.runInContext(queries, context);
  const app = express();
  app.set('trust proxy', 1);
  const env = { FREE_KEYS_ENABLED: 'true', LINKVERTISE_URL: 'https://linkvertise.com/12345/xitforge-test', LINKVERTISE_ANTI_BYPASS_TOKEN: 'a'.repeat(64) };
  let providerSuccess = false, verifications = 0;
  const module = registerFreeKeyRoutes({ app, pool, env,
    secret: 'test-secret-with-at-least-32-characters',
    rateLimit: () => (req, res, next) => next(),
    generateKey: context.generateKey, normalizeKey: context.normalizeKey, hashValue: context.hashValue,
    fetchImpl: async (url, options) => {
      verifications++;
      assert.equal(url.searchParams.get('token'), env.LINKVERTISE_ANTI_BYPASS_TOKEN);
      assert.equal(options.method, 'POST');
      return { ok: true, text: async () => providerSuccess ? 'true' : 'false' };
    }
  });
  await module.ensureTables();
  await module.ensureTables();
  const server = await new Promise(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
  const base = 'http://127.0.0.1:' + server.address().port;
  t.after(async () => { await new Promise(resolve => server.close(resolve)); await db.close(); });
  async function request(url, cookie = '', ip = '203.0.113.10', extra = {}) {
    return fetch(base + url, { redirect: 'manual', headers: { 'X-Forwarded-For': ip, Cookie: cookie, ...extra } });
  }
  const redirect = res => new URL(res.headers.get('location'));
  const fragment = res => new URLSearchParams(redirect(res).hash.split('?')[1]);
  const count = async () => Number((await pool.query('SELECT COUNT(*) AS n FROM licenses')).rows[0].n);
  const config = await request('/api/free-key/config');
  assert.equal((await config.json()).enabled, true);
  assert.equal(config.headers.get('cache-control'), 'no-store');
  const missing = await request('/free-key/return?hash=' + 'b'.repeat(64));
  assert.equal(fragment(missing).get('error'), 'session_missing');
  assert.equal(verifications, 0);
  const start = await request('/free-key/start');
  assert.equal(start.headers.get('location'), env.LINKVERTISE_URL);
  const rawCookie = start.headers.get('set-cookie');
  assert.match(rawCookie, /HttpOnly/);
  assert.match(rawCookie, /Secure/);
  assert.match(rawCookie, /SameSite=Lax/);
  const cookie = rawCookie.split(';')[0];
  const denied = await request('/free-key/return?hash=' + 'b'.repeat(64), cookie);
  assert.equal(fragment(denied).get('error'), 'ads_not_verified');
  assert.equal(await count(), 0);
  assert.equal((await pool.query('SELECT last_claim_at FROM xf_free_visitors')).rows[0].last_claim_at, null);
  providerSuccess = true;
  const success = await request('/free-key/return?hash=' + 'b'.repeat(64), cookie);
  const receipt = fragment(success).get('receipt');
  assert(receipt);
  assert.equal(await count(), 1);
  const license = (await pool.query('SELECT * FROM licenses')).rows[0];
  assert.equal(Number(license.duration_seconds), 10800);
  assert.equal(license.expires_at, null);
  assert.equal(license.first_used_at, null);
  assert.equal(license.device_limit, 1);
  const auth = { Authorization: 'Bearer ' + receipt, Origin: 'https://jasonxitoficial.com' };
  const result = await (await request('/api/free-key/receipt', '', '203.0.113.10', auth)).json();
  assert.equal(context.hashValue(result.key), license.key_hash);
  assert.equal(Date.parse(result.nextClaimAt) - new Date((await pool.query('SELECT claimed_at FROM xf_free_claims')).rows[0].claimed_at).getTime(), COOLDOWN_MS);
  assert.equal((await request('/api/free-key/receipt', '', '203.0.113.10', { ...auth, Origin: 'https://untrusted.invalid' })).status, 403);
  assert.equal((await request('/api/free-key/receipt', '', '203.0.113.10', { Authorization: 'Bearer invalid' })).status, 401);
  const repeats = await Promise.all([
    request('/free-key/return?hash=' + 'b'.repeat(64), cookie),
    request('/free-key/return?hash=' + 'b'.repeat(64), cookie)
  ]);
  assert(repeats.every(res => fragment(res).get('receipt') === receipt));
  assert.equal(verifications, 2); // One rejected proof and one accepted proof.
  assert.equal(await count(), 1);
  const again = await request('/free-key/start', cookie);
  assert.equal(fragment(again).get('receipt'), receipt);
  const newBrowser = await request('/free-key/start');
  assert(Number(fragment(newBrowser).get('waitUntil')) > Date.now());

  // First-use timing is exercised against the actual functions in server.js.
  now += 10 * 60 * 1000;
  const unused = await context.getLicenseByHash(license.key_hash);
  const activated = await context.activateLicenseOnFirstUse(unused);
  assert.equal(new Date(activated.first_used_at).getTime(), now);
  assert.equal(new Date(activated.expires_at).getTime(), now + 10800000);
  now += 3600000;
  const checkedAgain = await context.activateLicenseOnFirstUse(await context.getLicenseByHash(license.key_hash));
  assert.equal(new Date(checkedAgain.expires_at).getTime(), new Date(activated.expires_at).getTime());
  now += 7200000;
  assert.equal(context.isExpired(checkedAgain.expires_at), true);

  // Existing day-based licenses retain their first-use duration.
  await pool.query("INSERT INTO licenses (key_hash,key_prefix,key_last4,status,duration_days,device_limit,created_at,updated_at) VALUES ('paid','PAID','PAID','new',7,1,NOW(),NOW())");
  const paid = await context.activateLicenseOnFirstUse(await context.getLicenseByHash('paid'));
  assert.equal(new Date(paid.expires_at).getTime(), now + 7 * 86400000);

  // Two visitors sharing one network cannot both complete pending attempts.
  const pendingA = await request('/free-key/start', '', '203.0.113.20');
  const pendingB = await request('/free-key/start', '', '203.0.113.20');
  const cookies = [pendingA, pendingB].map(res => res.headers.get('set-cookie').split(';')[0]);
  const race = await Promise.all(cookies.map(c => request('/free-key/return?hash=' + 'c'.repeat(64), c, '203.0.113.20')));
  assert.equal(race.filter(res => fragment(res).has('receipt')).length, 1);
  assert.equal(race.filter(res => fragment(res).has('waitUntil')).length, 1);

  // Once 24 hours have elapsed, the original visitor can begin a new claim.
  await pool.query("UPDATE xf_free_visitors SET last_claim_at = NOW() - INTERVAL '25 hours'");
  await pool.query("UPDATE xf_free_networks SET last_claim_at = NOW() - INTERVAL '25 hours'");
  await pool.query("UPDATE xf_free_claims SET claimed_at = NOW() - INTERVAL '25 hours' WHERE claimed_at IS NOT NULL");
  const afterCooldown = await request('/free-key/start', cookie);
  assert.equal(afterCooldown.headers.get('location'), env.LINKVERTISE_URL);
});
