'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');

const { createTestApp, signIn, cookieValue, TEST_IDENTITY, TEST_SESSION_SECRET } = require('./helpers');
const { createSessionManager, seal, deriveKey } = require('../src/session');

test('unauthenticated /workspace redirects to sign-in', async () => {
  const { app } = createTestApp();

  const res = await request(app).get('/workspace').expect(302);

  assert.equal(res.headers.location, '/auth/signin');
  assert.ok(!/Corporate Access Active/.test(res.text || ''));
});

test('authenticated /workspace renders the identity from the sealed session', async () => {
  const { app, entra } = createTestApp();
  const agent = request.agent(app);

  await signIn(agent, entra);
  const res = await agent.get('/workspace').expect(200);

  assert.match(res.text, /Welcome, Priya Raman/);
  assert.match(res.text, /priya\.raman@contoso\.com/);
  assert.match(res.text, /Identity Verified/);
  assert.match(res.text, /Corporate Access Active/);
  assert.match(res.text, /Verify Corporate Access/);
});

test('landing page sends an already-authenticated employee to the workspace', async () => {
  const { app, entra } = createTestApp();
  const agent = request.agent(app);

  await signIn(agent, entra);
  const res = await agent.get('/').expect(302);

  assert.equal(res.headers.location, '/workspace');
});

test('the public landing page renders for an anonymous visitor', async () => {
  const { app } = createTestApp();

  const res = await request(app).get('/').expect(200);

  assert.match(res.text, /Enterprise Workspace/);
  assert.match(res.text, /Secure Employee Access/);
  assert.match(res.text, /Sign in with Microsoft/);
  assert.match(res.text, /Authorized users only/);
  // The employee-facing page carries no hosting-provider or demo language.
  assert.ok(!/\bGCP\b|Google Cloud|\bdemo\b/i.test(res.text));
});

test('the protected route does not trust client-supplied identity', async () => {
  const { app } = createTestApp();

  // 1. A hand-written, unencrypted session cookie.
  const forged = Buffer.from(
    JSON.stringify({
      displayName: 'Intruder',
      username: 'intruder@contoso.com',
      exp: Date.now() + 60_000,
    }),
  ).toString('base64url');

  const plaintextAttempt = await request(app)
    .get('/workspace')
    .set('Cookie', [`eap_session=${forged}`])
    .expect(302);
  assert.equal(plaintextAttempt.headers.location, '/auth/signin');

  // 2. A properly sealed cookie - but sealed under the attacker's own key.
  const attackerKey = deriveKey('attacker-controlled-secret-value-0123456789', 'session');
  const wrongKeyCookie = seal(
    { displayName: 'Intruder', username: 'intruder@contoso.com', exp: Date.now() + 60_000 },
    attackerKey,
  );

  const wrongKeyAttempt = await request(app)
    .get('/workspace')
    .set('Cookie', [`eap_session=${wrongKeyCookie}`])
    .expect(302);
  assert.equal(wrongKeyAttempt.headers.location, '/auth/signin');

  // 3. Identity smuggled through query, headers and form-style parameters.
  const parameterAttempt = await request(app)
    .get('/workspace')
    .query({ username: 'intruder@contoso.com', displayName: 'Intruder', authenticated: 'true' })
    .set('X-Forwarded-User', 'intruder@contoso.com')
    .expect(302);
  assert.equal(parameterAttempt.headers.location, '/auth/signin');
});

test('a session sealed with the right key but past its expiry is refused', async () => {
  const { app, config } = createTestApp();
  const sessions = createSessionManager(config);
  const key = deriveKey(TEST_SESSION_SECRET, 'session');

  const expired = seal({ ...TEST_IDENTITY, csrf: 'x', exp: Date.now() - 1 }, key);

  const res = await request(app)
    .get('/workspace')
    .set('Cookie', [`${sessions.SESSION_COOKIE}=${expired}`])
    .expect(302);

  assert.equal(res.headers.location, '/auth/signin');
});

test('a tampered session cookie fails authentication rather than degrading', async () => {
  const { app, entra } = createTestApp();

  const signinRes = await request(app).get('/auth/signin').expect(302);
  assert.ok(signinRes.headers.location.startsWith('https://login.microsoftonline.com/'));

  const txn = cookieValue(signinRes, 'eap_auth_txn');
  const callback = await request(app)
    .get('/auth/redirect')
    .query({ code: 'valid-authorization-code', state: entra.lastRequest.state })
    .set('Cookie', [`eap_auth_txn=${txn}`])
    .expect(302);

  const sealed = cookieValue(callback, 'eap_session');
  assert.ok(sealed && sealed.length > 40);

  // The intact cookie authenticates.
  const intact = await request(app).get('/workspace').set('Cookie', [`eap_session=${sealed}`]).expect(200);
  assert.match(intact.text, /Priya Raman/);

  // Flipping any character breaks the GCM authentication tag.
  const tampered = `${sealed.slice(0, -2)}${sealed.slice(-2) === 'AA' ? 'BB' : 'AA'}`;
  const res = await request(app)
    .get('/workspace')
    .set('Cookie', [`eap_session=${tampered}`])
    .expect(302);

  assert.equal(res.headers.location, '/auth/signin');
});
