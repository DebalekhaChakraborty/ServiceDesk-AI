'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');

const { createTestApp, cookieValue, cookieHeader, hasNoActiveSession } = require('./helpers');

/** Start an authorization request and return its transaction cookie + state. */
async function beginSignIn(app, entra) {
  const res = await request(app).get('/auth/signin').expect(302);
  return {
    txnCookie: cookieValue(res, 'eap_auth_txn'),
    state: entra.lastRequest.state,
    location: res.headers.location,
  };
}

test('GET /auth/signin redirects to the tenant-specific Microsoft authority', async () => {
  const { app, config } = createTestApp();

  const res = await request(app).get('/auth/signin').expect(302);
  const url = new URL(res.headers.location);

  assert.equal(url.origin, 'https://login.microsoftonline.com');
  assert.ok(url.pathname.startsWith(`/${config.tenantId}/`));
  // Multi-tenant and consumer authorities must never appear.
  assert.ok(!/\/(common|organizations|consumers)\//.test(url.pathname));
  assert.equal(url.searchParams.get('response_type'), 'code');
  assert.ok(cookieValue(res, 'eap_auth_txn'));
});

test('the authorization callback rejects an invalid state', async () => {
  const { app, entra } = createTestApp();
  const { txnCookie } = await beginSignIn(app, entra);

  const res = await request(app)
    .get('/auth/redirect')
    .query({ code: 'valid-authorization-code', state: 'attacker-supplied-state' })
    .set('Cookie', [`eap_auth_txn=${txnCookie}`])
    .expect(400);

  assert.match(res.text, /Corporate access could not be verified/);
  // No session is issued, and the code is never redeemed.
  assert.ok(hasNoActiveSession(res), 'no usable session may be issued');
  assert.equal(entra.redemptions.length, 0);
});

test('the authorization callback rejects a missing code', async () => {
  const { app, entra } = createTestApp();
  const { txnCookie, state } = await beginSignIn(app, entra);

  const res = await request(app)
    .get('/auth/redirect')
    .query({ state })
    .set('Cookie', [`eap_auth_txn=${txnCookie}`])
    .expect(400);

  assert.match(res.text, /Corporate access could not be verified/);
  assert.ok(hasNoActiveSession(res), 'no usable session may be issued');
  assert.equal(entra.redemptions.length, 0);
});

test('the authorization callback rejects a response with no in-flight transaction', async () => {
  const { app, entra } = createTestApp();
  const { state } = await beginSignIn(app, entra);

  // No transaction cookie presented at all.
  const res = await request(app)
    .get('/auth/redirect')
    .query({ code: 'valid-authorization-code', state })
    .expect(400);

  assert.ok(hasNoActiveSession(res), 'no usable session may be issued');
  assert.equal(entra.redemptions.length, 0);
});

test('a Microsoft-reported error never renders an authenticated workspace', async () => {
  const { app, entra } = createTestApp();
  const { txnCookie } = await beginSignIn(app, entra);

  const res = await request(app)
    .get('/auth/redirect')
    .query({
      error: 'access_denied',
      error_description: 'AADSTS50057: The user account is disabled.',
    })
    .set('Cookie', [`eap_auth_txn=${txnCookie}`])
    .expect(303);

  assert.equal(res.headers.location, '/auth/error?code=access_denied');
  assert.ok(hasNoActiveSession(res), 'no usable session may be issued');
  assert.equal(entra.redemptions.length, 0);

  // And the workspace stays unreachable.
  const workspace = await request(app).get('/workspace').expect(302);
  assert.equal(workspace.headers.location, '/auth/signin');
});

test('the error page shows the sanitized Microsoft code and invents no reason', async () => {
  const { app } = createTestApp();

  const res = await request(app).get('/auth/error').query({ code: 'access_denied' }).expect(200);

  assert.match(res.text, /Corporate access could not be verified\./);
  assert.match(res.text, /did not complete authentication/);
  assert.match(res.text, /contact the Service Desk/);
  assert.match(res.text, /access_denied/);
  // The portal has no directory visibility, so it must not assert a cause.
  assert.ok(!/disabled|locked out|password/i.test(res.text));
});

test('a hostile error code is not reflected into the page', async () => {
  const { app } = createTestApp();

  const res = await request(app)
    .get('/auth/error')
    .query({ code: '<script>alert(1)</script>' })
    .expect(200);

  assert.ok(!res.text.includes('<script>alert(1)</script>'));
  assert.ok(!res.text.includes('alert(1)'));
});

test('a failed token redemption never establishes a session', async () => {
  const { app, entra } = createTestApp();
  const { txnCookie, state } = await beginSignIn(app, entra);
  entra.failNextRedemption(new Error('nonce_mismatch'));

  const res = await request(app)
    .get('/auth/redirect')
    .query({ code: 'replayed-code', state })
    .set('Cookie', [`eap_auth_txn=${txnCookie}`])
    .expect(401);

  assert.match(res.text, /Corporate access could not be verified/);
  assert.ok(hasNoActiveSession(res), 'no usable session may be issued');
});

test('a successful callback seals a session and clears the transaction', async () => {
  const { app, entra } = createTestApp();
  const { txnCookie, state } = await beginSignIn(app, entra);

  const res = await request(app)
    .get('/auth/redirect')
    .query({ code: 'valid-authorization-code', state })
    .set('Cookie', [`eap_auth_txn=${txnCookie}`])
    .expect(302);

  assert.equal(res.headers.location, '/workspace');
  assert.ok(cookieValue(res, 'eap_session'));
  // The single-use transaction cookie is expired on the way out.
  assert.match(cookieHeader(res, 'eap_auth_txn'), /Expires=Thu, 01 Jan 1970|Max-Age=0/);

  // The PKCE verifier and nonce came from the sealed transaction, not the client.
  assert.equal(entra.redemptions.length, 1);
  assert.equal(entra.redemptions[0].codeVerifier, entra.lastRequest.codeVerifier);
  assert.equal(entra.redemptions[0].expectedNonce, entra.lastRequest.nonce);
});

test('an authorization transaction cannot be replayed', async () => {
  const { app, entra } = createTestApp();
  const { txnCookie, state } = await beginSignIn(app, entra);

  await request(app)
    .get('/auth/redirect')
    .query({ code: 'valid-authorization-code', state })
    .set('Cookie', [`eap_auth_txn=${txnCookie}`])
    .expect(302);

  // Re-presenting the same transaction is still refused by the server, because
  // a fresh state is required for every attempt.
  const replay = await request(app)
    .get('/auth/redirect')
    .query({ code: 'valid-authorization-code', state: 'stale-state' })
    .set('Cookie', [`eap_auth_txn=${txnCookie}`])
    .expect(400);

  assert.ok(hasNoActiveSession(replay), 'no usable session may be issued');
});

test('POST /auth/redirect is accepted for form_post tenants', async () => {
  const { app, entra } = createTestApp();
  const { txnCookie, state } = await beginSignIn(app, entra);

  const res = await request(app)
    .post('/auth/redirect')
    .set('Cookie', [`eap_auth_txn=${txnCookie}`])
    .type('form')
    .send({ code: 'valid-authorization-code', state })
    .expect(302);

  assert.equal(res.headers.location, '/workspace');
});
