'use strict';

/**
 * "Verify Corporate Access" is the behaviour the whole demonstration rests on.
 *
 * It must never answer from local state. It must throw the employee back at
 * Microsoft Entra with prompt=login so that Entra - and only Entra - decides
 * whether the account can still authenticate.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');

const { createTestApp, signIn, csrfTokenFrom, cookieHeader, hasNoActiveSession } = require('./helpers');

async function authenticatedAgent() {
  const { app, entra, config } = createTestApp();
  const agent = request.agent(app);
  await signIn(agent, entra);
  const workspace = await agent.get('/workspace').expect(200);
  return { app, entra, config, agent, csrf: csrfTokenFrom(workspace.text) };
}

test('Verify Corporate Access clears the local portal session', async () => {
  const { agent, csrf } = await authenticatedAgent();

  const res = await agent.post('/auth/verify').type('form').send({ csrf_token: csrf }).expect(302);

  // The session cookie is actively expired in the same response.
  const cleared = cookieHeader(res, 'eap_session');
  assert.ok(cleared, 'expected the session cookie to be cleared');
  assert.match(cleared, /Expires=Thu, 01 Jan 1970|Max-Age=0/);

  // And the workspace is no longer reachable with the old session.
  const workspace = await agent.get('/workspace').expect(302);
  assert.equal(workspace.headers.location, '/auth/signin');
});

test('Verify Corporate Access starts a new authentication with prompt=login', async () => {
  const { agent, entra, csrf } = await authenticatedAgent();
  const requestsBefore = entra.requests.length;

  const res = await agent.post('/auth/verify').type('form').send({ csrf_token: csrf }).expect(302);

  assert.equal(entra.requests.length, requestsBefore + 1, 'a new authorization request must be created');

  const authorization = entra.lastRequest;
  assert.equal(authorization.prompt, 'login');

  const url = new URL(res.headers.location);
  assert.equal(url.origin, 'https://login.microsoftonline.com');
  assert.equal(url.searchParams.get('prompt'), 'login');
  assert.equal(res.headers.location, authorization.url);
});

test('Verify Corporate Access mints fresh state, nonce and PKCE material', async () => {
  const { agent, entra, csrf } = await authenticatedAgent();
  const initial = entra.requests[0];

  await agent.post('/auth/verify').type('form').send({ csrf_token: csrf }).expect(302);
  const reverify = entra.lastRequest;

  assert.notEqual(reverify.state, initial.state);
  assert.notEqual(reverify.nonce, initial.nonce);
  assert.notEqual(reverify.codeVerifier, initial.codeVerifier);
});

test('a refused re-authentication leaves the employee locked out of the workspace', async () => {
  const { app, agent, entra, csrf } = await authenticatedAgent();

  await agent.post('/auth/verify').type('form').send({ csrf_token: csrf }).expect(302);

  // Microsoft Entra refuses the disabled account.
  const res = await agent
    .get('/auth/redirect')
    .query({ error: 'access_denied', error_description: 'AADSTS50057' })
    .expect(303);

  assert.equal(res.headers.location, '/auth/error?code=access_denied');
  assert.ok(hasNoActiveSession(res), 'no usable session may be issued');

  const workspace = await agent.get('/workspace').expect(302);
  assert.equal(workspace.headers.location, '/auth/signin');

  // Nothing in the portal can grant access without Entra.
  const landing = await request(app).get('/').expect(200);
  assert.ok(!/Corporate Access Active/.test(landing.text));
});

test('a successful re-authentication restores the workspace for the same employee', async () => {
  const { agent, entra, csrf } = await authenticatedAgent();

  await agent.post('/auth/verify').type('form').send({ csrf_token: csrf }).expect(302);

  const res = await agent
    .get('/auth/redirect')
    .query({ code: 'fresh-authorization-code', state: entra.lastRequest.state })
    .expect(302);
  assert.equal(res.headers.location, '/workspace');

  const workspace = await agent.get('/workspace').expect(200);
  assert.match(workspace.text, /priya\.raman@contoso\.com/);
  assert.match(workspace.text, /Corporate Access Active/);
});

test('Verify Corporate Access requires a valid CSRF token', async () => {
  const { agent } = await authenticatedAgent();

  const res = await agent
    .post('/auth/verify')
    .type('form')
    .send({ csrf_token: 'forged-token-value' })
    .expect(403);

  assert.match(res.text, /Corporate access could not be verified/);
});

test('Verify Corporate Access is refused outright without a session', async () => {
  const { app, entra } = createTestApp();

  const res = await request(app).post('/auth/verify').type('form').send({}).expect(302);

  assert.equal(res.headers.location, '/');
  assert.equal(entra.requests.length, 0);
});

test('sign-out clears the local session only', async () => {
  const { agent, csrf } = await authenticatedAgent();

  const res = await agent.post('/auth/signout').type('form').send({ csrf_token: csrf }).expect(303);

  assert.equal(res.headers.location, '/');
  assert.match(cookieHeader(res, 'eap_session'), /Expires=Thu, 01 Jan 1970|Max-Age=0/);

  const workspace = await agent.get('/workspace').expect(302);
  assert.equal(workspace.headers.location, '/auth/signin');
});

test('sign-out requires a valid CSRF token', async () => {
  const { agent } = await authenticatedAgent();

  await agent.post('/auth/signout').type('form').send({ csrf_token: 'nope' }).expect(403);
});
