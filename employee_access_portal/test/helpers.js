'use strict';

/**
 * Shared test scaffolding.
 *
 * Routing, session sealing and CSRF are exercised against the real
 * implementation. Only the Microsoft network round trip is substituted, via an
 * injected Entra client. That substitution is a unit-test convenience and is
 * explicitly NOT accepted as end-to-end acceptance evidence: acceptance
 * requires live Microsoft Entra authentication (see README, Acceptance Tests).
 */

const { randomUUID } = require('node:crypto');
const { createApp } = require('../src/app');
const { loadConfig } = require('../src/config');

const TEST_TENANT_ID = '11111111-2222-3333-4444-555555555555';
const TEST_CLIENT_ID = '66666666-7777-8888-9999-000000000000';
// Distinctive sentinels so a leak into logs or markup is unmistakable.
const TEST_CLIENT_SECRET = 'CLIENT-SECRET-SENTINEL-a1b2c3d4e5f6g7h8';
const TEST_SESSION_SECRET = 'SESSION-SECRET-SENTINEL-0123456789abcdefghij';

const TEST_IDENTITY = Object.freeze({
  displayName: 'Priya Raman',
  username: 'priya.raman@contoso.com',
  tenantId: TEST_TENANT_ID,
  objectId: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
  authenticatedAt: '2026-08-15T09:00:00.000Z',
});

function testEnv(overrides = {}) {
  return {
    ENTRA_PORTAL_TENANT_ID: TEST_TENANT_ID,
    ENTRA_PORTAL_CLIENT_ID: TEST_CLIENT_ID,
    ENTRA_PORTAL_CLIENT_SECRET: TEST_CLIENT_SECRET,
    PORTAL_BASE_URL: 'http://localhost:8080',
    PORTAL_SESSION_SECRET: TEST_SESSION_SECRET,
    ...overrides,
  };
}

function testConfig(overrides = {}) {
  return loadConfig(testEnv(overrides));
}

/**
 * Stand-in for the Entra client with the same contract as src/entra.js.
 */
function createFakeEntra(config) {
  const requests = [];
  const redemptions = [];
  let identity = { ...TEST_IDENTITY };
  let redemptionError = null;

  return {
    requests,
    redemptions,
    get lastRequest() {
      return requests[requests.length - 1];
    },
    setIdentity(next) {
      identity = { ...identity, ...next };
    },
    failNextRedemption(error) {
      redemptionError = error instanceof Error ? error : new Error(String(error));
    },

    async createAuthorizationRequest({ prompt } = {}) {
      const state = `state-${randomUUID()}`;
      const nonce = `nonce-${randomUUID()}`;
      const codeVerifier = `verifier-${randomUUID()}`;

      const url = new URL(`https://login.microsoftonline.com/${config.tenantId}/oauth2/v2.0/authorize`);
      url.searchParams.set('client_id', config.clientId);
      url.searchParams.set('response_type', 'code');
      url.searchParams.set('response_mode', 'query');
      url.searchParams.set('redirect_uri', config.redirectUri);
      url.searchParams.set('scope', config.scopes.join(' '));
      url.searchParams.set('state', state);
      url.searchParams.set('nonce', nonce);
      url.searchParams.set('code_challenge_method', 'S256');
      if (prompt) url.searchParams.set('prompt', prompt);

      const request = { url: url.toString(), state, nonce, codeVerifier, prompt: prompt || null };
      requests.push(request);
      return request;
    },

    async redeemAuthorizationCode({ code, codeVerifier, expectedNonce }) {
      redemptions.push({ code, codeVerifier, expectedNonce });
      if (redemptionError) {
        const error = redemptionError;
        redemptionError = null;
        throw error;
      }
      return { ...identity };
    },
  };
}

function createTestApp(overrides = {}) {
  const config = testConfig(overrides);
  const entra = createFakeEntra(config);
  const app = createApp({ config, entraClient: entra });
  return { app, config, entra };
}

/** All Set-Cookie headers on a response, as an array. */
function setCookies(res) {
  const raw = res.headers['set-cookie'];
  if (!raw) return [];
  return Array.isArray(raw) ? raw : [raw];
}

/** The Set-Cookie header for one cookie name, or undefined. */
function cookieHeader(res, name) {
  return setCookies(res).find((cookie) => cookie.startsWith(`${name}=`));
}

/** The value of a cookie in a Set-Cookie header, or undefined. */
function cookieValue(res, name) {
  const header = cookieHeader(res, name);
  if (!header) return undefined;
  return header.slice(name.length + 1).split(';')[0];
}

/**
 * The value of a cookie that would actually authenticate a later request.
 *
 * Clearing a cookie is itself a Set-Cookie header with an empty value and a
 * past expiry, so presence of the header is not evidence of a live session.
 */
function activeCookie(res, name) {
  const header = cookieHeader(res, name);
  if (!header) return null;
  const value = header.slice(name.length + 1).split(';')[0];
  if (!value) return null;
  if (/Max-Age=0|Expires=Thu,\s*01 Jan 1970/i.test(header)) return null;
  return value;
}

/** True when the response leaves the browser holding no usable session. */
function hasNoActiveSession(res) {
  return activeCookie(res, 'eap_session') === null;
}

/**
 * Drive a complete (fake) authorization round trip on a supertest agent so the
 * agent ends up holding a genuine, server-sealed session cookie.
 */
async function signIn(agent, entra) {
  await agent.get('/auth/signin').expect(302);
  const request = entra.lastRequest;
  const response = await agent
    .get('/auth/redirect')
    .query({ code: 'valid-authorization-code', state: request.state })
    .expect(302);
  return { request, response };
}

/** Pull the CSRF token out of a rendered workspace page. */
function csrfTokenFrom(html) {
  const match = html.match(/name="csrf_token" value="([^"]+)"/);
  return match ? match[1] : null;
}

module.exports = {
  TEST_TENANT_ID,
  TEST_CLIENT_ID,
  TEST_CLIENT_SECRET,
  TEST_SESSION_SECRET,
  TEST_IDENTITY,
  testEnv,
  testConfig,
  createFakeEntra,
  createTestApp,
  setCookies,
  cookieHeader,
  cookieValue,
  activeCookie,
  hasNoActiveSession,
  signIn,
  csrfTokenFrom,
};
