'use strict';

/**
 * Tests the REAL src/entra.js by substituting the @azure/msal-node module in
 * the CommonJS cache before it is required. This checks what the portal
 * actually asks Microsoft for - scopes, response mode, PKCE, prompt - and how
 * it validates what comes back, without a network round trip.
 *
 * node:test runs each test file in its own process, so this substitution does
 * not affect any other suite.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

// Deliberately NOT ./helpers: that module loads src/app.js, which would pull in
// the real @azure/msal-node before the substitution below could take effect.
// src/config.js has no MSAL dependency, so it is safe to load first.
const { loadConfig } = require('../src/config');

const TEST_TENANT_ID = '11111111-2222-3333-4444-555555555555';

// --- Fake @azure/msal-node ---------------------------------------------------

const calls = { constructed: [], authCodeUrl: [], acquireByCode: [], removedAccounts: [] };
let pkceCounter = 0;
let nextTokenResponse = null;
let nextTokenError = null;
let cachedAccounts = [];

class FakeConfidentialClientApplication {
  constructor(options) {
    calls.constructed.push(options);
  }

  async getAuthCodeUrl(request) {
    calls.authCodeUrl.push(request);
    const url = new URL(`https://login.microsoftonline.com/${TEST_TENANT_ID}/oauth2/v2.0/authorize`);
    url.searchParams.set('scope', (request.scopes || []).join(' '));
    url.searchParams.set('state', request.state);
    url.searchParams.set('response_mode', request.responseMode || '');
    if (request.prompt) url.searchParams.set('prompt', request.prompt);
    return url.toString();
  }

  async acquireTokenByCode(request) {
    calls.acquireByCode.push(request);
    // A real redemption populates the token cache; mirror that so cache
    // purging is observable.
    cachedAccounts = [{ homeAccountId: 'home-account-1' }];
    if (nextTokenError) throw nextTokenError;
    return nextTokenResponse;
  }

  getTokenCache() {
    return {
      async getAllAccounts() {
        return cachedAccounts;
      },
      async removeAccount(account) {
        calls.removedAccounts.push(account);
        cachedAccounts = cachedAccounts.filter((entry) => entry !== account);
      },
    };
  }
}

class FakeCryptoProvider {
  async generatePkceCodes() {
    pkceCounter += 1;
    return { verifier: `verifier-${pkceCounter}`, challenge: `challenge-${pkceCounter}` };
  }
}

const msalPath = require.resolve('@azure/msal-node');
require.cache[msalPath] = {
  id: msalPath,
  filename: msalPath,
  loaded: true,
  children: [],
  paths: [],
  exports: {
    ConfidentialClientApplication: FakeConfidentialClientApplication,
    CryptoProvider: FakeCryptoProvider,
    LogLevel: { Error: 0, Warning: 1, Info: 2, Verbose: 3 },
  },
};

// Required only after the substitution is in place.
const { createEntraClient } = require('../src/entra');

const config = loadConfig({
  ENTRA_PORTAL_TENANT_ID: TEST_TENANT_ID,
  ENTRA_PORTAL_CLIENT_ID: '66666666-7777-8888-9999-000000000000',
  ENTRA_PORTAL_CLIENT_SECRET: 'CLIENT-SECRET-SENTINEL-a1b2c3d4e5f6g7h8',
  PORTAL_BASE_URL: 'http://localhost:8080',
  PORTAL_SESSION_SECRET: 'SESSION-SECRET-SENTINEL-0123456789abcdefghij',
});

function validTokenResponse({ idTokenClaims = {}, ...overrides } = {}) {
  return {
    account: { name: 'Priya Raman', username: 'priya.raman@contoso.com', homeAccountId: 'home-account-1' },
    ...overrides,
    idTokenClaims: {
      nonce: 'expected-nonce',
      tid: TEST_TENANT_ID,
      oid: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
      name: 'Priya Raman',
      preferred_username: 'priya.raman@contoso.com',
      ...idTokenClaims,
    },
    accessToken: 'SHOULD-NEVER-BE-RETAINED',
    idToken: 'SHOULD-NEVER-BE-RETAINED',
  };
}

test.beforeEach(() => {
  calls.authCodeUrl.length = 0;
  calls.acquireByCode.length = 0;
  calls.removedAccounts.length = 0;
  pkceCounter = 0;
  nextTokenResponse = validTokenResponse();
  nextTokenError = null;
  cachedAccounts = [];
});

// --- Authorization request ---------------------------------------------------

test('MSAL is configured with the tenant-specific authority', () => {
  createEntraClient(config);
  const options = calls.constructed[calls.constructed.length - 1];

  assert.equal(options.auth.authority, `https://login.microsoftonline.com/${TEST_TENANT_ID}`);
  assert.equal(options.auth.clientId, config.clientId);
  assert.ok(!/\/(common|organizations|consumers)$/.test(options.auth.authority));
  // MSAL's own logging is silenced so tokens cannot reach stdout through it.
  assert.equal(options.system.loggerOptions.piiLoggingEnabled, false);
});

test('the authorization request asks only for openid, profile and email', async () => {
  const client = createEntraClient(config);

  await client.createAuthorizationRequest();
  const sent = calls.authCodeUrl[0];

  assert.deepEqual(sent.scopes, ['openid', 'profile', 'email']);
  assert.ok(!sent.scopes.some((scope) => /graph\.microsoft\.com|\.All|\.ReadWrite|\.default/i.test(scope)));
});

test('the authorization request uses PKCE, query response mode and the configured redirect URI', async () => {
  const client = createEntraClient(config);

  const request = await client.createAuthorizationRequest();
  const sent = calls.authCodeUrl[0];

  assert.equal(sent.responseMode, 'query');
  assert.equal(sent.redirectUri, config.redirectUri);
  assert.equal(sent.codeChallengeMethod, 'S256');
  assert.ok(sent.codeChallenge);
  assert.equal(request.codeVerifier, 'verifier-1');
  // The implicit flow is never used: no response_type of token/id_token.
  assert.equal(sent.responseType, undefined);
});

test('state and nonce are cryptographically random and unique per request', async () => {
  const client = createEntraClient(config);

  const first = await client.createAuthorizationRequest();
  const second = await client.createAuthorizationRequest();

  for (const value of [first.state, first.nonce, second.state, second.nonce]) {
    // 32 random bytes, base64url encoded.
    assert.ok(value.length >= 43, `expected high-entropy value, got length ${value.length}`);
  }
  assert.notEqual(first.state, second.state);
  assert.notEqual(first.nonce, second.nonce);
  assert.notEqual(first.codeVerifier, second.codeVerifier);
});

test('prompt is omitted by default and set to login on demand', async () => {
  const client = createEntraClient(config);

  await client.createAuthorizationRequest();
  assert.equal(calls.authCodeUrl[0].prompt, undefined);

  const forced = await client.createAuthorizationRequest({ prompt: 'login' });
  assert.equal(calls.authCodeUrl[1].prompt, 'login');
  assert.equal(new URL(forced.url).searchParams.get('prompt'), 'login');
});

// --- Redemption --------------------------------------------------------------

test('a valid authorization code yields display claims only', async () => {
  const client = createEntraClient(config);

  const identity = await client.redeemAuthorizationCode({
    code: 'auth-code',
    codeVerifier: 'verifier-1',
    expectedNonce: 'expected-nonce',
  });

  assert.deepEqual(Object.keys(identity).sort(), [
    'authenticatedAt',
    'displayName',
    'objectId',
    'tenantId',
    'username',
  ]);
  assert.equal(identity.displayName, 'Priya Raman');
  assert.equal(identity.username, 'priya.raman@contoso.com');
  assert.equal(identity.tenantId, TEST_TENANT_ID);
  // No token of any kind is carried out of this module.
  assert.ok(!JSON.stringify(identity).includes('SHOULD-NEVER-BE-RETAINED'));
});

test('the PKCE verifier and redirect URI are sent with the redemption', async () => {
  const client = createEntraClient(config);

  await client.redeemAuthorizationCode({
    code: 'auth-code',
    codeVerifier: 'verifier-1',
    expectedNonce: 'expected-nonce',
  });

  const sent = calls.acquireByCode[0];
  assert.equal(sent.code, 'auth-code');
  assert.equal(sent.codeVerifier, 'verifier-1');
  assert.equal(sent.redirectUri, config.redirectUri);
  assert.deepEqual(sent.scopes, ['openid', 'profile', 'email']);
});

test('a mismatched nonce is rejected', async () => {
  const client = createEntraClient(config);

  await assert.rejects(
    () => client.redeemAuthorizationCode({ code: 'c', codeVerifier: 'v', expectedNonce: 'a-different-nonce' }),
    /nonce_mismatch/,
  );
});

test('an ID token from another tenant is rejected', async () => {
  const client = createEntraClient(config);
  nextTokenResponse = validTokenResponse({
    idTokenClaims: { tid: '99999999-9999-9999-9999-999999999999' },
  });

  await assert.rejects(
    () => client.redeemAuthorizationCode({ code: 'c', codeVerifier: 'v', expectedNonce: 'expected-nonce' }),
    /tenant_mismatch/,
  );
});

test('a response with no ID token claims is rejected', async () => {
  const client = createEntraClient(config);
  nextTokenResponse = { account: null };

  await assert.rejects(
    () => client.redeemAuthorizationCode({ code: 'c', codeVerifier: 'v', expectedNonce: 'expected-nonce' }),
    /id_token_missing/,
  );
});

test('the token cache is purged after a successful redemption', async () => {
  const client = createEntraClient(config);

  await client.redeemAuthorizationCode({
    code: 'auth-code',
    codeVerifier: 'verifier-1',
    expectedNonce: 'expected-nonce',
  });

  assert.equal(calls.removedAccounts.length, 1);
  assert.equal(cachedAccounts.length, 0);
});

test('the token cache is purged even when redemption fails', async () => {
  const client = createEntraClient(config);
  nextTokenError = new Error('invalid_grant');

  await assert.rejects(
    () => client.redeemAuthorizationCode({ code: 'c', codeVerifier: 'v', expectedNonce: 'expected-nonce' }),
    /invalid_grant/,
  );

  assert.equal(cachedAccounts.length, 0);
});
