'use strict';

/**
 * Guardrails that keep this portal an authentication-only application.
 *
 * Several of these are static assertions over the shipped source. They exist so
 * that a future change which starts administering accounts from the portal
 * fails the build instead of quietly widening its blast radius.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const request = require('supertest');

const {
  createTestApp,
  signIn,
  csrfTokenFrom,
  cookieHeader,
  cookieValue,
  testEnv,
  TEST_CLIENT_SECRET,
  TEST_SESSION_SECRET,
} = require('./helpers');
const { loadConfig, AUTH_SCOPES, SESSION_TTL_MS } = require('../src/config');

const SRC_DIR = path.join(__dirname, '..', 'src');
const CLOUD_RUN_URL = 'https://servicedesk-employee-access-abcdef1234-uc.a.run.app';

function readSourceFiles(dir = SRC_DIR) {
  const files = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) files.push(...readSourceFiles(full));
    else if (entry.name.endsWith('.js')) files.push({ file: path.relative(SRC_DIR, full), text: fs.readFileSync(full, 'utf8') });
  }
  return files;
}

// --- Scopes ------------------------------------------------------------------

test('no administrative Microsoft Graph scopes are requested', () => {
  assert.deepEqual([...AUTH_SCOPES], ['openid', 'profile', 'email']);

  const forbidden = [
    /graph\.microsoft\.com/i,
    /\.default$/,
    /Directory\./i,
    /User\.(Read|ReadWrite)\.All/i,
    /UserAuthenticationMethod/i,
    /RoleManagement/i,
    /\.ReadWrite/i,
    /\.All$/i,
  ];

  for (const scope of AUTH_SCOPES) {
    for (const pattern of forbidden) {
      assert.ok(!pattern.test(scope), `scope "${scope}" matches forbidden pattern ${pattern}`);
    }
  }
});

test('the authorization request carries only the authentication scopes', async () => {
  const { app, config } = createTestApp();

  const res = await request(app).get('/auth/signin').expect(302);
  const scope = new URL(res.headers.location).searchParams.get('scope');

  assert.equal(scope, 'openid profile email');
  assert.ok(!/graph\.microsoft\.com/i.test(scope));
  assert.deepEqual([...config.scopes], ['openid', 'profile', 'email']);
});

// --- No directory mutation ---------------------------------------------------

test('the portal contains no Microsoft Graph endpoint or mutation surface', () => {
  const forbidden = [
    'graph.microsoft.com',
    'accountEnabled',
    'passwordProfile',
    '/v1.0/users',
    '/beta/users',
    'microsoft-graph-client',
    'Directory.ReadWrite',
    'User.ReadWrite',
    'UserAuthenticationMethod',
    '.default',
  ];

  for (const { file, text } of readSourceFiles()) {
    for (const needle of forbidden) {
      assert.ok(!text.includes(needle), `src/${file} must not reference "${needle}"`);
    }
  }
});

test('only the recovery route makes an outbound call, and only to the gateway', () => {
  // MSAL performs the token exchange. The portal itself never became an API
  // client, which is what kept it incapable of administering a directory.
  //
  // Phase 6 opens exactly ONE hole: recovery.js calls the voice gateway on the
  // private bridge to create and verify TOTP enrollments. That is deliberate
  // and is confined here - the guard now proves the exception has not spread
  // to any other file, rather than being deleted.
  const forbidden = [/\bfetch\s*\(/, /require\(['"]node:https?['"]\)/, /require\(['"]axios['"]\)/, /node-fetch/];
  const ALLOWED_CALLER = 'routes/recovery.js';

  for (const { file, text } of readSourceFiles()) {
    for (const pattern of forbidden) {
      if (file === ALLOWED_CALLER && pattern.source.includes('fetch')) continue;
      assert.ok(!pattern.test(text), `src/${file} must not perform its own HTTP calls (${pattern})`);
    }
  }

  // The one permitted caller must still not pull in an HTTP client library.
  const recovery = readSourceFiles().find((f) => f.file === ALLOWED_CALLER);
  assert.ok(recovery, 'recovery route not found');
  assert.ok(!/axios|node-fetch|require\(['"]node:https?['"]\)/.test(recovery.text));
  // ...and it must never call anything but the configured gateway.
  assert.ok(!/fetch\(\s*['"`]http/.test(recovery.text),
    'recovery.js must not fetch a hard-coded URL; the gateway comes from config');
});

test('no directory or HTTP client dependency is declared', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
  const deps = Object.keys(pkg.dependencies || {});

  assert.deepEqual(deps.sort(), ['@azure/msal-node', 'cookie-parser', 'express']);
  for (const dep of deps) {
    assert.ok(!/graph|axios|node-fetch|got|request/i.test(dep), `unexpected dependency ${dep}`);
  }
});

test('the portal talks to no host other than Microsoft', () => {
  // The two systems share an identity provider but stay independently
  // authorized. Portal sign-in must never become an authorization signal for
  // ServiceDesk AI, so the portal knows no ServiceDesk address or setting.
  // 172.18.0.1 is the private Docker bridge address of the voice gateway.
  // It is not routable off this host, and it is the ONLY new host Phase 6 adds.
  const allowedHosts = new Set([
    'login.microsoftonline.com', 'localhost', '127.0.0.1', '172.18.0.1',
  ]);

  for (const { file, text } of readSourceFiles()) {
    for (const match of text.match(/https?:\/\/[A-Za-z0-9.:\-]+/g) || []) {
      const { hostname } = new URL(match);
      assert.ok(allowedHosts.has(hostname), `src/${file} references unexpected host "${hostname}"`);
    }
    assert.ok(
      !/SERVICEDESK_|SD_CHAT|ADK_|AAD_CLIENT|AD_ACCOUNT_MODE/.test(text),
      `src/${file} must not read ServiceDesk AI configuration`,
    );
  }
});

// --- Cookies -----------------------------------------------------------------

test('session cookies are Secure, HttpOnly and SameSite on an https origin', async () => {
  // Cookies are replayed by hand here: a supertest agent will not send a
  // Secure cookie back over its plain-http loopback connection.
  const { app, entra } = createTestApp({ PORTAL_BASE_URL: CLOUD_RUN_URL });

  const signinRes = await request(app).get('/auth/signin').expect(302);
  const txnCookie = cookieHeader(signinRes, 'eap_auth_txn');
  assert.match(txnCookie, /HttpOnly/i);
  assert.match(txnCookie, /Secure/i);
  assert.match(txnCookie, /SameSite=Lax/i);
  assert.match(txnCookie, /Path=\//);

  const callback = await request(app)
    .get('/auth/redirect')
    .query({ code: 'valid-authorization-code', state: entra.lastRequest.state })
    .set('Cookie', [`eap_auth_txn=${cookieValue(signinRes, 'eap_auth_txn')}`])
    .expect(302);

  const sessionCookie = cookieHeader(callback, 'eap_session');
  assert.match(sessionCookie, /HttpOnly/i);
  assert.match(sessionCookie, /Secure/i);
  assert.match(sessionCookie, /SameSite=Lax/i);
  assert.match(sessionCookie, /Path=\//);
  // Bounded lifetime, not a session-forever cookie.
  assert.match(sessionCookie, /Max-Age=1800/);
});

test('cookies drop the Secure flag only for localhost development', async () => {
  const { app } = createTestApp({ PORTAL_BASE_URL: 'http://localhost:8080' });

  const res = await request(app).get('/auth/signin').expect(302);
  const cookie = cookieHeader(res, 'eap_auth_txn');

  assert.match(cookie, /HttpOnly/i);
  assert.ok(!/Secure/i.test(cookie), 'Secure would make the cookie unusable over http://localhost');
});

test('the session lifetime is bounded to 30 minutes', () => {
  assert.equal(SESSION_TTL_MS, 30 * 60 * 1000);

  const config = loadConfig(testEnv());
  assert.equal(config.sessionTtlMs, 30 * 60 * 1000);
});

test('no token is ever placed in a cookie or in the page', async () => {
  const { app, entra } = createTestApp();
  const agent = request.agent(app);

  const { response } = await signIn(agent, entra);
  const workspace = await agent.get('/workspace').expect(200);

  const cookies = JSON.stringify(response.headers['set-cookie'] || []);
  for (const needle of ['access_token', 'id_token', 'refresh_token', 'Bearer', 'eyJ']) {
    assert.ok(!cookies.includes(needle), `cookie must not contain ${needle}`);
    assert.ok(!workspace.text.includes(needle), `page must not contain ${needle}`);
  }

  // No client-side storage of any kind is used, so there is nowhere to leak to.
  assert.ok(!/localStorage|sessionStorage/.test(workspace.text));
  assert.ok(!/<script/i.test(workspace.text));
});

// --- Logging -----------------------------------------------------------------

test('secret values are never written to logs', async () => {
  const captured = [];
  const originalStdout = process.stdout.write.bind(process.stdout);
  const originalStderr = process.stderr.write.bind(process.stderr);
  process.stdout.write = (chunk, ...rest) => { captured.push(String(chunk)); return originalStdout(chunk, ...rest); };
  process.stderr.write = (chunk, ...rest) => { captured.push(String(chunk)); return originalStderr(chunk, ...rest); };

  try {
    const { app, entra } = createTestApp();
    const agent = request.agent(app);

    await agent.get('/').expect(200);
    await agent.get('/healthz').expect(200);
    await signIn(agent, entra);
    const workspace = await agent.get('/workspace').expect(200);
    await agent
      .post('/auth/verify')
      .type('form')
      .send({ csrf_token: csrfTokenFrom(workspace.text) })
      .expect(302);
    // A failing authentication is the most log-chatty path.
    entra.failNextRedemption(new Error('invalid_grant'));
    await agent
      .get('/auth/redirect')
      .query({ code: 'SENSITIVE-AUTHORIZATION-CODE', state: entra.lastRequest.state })
      .expect(401);
  } finally {
    process.stdout.write = originalStdout;
    process.stderr.write = originalStderr;
  }

  const logged = captured.join('');
  assert.ok(!logged.includes(TEST_CLIENT_SECRET), 'client secret leaked into logs');
  assert.ok(!logged.includes(TEST_SESSION_SECRET), 'session secret leaked into logs');
  assert.ok(!logged.includes('SENSITIVE-AUTHORIZATION-CODE'), 'authorization code leaked into logs');
  assert.ok(!/eap_session=/.test(logged), 'session cookie leaked into logs');
});

test('the request log records the path but never the query string', async () => {
  const captured = [];
  const originalStdout = process.stdout.write.bind(process.stdout);
  process.stdout.write = (chunk, ...rest) => { captured.push(String(chunk)); return originalStdout(chunk, ...rest); };

  try {
    const { app } = createTestApp();
    await request(app).get('/auth/error').query({ code: 'access_denied', secret_param: 'LEAK-CANARY' }).expect(200);
  } finally {
    process.stdout.write = originalStdout;
  }

  const logged = captured.join('');
  assert.ok(logged.includes('/auth/error'), 'the path should be logged');
  assert.ok(!logged.includes('LEAK-CANARY'), 'the query string must not be logged');
});

// --- Configuration -----------------------------------------------------------

test('multi-tenant and consumer authorities are refused', () => {
  for (const tenant of ['common', 'organizations', 'consumers', 'COMMON']) {
    assert.throws(
      () => loadConfig(testEnv({ ENTRA_PORTAL_TENANT_ID: tenant })),
      /single tenant/i,
      `tenant "${tenant}" must be refused`,
    );
  }
});

test('the authority is always the tenant-specific Microsoft endpoint', () => {
  const config = loadConfig(testEnv());
  assert.equal(config.authority, `https://login.microsoftonline.com/${config.tenantId}`);
  assert.equal(config.redirectUri, 'http://localhost:8080/auth/redirect');
});

test('missing configuration fails closed and names only the variable', () => {
  assert.throws(
    () => loadConfig({ ...testEnv(), ENTRA_PORTAL_CLIENT_SECRET: '' }),
    (error) => {
      assert.match(error.message, /ENTRA_PORTAL_CLIENT_SECRET/);
      assert.ok(!error.message.includes(TEST_CLIENT_SECRET));
      return true;
    },
  );
});

test('a weak session secret is refused', () => {
  assert.throws(() => loadConfig(testEnv({ PORTAL_SESSION_SECRET: 'too-short' })), /at least 32 characters/);
});

test('a non-https base URL is refused outside localhost', () => {
  assert.throws(() => loadConfig(testEnv({ PORTAL_BASE_URL: 'http://portal.example.com' })), /must use https/);
});

test('security headers are applied to employee-facing pages', async () => {
  const { app } = createTestApp({ PORTAL_BASE_URL: CLOUD_RUN_URL });

  const res = await request(app).get('/').expect(200);

  assert.match(res.headers['content-security-policy'], /script-src 'none'|default-src 'none'/);
  assert.equal(res.headers['x-content-type-options'], 'nosniff');
  assert.equal(res.headers['x-frame-options'], 'DENY');
  assert.equal(res.headers['referrer-policy'], 'no-referrer');
  assert.match(res.headers['strict-transport-security'], /max-age=31536000/);
  assert.equal(res.headers['x-powered-by'], undefined);
});

// --- Phase 7: Duo recovery -------------------------------------------------

test('the public recovery page collects no identifying input at all', async () => {
  // Recovery needs the voice channel configured, so build the app explicitly
  // rather than relying on the default auth-only test fixture.
  const { createApp } = require('../src/app');
  const app = createApp({
    config: loadConfig({
      ...testEnv(),
      VOICE_IDENTITY_SIGNING_SECRET: 'voice-signing-secret-for-tests-0123456789abcdef',
      DOGRAH_EMBED_TOKEN: 'emb_test_token_value',
      DOGRAH_EMBED_ORIGIN: 'http://localhost:3010',
      DOGRAH_API_ENDPOINT: 'http://localhost:8001',
      RECOVERY_ADMIN_KEY: 'test-admin-key-0123456789',
    }),
  });
  const response = await request(app).get('/recovery');
  assert.equal(response.status, 200);

  // An input here would be a probe: type an address, watch the response. The
  // caller states an identifier by voice instead, where Duo gates the answer.
  assert.ok(!/<input/i.test(response.text),
    'the public recovery page must not collect an identifier');
  for (const name of ['claimed_upn', 'employee_id', 'upn', 'email', 'mobile']) {
    assert.ok(!response.text.includes(name),
      `the public recovery page must not reference ${name}`);
  }
});

test('the public voice page is a Service Desk line, not a password-reset feature', async () => {
  // The caller is outside the portal because they could not sign in. That says
  // nothing about what they want, so the page must not narrow the offer — and
  // must not promise a reset the Service Desk has not agreed to.
  const { createApp } = require('../src/app');
  const app = createApp({
    config: loadConfig({
      ...testEnv(),
      VOICE_IDENTITY_SIGNING_SECRET: 'voice-signing-secret-for-tests-0123456789abcdef',
      DOGRAH_EMBED_TOKEN: 'emb_test_token_value',
      DOGRAH_EMBED_ORIGIN: 'http://localhost:3010',
      DOGRAH_API_ENDPOINT: 'http://localhost:8001',
      RECOVERY_ADMIN_KEY: 'test-admin-key-0123456789',
    }),
  });
  const response = await request(app).get('/recovery').expect(200);

  assert.match(response.text, /Talk to ServiceDesk/);
  assert.ok(!/password/i.test(response.text),
    'the public voice page must not promise a password reset');
  assert.ok(!/Account Recovery/i.test(response.text),
    'the public voice page must not be titled as account recovery');
  // It still says identity gets checked, because it does.
  assert.match(response.text, /Duo/);
});

test('recovery start sends no caller-supplied identifier to the gateway', () => {
  const recovery = readSourceFiles().find((f) => f.file === 'routes/recovery.js');
  const startHandler = recovery.text.slice(recovery.text.indexOf("router.post('/recovery/start'"));

  // Everything posted to /recovery/start is ignored. Reading req.body in this
  // handler would be the first step back towards an enumeration oracle.
  assert.ok(!/req\.body/.test(startHandler),
    '/recovery/start must not read anything from the request body');
});

test('duo enrollment identity comes only from the sealed session', () => {
  const recovery = readSourceFiles().find((f) => f.file === 'routes/recovery.js');
  const identityFn = recovery.text.slice(
    recovery.text.indexOf('function sessionIdentity'),
    recovery.text.indexOf('// --- Duo enrollment'),
  );
  assert.ok(identityFn.includes('session.tenantId'));
  assert.ok(identityFn.includes('session.objectId'));
  assert.ok(identityFn.includes('session.username'));
  assert.ok(!/req\.body/.test(identityFn),
    'enrollment identity must never be read from a form field');
});

test('the enrollment page renders a QR only from an inline data: URI', () => {
  const { enrollPage } = require('../src/views/recovery');
  const session = { username: 'employee@example.com', csrf: 'x' };

  // A remote src would mean adding Duo to img-src, and letting the browser talk
  // to Duo directly. The gateway fetches the image; the page only inlines it.
  const hostile = enrollPage({
    session, csrfToken: 'x', activationCode: 'abc',
    qrDataUri: 'https://api-abcd1234.duosecurity.com/frame/qr?value=x',
  });
  assert.ok(!hostile.includes('<img'), 'a non-data: QR source must not render');

  const inline = enrollPage({
    session, csrfToken: 'x', activationCode: 'abc',
    qrDataUri: 'data:image/png;base64,iVBORw0KGgo=',
  });
  assert.ok(inline.includes('<img src="data:image/png;base64,'));
});

test('the portal never handles a Duo secret, user id, or passcode', () => {
  // "passcode" appears in page copy telling the employee what to expect, which
  // is fine. What must not exist is code that reads, stores or forwards one -
  // so the check is for identifiers and property access, not for the word.
  const handling = [
    /DUO_SKEY/, /DUO_IKEY/, /duo_user_id/, /\btxid\b/,
    /\bpasscode\s*[:=]/, /\.passcode\b/, /\bactivation_barcode\b/,
  ];
  for (const { file, text } of readSourceFiles()) {
    for (const pattern of handling) {
      assert.ok(!pattern.test(text), `${file} must not handle ${pattern}`);
    }
  }
});
