'use strict';

/**
 * The portal originally shipped zero client-side JavaScript, so `default-src
 * 'none'` was free. The Dograh voice widget is third-party script on a page
 * that holds an authenticated session cookie, so every allowance it needs is
 * asserted here explicitly. These tests fail if the policy ever broadens.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');

const { createApp } = require('../src/app');
const { loadConfig } = require('../src/config');

const BASE_ENV = {
  ENTRA_PORTAL_TENANT_ID: '8bd45b04-aa1e-4de5-b83c-68ab45726aa5',
  ENTRA_PORTAL_CLIENT_ID: '00000000-0000-0000-0000-000000000001',
  ENTRA_PORTAL_CLIENT_SECRET: 'test-client-secret-value-not-real',
  PORTAL_BASE_URL: 'http://localhost:8080',
  PORTAL_SESSION_SECRET: 'local-session-secret-for-tests-0123456789abcdef',
};

const VOICE_ENV = {
  ...BASE_ENV,
  VOICE_IDENTITY_SIGNING_SECRET: 'voice-signing-secret-for-tests-0123456789abcdef',
  DOGRAH_EMBED_TOKEN: 'emb_test_token_value',
  DOGRAH_EMBED_ORIGIN: 'http://localhost:3010',
  DOGRAH_API_ENDPOINT: 'http://localhost:8001',
};

function appFor(env) {
  // createApp takes an options object; pass the pre-validated config so the
  // test never depends on the ambient process environment.
  return createApp({ config: loadConfig(env) });
}

function parseCsp(header) {
  return header.split(';').reduce((acc, part) => {
    const [name, ...values] = part.trim().split(/\s+/);
    if (name) acc[name] = values;
    return acc;
  }, {});
}

async function cspFor(env) {
  const response = await request(appFor(env)).get('/').expect(200);
  return parseCsp(response.headers['content-security-policy']);
}

test('without voice the original zero-JavaScript policy is unchanged', async () => {
  const csp = await cspFor(BASE_ENV);
  assert.deepEqual(csp['default-src'], ["'none'"]);
  assert.equal(csp['script-src'], undefined, 'no script-src should be emitted without voice');
  assert.equal(csp['connect-src'], undefined);
  assert.deepEqual(csp['style-src'], ["'self'"]);
});

test('voice mode allows exactly the Dograh origins and nothing more', async () => {
  const csp = await cspFor(VOICE_ENV);
  assert.deepEqual(csp['script-src'], ["'self'", 'http://localhost:3010']);
  assert.deepEqual(csp['connect-src'], ["'self'", 'http://localhost:8001', 'ws://localhost:8001']);
  assert.deepEqual(csp['default-src'], ["'none'"]);
});

test('no wildcard, scheme-only source, or unsafe-eval anywhere in the policy', async () => {
  const raw = (await request(appFor(VOICE_ENV)).get('/')).headers['content-security-policy'];
  const csp = parseCsp(raw);

  // Token-wise, not substring-wise: " http:" also occurs inside the legitimate
  // origin " http://localhost:3010", so a substring check gives a false alarm.
  // A bare scheme source like `http:` would allow ANY host over that scheme.
  const FORBIDDEN_TOKENS = new Set(["*", "'unsafe-eval'", 'http:', 'https:', 'data:', 'blob:']);
  for (const [directive, values] of Object.entries(csp)) {
    for (const value of values) {
      if (directive === 'img-src' && value === 'data:') continue;     // pre-existing
      if ((directive === 'media-src' || directive === 'worker-src') && value === 'blob:') continue;
      assert.equal(
        FORBIDDEN_TOKENS.has(value), false,
        `${directive} must not contain the token ${value}: ${raw}`,
      );
      assert.equal(value.includes('*'), false, `${directive} must not contain a wildcard: ${raw}`);
    }
  }
});

test("script-src never permits unsafe-inline, and unsafe-inline is style-only", async () => {
  const csp = await cspFor(VOICE_ENV);
  assert.equal(csp['script-src'].includes("'unsafe-inline'"), false);

  // The widget injects its own stylesheet, so style-src needs 'unsafe-inline'.
  // That is a real relaxation and is deliberately confined to styles: it must
  // never leak into a directive that can execute code.
  const relaxed = Object.entries(csp)
    .filter(([, values]) => values.includes("'unsafe-inline'"))
    .map(([name]) => name);
  assert.deepEqual(relaxed, ['style-src']);
});

test('CSP tracks configuration rather than hard-coded hosts', async () => {
  const csp = await cspFor({
    ...VOICE_ENV,
    DOGRAH_EMBED_ORIGIN: 'http://localhost:4010',
    DOGRAH_API_ENDPOINT: 'http://localhost:9001',
  });
  assert.deepEqual(csp['script-src'], ["'self'", 'http://localhost:4010']);
  assert.deepEqual(csp['connect-src'], ["'self'", 'http://localhost:9001', 'ws://localhost:9001']);
});

test('unrelated hardening headers survive the voice change', async () => {
  const response = await request(appFor(VOICE_ENV)).get('/').expect(200);
  assert.equal(response.headers['x-content-type-options'], 'nosniff');
  assert.equal(response.headers['x-frame-options'], 'DENY');
  assert.equal(response.headers['referrer-policy'], 'no-referrer');
  assert.equal(response.headers['cross-origin-opener-policy'], 'same-origin');
  const csp = parseCsp(response.headers['content-security-policy']);
  assert.deepEqual(csp['frame-ancestors'], ["'none'"]);
  assert.deepEqual(csp['base-uri'], ["'none'"]);
  assert.deepEqual(csp['form-action'], ["'self'"]);
});

test('the voice bootstrap ships no secret and no identity claim', async () => {
  const response = await request(appFor(VOICE_ENV)).get('/voice-widget.js').expect(200);
  const body = response.text;
  assert.equal(body.includes(VOICE_ENV.VOICE_IDENTITY_SIGNING_SECRET), false);
  assert.equal(body.includes(VOICE_ENV.PORTAL_SESSION_SECRET), false);
  assert.equal(body.includes(VOICE_ENV.ENTRA_PORTAL_CLIENT_SECRET), false);
  // The browser must never assemble an identity claim itself. Assert the
  // property that matters -- the context object handed to Dograh -- rather than
  // scanning for the word "UPN", which legitimately appears in a comment
  // explaining why no UPN is sent.
  const code = body.replace(/\/\*[\s\S]*?\*\/|\/\/.*$/gm, '');
  for (const claim of ['upn', 'UPN', 'userPrincipalName', 'verified_upn', 'email', 'oid']) {
    assert.equal(code.includes(claim), false, `bootstrap code must not reference ${claim}`);
  }
  // The only two context variables ever sent.
  const context = code.match(/var context = \{([\s\S]*?)\};/);
  assert.ok(context, 'context object not found');
  const keys = [...context[1].matchAll(/(\w+)\s*:/g)].map((m) => m[1]);
  assert.deepEqual(keys.sort(), ['call_id', 'voice_identity_token']);
});

test('voice session route refuses an unauthenticated caller', async () => {
  await request(appFor(VOICE_ENV))
    .post('/voice/session')
    .type('form')
    .send({ csrf_token: 'anything' })
    .expect(401);
});

test('voice session route is unavailable when voice is not configured', async () => {
  await request(appFor(BASE_ENV))
    .post('/voice/session')
    .type('form')
    .send({ csrf_token: 'anything' })
    .expect(401); // no session -> authentication first, still never 200
});

test('a signing secret equal to the session secret is refused at boot', () => {
  assert.throws(
    () => loadConfig({ ...VOICE_ENV, VOICE_IDENTITY_SIGNING_SECRET: BASE_ENV.PORTAL_SESSION_SECRET }),
    /must differ from PORTAL_SESSION_SECRET/,
  );
});

test('a short signing secret is refused at boot', () => {
  assert.throws(
    () => loadConfig({ ...VOICE_ENV, VOICE_IDENTITY_SIGNING_SECRET: 'too-short' }),
    /at least 32 characters/,
  );
});

/**
 * The widget builds its script URL from the JSON that /voice/session and
 * /recovery/start return. A field the widget reads but the route omits does not
 * throw — it interpolates the string "undefined" into the URL and the voice
 * channel dies with no server-side error at all. So the contract is asserted
 * from the consumer's side: every `data.X` the bootstrap reads must be a key
 * the route actually sends.
 */
function fieldsReadByWidget(source) {
  const code = require('node:fs').readFileSync(
    require('node:path').join(__dirname, '..', 'public', source), 'utf8');
  return [...new Set([...code.matchAll(/\bdata\.(\w+)/g)].map((m) => m[1]))].sort();
}

test('authenticated /voice/session returns every field its widget reads', () => {
  const routeSource = require('node:fs').readFileSync(
    require('node:path').join(__dirname, '..', 'src', 'routes', 'voice.js'), 'utf8');
  for (const field of fieldsReadByWidget('voice-widget.js')) {
    assert.match(routeSource, new RegExp(`\\b${field}\\s*:`),
      `/voice/session must return ${field}, which voice-widget.js reads`);
  }
});

test('public /recovery/start returns every field its widget reads', () => {
  const routeSource = require('node:fs').readFileSync(
    require('node:path').join(__dirname, '..', 'src', 'routes', 'recovery.js'), 'utf8');
  for (const field of fieldsReadByWidget('recovery-widget.js')) {
    assert.match(routeSource, new RegExp(`\\b${field}\\s*:`),
      `/recovery/start must return ${field}, which recovery-widget.js reads`);
  }
});

/**
 * ServiceDesk Voice on the SIGN-IN page.
 *
 * The caller often cannot sign in, so the sign-in page is where they are
 * standing when they need this. These tests pin the two properties that make
 * putting it on a public page safe: it is only rendered when voice is actually
 * configured, and it ships no third-party script to a passive visitor.
 */
test('the landing page offers ServiceDesk voice when voice is configured', async () => {
  const res = await request(appFor(VOICE_ENV)).get('/').expect(200);
  assert.match(res.text, /Talk to ServiceDesk/);
  assert.match(res.text, /recovery-widget\.js/);
  assert.match(res.text, /Sign in with Microsoft/);      // primary path intact
});

test('the landing page hides ServiceDesk voice when voice is not configured', async () => {
  const res = await request(appFor(BASE_ENV)).get('/').expect(200);
  assert.doesNotMatch(res.text, /Talk to ServiceDesk/);
  assert.doesNotMatch(res.text, /recovery-widget\.js/);
  assert.match(res.text, /Sign in with Microsoft/);
});

/**
 * The external entry is a Service Desk line, not a password-reset feature.
 *
 * Labelling it "recover my account" told every caller with a VPN or printer
 * problem that they were in the wrong place, and told the ones who stayed that
 * the only thing on offer was a password. The copy must name the Service Desk
 * and must not narrow the offer to account recovery.
 */
test('the landing page does not present the voice line as account recovery only', async () => {
  const res = await request(appFor(VOICE_ENV)).get('/').expect(200);
  assert.doesNotMatch(res.text, /Recover my account/i);
  assert.doesNotMatch(res.text, /password/i);
  // ...and it still says the line works for someone who is locked out.
  assert.match(res.text, /can't sign in/i);
});

/**
 * The launcher lives OUTSIDE the sign-in card.
 *
 * Inside it, the voice entry read as one more way to sign in — a fallback
 * credential flow — which is the framing 7.6 exists to remove. Position is the
 * argument here, so it is asserted rather than left to a later tidy-up moving
 * it back.
 */
test('the voice launcher is a corner control, not part of the sign-in card', async () => {
  const res = await request(appFor(VOICE_ENV)).get('/').expect(200);

  const cardEnd = res.text.indexOf('</main>');
  const launcherAt = res.text.indexOf('id="voice-launcher"');
  assert.ok(launcherAt > -1, 'the launcher must be rendered');
  assert.ok(launcherAt > cardEnd,
    'the launcher must sit outside the sign-in card, not inside it');

  // Sign-in remains the card's single call to action.
  const card = res.text.slice(0, cardEnd);
  assert.match(card, /Sign in with Microsoft/);
  assert.doesNotMatch(card, /ServiceDesk/);
});

test('the launcher keeps the markup contract recovery-widget.js depends on', () => {
  // The bootstrap looks these up by id. A rename here fails silently in the
  // browser — the button simply stops working — so it is pinned from the
  // consumer's side, the same way the JSON field contract is above.
  const view = require('node:fs').readFileSync(
    require('node:path').join(__dirname, '..', 'src', 'views', 'landing.js'), 'utf8');
  const bootstrap = require('node:fs').readFileSync(
    require('node:path').join(__dirname, '..', 'public', 'recovery-widget.js'), 'utf8');

  for (const id of [...bootstrap.matchAll(/getElementById\('([\w-]+)'\)/g)].map((m) => m[1])) {
    assert.match(view, new RegExp(`id="${id}"`),
      `landing.js must render #${id}, which recovery-widget.js looks up`);
  }
});

test('the launcher styles ship in the same-origin stylesheet, not inline', async () => {
  // `style-src` is 'self' until voice is configured, and the launcher must not
  // depend on the looser policy that arrives with the widget.
  const res = await request(appFor(VOICE_ENV)).get('/').expect(200);
  assert.doesNotMatch(res.text, /<style/i);
  assert.doesNotMatch(res.text, /\sstyle="/i);

  const css = require('node:fs').readFileSync(
    require('node:path').join(__dirname, '..', 'public', 'styles.css'), 'utf8');
  assert.match(css, /\.launcher\b/);
  assert.match(css, /position:\s*fixed/);
});

test('the sign-in page loads no third-party script until the button is pressed', async () => {
  const res = await request(appFor(VOICE_ENV)).get('/').expect(200);
  // Only the same-origin bootstrap is referenced; the Dograh widget is injected
  // by that script on click, so a passive visitor fetches nothing from Dograh.
  assert.doesNotMatch(res.text, /localhost:3010/);
  assert.doesNotMatch(res.text, /dograh-widget\.js/);
});

test('the landing page asks for no identifier and leaks no secret', async () => {
  const res = await request(appFor(VOICE_ENV)).get('/').expect(200);
  // No input field: the endpoint accepts no identifier, so the page offers none.
  assert.doesNotMatch(res.text, /<input[^>]+name=["'](employee|upn|email|user)/i);
  for (const secret of [
    VOICE_ENV.VOICE_IDENTITY_SIGNING_SECRET,
    VOICE_ENV.DOGRAH_EMBED_TOKEN,
    VOICE_ENV.ENTRA_PORTAL_CLIENT_SECRET,
  ]) {
    assert.equal(res.text.includes(secret), false);
  }
});

test('the removed developer page is gone', async () => {
  await request(appFor({ ...VOICE_ENV, VOICE_DOGRAH_RECOVERY_TEST_MODE: 'true' }))
    .get('/dev/recovery-test')
    .expect(404);
});
