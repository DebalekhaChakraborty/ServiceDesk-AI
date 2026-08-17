'use strict';

/**
 * The in-call panel: presentation only, and one call.
 *
 * The panel is a shell around the Dograh widget. The risk it introduces is not
 * visual — it is that a second control over a live call quietly becomes a
 * second call, a second microphone, or a parallel lifecycle that ends the UI
 * without ending the session. So these tests drive the real bootstrap and check
 * what it does to the widget, not what it looks like.
 *
 * There is no jsdom here on purpose. This portal keeps a deliberately small
 * dependency surface, and the script touches few enough DOM APIs that a stub
 * covering exactly those is both honest and reviewable — an unimplemented API
 * throws rather than silently passing.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const request = require('supertest');

const { landingPage } = require('../src/views/landing');
const { loadConfig } = require('../src/config');
const { createApp } = require('../src/app');

const BOOTSTRAP = fs.readFileSync(
  path.join(__dirname, '..', 'public', 'voice-call.js'), 'utf8');

const VOICE_ENV = {
  PORTAL_BASE_URL: 'http://localhost:8080',
  PORTAL_SESSION_SECRET: 'session-secret-value-for-tests-0123456789abcdef',
  ENTRA_PORTAL_TENANT_ID: '11111111-2222-3333-4444-555555555555',
  ENTRA_PORTAL_CLIENT_ID: '66666666-7777-8888-9999-000000000000',
  ENTRA_PORTAL_CLIENT_SECRET: 'entra-client-secret-for-tests',
  VOICE_IDENTITY_SIGNING_SECRET: 'voice-signing-secret-for-tests-0123456789abcdef',
  DOGRAH_EMBED_TOKEN: 'emb_test_token_value',
  DOGRAH_EMBED_ORIGIN: 'http://localhost:3010',
  DOGRAH_API_ENDPOINT: 'http://localhost:8001',
  RECOVERY_ADMIN_KEY: 'test-admin-key-0123456789',
};

// ---------------------------------------------------------------------------
// A DOM just large enough to run the bootstrap.
// ---------------------------------------------------------------------------

function makeElement(id, tag = 'div') {
  const classes = new Set();
  return {
    id,
    tagName: tag,
    hidden: false,
    disabled: false,
    textContent: '',
    focused: 0,
    attributes: {},
    listeners: {},
    children: [],
    classList: {
      add: (...names) => names.forEach((n) => classes.add(n)),
      remove: (...names) => names.forEach((n) => classes.delete(n)),
      contains: (n) => classes.has(n),
      values: () => [...classes],
    },
    setAttribute(name, value) { this.attributes[name] = value; },
    getAttribute(name) { return this.attributes[name] ?? null; },
    addEventListener(name, fn) { (this.listeners[name] ||= []).push(fn); },
    focus() { this.focused += 1; },
    fire(name, arg) { (this.listeners[name] || []).forEach((fn) => fn(arg)); },
  };
}

/** The ids landing.js actually renders, so the stub mirrors the real page. */
const PAGE_IDS = [
  'recovery-form', 'recovery-start', 'voice-status', 'voice-launcher',
  'voice-caption', 'voice-panel', 'voice-state', 'voice-live-text', 'voice-end',
];

function makeHarness({ startResponse = null, widget = null } = {}) {
  const els = new Map(PAGE_IDS.map((id) => [id, makeElement(id)]));
  const created = [];
  const body = makeElement('body', 'body');

  const document = {
    // Faithful to a real DOM: an element becomes findable once it is IN the
    // document, not when it is constructed. The bootstrap's guard against
    // injecting a second widget depends on exactly that, so a stub that
    // resolved created-but-unappended elements would test nothing.
    getElementById: (id) => els.get(id) || null,
    createElement: (tag) => {
      const el = makeElement(null, tag);
      created.push(el);
      return el;
    },
    body,
  };
  body.appendChild = (el) => {
    body.children.push(el);
    if (el.id) els.set(el.id, el);
    return el;
  };

  const payload = startResponse || {
    call_id: 'voice_abc123',
    voice_identity_token: 'TOKEN.VALUE.SIGNATURE',
    embed_token: 'emb_test_token_value',
    embed_origin: 'http://localhost:3010',
    api_endpoint: 'http://localhost:8001',
  };

  const fetchCalls = [];
  const timers = [];
  const context = {
    document,
    window: {
      // Reduced motion ON: the close path then runs synchronously, which keeps
      // these tests free of timing races. The animated path is covered by the
      // transitionend/backstop assertions below.
      matchMedia: () => ({ matches: true }),
      setTimeout: (fn, ms) => { timers.push(fn); return timers.length; },
      DograhWidget: widget,
    },
    requestAnimationFrame: (fn) => fn(),
    fetch: (url, opts) => {
      fetchCalls.push({ url, opts });
      return Promise.resolve({ ok: true, json: () => Promise.resolve(payload) });
    },
    console,
  };
  context.window.document = document;
  context.globalThis = context;
  vm.createContext(context);
  vm.runInContext(BOOTSTRAP, context);

  return {
    el: (id) => els.get(id),
    body,
    created,
    fetchCalls,
    timers,
    context,
    setWidget: (w) => { context.window.DograhWidget = w; },
    /** Press the launcher and settle the promise chain. */
    async start() {
      els.get('recovery-form').fire('submit', { preventDefault() {} });
      await new Promise((r) => setImmediate(r));
      await new Promise((r) => setImmediate(r));
    },
    /** The injected Dograh <script>, if any. */
    script() { return created.find((e) => e.id === 'dograh-widget') || null; },
  };
}

function fakeWidget() {
  const calls = { start: 0, end: 0 };
  const cb = {};
  const register = (name) => (fn) => { cb[name] = fn; };
  return {
    calls,
    cb,
    start: () => { calls.start += 1; return Promise.resolve(); },
    end: () => { calls.end += 1; return Promise.resolve(); },
    onCallStart: register('onCallStart'),
    onCallConnected: register('onCallConnected'),
    onCallDisconnected: register('onCallDisconnected'),
    onCallEnd: register('onCallEnd'),
    onError: register('onError'),
    onStatusChange: register('onStatusChange'),
  };
}

// ---------------------------------------------------------------------------
// Server-rendered structure
// ---------------------------------------------------------------------------

test('idle page renders the call-to-action and the panel starts hidden', () => {
  const html = landingPage({ voiceEnabled: true });

  assert.match(html, /Talk to ServiceDesk/);
  assert.match(html, /id="voice-panel"/);
  // `hidden` on the section itself: no call is in progress on a fresh load.
  assert.match(html, /<section class="callpanel" id="voice-panel" hidden/);
  assert.match(html, /id="voice-end"/);
});

test('the panel ships an orb and a waveform, both hidden from assistive tech', () => {
  const html = landingPage({ voiceEnabled: true });

  assert.match(html, /class="orb"/);
  assert.equal((html.match(/class="orb__ring"/g) || []).length, 3);
  assert.equal((html.match(/class="wave__bar"/g) || []).length, 9);
  // Decoration must not be announced.
  assert.match(html, /<div class="callpanel__stage" aria-hidden="true">/);
});

test('the panel is accessible: labelled, live status, real button', () => {
  const html = landingPage({ voiceEnabled: true });

  assert.match(html, /aria-labelledby="callpanel-title"/);
  assert.match(html, /id="voice-state"[^>]*role="status"[^>]*aria-live="polite"/);
  // A real <button>, so it is keyboard reachable and activatable by default.
  assert.match(html, /<button class="callpanel__end" type="button" id="voice-end">End call<\/button>/);
});

test('a voice-unconfigured deployment renders the portal with no panel at all', () => {
  const html = landingPage({ voiceEnabled: false });

  assert.doesNotMatch(html, /voice-panel/);
  assert.doesNotMatch(html, /callpanel/);
  assert.doesNotMatch(html, /voice-call\.js/);
  // ...and the portal itself is untouched.
  assert.match(html, /Sign in with Microsoft/);
  assert.match(html, /Enterprise Workspace/);
});

test('the unconfigured portal still serves normally over HTTP', async () => {
  const app = createApp({
    config: loadConfig({
      PORTAL_BASE_URL: VOICE_ENV.PORTAL_BASE_URL,
      PORTAL_SESSION_SECRET: VOICE_ENV.PORTAL_SESSION_SECRET,
      ENTRA_PORTAL_TENANT_ID: VOICE_ENV.ENTRA_PORTAL_TENANT_ID,
      ENTRA_PORTAL_CLIENT_ID: VOICE_ENV.ENTRA_PORTAL_CLIENT_ID,
      ENTRA_PORTAL_CLIENT_SECRET: VOICE_ENV.ENTRA_PORTAL_CLIENT_SECRET,
    }),
  });
  const res = await request(app).get('/').expect(200);
  assert.doesNotMatch(res.text, /callpanel/);
  assert.match(res.text, /Sign in with Microsoft/);
});

// ---------------------------------------------------------------------------
// Privacy: the panel has nowhere to leak to
// ---------------------------------------------------------------------------

test('no identity, token or transcript surface exists in the rendered UI', () => {
  const html = landingPage({ voiceEnabled: true });

  for (const forbidden of [
    'employee_id', 'employeeId', 'upn', 'userPrincipalName', 'mobile',
    'txid', 'transaction', 'passcode', 'object_id', 'objectId',
    'voice_identity_token', 'recovery_token', 'identity_context',
  ]) {
    assert.ok(!html.includes(forbidden), `rendered UI must not mention ${forbidden}`);
  }
  // No transcript in this phase, and no element that could become one.
  assert.doesNotMatch(html, /transcript|messages|conversation-log/i);
  assert.doesNotMatch(html, /<textarea|<input/i);
});

test('the live call payload never reaches the rendered panel', async () => {
  const widget = fakeWidget();
  const h = makeHarness({ widget });
  await h.start();
  h.script().fire('load');

  // The token travels to Dograh in a script attribute, never into visible text.
  const visible = [
    h.el('voice-state').textContent,
    h.el('voice-live-text').textContent,
    h.el('voice-status').textContent,
  ].join(' ');
  assert.ok(!visible.includes('TOKEN.VALUE.SIGNATURE'));
  assert.ok(!visible.includes('voice_abc123'));
});

// ---------------------------------------------------------------------------
// One call, one widget, one lifecycle
// ---------------------------------------------------------------------------

test('initiating a call opens the panel and hides the launcher', async () => {
  const widget = fakeWidget();
  const h = makeHarness({ widget });

  assert.equal(h.el('voice-panel').hidden, false, 'stub starts visible');
  await h.start();
  h.script().fire('load');

  assert.equal(h.el('voice-panel').hidden, false);
  assert.ok(h.el('voice-panel').classList.contains('is-open'));
  assert.equal(h.el('voice-launcher').hidden, true);
  assert.ok(h.body.classList.contains('voice-call-active'),
    'the widget’s own floating button is clipped while the panel is up');
});

test('exactly one Dograh widget and one call, however many times it is pressed',
  async () => {
    const widget = fakeWidget();
    const h = makeHarness({ widget });

    await h.start();
    await h.start();
    await h.start();
    h.script().fire('load');
    h.script().fire('load');

    const scripts = h.created.filter((e) => e.id === 'dograh-widget');
    assert.equal(scripts.length, 1, 'a second <script> would be a second widget');
    assert.equal(h.fetchCalls.length, 1, 'a second /recovery/start would be a second call');
    assert.equal(widget.calls.start, 1, 'start() must be invoked exactly once');
  });

test('the bootstrap opens no media stream and asks for no microphone', () => {
  assert.doesNotMatch(BOOTSTRAP, /getUserMedia|mediaDevices|AudioContext|MediaRecorder/);
  assert.doesNotMatch(BOOTSTRAP, /new WebSocket|RTCPeerConnection/);
});

test('End Call invokes the widget’s own termination, not a parallel one', async () => {
  const widget = fakeWidget();
  const h = makeHarness({ widget });
  await h.start();
  h.script().fire('load');

  h.el('voice-end').fire('click');
  await new Promise((r) => setImmediate(r));

  assert.equal(widget.calls.end, 1, 'must call DograhWidget.end()');
  assert.equal(widget.calls.start, 1, 'and must not start anything else');
});

test('ending the call restores the launcher', async () => {
  const widget = fakeWidget();
  const h = makeHarness({ widget });
  await h.start();
  h.script().fire('load');
  assert.equal(h.el('voice-launcher').hidden, true);

  h.el('voice-end').fire('click');
  await new Promise((r) => setImmediate(r));

  assert.equal(h.el('voice-panel').hidden, true);
  assert.equal(h.el('voice-launcher').hidden, false);
  assert.equal(h.el('recovery-start').disabled, false);
  assert.ok(!h.body.classList.contains('voice-call-active'));
});

test('a call ended from the widget side also closes the panel', async () => {
  // The caller can hang up in Dograh's own UI, or the agent can end the call.
  // The panel must follow the session rather than the button that was pressed.
  const widget = fakeWidget();
  const h = makeHarness({ widget });
  await h.start();
  h.script().fire('load');

  widget.cb.onCallEnd();

  assert.equal(h.el('voice-panel').hidden, true);
  assert.equal(h.el('voice-launcher').hidden, false);
});

test('after ending, the caller can start a fresh call', async () => {
  const widget = fakeWidget();
  const h = makeHarness({ widget });
  await h.start();
  h.script().fire('load');
  widget.cb.onCallEnd();

  await h.start();
  // The guard against a duplicate <script> is the surviving element, so no
  // second widget is injected — but the launcher is usable again.
  assert.equal(h.el('recovery-start').disabled, true, 'a new attempt is in flight');
});

// ---------------------------------------------------------------------------
// State comes from the widget, never from a timer or the caller's words
// ---------------------------------------------------------------------------

test('panel state is driven by the widget lifecycle callbacks', async () => {
  const widget = fakeWidget();
  const h = makeHarness({ widget });
  await h.start();
  h.script().fire('load');

  assert.equal(h.el('voice-state').textContent, 'Connecting to ServiceDesk…');

  widget.cb.onCallConnected();
  assert.equal(h.el('voice-state').textContent, 'Listening…');
  assert.equal(h.el('voice-live-text').textContent, 'Live');
  assert.ok(h.el('voice-panel').classList.contains('callpanel--active'));

  widget.cb.onCallDisconnected();
  assert.equal(h.el('voice-state').textContent, 'Ending call…');
});

test('the widget’s own status vocabulary maps onto the panel', async () => {
  const widget = fakeWidget();
  const h = makeHarness({ widget });
  await h.start();
  h.script().fire('load');

  widget.cb.onStatusChange('connected');
  assert.ok(h.el('voice-panel').classList.contains('callpanel--active'));
  widget.cb.onStatusChange('failed');
  assert.ok(h.el('voice-panel').classList.contains('callpanel--failed'));
  assert.equal(h.el('voice-live-text').textContent, 'Not connected');
});

test('nothing infers call state from time or from what the caller said', () => {
  // Comments legitimately discuss identity and verification; the CODE must not
  // act on either, so the prose is stripped before asserting.
  const code = BOOTSTRAP
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/^\s*\/\/.*$/gm, '');

  assert.doesNotMatch(code, /setInterval/, 'no polling loop');
  // No claim of verification is rendered, and no caller utterance is read.
  assert.doesNotMatch(code, /verified|approved|transcript|utterance/i);
  // The only setTimeout is the close-transition backstop, and it only closes UI.
  assert.equal((code.match(/setTimeout/g) || []).length, 1);
});

test('a widget that fails to load leaves the launcher usable', async () => {
  const h = makeHarness({ widget: null });
  await h.start();

  h.script().fire('error');

  assert.equal(h.el('voice-launcher').hidden, false);
  assert.equal(h.el('recovery-start').disabled, false);
  assert.match(h.el('voice-status').textContent, /could not start/i);
});

test('End Call still closes the panel if the widget API has gone', async () => {
  const h = makeHarness({ widget: fakeWidget() });
  await h.start();
  h.script().fire('load');

  h.setWidget(undefined);          // the widget vanished mid-call
  h.el('voice-end').fire('click');
  await new Promise((r) => setImmediate(r));

  assert.equal(h.el('voice-panel').hidden, true,
    'the caller must never be stranded in a dead panel');
  assert.equal(h.el('voice-launcher').hidden, false);
});

// ---------------------------------------------------------------------------
// Both doors, one panel
//
// The workspace used to carry its own inline "Start voice call" section and its
// own bootstrap. Two copies of a floating call panel drift — one keeps a
// control the other removed, or ends a call the other only hides — so both
// pages now render the same view and load the same script.
// ---------------------------------------------------------------------------

const { workspacePage } = require('../src/views/workspace');

function workspaceHtml(voiceEnabled = true) {
  return workspacePage({
    session: { username: 'alice@example.invalid', displayName: 'Alice Test' },
    csrfToken: 'csrf-token-value',
    voiceEnabled,
  });
}

test('the workspace offers the same corner launcher, not an inline section', () => {
  const html = workspaceHtml();

  assert.match(html, /id="voice-launcher"/);
  assert.match(html, /Talk to ServiceDesk/);
  // The old inline block is gone.
  assert.doesNotMatch(html, /Start voice call/);
  assert.doesNotMatch(html, /<section class="voice"/);
});

test('the workspace renders the identical panel, hidden', () => {
  const html = workspaceHtml();

  assert.match(html, /<section class="callpanel" id="voice-panel" hidden/);
  assert.equal((html.match(/class="orb__ring"/g) || []).length, 3);
  assert.equal((html.match(/class="wave__bar"/g) || []).length, 9);
  assert.match(html, /id="voice-end"/);
});

test('both pages render byte-identical voice UI apart from the endpoint', () => {
  const strip = (html) => {
    const start = html.indexOf('<div class="launcher"');
    return html.slice(start, html.indexOf('</section>', html.indexOf('callpanel')));
  };
  const normalise = (s) => s
    .replace(/data-endpoint="[^"]*"/, 'ENDPOINT')
    .replace(/ data-csrf="[^"]*"/, '')
    .replace(/<p class="launcher__caption"[\s\S]*?<\/p>/, 'CAPTION');

  assert.equal(normalise(strip(workspaceHtml())),
               normalise(strip(landingPage({ voiceEnabled: true }))));
});

test('each page points the shared bootstrap at its own endpoint', () => {
  assert.match(workspaceHtml(), /data-endpoint="\/voice\/session"/);
  assert.match(landingPage({ voiceEnabled: true }), /data-endpoint="\/recovery\/start"/);
  // The public door carries no CSRF, because it accepts no session.
  assert.doesNotMatch(landingPage({ voiceEnabled: true }), /data-csrf=/);
  assert.match(workspaceHtml(), /data-csrf="csrf-token-value"/);
});

test('the workspace CSRF token is a form guard, never rendered as identity', () => {
  const html = workspaceHtml();

  // Asserted by CONTEXT rather than by count: the page already had two
  // CSRF-protected forms before the voice launcher arrived, and a bare number
  // would silently pass the day one of them is removed.
  const occurrences = [...html.matchAll(/csrf-token-value/g)].map((m) => {
    const before = html.slice(Math.max(0, m.index - 80), m.index);
    return /name="csrf_token" value="$/.test(before) ? 'hidden-input'
      : /data-csrf="$/.test(before) ? 'voice-form-attribute'
      : 'UNEXPECTED';
  });
  assert.ok(occurrences.length > 0);
  assert.deepEqual(occurrences.filter((o) => o === 'UNEXPECTED'), [],
    'the CSRF token must appear only inside form plumbing');
  assert.ok(occurrences.includes('voice-form-attribute'));

  // And never inside the panel, which is presentation only.
  const panel = html.slice(html.indexOf('<section class="callpanel"'));
  assert.doesNotMatch(panel, /csrf-token-value/, 'the panel must not carry the token');
});

test('a voice-unconfigured workspace renders no panel and no bootstrap', () => {
  const html = workspaceHtml(false);
  assert.doesNotMatch(html, /callpanel|voice-launcher|voice-call\.js/);
  // ...and the workspace itself still works.
  assert.match(html, /Your Workspace/);
  assert.match(html, /Verify Corporate Access/);
});

test('the shared bootstrap posts a CSRF token only when the page supplies one', () => {
  // The public endpoint must not receive a token it never issued, and the
  // authenticated one must not be called without one.
  assert.match(BOOTSTRAP, /data-csrf/);
  assert.match(BOOTSTRAP, /if \(csrfToken\)/);
});
