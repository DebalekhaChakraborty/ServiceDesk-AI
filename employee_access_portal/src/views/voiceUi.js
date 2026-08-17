'use strict';

/**
 * The ServiceDesk Voice launcher and in-call panel, shared by both pages.
 *
 * There are two entry points into the same voice channel — the public sign-in
 * page and the authenticated workspace — and they differ in exactly two ways:
 * which endpoint mints the call, and whether a CSRF token rides with it.
 * Everything a caller sees is identical, so it is built once here.
 *
 * That is not only tidiness. Two copies of a floating call panel drift, and the
 * way they drift is that one of them keeps a control the other removed, or ends
 * a call the other only hides. One definition means one behaviour to review.
 *
 * The panel is PRESENTATION ONLY. It starts no call, ends no call and captures
 * nothing; every control routes into the Dograh widget's own lifecycle (see
 * public/voice-call.js). Nothing identifying is rendered here — there is no
 * element for a name, employee ID, UPN, token or transcript, so none can leak
 * into one.
 */

const { escapeHtml } = require('./layout');

// Headset outline, inlined because the CSP forbids an external request.
const HEADSET_MARK = `<svg class="launcher__icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
<path d="M4 13a8 8 0 0 1 16 0" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
<rect x="2" y="13" width="4.5" height="7" rx="2.25" fill="currentColor"/>
<rect x="17.5" y="13" width="4.5" height="7" rx="2.25" fill="currentColor"/>
<path d="M20 20v.5a2.5 2.5 0 0 1-2.5 2.5H13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
</svg>`;

/**
 * The in-call panel, rendered hidden.
 *
 * Kept in the DOM rather than injected on demand: the open/close transition
 * needs both states to exist, and a server-rendered panel keeps the page free
 * of markup-building script.
 */
function callPanel() {
  // 9 bars. Decorative only — this represents no audio signal, and the page
  // opens no MediaStream of its own; Dograh remains the sole owner of the mic.
  //
  // No inline style carries the per-bar delay: `style-src` is 'self' alone
  // until the voice widget is configured, and this panel must not depend on the
  // looser policy that arrives with it. The stagger lives in :nth-child rules.
  const bars = '<span class="wave__bar"></span>'.repeat(9);

  return `
  <section class="callpanel" id="voice-panel" hidden
           aria-labelledby="callpanel-title">
    <header class="callpanel__head">
      <h2 class="callpanel__title" id="callpanel-title">ServiceDesk Voice</h2>
      <span class="callpanel__live" id="voice-live">
        <span class="callpanel__dot" aria-hidden="true"></span>
        <span class="callpanel__live-text" id="voice-live-text">Live</span>
      </span>
    </header>

    <div class="callpanel__stage" aria-hidden="true">
      <div class="orb">
        <span class="orb__ring"></span>
        <span class="orb__ring"></span>
        <span class="orb__ring"></span>
        <span class="orb__core"></span>
      </div>
      <div class="wave">${bars}</div>
    </div>

    <p class="callpanel__state" id="voice-state" role="status" aria-live="polite">Connecting to ServiceDesk…</p>
    <p class="callpanel__hint">Speak naturally — I'm here to help with your IT issue.</p>

    <button class="callpanel__end" type="button" id="voice-end">End call</button>
  </section>`;
}

/**
 * The corner launcher plus its panel.
 *
 * `endpoint` and `csrfToken` are read by the bootstrap off the form. The token
 * is a page-scoped CSRF value, not an identity: the authenticated endpoint
 * still derives who the caller is from the sealed session cookie, and the
 * public one accepts no identity at all.
 */
function voiceUi({ endpoint, csrfToken = '', captionTitle, captionText }) {
  const csrfAttr = csrfToken ? ` data-csrf="${escapeHtml(csrfToken)}"` : '';

  return `
  <div class="launcher" id="voice-launcher">
    <p class="launcher__caption" id="voice-caption">
      <span class="launcher__caption-title">${escapeHtml(captionTitle)}</span>
      ${escapeHtml(captionText)}
    </p>
    <p class="launcher__status" id="voice-status" role="status" aria-live="polite"></p>
    <form id="recovery-form" class="launcher__form"
          data-endpoint="${escapeHtml(endpoint)}"${csrfAttr}>
      <button class="launcher__button" type="submit" id="recovery-start">
        ${HEADSET_MARK}
        <span class="launcher__label">Talk to ServiceDesk</span>
      </button>
    </form>
  </div>
${callPanel()}
  <script src="/voice-call.js" defer></script>`;
}

/** Public sign-in page: no session, no CSRF, no identity asserted. */
function publicVoiceUi() {
  return voiceUi({
    endpoint: '/recovery/start',
    captionTitle: 'Need help?',
    captionText: 'Available even if you can\u2019t sign in.',
  });
}

/** Authenticated workspace: identity already comes from the sealed session. */
function authenticatedVoiceUi(csrfToken) {
  return voiceUi({
    endpoint: '/voice/session',
    csrfToken,
    captionTitle: 'Talk to the Service Desk',
    captionText: 'Your signed-in session confirms who you are. Nothing you say sets that.',
  });
}

module.exports = { voiceUi, publicVoiceUi, authenticatedVoiceUi, callPanel };
