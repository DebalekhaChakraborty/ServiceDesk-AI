'use strict';

const { layout } = require('./layout');

// Official four-square Microsoft mark, inlined so the page makes no external
// request (the Content-Security-Policy forbids one).
const MICROSOFT_MARK = `<svg class="ms-mark" viewBox="0 0 23 23" aria-hidden="true" focusable="false">
<rect x="1" y="1" width="10" height="10" fill="#f25022"/>
<rect x="12" y="1" width="10" height="10" fill="#7fba00"/>
<rect x="1" y="12" width="10" height="10" fill="#00a4ef"/>
<rect x="12" y="12" width="10" height="10" fill="#ffb900"/>
</svg>`;

/**
 * ServiceDesk Voice AI, offered on the SIGN-IN page.
 *
 * This is the right place for it: an employee who cannot sign in is looking at
 * this page when they discover it, and sending them elsewhere assumes they know
 * a URL they have no reason to know.
 *
 * It is deliberately NOT labelled as password reset or account recovery. The
 * caller may want VPN, a printer, software, an incident, or a locked account —
 * being outside the portal says nothing about which. Duo is how the line proves
 * who they are, not what the line is for.
 *
 * It asserts nothing and reveals nothing. The button posts to the same public
 * `/recovery/start` the standalone page uses, which accepts no identifier at
 * all, so this cannot be probed to learn whether an account exists. There is no
 * identifier field here for the same reason. Identity is established later, on
 * the call, by Duo.
 *
 * The Dograh script is appended only on click, not at page load, so the
 * unauthenticated sign-in page continues to ship zero third-party JavaScript to
 * everyone who merely visits it.
 */
// Headset outline, inlined for the same reason as the Microsoft mark: the CSP
// forbids an external request, and this page must ship no third-party asset.
const HEADSET_MARK = `<svg class="launcher__icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
<path d="M4 13a8 8 0 0 1 16 0" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
<rect x="2" y="13" width="4.5" height="7" rx="2.25" fill="currentColor"/>
<rect x="17.5" y="13" width="4.5" height="7" rx="2.25" fill="currentColor"/>
<path d="M20 20v.5a2.5 2.5 0 0 1-2.5 2.5H13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
</svg>`;

/**
 * The launcher is deliberately OUTSIDE the sign-in card.
 *
 * Inside it, the voice entry read as one of the ways to sign in — a fallback
 * credential flow — which is exactly the framing 7.6 removes. It is not a
 * sign-in method and it is not account recovery; it is the Service Desk,
 * reachable whatever the caller needs. A persistent corner launcher says that,
 * and leaves `Sign in with Microsoft` as the card's single call to action.
 *
 * It also sits where the Dograh widget will appear, so pressing it hands the
 * corner over rather than stacking two controls on top of each other.
 *
 * The markup contract with `recovery-widget.js` is unchanged: `#recovery-form`,
 * `#recovery-start`, `#voice-status`. The Dograh script is still appended only
 * on click, so a passive visitor fetches nothing third-party.
 */
function voiceLauncher() {
  return `
  <div class="launcher" id="voice-launcher">
    <p class="launcher__caption" id="voice-caption">
      <span class="launcher__caption-title">Need help?</span>
      Available even if you can't sign in.
    </p>
    <p class="launcher__status" id="voice-status" role="status" aria-live="polite"></p>
    <form id="recovery-form" class="launcher__form">
      <button class="launcher__button" type="submit" id="recovery-start">
        ${HEADSET_MARK}
        <span class="launcher__label">Talk to ServiceDesk</span>
      </button>
    </form>
  </div>
  <script src="/recovery-widget.js" defer></script>`;
}

function landingPage({ voiceEnabled = false } = {}) {
  const body = `<main class="shell shell--centered">
  <section class="card card--auth" aria-labelledby="portal-title">
    <div class="brand">
      <div class="brand__mark" aria-hidden="true"></div>
      <h1 class="brand__name" id="portal-title">Enterprise Workspace</h1>
      <p class="brand__tagline">Secure Employee Access</p>
    </div>

    <p class="lede">Access corporate applications using your organizational identity.</p>

    <a class="button button--primary" href="/auth/signin">
      ${MICROSOFT_MARK}
      <span>Sign in with Microsoft</span>
    </a>

    <p class="fineprint">Authorized users only</p>
  </section>
</main>${voiceEnabled ? voiceLauncher() : ''}`;

  return layout({ title: 'Enterprise Workspace', body, bodyClass: 'page--auth' });
}

module.exports = { landingPage };
