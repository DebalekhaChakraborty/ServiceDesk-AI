'use strict';

const { layout } = require('./layout');
const { publicVoiceUi } = require('./voiceUi');

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
 * The launcher and in-call panel themselves live in ./voiceUi so the workspace
 * renders the identical thing; only the placement argument is made here.
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
</main>${voiceEnabled ? publicVoiceUi() : ''}`;

  return layout({ title: 'Enterprise Workspace', body, bodyClass: 'page--auth' });
}

module.exports = { landingPage };
