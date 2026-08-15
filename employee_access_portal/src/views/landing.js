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

function landingPage() {
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
</main>`;

  return layout({ title: 'Enterprise Workspace', body, bodyClass: 'page--auth' });
}

module.exports = { landingPage };
