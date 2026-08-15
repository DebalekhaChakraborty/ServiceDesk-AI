'use strict';

const { layout, escapeHtml } = require('./layout');

/**
 * Shown whenever a fresh Microsoft Entra authentication did not complete.
 *
 * The wording deliberately states only what is known: authentication did not
 * complete. The portal has no directory visibility, so it never asserts a
 * reason such as "your account is disabled" unless Microsoft itself supplied a
 * code, which is surfaced verbatim-but-sanitized as a technical detail.
 */
function authErrorPage({ code = null } = {}) {
  const detail = code
    ? `    <p class="error__detail">Reference: <code>${escapeHtml(code)}</code></p>\n`
    : '';

  const body = `<main class="shell shell--centered">
  <section class="card card--auth card--error" aria-labelledby="error-title">
    <div class="brand">
      <div class="brand__mark" aria-hidden="true"></div>
      <h1 class="brand__name">Enterprise Workspace</h1>
    </div>

    <h2 class="error__title" id="error-title">Corporate access could not be verified.</h2>
    <p class="error__body">Your organizational identity did not complete authentication.</p>
    <p class="error__body">Please contact the Service Desk if you require assistance.</p>
${detail}
    <a class="button button--secondary" href="/">Return to sign in</a>
  </section>
</main>`;

  return layout({ title: 'Access could not be verified', body, bodyClass: 'page--auth' });
}

module.exports = { authErrorPage };
