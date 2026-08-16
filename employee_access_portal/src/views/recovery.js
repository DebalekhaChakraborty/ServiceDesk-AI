'use strict';

const { layout } = require('./layout');

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

/**
 * A data: URI is the only image source this page will render.
 *
 * The QR comes from Duo, but the gateway fetches it server-side and inlines it,
 * so the browser never contacts Duo and `img-src 'self' data:` is untouched.
 * This check makes that guarantee structural rather than a matter of trusting
 * the upstream response.
 */
function safeImageSource(value) {
  return typeof value === 'string' && /^data:image\/(png|jpeg|gif|svg\+xml);base64,[A-Za-z0-9+/=]+$/.test(value)
    ? value
    : null;
}

/**
 * Duo enrollment page.
 *
 * The activation QR is shown once, and showing it activates nothing: the
 * employee scans it in Duo Mobile and then confirms, at which point Duo - not
 * this page - decides whether enrollment is complete.
 */
function enrollPage({
  session, csrfToken, qrDataUri, activationCode,
  confirmed, confirmFailed, stillWaiting, unavailable, notMapped,
}) {
  let body = `<main class="shell">
  <section class="welcome">
    <h1 class="welcome__title">Account Recovery Setup</h1>
    <p class="verify__note">Signed in as ${escapeHtml(session?.username || '')}</p>`;

  const qr = safeImageSource(qrDataUri);

  if (notMapped) {
    body += `<p class="voice__status voice__status--error">Your account is not set up for voice
      recovery. Please contact the Service Desk.</p>`;
  } else if (unavailable) {
    body += `<p class="voice__status voice__status--error">Recovery enrollment is not available.</p>`;
  } else if (confirmed) {
    body += `<p class="voice__status"><strong>Enrollment is ACTIVE.</strong> If you ever lose access to
      your account, you can recover by voice: give your employee ID, then verify using an
      available Duo verification method.</p>`;
  } else if (activationCode) {
    body += `
    <p class="verify__note">Open <strong>Duo Mobile</strong>, add an account, and scan this code.
       Then choose <em>I've activated Duo Mobile</em> below. Enrollment is not complete until Duo
       confirms it.</p>`;
    if (qr) {
      body += `\n    <p><img src="${qr}" alt="Duo activation QR code" width="240" height="240"></p>`;
    }
    body += `
    <dl class="identity">
      <dt class="identity__label">Activation code</dt>
      <dd class="identity__value"><code style="word-break:break-all">${escapeHtml(activationCode)}</code></dd>
    </dl>
    <form method="post" action="/recovery/enroll/confirm">
      <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
      <button class="button button--primary" type="submit">I've activated Duo Mobile</button>
    </form>`;
  } else {
    if (stillWaiting) {
      body += `<p class="voice__status voice__status--error">Duo has not confirmed activation yet.
        Finish adding the account in Duo Mobile, then start again below.</p>`;
    } else if (confirmFailed) {
      body += `<p class="voice__status voice__status--error">That enrollment could not be confirmed.
        Start again below.</p>`;
    }
    body += `
    <p class="verify__note">Set up Duo so you can prove who you are by voice if you ever lose
       access to your account.</p>
    <form method="post" action="/recovery/enroll/begin">
      <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
      <button class="button button--primary" type="submit">Begin Duo enrollment</button>
    </form>`;
  }

  body += `\n  </section>\n</main>`;
  return layout({ title: 'Account Recovery Setup', body, bodyClass: 'page--app' });
}

/**
 * Public ServiceDesk Voice entry. Reachable without a session by necessity: an
 * employee who is locked out cannot sign in to ask for help.
 *
 * Deliberately not framed as password reset. Whatever the caller needs — VPN, a
 * printer, software, an incident, a locked account — they say it on the call.
 * Nothing identifying is typed here, which is what stops this page being probed
 * to learn who is enrolled; identity is proven by Duo, by voice.
 */
function recoveryPage({ unavailable }) {
  const body = `<main class="shell">
  <section class="welcome">
    <h1 class="welcome__title">Talk to ServiceDesk</h1>
    ${unavailable
      ? '<p class="voice__status voice__status--error">ServiceDesk voice is not available.</p>'
      : `<p class="verify__note">Start a call and tell us what you need help with. Because you're
         not signed in, we'll verify who you are with Duo before the Service Desk acts on your
         account.</p>
    <form id="recovery-form">
      <button class="button button--primary" type="submit" id="recovery-start">Talk to ServiceDesk</button>
    </form>
    <p class="voice__status" id="voice-status" role="status" aria-live="polite"></p>
    <script src="/recovery-widget.js" defer></script>`}
  </section>
</main>`;
  return layout({ title: 'Talk to ServiceDesk', body, bodyClass: 'page--app' });
}

module.exports = { enrollPage, recoveryPage };
