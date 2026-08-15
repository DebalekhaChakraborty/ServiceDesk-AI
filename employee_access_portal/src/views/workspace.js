'use strict';

const { layout, escapeHtml } = require('./layout');

const CHECK = `<svg class="status__icon" viewBox="0 0 20 20" aria-hidden="true" focusable="false">
<circle cx="10" cy="10" r="9" fill="none" stroke="currentColor" stroke-width="1.5"/>
<path d="M6 10.4l2.6 2.6L14.2 7.4" fill="none" stroke="currentColor" stroke-width="1.8"
      stroke-linecap="round" stroke-linejoin="round"/>
</svg>`;

const TILES = [
  { name: 'Applications', detail: 'Corporate application catalogue' },
  { name: 'Knowledge', detail: 'Policies, guides and how-to articles' },
  { name: 'My Devices', detail: 'Devices registered to your identity' },
];

/**
 * The authenticated workspace.
 *
 * Every claim on this page comes from the ID token that Microsoft Entra just
 * issued. Nothing here is inferred, cached from a previous visit, or read from
 * local configuration: if the page renders, Entra authenticated this employee.
 */
function workspacePage({ session, csrfToken }) {
  const tiles = TILES.map(
    (tile) => `      <article class="tile">
        <h3 class="tile__name">${escapeHtml(tile.name)}</h3>
        <p class="tile__detail">${escapeHtml(tile.detail)}</p>
      </article>`,
  ).join('\n');

  const body = `<header class="topbar">
  <div class="topbar__inner">
    <div class="topbar__brand">
      <div class="brand__mark brand__mark--sm" aria-hidden="true"></div>
      <span class="topbar__name">Enterprise Workspace</span>
    </div>
    <form class="topbar__actions" method="post" action="/auth/signout">
      <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
      <button class="button button--ghost" type="submit">Sign out</button>
    </form>
  </div>
</header>

<main class="shell">
  <section class="welcome">
    <h1 class="welcome__title">Welcome, ${escapeHtml(session.displayName)}</h1>

    <ul class="status" role="list">
      <li class="status__item">${CHECK}<span>Identity Verified</span></li>
      <li class="status__item">${CHECK}<span>Corporate Access Active</span></li>
    </ul>

    <dl class="identity">
      <dt class="identity__label">Signed in as</dt>
      <dd class="identity__value">${escapeHtml(session.username)}</dd>
    </dl>
  </section>

  <section class="workspace" aria-labelledby="workspace-title">
    <h2 class="section__title" id="workspace-title">Your Workspace</h2>
    <div class="tiles">
${tiles}
    </div>
  </section>

  <section class="verify">
    <form method="post" action="/auth/verify">
      <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
      <button class="button button--primary button--wide" type="submit">Verify Corporate Access</button>
    </form>
    <p class="verify__note">
      Re-checks your account directly with your organization's identity provider.
    </p>
  </section>
</main>`;

  return layout({ title: 'Enterprise Workspace', body, bodyClass: 'page--app' });
}

module.exports = { workspacePage };
