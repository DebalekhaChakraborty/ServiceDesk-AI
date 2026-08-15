'use strict';

/**
 * Server-rendered HTML. No client-side framework and no inline script, which
 * lets the Content-Security-Policy stay at `script-src 'none'`.
 */

const HTML_ESCAPES = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

/** Escape any interpolated value; all page content passes through this. */
function escapeHtml(value) {
  if (value === null || value === undefined) return '';
  return String(value).replace(/[&<>"']/g, (char) => HTML_ESCAPES[char]);
}

function layout({ title, body, bodyClass = '' }) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>${escapeHtml(title)}</title>
<link rel="stylesheet" href="/styles.css">
<link rel="icon" href="data:,">
</head>
<body class="${escapeHtml(bodyClass)}">
${body}
</body>
</html>
`;
}

module.exports = { layout, escapeHtml };
