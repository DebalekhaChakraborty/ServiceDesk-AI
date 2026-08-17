'use strict';

/**
 * Two presentation-only fixes, pinned so they cannot silently regress:
 *
 * 1. The launcher's explanatory caption used to render permanently. It must
 *    now default to hidden and reveal only on hover/keyboard focus, without
 *    reserving layout space while hidden (no blank gap above the button).
 *
 * 2. The in-call panel's top-right status used to render as a plain grey
 *    rectangle. The root cause was `.callpanel--connecting .callpanel__live`
 *    setting `background` to the SAME value as `color`, making the
 *    "Connecting" text (and the dot) invisible against its own background.
 *    These tests assert the badge is a small pill with contrasting
 *    foreground/background in every state, not just the default one.
 *
 * No jsdom in this portal (see voice-panel.test.js) - CSS is asserted against
 * the raw stylesheet text, the same way voice-panel.test.js asserts against
 * the raw bootstrap script text.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { landingPage } = require('../src/views/landing');

const CSS = fs.readFileSync(
  path.join(__dirname, '..', 'public', 'styles.css'), 'utf8');

// Comments may legitimately mention a selector in prose (e.g. "the
// positioning context for .launcher__caption below"), which would otherwise
// be mistaken for the rule itself. Strip them before searching for rules.
const CSS_CODE = CSS.replace(/\/\*[\s\S]*?\*\//g, '');

/**
 * Pulls one `selector { ... }` block's body out of the (comment-stripped)
 * stylesheet.
 *
 * Finds the selector text, then the NEXT `{...}` pair after it - which
 * handles a selector that is one entry in a comma-separated list (its own
 * rule body only starts at the closing `{` of the whole list), not just a
 * selector immediately followed by `{`.
 */
function ruleBody(selector) {
  const idx = CSS_CODE.indexOf(selector);
  assert.ok(idx !== -1, `selector not found in stylesheet: ${selector}`);
  const braceStart = CSS_CODE.indexOf('{', idx);
  const braceEnd = CSS_CODE.indexOf('}', braceStart);
  assert.ok(braceStart !== -1 && braceEnd !== -1,
    `no rule body found for ${selector}`);
  return CSS_CODE.slice(braceStart + 1, braceEnd);
}

function declValue(body, prop) {
  const m = body.match(new RegExp(`(?:^|;)\\s*${prop}\\s*:\\s*([^;]+);`));
  return m ? m[1].trim() : null;
}

// ---------------------------------------------------------------------------
// 1. Launcher caption: hidden by default, revealed on hover/focus-within
// ---------------------------------------------------------------------------

test('the caption stays in the markup, not stripped out', () => {
  const html = landingPage({ voiceEnabled: true });

  assert.match(html, /id="voice-caption"/);
  assert.match(html, /Talk to the Service Desk|Need help\?/);
});

test('the caption defaults to visually hidden', () => {
  const body = ruleBody('.launcher__caption');

  assert.equal(declValue(body, 'opacity'), '0');
  assert.equal(declValue(body, 'visibility'), 'hidden');
  assert.equal(declValue(body, 'pointer-events'), 'none');
  assert.match(body, /transform:\s*translateY\(4px\)/);
});

test('the hidden caption reserves no layout space', () => {
  const body = ruleBody('.launcher__caption');

  // Taken out of normal flow entirely, so a hidden caption cannot leave a
  // blank gap in the launcher's flex column.
  assert.equal(declValue(body, 'position'), 'absolute');
});

test('hover reveals the caption', () => {
  const body = ruleBody('.launcher:hover .launcher__caption');

  assert.equal(declValue(body, 'opacity'), '1');
  assert.equal(declValue(body, 'visibility'), 'visible');
});

test('keyboard focus (focus-within) reveals the caption, independent of hover', () => {
  const body = ruleBody('.launcher:focus-within .launcher__caption');

  assert.equal(declValue(body, 'opacity'), '1');
  assert.equal(declValue(body, 'visibility'), 'visible');
});

test('the reveal transition is subtle and short, not a JS timer', () => {
  const body = ruleBody('.launcher__caption');
  const transition = declValue(body, 'transition');

  assert.ok(transition, 'expected a CSS transition on the caption');
  // 150-200ms range, per the requested feel.
  const durations = [...transition.matchAll(/\.(\d+)s/g)].map((m) => Number(`0.${m[1]}`));
  assert.ok(durations.length > 0);
  for (const d of durations) {
    assert.ok(d >= 0.1 && d <= 0.25, `${d}s outside the intended subtle range`);
  }
  // No setInterval/setTimeout-driven tooltip anywhere in this stylesheet's
  // companion script; the reveal is CSS-only.
  const bootstrap = fs.readFileSync(
    path.join(__dirname, '..', 'public', 'voice-call.js'), 'utf8');
  assert.doesNotMatch(bootstrap, /voice-caption[\s\S]{0,200}(setTimeout|setInterval)/);
});

test('small screens keep the existing behaviour: caption never renders at all', () => {
  // Several `@media (max-width: 520px)` blocks exist in this stylesheet
  // (auth card, launcher, call panel); find the one that is actually the
  // launcher's own, rather than assuming position in the file.
  const blocks = [...CSS_CODE.matchAll(/@media \(max-width: 520px\) \{([\s\S]*?)\n\}/g)]
    .map((m) => m[1]);
  const launcherBlock = blocks.find((b) => /\.launcher\s*\{\s*left:/.test(b));

  assert.ok(launcherBlock, 'expected to find the launcher\'s own mobile block');
  assert.match(launcherBlock, /\.launcher__caption\s*\{\s*display:\s*none;\s*\}/);
});

// ---------------------------------------------------------------------------
// 2 & 3. Live badge: no invisible-text collision, restrained pill shape
// ---------------------------------------------------------------------------

test('root-cause regression guard: no state ever sets the badge background '
  + 'to the same value as its own foreground', () => {
  for (const selector of [
    '.callpanel__live',
    '.callpanel--connecting .callpanel__live',
    '.callpanel--failed .callpanel__live',
  ]) {
    const body = ruleBody(selector);
    const color = declValue(body, 'color');
    const background = declValue(body, 'background');
    if (color && background) {
      assert.notEqual(background, color,
        `${selector}: background equals color, text would be invisible`);
      assert.doesNotMatch(background, new RegExp(`^${color.replace(/[()]/g, '\\$&')}$`));
    }
  }
});

test('the badge is a shrink-to-fit pill, not a fixed-size rectangle', () => {
  const body = ruleBody('.callpanel__live');

  assert.equal(declValue(body, 'display'), 'inline-flex');
  assert.equal(declValue(body, 'width'), null, 'a fixed width would create an empty block');
  const radius = declValue(body, 'border-radius');
  assert.ok(radius && parseInt(radius, 10) >= 999 - 1,
    'expected a fully-rounded pill, e.g. 999px');
  const padding = declValue(body, 'padding');
  assert.ok(padding, 'expected padding so the chip is not a bare line of text');
});

test('the badge has a restrained enterprise look: small text, tinted background, subtle border', () => {
  const body = ruleBody('.callpanel__live');

  const fontSize = parseFloat(declValue(body, 'font-size'));
  assert.ok(fontSize >= 12 && fontSize <= 13.5, `font-size ${fontSize}px outside 12-13px`);
  assert.equal(declValue(body, 'font-weight'), '600');
  assert.match(declValue(body, 'background') || '', /color-mix|rgba?\(/,
    'expected a light tinted background, not a solid block color');
  assert.ok(declValue(body, 'border'), 'expected a subtle border per the chip spec');
});

test('the dot is a small circle (6-8px) that always matches the badge state', () => {
  const body = ruleBody('.callpanel__dot');

  const width = parseFloat(declValue(body, 'width'));
  const height = parseFloat(declValue(body, 'height'));
  assert.ok(width >= 6 && width <= 8, `dot width ${width}px outside 6-8px`);
  assert.equal(width, height);
  assert.equal(declValue(body, 'border-radius'), '50%');
  // currentColor, not a hardcoded color: it can never drift out of sync with
  // the text next to it the way two independently-set colors could.
  assert.equal(declValue(body, 'background'), 'currentColor');
});

test('the rendered markup carries readable "Live" text, not just a dot', () => {
  const html = landingPage({ voiceEnabled: true });

  assert.match(html, /<span class="callpanel__live-text" id="voice-live-text">Live<\/span>/);
});

test('no separate rule hides or blanks the live-text element itself', () => {
  assert.doesNotMatch(CSS_CODE, /\.callpanel__live-text\s*\{[^}]*(?:color:\s*transparent|display:\s*none|visibility:\s*hidden)/);
});
