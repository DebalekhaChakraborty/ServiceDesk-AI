'use strict';

/**
 * Public ServiceDesk Voice bootstrap. Same-origin so script-src stays
 * 'self' + Dograh.
 *
 * The page sends NOTHING identifying - not a name, not an address, not an
 * employee ID. It receives a call_id and a signed bootstrap that asserts no
 * identity at all. Everything that matters happens on the call: the caller says
 * what they need, states an identifier by voice, and Duo decides whether they
 * are that person before the Service Desk hears a word of it.
 */
(function () {
  var form = document.getElementById('recovery-form');
  var statusEl = document.getElementById('voice-status');
  if (!form || !statusEl) return;

  // Optional: the standalone /recovery page has no launcher chrome, so every
  // reference below tolerates a missing element rather than assuming one page.
  var launcher = document.getElementById('voice-launcher');
  var caption = document.getElementById('voice-caption');

  function fail(message) {
    statusEl.textContent = message;
    statusEl.classList.add('launcher__status--error');
    if (caption) caption.hidden = false;
  }

  form.addEventListener('submit', function (event) {
    event.preventDefault();
    var button = document.getElementById('recovery-start');
    button.disabled = true;
    statusEl.classList.remove('launcher__status--error');
    statusEl.textContent = 'Connecting you to ServiceDesk…';
    if (caption) caption.hidden = true;

    fetch('/recovery/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: '',
      credentials: 'same-origin',
    })
      .then(function (r) { if (!r.ok) throw new Error('unavailable'); return r.json(); })
      .then(function (data) {
        var script = document.createElement('script');
        script.id = 'dograh-widget';
        script.async = true;
        script.src = data.embed_origin + '/embed/dograh-widget.js?token=' +
          encodeURIComponent(data.embed_token) + '&environment=local&apiEndpoint=' +
          encodeURIComponent(data.api_endpoint);
        script.setAttribute('data-dograh-context', JSON.stringify({
          call_id: data.call_id,
          voice_identity_token: data.voice_identity_token,
        }));

        // Hand the corner over only once the widget has actually loaded. Hiding
        // on click would leave the caller staring at an empty corner for the
        // length of the fetch; hiding on load means the two controls are never
        // both on screen and never both absent.
        script.addEventListener('load', function () {
          if (launcher) launcher.hidden = true;
        });
        script.addEventListener('error', function () {
          if (launcher) launcher.hidden = false;
          button.disabled = false;
          fail('ServiceDesk voice could not start. Please try again.');
        });

        document.body.appendChild(script);
        statusEl.textContent = 'Connected. Tell ServiceDesk what you need help with.';
      })
      .catch(function () {
        button.disabled = false;
        fail('ServiceDesk voice is unavailable right now.');
      });
  });
})();
