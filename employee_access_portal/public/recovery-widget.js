'use strict';

/**
 * Public recovery bootstrap. Same-origin so script-src stays 'self' + Dograh.
 *
 * The page sends NOTHING identifying - not a name, not an address, not an
 * employee ID. It receives a call_id and a signed bootstrap that asserts no
 * identity at all. Everything that matters happens on the call: the employee
 * states an identifier by voice, and Duo decides whether they are that person.
 */
(function () {
  var form = document.getElementById('recovery-form');
  var statusEl = document.getElementById('voice-status');
  if (!form || !statusEl) return;

  form.addEventListener('submit', function (event) {
    event.preventDefault();
    var button = document.getElementById('recovery-start');
    button.disabled = true;
    statusEl.textContent = 'Starting recovery call…';

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
        document.body.appendChild(script);
        statusEl.textContent = 'Connected. When asked, say your employee ID, one digit at a time.';
      })
      .catch(function () {
        statusEl.textContent = 'Account recovery is unavailable right now.';
        button.disabled = false;
      });
  });
})();
