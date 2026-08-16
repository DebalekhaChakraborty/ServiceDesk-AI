'use strict';

/**
 * Voice channel bootstrap.
 *
 * Served same-origin so the page needs no inline script and the CSP can keep
 * script-src limited to 'self' plus the Dograh widget origin.
 *
 * What this file may and may not know:
 *   - it NEVER sees the signing secret; the assertion is minted server-side
 *   - it does not send a UPN, name, or object id; those travel inside the
 *     signed token where the browser cannot edit them
 *   - it hands Dograh exactly two context variables, call_id and
 *     voice_identity_token, which the tool reads back as preset parameters
 *
 * The assertion is short-lived, so it is fetched when the employee starts a
 * call rather than at page load.
 */
(function () {
  var button = document.getElementById('voice-start');
  var statusEl = document.getElementById('voice-status');
  if (!button || !statusEl) return;

  var started = false;

  function setStatus(text, isError) {
    statusEl.textContent = text;
    statusEl.className = isError ? 'voice__status voice__status--error' : 'voice__status';
  }

  button.addEventListener('click', function () {
    if (started) return;
    started = true;
    button.disabled = true;
    setStatus('Connecting to the Service Desk…', false);

    var body = new URLSearchParams();
    body.set('csrf_token', button.getAttribute('data-csrf') || '');

    fetch('/voice/session', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
      credentials: 'same-origin',
    })
      .then(function (response) {
        if (!response.ok) throw new Error('voice_session_failed');
        return response.json();
      })
      .then(function (data) {
        // The Dograh widget reads its context from this attribute and passes it
        // to /public/embed/init, which stores it in workflow_run.initial_context.
        var context = {
          call_id: data.call_id,
          voice_identity_token: data.voice_identity_token,
        };

        var script = document.createElement('script');
        script.id = 'dograh-widget';
        script.async = true;
        script.src =
          data.embed_origin +
          '/embed/dograh-widget.js?token=' +
          encodeURIComponent(data.embed_token) +
          '&environment=local&apiEndpoint=' +
          encodeURIComponent(data.api_endpoint);
        script.setAttribute('data-dograh-context', JSON.stringify(context));
        script.onerror = function () {
          setStatus('The voice service could not be reached.', true);
          button.disabled = false;
          started = false;
        };
        document.body.appendChild(script);

        setStatus('Voice channel ready. Use the widget to speak to the Service Desk.', false);
      })
      .catch(function () {
        // No verification detail is surfaced; the server logs the reason.
        setStatus('The voice channel is unavailable right now.', true);
        button.disabled = false;
        started = false;
      });
  });
})();
