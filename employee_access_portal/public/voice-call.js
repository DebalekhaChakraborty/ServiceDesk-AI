'use strict';

/**
 * ServiceDesk Voice bootstrap, shared by both entry points. Same-origin so
 * script-src stays 'self' + Dograh.
 *
 * ONE SCRIPT, TWO DOORS
 * ---------------------
 * The public sign-in page and the authenticated workspace reach the same voice
 * channel and differ in exactly two values, both read off the form:
 *
 *   data-endpoint  /recovery/start  (public)  |  /voice/session (authenticated)
 *   data-csrf      absent           (public)  |  session CSRF   (authenticated)
 *
 * Neither is an identity. The authenticated endpoint derives who the caller is
 * from the sealed session cookie; the public one accepts no identity at all and
 * leaves it to Duo on the call.
 *
 * The page sends NOTHING identifying - not a name, not an address, not an
 * employee ID. It receives a call_id and a signed bootstrap. Everything that
 * matters happens on the call: the caller says what they need, states an
 * identifier by voice, and Duo decides whether they are that person before the
 * Service Desk hears a word of it.
 *
 * THE PANEL IS A SHELL, NOT A SECOND CALLER
 * -----------------------------------------
 * The in-call panel below displays state; it does not own any. There is exactly
 * one call, owned by the Dograh widget:
 *
 *   start    -> DograhWidget.start()   (the widget's own start path)
 *   end      -> DograhWidget.end()     (literally the function its own End Call
 *                                       button binds - see `endBtn.onclick =
 *                                       stopCall` in the embed script)
 *   state    -> onCallStart / onCallConnected / onCallDisconnected /
 *               onCallEnd / onError / onStatusChange
 *
 * Every state shown is pushed by one of those callbacks. Nothing here polls,
 * infers state from elapsed time, or reads the caller's words. This page opens
 * no MediaStream and requests no microphone permission; Dograh remains the sole
 * owner of the microphone and the WebRTC session.
 *
 * The widget's own floating button is never removed, re-created, or driven by
 * a second instance - it keeps running the whole time, in the bottom-right
 * corner. This panel lives in the bottom-left instead (see styles.css) so the
 * two never overlap, without this page needing to know or clip the widget's
 * own markup.
 */
(function () {
  var form = document.getElementById('recovery-form');
  var statusEl = document.getElementById('voice-status');
  if (!form || !statusEl) return;

  // Optional: the standalone /recovery page has no launcher chrome, so every
  // reference below tolerates a missing element rather than assuming one page.
  var launcher = document.getElementById('voice-launcher');
  var caption = document.getElementById('voice-caption');
  var panel = document.getElementById('voice-panel');
  var panelState = document.getElementById('voice-state');
  var liveText = document.getElementById('voice-live-text');
  var endButton = document.getElementById('voice-end');
  var startButton = document.getElementById('recovery-start');

  // One call per page load. Guards a double submit, a double script injection,
  // and a second DograhWidget.start().
  var launching = false;
  var widgetStarted = false;

  // Server-rendered, never derived from the URL or anything the user typed.
  var endpoint = form.getAttribute('data-endpoint') || '/recovery/start';
  var csrfToken = form.getAttribute('data-csrf') || '';

  var STATES = {
    connecting: { text: 'Connecting to ServiceDesk…', live: 'Connecting' },
    active: { text: 'Listening…', live: 'Live' },
    ending: { text: 'Ending call…', live: 'Ending' },
    failed: { text: 'The call could not be completed.', live: 'Not connected' },
  };

  function prefersReducedMotion() {
    return window.matchMedia
      && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  }

  function setState(name) {
    var spec = STATES[name];
    if (!spec || !panel) return;
    if (panelState) panelState.textContent = spec.text;
    if (liveText) liveText.textContent = spec.live;
    panel.classList.remove(
      'callpanel--connecting', 'callpanel--active',
      'callpanel--ending', 'callpanel--failed');
    panel.classList.add('callpanel--' + name);
  }

  function openPanel() {
    if (!panel) return;
    document.body.classList.add('voice-call-active');
    if (launcher) launcher.hidden = true;
    panel.hidden = false;
    setState('connecting');
    // Two frames: the browser must paint the closed state before the class that
    // animates away from it, or the transition is skipped entirely.
    requestAnimationFrame(function () {
      requestAnimationFrame(function () { panel.classList.add('is-open'); });
    });
    if (endButton) endButton.focus();
  }

  function closePanel() {
    document.body.classList.remove('voice-call-active');
    if (!panel) {
      if (launcher) launcher.hidden = false;
      return;
    }
    panel.classList.remove('is-open');

    var restore = function () {
      panel.hidden = true;
      if (launcher) launcher.hidden = false;
      if (caption) caption.hidden = false;
      if (statusEl) {
        statusEl.textContent = '';
        statusEl.classList.remove('launcher__status--error');
      }
      if (startButton) {
        startButton.disabled = false;
        startButton.focus();
      }
      launching = false;
      widgetStarted = false;
    };

    if (prefersReducedMotion()) return restore();
    // transitionend is the truth, with a timer only as a backstop for the case
    // where the transition never fires (element hidden, tab backgrounded).
    var done = false;
    var finish = function () { if (!done) { done = true; restore(); } };
    panel.addEventListener('transitionend', finish, { once: true });
    window.setTimeout(finish, 400);
  }

  function fail(message) {
    statusEl.textContent = message;
    statusEl.classList.add('launcher__status--error');
    if (caption) caption.hidden = false;
    if (startButton) startButton.disabled = false;
    launching = false;
  }

  /**
   * Subscribe the panel to the widget's OWN lifecycle.
   *
   * Called once, after the embed script loads. Registering a callback does not
   * create anything: each setter simply stores a function the widget already
   * calls at the points it already calls it.
   */
  function bindWidgetLifecycle() {
    var widget = window.DograhWidget;
    if (!widget) return false;

    if (widget.onCallStart) widget.onCallStart(function () { setState('connecting'); });
    if (widget.onCallConnected) widget.onCallConnected(function () { setState('active'); });
    if (widget.onCallDisconnected) widget.onCallDisconnected(function () { setState('ending'); });
    if (widget.onCallEnd) widget.onCallEnd(function () { closePanel(); });
    if (widget.onError) widget.onError(function () { setState('failed'); });

    // The widget's own status vocabulary: idle | connecting | connected |
    // failed. Only the first argument is used — the display strings it also
    // passes are its wording, and this panel keeps its own.
    if (widget.onStatusChange) {
      widget.onStatusChange(function (status) {
        if (status === 'connected') setState('active');
        else if (status === 'connecting') setState('connecting');
        else if (status === 'failed') setState('failed');
      });
    }
    return true;
  }

  if (endButton) {
    endButton.addEventListener('click', function () {
      endButton.disabled = true;
      setState('ending');
      var widget = window.DograhWidget;
      // The SAME termination the widget's own control performs. If it is
      // somehow unavailable, the panel still closes rather than stranding the
      // caller in a dead UI.
      if (widget && typeof widget.end === 'function') {
        try {
          var result = widget.end();
          if (result && typeof result.then === 'function') {
            result.then(function () { closePanel(); },
                        function () { closePanel(); });
            return;
          }
        } catch (error) {
          /* fall through to closing the panel */
        }
      }
      closePanel();
    });
  }

  form.addEventListener('submit', function (event) {
    event.preventDefault();
    if (launching) return;
    launching = true;

    if (startButton) startButton.disabled = true;
    statusEl.classList.remove('launcher__status--error');
    statusEl.textContent = 'Connecting you to ServiceDesk…';
    if (caption) caption.hidden = true;

    var body = '';
    if (csrfToken) {
      var params = new URLSearchParams();
      params.set('csrf_token', csrfToken);
      body = params.toString();
    }

    fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body,
      credentials: 'same-origin',
    })
      .then(function (r) { if (!r.ok) throw new Error('unavailable'); return r.json(); })
      .then(function (data) {
        // Exactly one widget per page load.
        if (document.getElementById('dograh-widget')) return;

        var script = document.createElement('script');
        script.id = 'dograh-widget';
        script.async = true;
        script.src = data.embed_origin + '/embed/dograh-widget.js?token=' +
          encodeURIComponent(data.embed_token) + '&environment=local&apiEndpoint=' +
          encodeURIComponent(data.api_endpoint);
        // The ONLY two values the browser hands Dograh. Named rather than
        // inlined so the "exactly these two, and nothing identifying" property
        // stays mechanically checkable from outside.
        var context = {
          call_id: data.call_id,
          voice_identity_token: data.voice_identity_token,
        };
        script.setAttribute('data-dograh-context', JSON.stringify(context));

        script.addEventListener('load', function () {
          bindWidgetLifecycle();
          openPanel();
          // One press should place the call. Without this the caller must find
          // and press the widget's own button as a second step — which is the
          // control this panel deliberately covers.
          var widget = window.DograhWidget;
          if (!widgetStarted && widget && typeof widget.start === 'function') {
            widgetStarted = true;
            try {
              var started = widget.start();
              if (started && typeof started.catch === 'function') {
                started.catch(function () { setState('failed'); });
              }
            } catch (error) {
              setState('failed');
            }
          }
        });
        script.addEventListener('error', function () {
          if (launcher) launcher.hidden = false;
          closePanel();
          fail('ServiceDesk voice could not start. Please try again.');
        });

        document.body.appendChild(script);
        statusEl.textContent = 'Connected. Tell ServiceDesk what you need help with.';
      })
      .catch(function () {
        fail('ServiceDesk voice is unavailable right now.');
      });
  });
})();
