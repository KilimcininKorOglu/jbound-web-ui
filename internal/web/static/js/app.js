/**
 * Panel behaviour.
 *
 * The reference interface drives the page with jQuery and hand written ajax
 * calls. htmx replaces all of it, so this file only has to connect htmx to the
 * dialog and toast components and to handle the two clicks that cannot be
 * inline handlers under the content security policy.
 */

'use strict';

(function () {
  const PRIMARY = '#1B8A4E';
  const SECONDARY = '#8592a3';

  /* The texts this file raises come from the server, because the panel speaks
     more than one language and the content security policy allows no inline
     script to carry them. The body element holds them as JSON. */
  const STRINGS = readStrings();

  function readStrings() {
    const raw = document.body.getAttribute('data-strings');
    if (!raw) {
      return {};
    }
    try {
      return JSON.parse(raw);
    } catch (error) {
      /* A page without its texts still works. Falling back to the key is
         better than a dialog that never opens. */
      console.error('cannot read the interface texts', error);
      return {};
    }
  }

  /* text returns one interface string, falling back to its key. */
  function text(key) {
    return STRINGS[key] || key;
  }

  /* htmx injects a style element for its indicator classes. The content
     security policy allows no inline style, so the rules live in panel.css
     instead. */
  htmx.config.includeIndicatorStyles = false;

  /* Which status codes replace content.
   *
   * htmx swaps nothing on a 4xx by default. The panel answers a rejected form
   * with a rendered message, and that message has to reach the page. A 207
   * carries a partial fleet result, which is exactly the case the reader most
   * needs to see. Anything else keeps the page as it is and raises a toast. */
  htmx.config.responseHandling = [
    { code: '204', swap: false },
    { code: '[23]..', swap: true },
    { code: '400', swap: true },
    { code: '401', swap: true },
    { code: '409', swap: true },
    { code: '422', swap: true },
    { code: '429', swap: true },
    { code: '[45]..', swap: false, error: true }
  ];

  const Toast = Swal.mixin({
    toast: true,
    position: 'bottom-end',
    showConfirmButton: false,
    timer: 3000,
    timerProgressBar: true
  });

  function showToast(severity, message) {
    Toast.fire({ icon: severity || 'info', title: message });
  }

  /* The server raises a toast with the HX-Trigger header. htmx turns each
     entry into a DOM event, so the handler only has to read the detail. */
  document.body.addEventListener('toast', function (event) {
    const detail = event.detail || {};
    showToast(detail.severity, detail.message);
  });

  /* A failed request does not swap, so the reader would otherwise see nothing
     at all. The server sends a message when it can, and the status code is the
     fallback when it cannot, such as on a plain 403. */
  document.body.addEventListener('htmx:responseError', function (event) {
    const xhr = event.detail.xhr;
    let message = '';

    const header = xhr.getResponseHeader('HX-Trigger');
    if (header) {
      try {
        const triggers = JSON.parse(header);
        if (triggers.toast && triggers.toast.message) {
          message = triggers.toast.message;
        }
      } catch (error) {
        /* A header that will not parse is a server fault. Reporting the status
           is more useful to the reader than reporting the parse error. */
        message = '';
      }
    }
    if (!message) {
      message = text('client.request_failed').replace('%s', xhr.status);
    }
    showToast('error', message);
  });

  document.body.addEventListener('htmx:sendError', function () {
    showToast('error', text('client.unreachable'));
  });

  /* hx-confirm asks for a plain browser dialog. This replaces it with the
     dialog the rest of the interface uses. */
  document.body.addEventListener('htmx:confirm', function (event) {
    if (!event.detail.question) {
      return;
    }
    event.preventDefault();

    Swal.fire({
      title: event.target.getAttribute('data-confirm-title') || text('client.confirm_title'),
      text: event.detail.question,
      icon: 'warning',
      showCancelButton: true,
      confirmButtonColor: PRIMARY,
      cancelButtonColor: SECONDARY,
      confirmButtonText: text('client.yes'),
      cancelButtonText: text('client.cancel')
    }).then(function (result) {
      if (result.isConfirmed) {
        event.detail.issueRequest(true);
      }
    });
  });

  /* A refused form comes back as a swap, and the reader is left wherever they
     were. The first control the panel refused takes the focus, which is what
     carries a screen reader to the problem and scrolls the page to it. */
  document.body.addEventListener('htmx:afterSwap', function (event) {
    const target = event.detail ? event.detail.target : null;
    if (!target || !target.querySelector) {
      return;
    }

    const refused = target.querySelector('[aria-invalid="true"]');
    if (refused) {
      refused.focus();
    }
  });

  /* Click handlers, delegated from the document so they survive a swap. */
  document.addEventListener('click', function (event) {
    const trigger = event.target.closest('[data-action]');
    if (!trigger) {
      return;
    }

    if (trigger.dataset.action === 'toggle-password') {
      event.preventDefault();
      togglePassword(trigger);
      return;
    }

    if (trigger.dataset.action === 'logout') {
      event.preventDefault();
      confirmLogout();
      return;
    }

    /* Closing a panel is a client side concern. Asking the server for an
       empty fragment would be a round trip for nothing. */
    if (trigger.dataset.action === 'close-panel') {
      event.preventDefault();
      clearPanel('server-panel');
      return;
    }

    if (trigger.dataset.action === 'close-record-panel') {
      event.preventDefault();
      clearPanel('record-panel');
    }
  });

  /* The preference belongs to MX alone, so the field appears with it. */
  document.addEventListener('change', function (event) {
    const select = event.target.closest('[data-action="record-type"]');
    if (!select) {
      return;
    }

    const form = select.form;
    const priority = form ? form.querySelector('[data-field="priority"]') : null;
    if (priority) {
      priority.hidden = select.value !== 'MX';
    }
  });

  function clearPanel(id) {
    const panel = document.getElementById(id);
    if (panel) {
      panel.innerHTML = '';
    }
  }

  function togglePassword(trigger) {
    const input = document.getElementById(trigger.dataset.target);
    const icon = trigger.querySelector('[data-role="toggle-icon"]');
    if (!input) {
      return;
    }

    const hidden = input.type === 'password';
    input.type = hidden ? 'text' : 'password';
    if (icon) {
      icon.classList.replace(hidden ? 'bx-hide' : 'bx-show',
        hidden ? 'bx-show' : 'bx-hide');
    }
  }

  function confirmLogout() {
    Swal.fire({
      title: text('client.logout_title'),
      text: text('client.logout_question'),
      icon: 'warning',
      showCancelButton: true,
      confirmButtonColor: PRIMARY,
      cancelButtonColor: SECONDARY,
      confirmButtonText: text('client.yes'),
      cancelButtonText: text('client.cancel')
    }).then(function (result) {
      if (result.isConfirmed) {
        /* The token rides on the body element, so htmx adds it to this
           request the same way it does to every other one. */
        htmx.ajax('POST', '/logout', { source: document.body });
      }
    });
  }
})();
