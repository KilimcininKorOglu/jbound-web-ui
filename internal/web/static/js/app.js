/**
 * Panel behaviour.
 *
 * htmx does the requests and SweetAlert2 draws the dialogs, so this file only
 * has to connect the two and to handle the clicks that cannot be inline
 * handlers under the content security policy.
 */

'use strict';

(function () {
  /* The dialog buttons take their colours from panel.css rather than from
     here, so the two themes need no colour in JavaScript and the palette has
     one home. */

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

  /* A rendered fragment goes on the page whatever the status says.

     A fleet operation where every server failed answers 500, and the body is
     the per-server table naming what each of them said. Thrown away, it left
     the operator with a toast that vanishes and no way to find out which
     server refused the change or why. A bare error carries no header and is
     still handled as an error, so a panel that cannot answer at all does not
     write its plumbing onto the page. */
  document.body.addEventListener('htmx:beforeSwap', function (event) {
    const xhr = event.detail.xhr;
    if (xhr && xhr.getResponseHeader('HX-Fragment')) {
      event.detail.shouldSwap = true;
    }
  });

  const Toast = Swal.mixin({
    toast: true,
    position: 'bottom-end',
    showConfirmButton: false,
    timer: 3000,
    timerProgressBar: true
  });

  /* titleText rather than title. SweetAlert2 parses title as HTML and writes
     titleText with innerText, and this message reaches the client as JSON in a
     response header, outside the template engine that escapes everything else. */
  function showToast(severity, message) {
    Toast.fire({ icon: severity || 'info', titleText: message });
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

  /* No browser dialog reaches the reader.
   *
   * htmx calls window.confirm for hx-confirm and window.prompt for hx-prompt,
   * and both are handed over here instead. They are the only two native
   * dialogs the panel can produce: nothing it writes calls alert, confirm or
   * prompt, and a test holds that.
   *
   * A native dialog is worth replacing for more than its looks. It freezes the
   * page, it ignores the panel's language and theme, and its wording is the
   * browser's rather than the operator's. */
  document.body.addEventListener('htmx:confirm', function (event) {
    if (!event.detail.question) {
      return;
    }
    event.preventDefault();

    Swal.fire({
      titleText: event.target.getAttribute('data-confirm-title') || text('client.confirm_title'),
      text: event.detail.question,
      icon: 'warning',
      position: 'center',
      showCancelButton: true,
      confirmButtonText: text('client.yes'),
      cancelButtonText: text('client.cancel')
    }).then(function (result) {
      if (result.isConfirmed) {
        event.detail.issueRequest(true);
      }
    });
  });

  /* hx-prompt, before htmx reaches window.prompt for it.
   *
   * The panel uses no hx-prompt today. The handler is here so that adding one
   * cannot quietly bring the browser dialog back, which is the failure nobody
   * would notice until a screenshot. */
  document.body.addEventListener('htmx:prompt', function (event) {
    event.preventDefault();

    Swal.fire({
      titleText: event.detail.prompt || text('client.prompt_title'),
      input: 'text',
      inputAttributes: { autocapitalize: 'off', spellcheck: 'false' },
      icon: 'question',
      position: 'center',
      showCancelButton: true,
      confirmButtonText: text('client.yes'),
      cancelButtonText: text('client.cancel')
    }).then(function (result) {
      /* An empty answer is still an answer. Cancelling is the only way to
         call the whole thing off. */
      event.detail.promptValue = result.isConfirmed ? (result.value || '') : null;
      event.detail.issueRequest();
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

    /* A form that came back with several rows needs its remove buttons in the
       right state, and a form with one row needs its button off. */
    target.querySelectorAll('form').forEach(function (form) {
      if (form.querySelector('[data-field="record-row"]')) {
        updateRowControls(form);
      }
    });
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

    /* The message is on the page in front of the reader, so dismissing it is
       a page concern and reaches no server. */
    if (trigger.dataset.action === 'dismiss-alert') {
      event.preventDefault();
      const alert = trigger.closest('[role="alert"]');
      if (alert) {
        alert.remove();
      }
      return;
    }

    if (trigger.dataset.action === 'toggle-drawer') {
      event.preventDefault();
      setDrawer(!document.body.classList.contains('drawer-open'));
      return;
    }

    if (trigger.dataset.action === 'close-drawer') {
      event.preventDefault();
      setDrawer(false);
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
      return;
    }

    if (trigger.dataset.action === 'add-record-row') {
      event.preventDefault();
      addRecordRow(trigger.closest('form'));
      return;
    }

    if (trigger.dataset.action === 'remove-record-row') {
      event.preventDefault();
      removeRecordRow(trigger.closest('[data-field="record-row"]'));
    }
  });

  /* The transport decides what the rest of the server form is for. A record
     reached through an agent has no account, no tool paths and no commands:
     the agent owns all of them, and showing fields that reach nothing would
     be asking the operator to fill in decisions somebody else already made. */
  document.addEventListener('change', function (event) {
    const select = event.target.closest('[data-action="transport"]');
    if (!select) {
      return;
    }

    const form = select.form;
    if (!form) {
      return;
    }
    form.querySelectorAll('[data-transport]').forEach(function (block) {
      block.hidden = block.dataset.transport !== select.value;
    });
  });

  /* The types that name a behaviour rather than data. A blocked name answers
     NXDOMAIN or REFUSED on its own, so it takes neither a value nor a
     preference. */
  const BLOCK_TYPES = ['NXDOMAIN', 'REFUSED'];

  /* The preference belongs to MX alone, so the field appears with it. The
     value belongs to every type except the two that block a name. */
  document.addEventListener('change', function (event) {
    const select = event.target.closest('[data-action="record-type"]');
    if (!select) {
      return;
    }

    /* Scoped to the row rather than to the form. The add form holds several
       rows, and hiding the preference of every one of them because one row
       stopped being an MX is not what the operator asked for. */
    const scope = select.closest('[data-field="record-row"]') || select.form;
    if (!scope) {
      return;
    }

    const blocks = BLOCK_TYPES.indexOf(select.value) !== -1;

    const priority = scope.querySelector('[data-field="priority"]');
    if (priority) {
      priority.hidden = select.value !== 'MX';
    }

    /* The preference is a hidden field carrying the form's own default. It
       reaches nothing on a blocked name, so it goes back to zero rather than
       riding along at ten. */
    const priorityInput = priority
      ? (priority.tagName === 'INPUT' ? priority : priority.querySelector('input'))
      : null;
    if (priorityInput && blocks) {
      priorityInput.value = '0';
    }

    const help = scope.querySelector('[data-field="policy-help"]');
    if (help) {
      help.hidden = !blocks;
    }

    const value = scope.querySelector('[data-field="value"]');
    if (!value) {
      return;
    }
    value.hidden = blocks;

    /* The input is the block itself in a row and sits inside it in the edit
       form, so the required flag and the text are looked up either way. */
    const input = value.tagName === 'INPUT' ? value : value.querySelector('input');
    if (!input) {
      return;
    }
    input.required = !blocks;

    /* Cleared rather than left behind. A hidden field still posts, the server
       refuses a blocked name that carries a value, and the operator would be
       reading a complaint about a field they cannot see. */
    if (blocks) {
      input.value = '';
    }
  });

  /* Another record in the same submission. A row is cloned from the last one,
     so the markup lives in the template rather than in here. */
  function addRecordRow(form) {
    const rows = form ? form.querySelectorAll('[data-field="record-row"]') : [];
    if (!rows.length) {
      return;
    }

    const row = rows[rows.length - 1].cloneNode(true);
    row.querySelectorAll('input').forEach(function (input) {
      input.value = input.type === 'number' ? input.defaultValue : '';
    });
    rows[rows.length - 1].after(row);
    updateRowControls(form);

    const first = row.querySelector('input');
    if (first) {
      first.focus();
    }
  }

  function removeRecordRow(row) {
    const form = row ? row.closest('form') : null;
    if (!form || form.querySelectorAll('[data-field="record-row"]').length < 2) {
      return;
    }
    row.remove();
    updateRowControls(form);
  }

  /* A single row has nothing to remove, so its button says so rather than
     leaving a control that does nothing. */
  function updateRowControls(form) {
    const rows = form.querySelectorAll('[data-field="record-row"]');
    rows.forEach(function (row) {
      const button = row.querySelector('[data-action="remove-record-row"]');
      if (button) {
        button.disabled = rows.length < 2;
      }
    });
  }

  /* The navigation on a narrow screen. The state is a class on the body, so
     the stylesheet decides what it means and a wide screen ignores it. */
  function setDrawer(open) {
    document.body.classList.toggle('drawer-open', open);

    const toggle = document.querySelector('[data-action="toggle-drawer"]');
    if (toggle) {
      toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    }
  }

  /* Escape closes it. A reader who opened the menu by keyboard has no scrim
     to click. */
  document.addEventListener('keydown', function (event) {
    if (event.key === 'Escape' && document.body.classList.contains('drawer-open')) {
      setDrawer(false);
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
      titleText: text('client.logout_title'),
      text: text('client.logout_question'),
      icon: 'warning',
      position: 'center',
      showCancelButton: true,
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
