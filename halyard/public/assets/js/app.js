/*
 * Halyard front end.
 * Checks fields as you type, unfurls a flag for each valid field, and shows or hides passwords.
 * This is a convenience only: the server re-checks everything and is the one that decides.
 */
(() => {
  'use strict';

  const form = document.querySelector('form[data-auth-form]');
  if (!form) return;

  const inputs = Array.from(form.querySelectorAll('input[data-rule]'));
  const submit = form.querySelector('button[type="submit"]');
  const touched = new Set();

  const length = (value) => Array.from(value).length; // count characters, not UTF-16 units

  const rules = {
    identifier: (v) => (v.trim() ? '' : 'Enter your username or email.'),
    'current-password': (v) => (v ? '' : 'Enter your password.'),
    username: (v) => (/^[A-Za-z0-9_]{3,24}$/.test(v.trim()) ? '' : 'Use 3 to 24 letters, numbers or underscores.'),
    email: (v) => (v.trim().length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v.trim()) ? '' : 'Enter a valid email address.'),
    'new-password': (v) => {
      if (length(v) < 10) return 'Use at least 10 characters.';
      if (length(v) > 128) return 'Use 128 characters or fewer.';
      return '';
    },
    confirm: (v) => {
      const original = form.elements.namedItem('password');
      return v !== '' && original && v === original.value ? '' : 'Passwords don’t match.';
    },
  };

  const errorFor = (input) => form.querySelector(`[data-error-for="${input.dataset.flag}"]`);
  const flagFor = (input) => document.querySelector(`[data-flag-for="${input.dataset.flag}"]`);
  const check = (input) => rules[input.dataset.rule](input.value);

  function showError(input, message) {
    const slot = errorFor(input);
    if (slot) {
      slot.textContent = message;
      slot.hidden = message === '';
    }
    if (message) {
      input.setAttribute('aria-invalid', 'true');
    } else {
      input.removeAttribute('aria-invalid');
    }
  }

  // A flag is hoisted while its field is valid.
  function updateFlags() {
    inputs.forEach((input) => {
      const flag = flagFor(input);
      if (flag) flag.classList.toggle('is-hoisted', check(input) === '');
    });
  }

  inputs.forEach((input) => {
    input.addEventListener('input', () => {
      updateFlags();
      // Once a field has been visited, keep its message in step with what is typed.
      inputs.forEach((other) => {
        if (touched.has(other)) showError(other, check(other));
      });
    });
    input.addEventListener('change', updateFlags);
    input.addEventListener('blur', () => {
      if (input.value !== '') touched.add(input);
      if (touched.has(input)) showError(input, check(input));
    });
  });

  // Show or hide password text.
  form.querySelectorAll('button[data-toggle]').forEach((button) => {
    const target = document.getElementById(button.dataset.toggle);
    if (!target) return;
    button.addEventListener('click', () => {
      const reveal = target.type === 'password';
      target.type = reveal ? 'text' : 'password';
      button.textContent = reveal ? 'Hide' : 'Show';
      button.setAttribute('aria-pressed', String(reveal));
    });
  });

  form.addEventListener('submit', (event) => {
    let firstInvalid = null;
    inputs.forEach((input) => {
      const message = check(input);
      touched.add(input);
      showError(input, message);
      if (message && !firstInvalid) firstInvalid = input;
    });

    if (firstInvalid) {
      event.preventDefault();
      firstInvalid.focus();
      return;
    }

    // Stop double submits. Disabled in a tick so the form data is already captured.
    if (submit) {
      submit.dataset.label = submit.textContent;
      submit.textContent = submit.dataset.busy || 'Working…';
      window.setTimeout(() => { submit.disabled = true; }, 0);
    }
  });

  // Coming back with the browser's Back button should not leave the button stuck.
  window.addEventListener('pageshow', () => {
    if (submit && submit.disabled) {
      submit.disabled = false;
      submit.textContent = submit.dataset.label || submit.textContent;
    }
  });

  updateFlags();
  // Browsers fill saved passwords a moment after load without firing input events.
  window.setTimeout(updateFlags, 400);
})();
