import { beforeEach, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import '../../public/assets/js/scope-element.js';

describe('ScopeElement', () => {
  beforeEach(() => {
    document.body.innerHTML = `
      <script type="application/json" id="default-scopes">
        {"1":["a","b"],"2":["c","d"]}
      </script>
      <select id="ial">
        <option selected value="1">
        <option value="2">
      </select>
    `;
  });

  it('is checked when connected if value is in default scope for selected ial value', () => {
    document.body.innerHTML += `
      <lg-scope ial-element="ial" default-scopes-element="default-scopes">
        <input type="checkbox" value="a">
      </lg-scope>
    `;

    const checkbox = document.querySelector('[type=checkbox]');
    assert(checkbox.checked);
  });

  it('is not checked when connected if value is not in default scope for selected ial value', () => {
    document.body.innerHTML += `
      <lg-scope ial-element="ial" default-scopes-element="default-scopes">
        <input type="checkbox" value="c">
      </lg-scope>
    `;

    const checkbox = document.querySelector('[type=checkbox]');
    assert(!checkbox.checked);
  });

  it('is checked if in default scope when selected ial value changes', () => {
    document.body.innerHTML += `
      <lg-scope ial-element="ial" default-scopes-element="default-scopes">
        <input type="checkbox" value="c">
      </lg-scope>
    `;

    const select = document.querySelector('select');
    select.value = '2';
    select.dispatchEvent(new window.InputEvent('input'));

    const checkbox = document.querySelector('[type=checkbox]');
    assert(checkbox.checked);
  });

  it('is unchecked if not in default scope when selected ial value changes', () => {
    document.body.innerHTML += `
      <lg-scope ial-element="ial" default-scopes-element="default-scopes">
        <input type="checkbox" value="a">
      </lg-scope>
    `;

    const select = document.querySelector('select');
    select.value = '2';
    select.dispatchEvent(new window.InputEvent('input'));

    const checkbox = document.querySelector('[type=checkbox]');
    assert(!checkbox.checked);
  });
});
