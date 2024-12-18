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

  describe('if the value is in default scope for selected ial value', () => {
    beforeEach(() => {
      document.body.innerHTML += `
        <lg-scope ial-element="ial" default-scopes-element="default-scopes">
          <input type="checkbox" value="a">
        </lg-scope>
      `;
    });

    it('is checked when connected', () => {
      const checkbox = document.querySelector('[type=checkbox]');
      assert(checkbox.checked);
    });
  });

  describe('if value is not in default scope for selected ial value', () => {
    beforeEach(() => {
      document.body.innerHTML += `
        <lg-scope ial-element="ial" default-scopes-element="default-scopes">
          <input type="checkbox" value="c">
        </lg-scope>
      `;
    });

    it('is not checked when connected', () => {
      const checkbox = document.querySelector('[type=checkbox]');
      assert(!checkbox.checked);
    });
  });

  describe('selected ial value changes', () => {
    describe('if in default scope', () => {
      beforeEach(() => {
        document.body.innerHTML += `
          <lg-scope ial-element="ial" default-scopes-element="default-scopes">
            <input type="checkbox" value="c">
          </lg-scope>
        `;

        const select = document.querySelector('select');
        select.value = '2';
        select.dispatchEvent(new window.InputEvent('input'));
      });

      it('is checked', () => {
        const checkbox = document.querySelector('[type=checkbox]');
        assert(checkbox.checked);
      });
    });

    describe('if not in default scope', () => {
      beforeEach(() => {
        document.body.innerHTML += `
          <lg-scope ial-element="ial" default-scopes-element="default-scopes">
            <input type="checkbox" value="a">
          </lg-scope>
        `;

        const select = document.querySelector('select');
        select.value = '2';
        select.dispatchEvent(new window.InputEvent('input'));
      });

      it('is unchecked', () => {
        const checkbox = document.querySelector('[type=checkbox]');
        assert(!checkbox.checked);
      });
    });
  });
});
