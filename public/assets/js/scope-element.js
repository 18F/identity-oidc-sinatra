class ScopeElement extends HTMLElement {
  connectedCallback() {
    this.syncCheckedToIAL();
    this.ial.addEventListener('input', () => this.syncCheckedToIAL());
  }

  /**
   * @return {HTMLInputElement}
   */
  get checkbox() {
    return this.querySelector('[type=checkbox]');
  }

  /**
   * @return {HTMLSelectElement}
   */
  get ial() {
    return this.ownerDocument.getElementById(this.getAttribute('ial-element'));
  }

  /**
   * @return {Record<string, string[]>}
   */
  get defaultScopesByIAL() {
    const defaultScopes = this.ownerDocument.getElementById(
      this.getAttribute('default-scopes-element')
    );
    return JSON.parse(defaultScopes.textContent);
  }

  syncCheckedToIAL() {
    const defaultScopes = this.defaultScopesByIAL[this.ial.value];
    this.checkbox.checked = defaultScopes.includes(this.checkbox.value);
  }
}

if (!window.customElements.get('lg-scope')) {
  window.customElements.define('lg-scope', ScopeElement);
}
