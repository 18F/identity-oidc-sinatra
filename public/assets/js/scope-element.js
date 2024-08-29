class ScopeElement extends HTMLElement {
  connectedCallback() {
    this.syncCheckedToIal();
    this.ial.addEventListener('input', () => this.syncCheckedToIal());
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

  syncCheckedToIal() {
    const defaultScopes = this.defaultScopesByIAL[this.ial.value];
    this.checkbox.checked = defaultScopes.includes(this.checkbox.value);
  }
}

if (!customElements.get('lg-scope')) {
  customElements.define('lg-scope', ScopeElement);
}
