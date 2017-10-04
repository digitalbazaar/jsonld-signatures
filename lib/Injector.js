/*
 * Copyright (c) 2017 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

module.exports = class Injector {
  constructor() {
    this._libs = {};
    this.env = {};
    this.env.nodejs = (typeof process !== 'undefined' &&
      process.versions && process.versions.node);
    if(!this.env.nodejs) {
      this.env.browser = true;
    }
  }

  /**
   * Allows injectables to be set or retrieved.
   *
   * @param name the name of the injectable to use (
   *          eg: `jsonld`, `jsonld-signatures`).
   * @param [injectable] the api to set for the injectable, only present for
   *          setter, omit for getter.
   *
   * @return the API for `name` if not using this method as a setter, otherwise
   *           undefined.
   */
  use(name, injectable) {
    // setter mode
    if(injectable) {
      this._libs[name] = injectable;
      return;
    }

    // getter mode:

    // api not set yet, load default
    if(!this._libs[name]) {
      const requireAliases = {
        'forge': 'node-forge',
        'bitcoreMessage': 'bitcore-message'
      };
      const requireName = requireAliases[name] || name;
      this._libs[name] = global[name] || (this.env.nodejs &&
        require(requireName));
      if(name === 'jsonld' && this.env.nodejs) {
        // locally configure jsonld
        this._libs[name] = this._libs[name]();
        this._libs[name].useDocumentLoader(
          'node', {secure: true, strictSSL: true});
      }
    }
    return this._libs[name];
  }
};
