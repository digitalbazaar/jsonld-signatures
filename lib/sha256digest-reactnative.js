/*
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const crypto = require('isomorphic-webcrypto');
require('fast-text-encoding');

module.exports = {
  /**
   * Hashes a string of data using SHA-256.
   *
   * @param {string} string - the string to hash.
   *
   * @return {Uint8Array} the hash digest.
   */
  async sha256digest({string}) {
    const bytes = new TextEncoder().encode(string);
    return new Uint8Array(
      await crypto.subtle.digest({name: 'SHA-256'}, bytes)
    );
  }
};
