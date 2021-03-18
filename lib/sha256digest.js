/*
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';
const crypto = require('crypto');

module.exports = {
  /**
   * Hashes a string of data using SHA-256.
   *
   * @param {string} string - the string to hash.
   *
   * @return {Uint8Array} the hash digest.
   */
  async sha256digest({string}) {
    return new Uint8Array(
      crypto.createHash('sha256').update(string).digest()
    );
  }
};
