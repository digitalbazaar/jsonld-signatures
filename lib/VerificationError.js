/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict'

/**
 * Used as an umbrella wrapper around multiple verification errors.
 */
class VerificationError extends Error {
  /**
   * @param {Error|Error[]} errors
   */
  constructor(errors) {
    super('Verification error(s).');

    this.name = 'VerificationError';
    this.errors = [].concat(errors);
  }
}
module.exports = VerificationError;
