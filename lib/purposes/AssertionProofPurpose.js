/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const ControllerProofPurpose = require('./ControllerProofPurpose');

module.exports = class AssertionProofPurpose extends ControllerProofPurpose {
  constructor({
    term = 'assertionMethod', controller, owner,
    date, maxTimestampDelta = Infinity} = {}) {
    super({term, controller, owner});
    if(maxTimestampDelta !== undefined &&
      typeof maxTimestampDelta !== 'number') {
      throw new TypeError('"maxTimestampDelta" must be a number.');
    }
    this.date = date;
    this.maxTimestampDelta = maxTimestampDelta;
  }

  async validate(proof, {verificationMethod, documentLoader, expansionMap}) {
    try {
      // check expiration
      if(this.maxTimestampDelta !== Infinity) {
        const expected = Date.parse(this.date || Date.now());
        const delta = this.maxTimestampDelta * 1000;
        const created = Date.parse(proof.created);
        if(created < (expected - delta) || created > (expected + delta)) {
          throw new Error('The proof\'s created timestamp is out of range.');
        }
      }
      return super.validate(
        proof, {verificationMethod, documentLoader, expansionMap});
    } catch(error) {
      return {valid: false, error};
    }
  }
};
