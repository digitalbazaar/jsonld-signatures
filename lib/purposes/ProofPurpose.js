/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

module.exports = class ProofPurpose {
  /**
   * @param term {string} the `proofPurpose` term, as defined in the
   *    SECURITY_CONTEXT_URL `@context` or a URI if not defined in such.
   * @param [date] {string or Date or integer} the expected date for
   *   the creation of the proof.
   * @param [maxTimestampDelta] {integer} a maximum number of seconds that
   *   the date on the signature can deviate from, defaults to `Infinity`.
   */
  constructor({term, date, maxTimestampDelta = Infinity} = {}) {
    if(term === undefined) {
      throw new Error('"term" is required.');
    }
    if(maxTimestampDelta !== undefined &&
      typeof maxTimestampDelta !== 'number') {
      throw new TypeError('"maxTimestampDelta" must be a number.');
    }
    this.term = term;
    this.date = date;
    this.maxTimestampDelta = maxTimestampDelta;
  }

  async validate(
    proof, {document, suite, verificationMethod,
      documentLoader, expansionMap}) {
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
      return {valid: true};
    } catch(error) {
      return {valid: false, error};
    }
  }

  async update(proof, {document, suite, documentLoader, expansionMap}) {
    proof.proofPurpose = this.term;
    return proof;
  }

  async match(proof, {document, documentLoader, expansionMap}) {
    return proof.proofPurpose === this.term;
  }
};
