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
    if(date !== undefined) {
      this.date = new Date(date);
      if(isNaN(this.date)) {
        throw TypeError(`"date" "${date}" is not a valid date.`);
      }
    }
    this.maxTimestampDelta = maxTimestampDelta;
  }

  /**
   * Called to validate the purpose of a proof. This method is called during
   * proof verification, after the proof value has been checked against the
   * given verification method (e.g. in the case of a digital signature, the
   * signature has been cryptographically verified against the public key).
   *
   * @param proof {object} the proof, in the `constants.SECURITY_CONTEXT_URL`,
   *   with the matching purpose to validate.
   *
   * @return {Promise<object>} resolves to an object with `valid` and `error`.
   */
  async validate(
    proof, {document, suite, verificationMethod,
      documentLoader, expansionMap}) {
    try {
      // check expiration
      if(this.maxTimestampDelta !== Infinity) {
        const expected = (this.date || new Date()).getTime();
        const delta = this.maxTimestampDelta * 1000;
        const created = new Date(proof.created).getTime();
        // comparing this way handles NaN case where `created` is invalid
        if(!(created >= (expected - delta) && created <= (expected + delta))) {
          throw new Error('The proof\'s created timestamp is out of range.');
        }
      }
      return {valid: true};
    } catch(error) {
      return {valid: false, error};
    }
  }

  /**
   * Called to update a proof when it is being created, adding any properties
   * specific to this purpose. This method is called prior to the proof
   * value being generated such that any properties added may be, for example,
   * included in a digital signature value.
   *
   * @param proof {object} the proof, in the `constants.SECURITY_CONTEXT_URL`
   *   to update.
   *
   * @return {Promise<object>} resolves to the proof instance (in the
   *   `constants.SECURITY_CONTEXT_URL`.
   */
  async update(proof, {document, suite, documentLoader, expansionMap}) {
    proof.proofPurpose = this.term;
    return proof;
  }

  /**
   * Determines if the given proof has a purpose that matches this instance,
   * i.e. this ProofPurpose instance should be used to validate the given
   * proof.
   *
   * @param proof {object} the proof to check.
   *
   * @return {Promise<boolean>} `true` if there's a match, `false` if not.
   */
  async match(proof, {document, documentLoader, expansionMap}) {
    return proof.proofPurpose === this.term;
  }
};
