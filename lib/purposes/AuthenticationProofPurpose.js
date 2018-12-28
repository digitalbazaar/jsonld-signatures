/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const ControllerProofPurpose = require('./ControllerProofPurpose');

module.exports = class AuthenticationProofPurpose extends
  ControllerProofPurpose {
  constructor({
    term = 'authentication', controller,
    challenge, date, domain, maxTimestampDelta = Infinity} = {}) {
    super({term, controller, date, maxTimestampDelta});
    if(typeof challenge !== 'string') {
      throw new TypeError('"challenge" must be a string.');
    }
    if(domain !== undefined && typeof domain !== 'string') {
      throw new TypeError('"domain" must be a string.');
    }
    this.challenge = challenge;
    this.domain = domain;
  }

  async validate(proof, {verificationMethod, documentLoader, expansionMap}) {
    try {
      // check challenge
      if(proof.challenge !== this.challenge) {
        throw new Error('The challenge is not as expected; ' +
          `challenge="${proof.challenge}", expected="${this.challenge}"`);
      }

      // check domain
      if(this.domain !== undefined && proof.domain !== this.domain) {
        throw new Error('The domain is not as expected; ' +
          `domain="${proof.domain}", expected="${this.domain}"`);
      }

      return super.validate(
        proof, {verificationMethod, documentLoader, expansionMap});
    } catch(error) {
      return {valid: false, error};
    }
  }

  async update(proof, {document, suite, documentLoader, expansionMap}) {
    proof = await super.update(
      proof, {document, suite, documentLoader, expansionMap});
    proof.challenge = this.challenge;
    if(this.domain !== undefined) {
      proof.domain = this.domain;
    }
    return proof;
  }
};
