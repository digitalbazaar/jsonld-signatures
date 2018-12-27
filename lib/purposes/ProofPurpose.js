/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

module.exports = class ProofPurpose {
  constructor({term} = {}) {
    if(term === undefined) {
      throw new Error('"term" is required.');
    }
    this.term = term;
  }

  async validate(
    proof, {document, suite, verificationMethod,
      documentLoader, expansionMap}) {
    throw new Error(
      '"validate" must be implemented in a derived class.');
  }

  async update(proof, {document, suite, documentLoader, expansionMap}) {
    proof.proofPurpose = this.term;
    return proof;
  }

  async match(proof, {document, documentLoader, expansionMap}) {
    return proof.proofPurpose === this.term;
  }
};
