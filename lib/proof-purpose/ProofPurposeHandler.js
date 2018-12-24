/**
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

module.exports = class ProofPurposeHandler {
  constructor() {
    // Must be overridden by child methods
    this.uri = null;
  }

  async validate({document, proof, suite, purposeParameters, documentLoader}) {
    throw new Error(
      '"validate" must be implemented in a derived class.');
  }

  async update({input, proof, purposeParameters, documentLoader}) {
    throw new Error(
      '"update" must be implemented in a derived class.');
  }

  async match({proof, document, documentLoader, expansionMap}) {
    throw new Error(
      '"match" must be implemented in a derived class.');
  }
};
