/**
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

module.exports = class ControllerProofPurpose extends ProofPurposeHandler {
  constructor() {
    // Must be overridden by child methods
    this.uri = null;
  }

  async validate({
    document, proof, suite, verificationMethod, purposeParameters,
    documentLoader}) {
    // FIXME: get `controller`/`owner` on verification method and retrieve
    // it... make sure `verificationMethod.id` can be found via `this.uri`
    // relationship on the controller's document
    throw new Error(
      '"validate" must be implemented in a derived class.');
  }

  async updateProof({input, proof, purposeParameters, documentLoader}) {
    throw new Error(
      '"createProof" must be implemented in a derived class.');
  }
};
