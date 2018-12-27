/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const ControllerProofPurpose = require('./ControllerProofPurpose');

module.exports = class PublicKeyProofPurpose extends ControllerProofPurpose {
  constructor({controller, owner} = {}) {
    super({term: 'publicKey', controller, owner});
  }

  async update(proof) {
    // do not add `term` to proof
    return proof;
  }

  async match(proof) {
    // `proofPurpose` must not be present in the proof to match as this
    // proof purpose is a legacy, non-descript purpose for signing
    return proof.proofPurpose === undefined;
  }
};
