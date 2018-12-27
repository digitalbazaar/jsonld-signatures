/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const ProofPurpose = require('../../lib/purposes/ProofPurpose');

const mock = {};
module.exports = mock;

mock.NOOP_PROOF_PURPOSE_URI = 'https://example.org/special-authentication';

class NoOpProofPurpose extends ProofPurpose {
  constructor() {
    super({term: mock.NOOP_PROOF_PURPOSE_URI});
  }
  async validate() {
    return {valid: true};
  }
}

mock.NoOpProofPurpose = NoOpProofPurpose;
