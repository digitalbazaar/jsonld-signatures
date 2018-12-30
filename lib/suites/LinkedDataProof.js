/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

module.exports = class LinkedDataProof {
  constructor({type} = {}) {
    if(typeof type !== 'string') {
      throw new TypeError('A LinkedDataProof must have a "type".');
    }
    this.type = type;
  }

  /**
   * @param document {object} to be signed.
   * @param purpose {ProofPurpose}
   * @param documentLoader {function}
   * @param expansionMap {function}
   * @param compactProof {boolean}
   *
   * @returns {Promise<object>} Resolves with the created proof object.
   */
  async createProof(
    {document, purpose, documentLoader, expansionMap, compactProof}) {
    throw new Error('"createProof" must be implemented in a derived class.');
  }

  /**
   * @param proof {object} the proof to be verified.
   * @param document {object} the document the proof applies to.
   * @param purpose {ProofPurpose}
   * @param documentLoader {function}
   * @param expansionMap {function}
   *
   * @returns {Promise<{object}>} Resolves with the verification result.
   */
  async verifyProof({proof, document, purpose, documentLoader, expansionMap}) {
    throw new Error('"verifyProof" must be implemented in a derived class.');
  }

  /**
   * @param proof {object} the proof to be matched.
   * @param document {object} the document the proof applies to.
   * @param purpose {ProofPurpose}
   * @param documentLoader {function}
   * @param expansionMap {function}
   *
   * @returns {Promise<{boolean}>} Resolves with the verification result.
   */
  async matchProof({proof, document, purpose, documentLoader, expansionMap}) {
    return proof.type === this.type;
  }
};
