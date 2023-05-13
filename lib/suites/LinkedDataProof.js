/*!
 * Copyright (c) 2018-2023 Digital Bazaar, Inc. All rights reserved.
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
   * @param {object} options - The options to use.
   * @param {object} options.document - The document to be signed.
   * @param {ProofPurpose} options.purpose - The proof purpose instance.
   * @param {Array} options.proofSet - Any existing proof set.
   * @param {function} options.documentLoader - The document loader to use.
   * @param {function} options.expansionMap - NOT SUPPORTED; do not use.
   *
   * @returns {Promise<object>} Resolves with the created proof object.
   */
  async createProof({
    /* document, purpose, proofSet, documentLoader, expansionMap */
  }) {
    throw new Error('"createProof" must be implemented in a derived class.');
  }

  /**
   * @param {object} options - The options to use.
   * @param {object} options.document - The document from which to derive
   *   a new document and proof.
   * @param {ProofPurpose} options.purpose - The proof purpose instance.
   * @param {Array} options.proofSet - Any existing proof set.
   * @param {function} options.documentLoader - The document loader to use.
   *
   * @returns {Promise<object>} Resolves with the new document with a new
   *   `proof` field.
   */
  async derive({
    /* document, purpose, proofSet, documentLoader */
  }) {
    throw new Error('"deriveProof" must be implemented in a derived class.');
  }

  /**
   * @param {object} options - The options to use.
   * @param {object} options.proof - The proof to be verified.
   * @param {object} options.document - The document the proof applies to.
   * @param {ProofPurpose} options.purpose - The proof purpose instance.
   * @param {Array} options.proofSet - Any existing proof set.
   * @param {function} options.documentLoader - The document loader to use.
   * @param {function} options.expansionMap - NOT SUPPORTED; do not use.
   *
   * @returns {Promise<{object}>} Resolves with the verification result.
   */
  async verifyProof({
    /* proof, document, purpose, proofSet, documentLoader, expansionMap */
  }) {
    throw new Error('"verifyProof" must be implemented in a derived class.');
  }

  /**
   * Checks whether a given proof exists in the document.
   *
   * @param {object} options - The options to use.
   * @param {object} options.proof - The proof to match.
   *
   * @returns {Promise<boolean>} Whether a match for the proof was found.
   */
  async matchProof({
    proof /*, document, purpose, documentLoader, expansionMap */
  }) {
    return proof.type === this.type;
  }
};
