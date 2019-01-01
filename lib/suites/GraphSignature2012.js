/*!
 * Copyright (c) 2017-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const jsonld = require('jsonld');
const forge = require('node-forge');
const LinkedDataSignature2015 = require('./LinkedDataSignature2015');

module.exports = class GraphSignature2012 extends LinkedDataSignature2015 {
  constructor({
    privateKeyPem, publicKeyPem, creator, date, domain, nonce} = {}) {
    super({
      type: 'GraphSignature2012',
      privateKeyPem, publicKeyPem,
      creator, date, domain, nonce});
  }

  async canonize(
    input, {documentLoader, expansionMap, skipExpansion}) {
    return jsonld.canonize(input, {
      algorithm: 'URGNA2012',
      format: 'application/n-quads',
      documentLoader,
      expansionMap,
      skipExpansion
    });
  }

  /**
   * @param document {object} to be signed/verified.
   * @param proof {object}
   * @param documentLoader {function}
   * @param expansionMap {function}
   * @param compactProof {boolean}
   *
   * @returns {Promise<{Uint8Array}>}.
   */
  async createVerifyData({
    document, proof, documentLoader, expansionMap}) {
    const c14n = await this.canonize(document, {
      documentLoader,
      expansionMap
    });

    let verifyData = '';
    if(proof.nonce !== null && proof.nonce !== undefined) {
      verifyData += proof.nonce;
    }
    verifyData += proof.created;
    verifyData += c14n;
    if(proof.domain !== null && proof.domain !== undefined) {
      verifyData += '@' + proof.domain;
    }
    const buffer = new forge.util.ByteBuffer(verifyData, 'utf8');
    return forge.util.binary.raw.decode(buffer.getBytes());
  }
};
