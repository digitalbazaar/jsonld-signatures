/*!
 * Copyright (c) 2017-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const env = require('../env');
const forge = require('node-forge');
const LinkedDataSignature = require('./LinkedDataSignature');

module.exports = class LinkedDataSignature2015 extends LinkedDataSignature {
  /**
   * Advanced optional parameters and overrides:
   *
   * @param [domain] {string} domain to include in the signature.
   * @param [nonce] {string} nonce to include in the signature.
   * @param [useNativeCanonize] {boolean} true to use a native canonize
   *   algorithm.
   */
  constructor({
    type = 'LinkedDataSignature2015',
    privateKeyPem, publicKeyPem, creator, date, domain, nonce,
    useNativeCanonize} = {}) {
    if(domain !== undefined && typeof domain !== 'string') {
      throw new TypeError('"domain" must be a string.');
    }
    if(nonce !== undefined && typeof nonce !== 'string') {
      throw new TypeError('"nonce" must be a string.');
    }
    super({type, creator, date, domain, nonce, useNativeCanonize});
    this.legacy = true;
    this.privateKeyPem = privateKeyPem;
    this.publicKeyPem = publicKeyPem;
    this.nonce = nonce;
    this.domain = domain;
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
  async updateProof({proof}) {
    if(this.domain !== undefined) {
      proof.domain = this.domain;
    }
    if(this.nonce !== undefined) {
      proof.nonce = this.nonce;
    }
    return proof;
  }

  /**
   * @param proof {object} the proof to be verified.
   * @param document {object} the document the proof applies to.
   * @param purpose {ProofPurpose}
   * @param documentLoader {function}
   * @param expansionMap {function}
   * @param compactProof {boolean}
   *
   * @returns {Promise<{object}>} Resolves with the verification result.
   */
  async verifyProof({
    proof, document, purpose, documentLoader, expansionMap,
    compactProof}) {
    try {
      // check domain
      if(this.domain !== undefined && proof.domain !== this.domain) {
        throw new Error('The domain is not as expected; ' +
          `domain="${proof.domain}", expected="${this.domain}"`);
      }

      return super.verifyProof({
        proof, document, purpose, documentLoader, expansionMap,
        compactProof});
    } catch(error) {
      return {verified: false, error};
    }
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
    const headers = {
      'http://purl.org/dc/elements/1.1/created': proof.created,
      'https://w3id.org/security#domain': proof.domain,
      'https://w3id.org/security#nonce': proof.nonce
    };
    // add headers in lexicographical order
    const keys = Object.keys(headers).sort();
    for(let i = 0; i < keys.length; ++i) {
      const key = keys[i];
      const value = headers[key];
      if(!(value === null || value === undefined)) {
        verifyData += key + ': ' + value + '\n';
      }
    }
    verifyData += c14n;
    const buffer = new forge.util.ByteBuffer(verifyData, 'utf8');
    return forge.util.binary.raw.decode(buffer.getBytes());
  }

  async sign({verifyData, proof}) {
    const {privateKeyPem} = this;
    if(typeof privateKeyPem !== 'string') {
      throw new TypeError('"privateKeyPem" must be a PEM formatted string.');
    }

    let signature;
    if(env.nodejs) {
      // optimize using node libraries
      const crypto = require('crypto');
      const signer = crypto.createSign('RSA-SHA256');
      signer.update(Buffer.from(
        verifyData.buffer, verifyData.byteOffset, verifyData.length));
      signature = signer.sign(privateKeyPem, 'base64');
    } else {
      // browser or other environment
      const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
      const md = forge.md.sha256.create();
      md.update(forge.util.binary.raw.encode(verifyData), 'binary');
      signature = forge.util.encode64(privateKey.sign(md));
    }

    proof.signatureValue = signature;
    return proof;
  }

  async verifySignature({verifyData, proof}) {
    const {publicKeyPem} = this;
    if(typeof publicKeyPem !== 'string') {
      throw new TypeError(
        'Could not verify signature; invalid "publicKeyPem".');
    }

    if(env.nodejs) {
      // optimize using node libraries
      const crypto = require('crypto');
      const verifier = crypto.createVerify('RSA-SHA256');
      verifier.update(Buffer.from(
        verifyData.buffer, verifyData.byteOffset, verifyData.length));
      return verifier.verify(publicKeyPem, proof.signatureValue, 'base64');
    }

    // browser or other environment
    const publicKey = forge.pki.publicKeyFromPem(publicKeyPem);
    const md = forge.md.sha256.create();
    md.update(forge.util.binary.raw.encode(verifyData), 'binary');
    try {
      return publicKey.verify(
        md.digest().bytes(), forge.util.decode64(proof.signatureValue));
    } catch(e) {
      // simply return false, do return information about malformed signature
      return false;
    }
  }

  async getVerificationMethod({proof, documentLoader}) {
    const verificationMethod = await super.getVerificationMethod(
      {proof, documentLoader});
    if(!this.publicKeyPem) {
      this.publicKeyPem = verificationMethod.publicKeyPem;
    }
    return verificationMethod;
  }
};
