/*
 * Copyright (c) 2017-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const env = require('../env');
const forge = require('node-forge');
const LinkedDataSignature = require('./LinkedDataSignature');

module.exports = class LinkedDataSignature2015 extends LinkedDataSignature {
  constructor({
    type = 'LinkedDataSignature2015',
    privateKeyPem, publicKeyPem,
    creator, date, domain, nonce, maxTimestampDelta}) {
    super({type, creator, date, domain, nonce, maxTimestampDelta});
    this.privateKeyPem = privateKeyPem;
    this.publicKeyPem = publicKeyPem;
  }

  /**
   * @param document {object} to be signed/verified.
   * @param proof {object}
   * @param documentLoader {function}
   * @param expansionMap {function}
   *
   * @returns {Promise<{Uint8Array}>}.
   */
  async createVerifyData({document, proof, documentLoader, expansionMap}) {
    const c14n = await this.canonize(document, {documentLoader, expansionMap});

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
    return forge.util.binary.raw.encode(buffer.getBytes());
  }

  async sign({verifyData, proof}) {
    if(typeof this.privateKeyPem !== 'string') {
      throw new TypeError('"privateKeyPem" must be a PEM formatted string.');
    }

    let signature;
    if(env.nodejs) {
      // optimize using node libraries
      const crypto = require('crypto');
      const signer = crypto.createSign('RSA-SHA256');
      signer.update(Buffer.from(
        verifyData.buffer, verifyData.byteOffset, verifyData.length));
      signature = signer.sign(this.privateKeyPem, 'base64');
    } else {
      // browser or other environment
      const privateKey = forge.pki.privateKeyFromPem(this.privateKeyPem);
      const md = forge.md.sha256.create();
      md.update(forge.util.binary.decode(verifyData), 'binary');
      signature = forge.util.encode64(privateKey.sign(md));
    }

    proof.signatureValue = signature;
    return proof;
  }

  async verifySignature({verifyData, proof}) {
    const publicKeyPem = this.publicKeyPem;
    if(typeof publicKeyPem !== 'string') {
      throw new TypeError(
        'Could not verify signature; invalid "publicKeyPem".');
    }

    if(env.nodejs) {
      // optimize using node libraries
      const crypto = require('crypto');
      const verifier = crypto.createVerify('RSA-SHA256');
      verifier.update(verifyData.data, verifyData.encoding);
      return verifier.verify(publicKeyPem, proof.signatureValue, 'base64');
    }

    // browser or other environment
    const publicKey = forge.pki.publicKeyFromPem(publicKeyPem);
    const md = forge.md.sha256.create();
    md.update(forge.util.binary.raw.encode(verifyData), 'binary');
    return publicKey.verify(
      md.digest().bytes(), forge.util.decode64(proof.signatureValue));
  }
};
