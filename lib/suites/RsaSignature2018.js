/**
 * Copyright (c) 2017-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const LinkedDataSignature = require('./LinkedDataSignature');
const util = require('../util');

module.exports = class RsaSignature2018 extends LinkedDataSignature {
  constructor(injector, algorithm = 'RsaSignature2018') {
    super(injector, algorithm);
  }

  async createSignatureValue(verifyData, options) {
    const forge = this.injector.use('forge');

    // TODO: should abstract JWS signing bits out for reuse elsewhere

    // JWS header
    const header = {
      alg: 'RS256',
      b64: false,
      crit: ['b64']
    };

    /*
    +-------+-----------------------------------------------------------+
    | "b64" | JWS Signing Input Formula                                 |
    +-------+-----------------------------------------------------------+
    | true  | ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' ||     |
    |       | BASE64URL(JWS Payload))                                   |
    |       |                                                           |
    | false | ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.') ||    |
    |       | JWS Payload                                               |
    +-------+-----------------------------------------------------------+
   */

    const encodedHeader = util.encodeBase64Url(
      JSON.stringify(header), {forge});

    let encodedSignature;
    if(this.injector.env.nodejs) {
      // optimize using node libraries
      const crypto = this.injector.use('crypto');
      const signer = crypto.createSign('RSA-SHA256');

      // build signing input per above comment
      signer.update(encodedHeader + '.', 'utf8');
      signer.update(new Buffer(verifyData.data, verifyData.encoding));
      const buffer = signer.sign(options.privateKeyPem);
      encodedSignature = util.encodeBase64Url(
        buffer.toString('binary'), {forge});
    } else {
      // browser or other environment
      const privateKey = forge.pki.privateKeyFromPem(options.privateKeyPem);
      const md = forge.md.sha256.create();
      // build signing input per above comment
      md.update(encodedHeader + '.', 'utf8');
      md.update(verifyData.data, verifyData.encoding);
      const binaryString = privateKey.sign(md);
      encodedSignature = util.encodeBase64Url(binaryString, {forge});
    }

    // create detached content signature
    return encodedHeader + '..' + encodedSignature;
  }

  async verifyProofNode(verifyData, proof, options) {
    const forge = this.injector.use('forge');

    const publicKeyPem = options.publicKey.publicKeyPem;
    if(typeof publicKeyPem !== 'string') {
      throw new TypeError(
        'Could not verify signature; invalid "publicKeyPem".');
    }

    // add payload into detached content signature
    const [encodedHeader, payload, encodedSignature] = proof.jws.split('.');

    const header = JSON.parse(util.decodeBase64Url(encodedHeader, {forge}));
    /*const expectedHeader = {
      alg: 'RS256',
      b64: false,
      crit: ['b64']
    };*/
    if(!(header && typeof header === 'object')) {
      throw new Error('Invalid JWS header.');
    }

    // confirm header matches all expectations
    if(!(header.alg === 'RS256' && header.b64 === false &&
      Array.isArray(header.crit) && header.crit.length === 1 &&
      header.crit[0] === 'b64') && Object.keys(header).length === 3) {
      throw new Error('Invalid JWS header parameters for RsaSignature2018.');
    }

    const rawSignature = util.decodeBase64Url(encodedSignature, {forge});

    if(this.injector.env.nodejs) {
      // optimize using node libraries
      const crypto = this.injector.use('crypto');
      const verifier = crypto.createVerify('RSA-SHA256');
      // rebuild signing input per JWS spec
      verifier.update(encodedHeader + '.', 'utf8');
      verifier.update(new Buffer(verifyData.data, verifyData.encoding));
      return verifier.verify(publicKeyPem, new Buffer(rawSignature, 'binary'));
    }

    // browser or other environment
    const publicKey = forge.pki.publicKeyFromPem(publicKeyPem);
    const md = forge.md.sha256.create();
    // rebuild signing input per JWS spec
    md.update(encodedHeader + '.', 'utf8');
    md.update(verifyData.data, verifyData.encoding);
    return publicKey.verify(md.digest().bytes(), rawSignature);
  }
};
