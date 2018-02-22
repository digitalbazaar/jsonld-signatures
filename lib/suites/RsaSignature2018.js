/**
 * Copyright (c) 2017-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const LinkedDataSignature = require('./LinkedDataSignature');
const util = require('../util');

module.exports = class RsaSignature2018 extends LinkedDataSignature {
  constructor(injector, algorithm = 'RsaSignature2018') {
    super(injector, algorithm);
    this.requiredKeyType = 'RsaVerificationKey2018';
  }

  async createSignatureValue(verifyData, options) {
    const forge = this.injector.use('forge');

    // TODO: should abstract JWS signing bits out for reuse elsewhere

    // JWS header
    const header = this.createJwsHeader();

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
      // FIXME: better abstract for future suites

      // optimize using node 8.0+ libraries
      const crypto = this.injector.use('crypto');
      if('RSA_PKCS1_PSS_PADDING' in crypto.constants) {
        const signer = crypto.createSign('RSA-SHA256');

        // build signing input per above comment
        signer.update(encodedHeader + '.', 'utf8');
        signer.update(new Buffer(verifyData.data, verifyData.encoding));
        const buffer = signer.sign(Object.assign({
          key: options.privateKeyPem
        }, this.createPss()));
        encodedSignature = util.encodeBase64Url(
          buffer.toString('binary'), {forge});
      }
    }

    if(!encodedSignature) {
      // browser or other environment (including node 6.x)
      const privateKey = forge.pki.privateKeyFromPem(options.privateKeyPem);
      const md = forge.md.sha256.create();
      // build signing input per above comment
      md.update(encodedHeader + '.', 'utf8');
      md.update(verifyData.data, verifyData.encoding);
      const pss = this.createPss(forge);
      const binaryString = privateKey.sign(md, pss);
      encodedSignature = util.encodeBase64Url(binaryString, {forge});
    }

    // create detached content signature
    return encodedHeader + '..' + encodedSignature;
  }

  async verifyProofNode(verifyData, proof, options) {
    const forge = this.injector.use('forge');

    const {publicKeyPem} = options.publicKey;

    // add payload into detached content signature
    const [encodedHeader, payload, encodedSignature] = proof.jws.split('.');

    const header = JSON.parse(util.decodeBase64Url(encodedHeader, {forge}));
    if(!(header && typeof header === 'object')) {
      throw new Error('Invalid JWS header.');
    }

    // confirm header matches all expectations
    this.checkJwsHeader(header);

    const rawSignature = util.decodeBase64Url(encodedSignature, {forge});

    if(this.injector.env.nodejs) {
      // optimize using node 8.0+ libraries
      const crypto = this.injector.use('crypto');
      if('RSA_PKCS1_PSS_PADDING' in crypto.constants) {
        const crypto = this.injector.use('crypto');
        const verifier = crypto.createVerify('RSA-SHA256');
        // rebuild signing input per JWS spec
        verifier.update(encodedHeader + '.', 'utf8');
        verifier.update(new Buffer(verifyData.data, verifyData.encoding));
        return verifier.verify(Object.assign({
          key: publicKeyPem
        }, this.createPss()), new Buffer(rawSignature, 'binary'));
      }
    }

    // browser or other environment
    const publicKey = forge.pki.publicKeyFromPem(publicKeyPem);
    const md = forge.md.sha256.create();
    // rebuild signing input per JWS spec
    md.update(encodedHeader + '.', 'utf8');
    md.update(verifyData.data, verifyData.encoding);
    return publicKey.verify(
      md.digest().bytes(), rawSignature, this.createPss(forge));
  }

  async validateKey(key, options) {
    if(typeof key.publicKeyPem !== 'string') {
      throw new TypeError(
        'Unknown public key encoding. Public key encoding must be ' +
        '"publicKeyPem".');
    }
    const jsonld = this.injector.use('jsonld');
    if(!jsonld.hasValue(key, 'type', this.requiredKeyType)) {
      throw new TypeError(
        `Invalid key type. Key type must be "${this.requiredKeyType}".`);
    }
  }

  createJwsHeader() {
    const header = {
      alg: 'PS256',
      b64: false,
      crit: ['b64']
    };
    return header;
  }

  checkJwsHeader(header) {
    /*
    const expectedHeader = {
      alg: 'PS256',
      b64: false,
      crit: ['b64']
    };
    */
    if(!(header.alg === 'PS256' && header.b64 === false &&
      Array.isArray(header.crit) && header.crit.length === 1 &&
      header.crit[0] === 'b64') && Object.keys(header).length === 3) {
      throw new Error('Invalid JWS header parameters for RsaSignature2018.');
    }
  }

  createPss(forge) {
    // Note: Per rfc7518, the digest algorithm for PS256 is SHA-256,
    // https://tools.ietf.org/html/rfc7518

    // sign data using RSASSA-PSS where PSS uses a SHA-256 hash,
    // a SHA-256 based masking function MGF1, and a 32 byte salt to match
    // the hash size
    if(forge) {
      const md = forge.md.sha256.create();
      return forge.pss.create({
        md,
        mgf: forge.mgf.mgf1.create(forge.md.sha256.create()),
        saltLength: md.digestLength
      });
    } else {
      const crypto = require('crypto');
      return {
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
      };
    }
  }
};
