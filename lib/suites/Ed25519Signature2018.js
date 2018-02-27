/**
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const LinkedDataSignature = require('./LinkedDataSignature');
const util = require('../util');

module.exports = class Ed25519Signature2018 extends LinkedDataSignature {
  constructor(injector, algorithm = 'Ed25519Signature2018') {
    super(injector, algorithm);
    this.requiredKeyType = 'Ed25519VerificationKey2018';
  }

  async createSignatureValue(verifyData, options) {
    const forge = this.injector.use('forge');

    // TODO: should abstract JWS signing bits out for reuse elsewhere

    // JWS header
    const header = {
      alg: 'EdDSA',
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
      const chloride = require('chloride');
      const bs58 = require('bs58');

      // decode private key
      const privateKey = bs58.decode(options.privateKeyBase58);

      // build signing input per above comment
      const tbs = Buffer.concat([
        new Buffer(encodedHeader + '.', 'utf8'),
        new Buffer(verifyData.data, verifyData.encoding)]);
      const buffer = chloride.crypto_sign_detached(tbs, privateKey);
      encodedSignature = util.encodeBase64Url(
        buffer.toString('binary'), {forge});
    } else {
      throw new Error('Not implemented');
      /*
      // browser or other environment
      const privateKey = forge.pki.privateKeyFromPem(options.privateKeyPem);
      const md = forge.md.sha256.create();
      // build signing input per above comment
      md.update(encodedHeader + '.', 'utf8');
      md.update(verifyData.data, verifyData.encoding);
      const binaryString = privateKey.sign(md);
      encodedSignature = util.encodeBase64Url(binaryString, {forge});*/
    }

    // create detached content signature
    return encodedHeader + '..' + encodedSignature;
  }

  async verifyProofNode(verifyData, proof, options) {
    const forge = this.injector.use('forge');

    const {publicKeyBase58} = options.publicKey;

    // add payload into detached content signature
    const [encodedHeader, payload, encodedSignature] = proof.jws.split('.');

    const header = JSON.parse(util.decodeBase64Url(encodedHeader, {forge}));
    /*const expectedHeader = {
      alg: 'EdDSA',
      b64: false,
      crit: ['b64']
    };*/
    if(!(header && typeof header === 'object')) {
      throw new Error('Invalid JWS header.');
    }

    // confirm header matches all expectations
    if(!(header.alg === 'EdDSA' && header.b64 === false &&
      Array.isArray(header.crit) && header.crit.length === 1 &&
      header.crit[0] === 'b64') && Object.keys(header).length === 3) {
      throw new Error(
        'Invalid JWS header parameters for Ed25519Signature2018.');
    }

    const rawSignature = util.decodeBase64Url(encodedSignature, {forge});

    if(this.injector.env.nodejs) {
      // optimize using node libraries
      const chloride = require('chloride');
      const bs58 = require('bs58');

      // decode public key
      const publicKey = bs58.decode(publicKeyBase58);

      // rebuild signing input per JWS spec
      const tbs = Buffer.concat([
        new Buffer(encodedHeader + '.', 'utf8'),
        new Buffer(verifyData.data, verifyData.encoding)]);
      return chloride.crypto_sign_verify_detached(
        new Buffer(rawSignature, 'binary'), tbs, publicKey);
    }

    throw new Error('Not implemented');
    /*
    // browser or other environment
    const publicKey = forge.pki.publicKeyFromPem(publicKeyPem);
    const md = forge.md.sha256.create();
    // rebuild signing input per JWS spec
    md.update(encodedHeader + '.', 'utf8');
    md.update(verifyData.data, verifyData.encoding);
    return publicKey.verify(md.digest().bytes(), rawSignature);*/
  }

  async validateKey(key, options) {
    if(typeof key.publicKeyBase58 !== 'string') {
      throw new TypeError(
        'Unknown public key encoding. Public key encoding must be ' +
        '"publicKeyBase58".');
    }
    const jsonld = this.injector.use('jsonld');
    if(!jsonld.hasValue(key, 'type', this.requiredKeyType)) {
      throw new TypeError(
        `Invalid key type. Key type must be "${this.requiredKeyType}".`);
    }
  }
};
