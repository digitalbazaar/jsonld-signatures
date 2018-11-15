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
    const {nodejs} = this.injector.env;
    if(options.signer) {
      // a custom signing API has been provided
      // a Uint8Array is passed to the signer
      const {data} = util.createJws({encodedHeader, forge, nodejs, verifyData});
      let message;
      if(nodejs) {
        // convert Buffer to Uint8Array
        message = new Uint8Array(data.buffer);
      } else {
        // convert binary encoded string to Uint8Array
        message = forge.util.binary.raw.decode(data);
      }
      encodedSignature = await options.signer.sign({message});
    } else if(nodejs) {
      // optimize using node libraries
      const chloride = require('chloride');
      const bs58 = require('bs58');

      // decode private key
      const privateKey = bs58.decode(options.privateKeyBase58);

      // build signing input per above comment
      const {data} = util.createJws(
        {encodedHeader, forge, nodejs, verifyData});
      const buffer = chloride.crypto_sign_detached(data, privateKey);
      encodedSignature = util.encodeBase64Url(
        buffer.toString('binary'), {forge});
    } else {
      // browser or other environment
      // decode private key
      const privateKey = forge.util.binary.base58.decode(
        options.privateKeyBase58);
      // build signing input per above comment
      const message = util.createJws(
        {encodedHeader, forge, nodejs, verifyData});
      const binaryString = forge.util.binary.raw.encode(
        forge.ed25519.sign({message, privateKey}));
      encodedSignature = util.encodeBase64Url(binaryString, {forge});
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
        Buffer.from(encodedHeader + '.', 'utf8'),
        Buffer.from(verifyData.data, verifyData.encoding)]);
      return chloride.crypto_sign_verify_detached(
        Buffer.from(rawSignature, 'binary'), tbs, publicKey);
    }

    // browser or other environment
    const publicKey = forge.util.binary.base58.decode(publicKeyBase58);
    // rebuild signing input per JWS spec
    const buffer = new forge.util.ByteBuffer(encodedHeader + '.', 'utf8');
    buffer.putBuffer(new forge.util.ByteBuffer(
      verifyData.data, verifyData.encoding));
    return forge.ed25519.verify({
      message: buffer,
      signature: rawSignature,
      publicKey
    });
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
