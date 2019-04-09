/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const LinkedDataSignature = require('./LinkedDataSignature');
const jsonld = require('jsonld');
const util = require('../util');

module.exports = class JwsLinkedDataSignature extends LinkedDataSignature {
  /**
   * @param type {string} Provided by subclass.
   * @param alg {string} JWS alg provided by subclass.
   * @param [LDKeyClass] {LDKeyClass} provided by subclass or subclass
   *   overrides `getVerificationMethod`.
   *
   * One of these parameters is required to use a suite for signing:
   *
   * @param [creator] {string} A key id URL to the paired public key.
   * @param [verificationMethod] {string} A key id URL to the paired public key.
   *
   * This parameter is required for signing:
   *
   * @param [signer] {function} an optional signer.
   *
   * Advanced optional parameters and overrides:
   *
   * @param [proof] {object} a JSON-LD document with options to use for
   *   the `proof` node (e.g. any other custom fields can be provided here
   *   using a context different from security-v2).
   * @param [date] {string|Date} signing date to use if not passed.
   * @param [key] {LDKeyPair} an optional crypto-ld KeyPair.
   * @param [useNativeCanonize] {boolean} true to use a native canonize
   *   algorithm.
   */
  constructor({
    type, alg, LDKeyClass, creator, verificationMethod, signer, key, proof,
    date, useNativeCanonize} = {}) {
    super({type, creator, verificationMethod, proof, date, useNativeCanonize});
    this.alg = alg;
    this.LDKeyClass = LDKeyClass;
    this.signer = signer;
    if(key) {
      if(verificationMethod === undefined && creator === undefined) {
        const publicKey = key.publicNode();
        if(publicKey.owner) {
          // use legacy signature terms
          this.creator = publicKey.id;
        } else {
          // use newer signature terms
          this.verificationMethod = publicKey.id;
        }
      }
      this.key = key;
      if(typeof key.signer === 'function') {
        this.signer = key.signer();
      }
      if(typeof key.verifier === 'function') {
        this.verifier = key.verifier();
      }
    }
  }

  /**
   * @param verifyData {Uint8Array}.
   * @param proof {object}
   *
   * @returns {Promise<{object}>} the proof containing the signature value.
   */
  async sign({verifyData, proof}) {
    if(!(this.signer && typeof this.signer.sign === 'function')) {
      throw new Error('A signer API has not been specified.');
    }
    // JWS header
    const header = {
      alg: this.alg,
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

    // create JWS data and sign
    const encodedHeader = util.encodeBase64Url(JSON.stringify(header));
    const data = util.createJws({encodedHeader, verifyData});
    const signature = await this.signer.sign({data});

    // create detached content signature
    const encodedSignature = util.encodeBase64Url(signature);
    proof.jws = encodedHeader + '..' + encodedSignature;
    return proof;
  }

  /**
   * @param verifyData {Uint8Array}.
   * @param verificationMethod {object}.
   * @param document {object} the document the proof applies to.
   * @param proof {object} the proof to be verified.
   * @param purpose {ProofPurpose}
   * @param documentLoader {function}
   * @param expansionMap {function}
   *
   * @returns {Promise<{boolean}>} Resolves with the verification result.
   */
  async verifySignature({verifyData, verificationMethod, proof}) {
    // add payload into detached content signature
    const [encodedHeader, /*payload*/, encodedSignature] = proof.jws.split('.');

    let header;
    try {
      header = JSON.parse(util.decodeBase64UrlToString(encodedHeader));
    } catch(e) {
      throw new Error('Could not parse JWS header; ' + e);
    }
    if(!(header && typeof header === 'object')) {
      throw new Error('Invalid JWS header.');
    }

    // confirm header matches all expectations
    if(!(header.alg === this.alg && header.b64 === false &&
      Array.isArray(header.crit) && header.crit.length === 1 &&
      header.crit[0] === 'b64') && Object.keys(header).length === 3) {
      throw new Error(
        `Invalid JWS header parameters for ${this.type}.`);
    }

    // do signature verification
    const signature = util.decodeBase64Url(encodedSignature);
    const data = util.createJws({encodedHeader, verifyData});
    let {verifier} = this;
    if(!verifier) {
      const key = await this.LDKeyClass.from(verificationMethod);
      verifier = key.verifier();
    }
    return verifier.verify({data, signature});
  }

  async assertVerificationMethod({verificationMethod}) {
    if(!jsonld.hasValue(verificationMethod, 'type', this.requiredKeyType)) {
      throw new Error(
        `Invalid key type. Key type must be "${this.requiredKeyType}".`);
    }
  }

  async getVerificationMethod({proof, documentLoader}) {
    if(this.key) {
      return this.key.publicNode();
    }

    const verificationMethod = await super.getVerificationMethod(
      {proof, documentLoader});
    await this.assertVerificationMethod({verificationMethod});
    return verificationMethod;
  }

  async matchProof({proof, document, purpose, documentLoader, expansionMap}) {
    if(!await super.matchProof(
      {proof, document, purpose, documentLoader, expansionMap})) {
      return false;
    }
    if(!this.key) {
      // no key specified, so assume this suite matches and it can be retrieved
      return true;
    }

    let {verificationMethod} = proof;
    if(!verificationMethod) {
      verificationMethod = proof.creator;
    }
    // only match if the key specified matches the one in the proof
    if(typeof verificationMethod === 'object') {
      return verificationMethod.id === this.key.id;
    }
    return verificationMethod === this.key.id;
  }
};
