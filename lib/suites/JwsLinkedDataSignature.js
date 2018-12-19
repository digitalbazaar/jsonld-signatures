/**
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const LinkedDataSignature = require('./LinkedDataSignature');
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
   * @param [domain] {string} domain to include in the signature.
   * @param [nonce] {string} nonce to include in the signature.
   * @param [maxTimestampDelta] {integer} a maximum number of seconds that
   *   the date on the signature can deviate from, defaults to `Infinity`.
   * @param [key] {LDKeyPair} an optional crypto-ld KeyPair.
   */
  constructor({
    type, alg, LDKeyClass, creator, verificationMethod, signer, key, proof,
    date, domain, nonce, maxTimestampDelta} = {}) {
    super({
      type, creator, verificationMethod, proof, date, domain,
      nonce, maxTimestampDelta});
    this.alg = alg;
    this.LDKeyClass = LDKeyClass;
    this.signer = signer;
    if(key) {
      this.setKey(key);
    }
  }

  /**
   * @param verifyData {Uint8Array}.
   * @param proof {object}
   *
   * @returns {Promise<{object}>} the proof containing the signature value.
   */
  async sign({verifyData, proof}) {
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

    const encodedHeader = util.encodeBase64Url(JSON.stringify(header));

    // create JWS data and sign
    const data = util.createJws({encodedHeader, verifyData});
    const signature = await this.signer.sign({data});

    const encodedSignature = util.encodeBase64Url(signature);

    // create detached content signature
    proof.jws = encodedHeader + '..' + encodedSignature;
    return proof;
  }

  /**
   * @param verifyData {Uint8Array}.
   * @param document {object} the document the proof applies to.
   * @param proof {object} the proof to be verified.
   * @param purpose {ProofPurpose}
   * @param documentLoader {function}
   * @param expansionMap {function}
   *
   * @returns {Promise<{boolean}>} Resolves with the verification result.
   */
  async verifySignature({verifyData, proof}) {
    // add payload into detached content signature
    const [encodedHeader, /*payload*/, encodedSignature] = proof.jws.split('.');

    const header = JSON.parse(util.decodeBase64Url(encodedHeader));
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

    const signature = util.decodeBase64Url(encodedSignature);

    // rebuild signing input per JWS spec
    const data = util.concat(
      util.stringToBytes(encodedHeader + '.', 'utf8'),
      verifyData);

    // do signature verification
    return this.verifer.verify({data, signature});
  }

  async assertVerificationMethod({verificationMethod}) {
    if(verificationMethod.type !== this.requiredKeyType) {
      new Error(
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
    const key = this.LDKeyClass.from(verificationMethod);
    this.setKey(key);
    return verificationMethod;
  }

  setKey(key) {
    this.key = key;
    this.signer = this.key.signer();
    this.verifier = this.key.verifier();
  }
};
