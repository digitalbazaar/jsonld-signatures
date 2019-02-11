/*!s
 * Copyright (c) 2017-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {RSAKeyPair} = require('crypto-ld');
const JwsLinkedDataSignature = require('./JwsLinkedDataSignature');

module.exports = class RsaSignature2018 extends JwsLinkedDataSignature {
  /**
   * @param type {string} Provided by subclass.
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
    signer, key, creator, verificationMethod, proof, date, useNativeCanonize
  } = {}) {
    super({
      type: 'RsaSignature2018', alg: 'PS256', LDKeyClass: RSAKeyPair,
      creator, verificationMethod, signer, key, proof, date,
      useNativeCanonize});
    this.requiredKeyType = 'RsaVerificationKey2018';
  }
};
