/**
 * Copyright (c) 2017 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const LinkedDataSignature2015 = require('./LinkedDataSignature2015');
const util = require('../util');

module.exports = class RsaSignature2017 extends LinkedDataSignature2015 {
  constructor(injector, algorithm = 'RsaSignature2017') {
    super(injector, algorithm);
  }

  async createSignatureValue(verifyData, options) {
    const jws = this.injector.use('jws');
    const fullSignature = jws.sign({
      header: {
        alg: 'RS256',
        b64: false,
        crit: ['b64']
      },
      privateKey: options.privateKeyPem,
      payload: verifyData
    });
    // detached content signature
    const parts = fullSignature.split('.');
    parts[1] = '';
    const detachedSignature = parts.join('.');
    return detachedSignature;
  }

  async verifySignatureNode(verifyData, signature, options) {
    const jws = this.injector.use('jws');
    const forge = this.injector.use('forge');
    // rebuild detached content signature
    const parts = signature.signatureValue.split('.');
    parts[1] = util.encodeBase64Url(verifyData, {forge});
    const fullSignature = parts.join('.');
    const verified =
      jws.verify(fullSignature, 'RS256', options.publicKey.publicKeyPem);
    return verified;
  }
};
