/*
 * Copyright (c) 2017-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const LinkedDataSignature2015 = require('./LinkedDataSignature2015');

module.exports = class EcdsaKoblitzSignature2016
  extends LinkedDataSignature2015 {
  constructor(injector, algorithm = 'EcdsaKoblitzSignature2016') {
    super(injector, algorithm);
  }

  async createSignatureValue(verifyData, options) {
    if(typeof options.privateKeyWif !== 'string') {
      throw new TypeError(
        '"options.privateKeyWif" must be a base 58 formatted string.');
    }

    const bitcoreMessage = this.injector.use('bitcoreMessage');
    const bitcore = bitcoreMessage.Bitcore;
    const privateKey = bitcore.PrivateKey.fromWIF(options.privateKeyWif);
    const message = bitcoreMessage(verifyData.data);
    return message.sign(privateKey);
  }

  async verifyProofNode(verifyData, proof, options) {
    const publicKeyWif = options.publicKey.publicKeyWif;
    if(typeof publicKeyWif !== 'string') {
      throw new TypeError(
        'Could not verify signature; invalid "publicKeyWif".');
    }

    const bitcoreMessage = this.injector.use('bitcoreMessage');
    const message = bitcoreMessage(verifyData.data);
    return message.verify(
      options.publicKey.publicKeyWif, proof.signatureValue);
  }
};
