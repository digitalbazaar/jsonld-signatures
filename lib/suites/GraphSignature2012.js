/*
 * Copyright (c) 2017-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const constants = require('../constants');
const LinkedDataSignature2015 = require('./LinkedDataSignature2015');

module.exports = class GraphSignature2012 extends LinkedDataSignature2015 {
  constructor(injector, algorithm = 'GraphSignature2012') {
    super(injector, algorithm);
  }

  async canonize(input, options) {
    const jsonld = this.injector.use('jsonld');
    const opts = {
      algorithm: 'URGNA2012',
      format: 'application/n-quads',
      expansionMap: options.expansionMap
    };
    if(options.documentLoader) {
      opts.documentLoader = options.documentLoader;
    }
    return jsonld.canonize(input, opts);
  }

  async createVerifyData(input, options) {
    // TODO: frame before getting signature, not just compact? considerations:
    // should the assumption be (for this library) that the signature is on
    // the top-level object and thus framing is unnecessary?

    const jsonld = this.injector.use('jsonld');
    const opts = {expansionMap: options.expansionMap};
    if(options.documentLoader) {
      opts.documentLoader = options.documentLoader;
    }
    const compacted = await jsonld.compact(
      input, constants.SECURITY_CONTEXT_URL, opts);

    // TODO: will need to preserve `signature` when chained signature
    // option is set in the future

    // delete the existing signature(s) prior to canonicalization
    delete compacted.signature;

    const c14n = await this.canonize(compacted, options);

    let verifyData = '';
    if(options.nonce !== null && options.nonce !== undefined) {
      verifyData += options.nonce;
    }
    verifyData += options.date;
    verifyData += c14n;
    if(options.domain !== null && options.domain !== undefined) {
      verifyData += '@' + options.domain;
    }
    return {
      data: verifyData,
      encoding: 'utf8'
    };
  }

  async validateKey(key, options) {
    if(typeof key.publicKeyPem !== 'string') {
      throw new TypeError(
        'Unknown public key encoding. Public key encoding must be ' +
        '"publicKeyPem".');
    }
    const jsonld = this.injector.use('jsonld');
    if(!jsonld.hasValue(key, 'type', 'CryptographicKey')) {
      throw new TypeError(
        'Invalid key type. Key type must be "CryptographicKey".');
    }
  }
};
