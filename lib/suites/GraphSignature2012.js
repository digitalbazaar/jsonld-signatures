/*
 * Copyright (c) 2017 Digital Bazaar, Inc. All rights reserved.
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
    return jsonld.canonize(input, {
      algorithm: 'URGNA2012',
      format: 'application/nquads',
      expansionMap: options.expansionMap
    });
  }

  async createVerifyData(input, options) {
    // TODO: frame before getting signature, not just compact? considerations:
    // should the assumption be (for this library) that the signature is on
    // the top-level object and thus framing is unnecessary?

    const jsonld = this.injector.use('jsonld');
    const compacted = await jsonld.compact(
      input, constants.SECURITY_CONTEXT_URL,
      {expansionMap: options.expansionMap});

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
    return verifyData;
  }
};
