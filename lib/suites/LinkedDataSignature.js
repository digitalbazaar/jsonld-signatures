/*
 * Copyright (c) 2017 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const constants = require('../constants');
const util = require('../util');
const Helper = require('../Helper');

module.exports = class LinkedDataSignature {
  constructor(injector, algorithm) {
    this.injector = injector;
    this.algorithm = algorithm;
    this.helper = new Helper(injector);
  }

  async canonize(input, options) {
    const jsonld = this.injector.use('jsonld');
    return jsonld.canonize(input, {
      algorithm: 'URDNA2015',
      format: 'application/nquads',
      expansionMap: options.expansionMap
    });
  }

  async createVerifyData(input, options) {
    // TODO: implement according to Linked Data Signatures 1.0 spec
    throw new Error('Not implemented.');
  }

  async digest() {
    // TODO: implement according to Linked Data Signatures 1.0 spec
    throw new Error('Not implemented.');
  }

  async sign(input, options) {
    // set default options
    options = Object.assign({
      date: new Date()
    }, options || {});

    // validate common options
    if(typeof options.creator !== 'string') {
      throw new TypeError('"options.creator" must be a URL string.');
    }
    if('domain' in options && typeof options.domain !== 'string') {
      throw new TypeError('"options.domain" must be a string.');
    }
    if('nonce' in options && typeof options.nonce !== 'string') {
      throw new TypeError('"options.nonce" must be a string.');
    }

    // ensure date is in string format
    if(typeof date !== 'string') {
      // TODO: parse non-string date and force to w3c format?
      options.date = util.w3cDate(options.date);
    }

    // disallow dropping properties when expanding by default
    if(options.expansionMap !== false) {
      options.expansionMap = info => {
        if(info.unmappedProperty) {
          throw new Error('The property "' +
             info.unmappedProperty + '" in the input ' +
            'was not defined in the context.');
        }
      };
    }

    // produce data to sign
    const verifyData = await this.createVerifyData(input, options);

    // create signature node
    const signatureNode = await this.createSignatureNode(verifyData, options);

    // compact signature node to match input context
    const tmp = {
      'https://w3id.org/security#signature': signatureNode
    };
    const jsonld = this.injector.use('jsonld');
    const ctx = jsonld.getValues(input, '@context');
    const compactSignatureNode = await jsonld.compact(tmp, ctx);

    // TODO: it is unclear how the signature would be easily added without
    // reshaping the input... so perhaps this library should just require
    // the caller to accept that the signature will be added to the top
    // level of the input

    // attach signature node to cloned input and return it
    const output = util.deepClone(input);
    delete compactSignatureNode['@context'];
    const signatureKey = Object.keys(compactSignatureNode)[0];
    jsonld.addValue(output, signatureKey, compactSignatureNode[signatureKey]);
    return output;
  }

  async createSignatureNode(verifyData, options) {
    // TODO: implement according to Linked Data Signatures 1.0 spec
    throw new Error('Not implemented');
  }

  async verify(framed, options) {
    options = Object.assign({}, options || {});

    const signature = framed.signature;

    // destructure options
    let {
      maxTimestampDelta = (15 * 60),
      checkNonce = () => (
        signature.nonce === null || signature.nonce === undefined),
      checkDomain = () => (
        signature.domain === null || signature.domain === undefined),
      checkTimestamp = () => {
        const now = Date.now();
        const delta = maxTimestampDelta * 1000;
        const created = Date.parse(signature.created);
        if(created < (now - delta) || created > (now + delta)) {
          throw new Error('The digital signature timestamp is out of range.');
        }
        return true;
      },
      checkKey = this.helper.checkKey.bind(this.helper),
      publicKey: getPublicKey = this.helper.getPublicKey.bind(this.helper)
    } = options;

    // normalize function options
    if(checkNonce === false) {
      // not checking nonce, so return true
      checkNonce = () => true;
    }
    if(checkDomain === false) {
      // not checking domain, so return true
      checkDomain = () => true;
    }
    if(checkTimestamp === false) {
      // not checking timestamp, so return true
      checkTimestamp = () => true;
    }
    if(typeof getPublicKey !== 'function') {
      const key = getPublicKey;
      getPublicKey = keyId => {
        if(keyId !== key.id) {
          throw new Error('Public key not found.');
        }
        return key;
      };
    }
    checkNonce = util.normalizeAsyncFn(checkNonce, 2);
    checkDomain = util.normalizeAsyncFn(checkDomain, 2);
    checkTimestamp = util.normalizeAsyncFn(checkTimestamp, 2);
    checkKey = util.normalizeAsyncFn(checkKey, 2);
    getPublicKey = util.normalizeAsyncFn(getPublicKey, 2);

    // run nonce, domain, and timestamp checks in parallel
    const checks = await Promise.all([
      checkNonce(signature.nonce, options),
      checkDomain(signature.domain, options),
      checkTimestamp(signature.date, options)
    ]);

    if(!checks[0]) {
      throw new Error('The nonce is invalid.');
    }
    if(!checks[1]) {
      throw new Error('The domain is invalid.');
    }
    if(!checks[2]) {
      throw new Error('The timestamp is invalid.');
    }

    // get public key
    const publicKey = await getPublicKey(signature.creator, options);

    // TODO: should be able to override revocation check to ensure that
    // signatures made prior to the revocation check could potentially still
    // be verified

    // ensure key is not revoked
    if('revoked' in publicKey) {
      throw new Error(
        'The document was signed with a key that has been revoked.');
    }

    // ensure key is trusted before proceeding
    const isKeyTrusted = await checkKey(publicKey, options);
    if(!isKeyTrusted) {
      throw new Error('The document was not signed with a trusted key.');
    }

    // verify input
    const verifyData = await this.createVerifyData(
      framed, Object.assign({}, options, {
        date: signature.created,
        nonce: signature.nonce,
        domain: signature.domain
      }));

    return await this.verifySignatureNode(
      verifyData, signature,
      Object.assign({}, options, {publicKey: publicKey}));
  }
};
