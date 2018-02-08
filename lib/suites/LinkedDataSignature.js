/*
 * Copyright (c) 2017-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const constants = require('../constants');
const util = require('../util');
const Helper = require('../Helper');

// TODO: reorganize this class further and make it more obvious which
// methods need to be extended in proof plugins

// TODO: make signature and verification code (and potentially other code)
// more DRY, especially wrt. plugins having reimplement functionality

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
    // TODO: frame before getting signature, not just compact? considerations:
    // should the assumption be (for this library) that the signature is on
    // the top-level object and thus framing is unnecessary?

    const jsonld = this.injector.use('jsonld');
    const compacted = await jsonld.compact(
      input, constants.SECURITY_CONTEXT_URL,
      {expansionMap: options.expansionMap});

    // TODO: will need to preserve `signature` when chained signature
    // option is used and implemented in the future

    // delete the existing proofs(s) prior to canonicalization
    delete compacted.proof;

    // `jws` must not be included in the proof options
    const proof = util.deepClone(options.proof);
    delete proof.jws;

    // concatenate hash of c14n proof options and hash of c14n document
    const c14nProofOptions = await this.canonize(proof, options);
    const c14nDocument = await this.canonize(compacted, options);
    return {
      data: this._sha256(c14nProofOptions).getBytes() +
        this._sha256(c14nDocument).getBytes(),
      encoding: 'binary'
    };
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

    // build proof (aka signature options)
    let proof;
    if(options.proof) {
      // use proof JSON-LD document passed to API
      const jsonld = this.injector.use('jsonld');
      proof = await jsonld.compact(
        options.proof, constants.SECURITY_CONTEXT_URL,
        {expansionMap: options.expansionMap});
    } else {
      // create proof JSON-LD document
      proof = {'@context': constants.SECURITY_CONTEXT_URL};
    }

    // ensure algorithm is set
    proof.type = options.algorithm;

    // add API overrides
    proof.creator = options.creator;
    proof.created = options.date;
    if('domain' in options) {
      proof.domain = options.domain;
    }
    if('nonce' in options) {
      proof.nonce = options.nonce;
    }

    // produce data to sign
    options = Object.assign({}, options, {proof});
    const verifyData = await this.createVerifyData(input, options);

    // create proof node
    const proofNode = await this.createProofNode(verifyData, options);

    // attach proof node
    return this.attachProofNode(input, proofNode, options);
  }

  async createProofNode(verifyData, options) {
    const proof = options.proof;
    proof.jws = await this.createSignatureValue(verifyData, options);
    return proof;
  }

  async attachProofNode(input, proofNode, options) {
    // compact proof node to match input context
    const tmp = {
      'https://w3id.org/security#proof': proofNode
    };
    const jsonld = this.injector.use('jsonld');
    const ctx = jsonld.getValues(input, '@context');
    const compactProofNode = await jsonld.compact(tmp, ctx);

    // TODO: it is unclear how the signature would be easily added without
    // reshaping the input... so perhaps this library should just require
    // the caller to accept that the signature will be added to the top
    // level of the input

    // attach signature node to cloned input and return it
    const output = util.deepClone(input);
    delete compactProofNode['@context'];
    const proofKey = Object.keys(compactProofNode)[0];
    jsonld.addValue(output, proofKey, compactProofNode[proofKey]);
    return output;
  }

  async verify(framed, options) {
    options = Object.assign({}, options || {});

    const proof = framed.signature || framed.proof;
    proof['@context'] = framed['@context'];

    // destructure options
    let {
      maxTimestampDelta = (15 * 60),
      checkNonce = () => (
        proof.nonce === null || proof.nonce === undefined),
      checkDomain = () => (
        proof.domain === null || proof.domain === undefined),
      checkTimestamp = () => {
        const now = Date.now();
        const delta = maxTimestampDelta * 1000;
        const created = Date.parse(proof.created);
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
      checkNonce(proof.nonce, options),
      checkDomain(proof.domain, options),
      checkTimestamp(proof.date, options)
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
    const publicKey = await getPublicKey(proof.creator, options);

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
        date: proof.created,
        nonce: proof.nonce,
        domain: proof.domain,
        proof
      }));

    return this.verifyProofNode(
      verifyData, proof,
      Object.assign({}, options, {publicKey: publicKey}));
  }

  async verifyProofNode(verifyData, proof, options) {
    throw new Error(
      '"verifyProofNode" must be implemented in a derived class.');
  }

  // TODO: use node `crypto` and Buffers in node environment
  // returns a forge buffer
  _sha256(str, encoding) {
    // browser or other environment
    const forge = this.injector.use('forge');
    const md = forge.md.sha256.create();
    md.update(str, encoding || 'utf8');
    return md.digest();
  }
};
