/*
 * Copyright (c) 2017-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const constants = require('../constants');
const jsonld = require('jsonld');
const util = require('../util');
const LinkedDataProof = require('./LinkedDataProof');

module.exports = class LinkedDataSignature extends LinkedDataProof {
  /**
   * @param type {string} Provided by subclass.
   *
   * One of these parameters is required to use a suite for signing:
   *
   * @param [creator] {string} A key id URL to the paired public key.
   * @param [verificationMethod] {string} A key id URL to the paired public key.
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
   */
  constructor({
    type, creator, verificationMethod, proof, date, domain, nonce,
    maxTimestampDelta = Infinity} = {}) {
    // validate common options
    if(verificationMethod !== undefined &&
      typeof verificationMethod !== 'string') {
      throw new TypeError('"verificationMethod" must be a URL string.');
    }
    if(domain !== undefined && typeof domain !== 'string') {
      throw new TypeError('"domain" must be a string.');
    }
    if(nonce !== undefined && typeof nonce !== 'string') {
      throw new TypeError('"nonce" must be a string.');
    }

    super({type});
    this.creator = creator;
    this.verificationMethod = verificationMethod;
    this.proof = proof;
    this.date = date;
    this.domain = domain;
    this.nonce = nonce;
    this.maxTimestampDelta = maxTimestampDelta;
  }

  /**
   * @param document {object} to be signed.
   * @param purpose {ProofPurpose}
   * @param documentLoader {function}
   * @param expansionMap {function}
   *
   * @returns {Promise<object>} Resolves with the created proof object.
   */
  async createProof(document, {purpose, documentLoader, expansionMap}) {
    // build proof (currently known as `signature options` in spec)
    let proof;
    if(this.proof) {
      // use proof JSON-LD document passed to API
      const options = {documentLoader, expansionMap};
      proof = await jsonld.compact(
        this.proof, constants.SECURITY_CONTEXT_URL, options);
    } else {
      // create proof JSON-LD document
      proof = {'@context': constants.SECURITY_CONTEXT_URL};
    }

    // ensure proof type is set
    proof.type = this.type;

    // set default `now` date if not given in `proof` or `options`
    let date = this.date;
    if(proof.created === undefined && date === undefined) {
      date = new Date();
    }

    // ensure date is in string format
    if(date !== undefined && typeof date !== 'string') {
      date = util.w3cDate(date);
    }

    // add API overrides
    if(date !== undefined) {
      proof.created = date;
    }
    // `verificationMethod` is for newer suites, `creator` for legacy
    if(this.verificationMethod !== undefined) {
      proof.verificationMethod = this.verificationMethod;
    }
    if(this.creator !== undefined) {
      proof.creator = this.creator;
    }
    if(this.domain !== undefined) {
      proof.domain = this.domain;
    }
    if(this.nonce !== undefined) {
      proof.nonce = this.nonce;
    }

    if(!this.legacy) {
      // allow purpose to update the proof; the `proof` is in the
      // SECURITY_CONTEXT_URL `@context` -- therefore the `purpose` must
      // ensure any added fields are also represented in that same `@context`
      proof = await purpose.update(
        proof, {document, suite: this, documentLoader, expansionMap});
    }

    // create data to sign
    const verifyData = await this.createVerifyData(
      {document, proof, documentLoader, expansionMap});

    // sign data
    proof = await this.sign(
      {verifyData, document, proof, documentLoader, expansionMap});

    return proof;
  }

  /**
   * @param proof {object} the proof to be verified.
   * @param document {object} the document the proof applies to.
   * @param purpose {ProofPurpose}
   * @param documentLoader {function}
   * @param expansionMap {function}
   *
   * @returns {Promise<{object}>} Resolves with the verification result.
   */
  async verifyProof({proof, document, purpose, documentLoader, expansionMap}) {
    try {
      // create data to verify
      const verifyData = await this.createVerifyData(
        {document, proof, documentLoader, expansionMap});

      // fetch verification method
      const verificationMethod = await this.getVerificationMethod(
        {proof, document, documentLoader, expansionMap});

      // verify signature on data
      const verified = await this.verifySignature({
        verifyData, verificationMethod, document, proof,
        documentLoader, expansionMap});
      if(!verified) {
        throw new Error('Invalid signature.');
      }

      // check expiration
      if(this.maxTimestampDelta !== Infinity) {
        const expected = Date.parse(this.date || Date.now());
        const delta = this.maxTimestampDelta * 1000;
        const created = Date.parse(proof.created);
        if(created < (expected - delta) || created > (expected + delta)) {
          throw new Error('The proof\'s created timestamp is out of range.');
        }
      }

      // check domain
      if(this.domain !== undefined && this.proof.domain !== this.domain) {
        throw new Error('The domain is not as expected; ' +
          `domain="${this.proof.domain}", expected="${this.domain}"`);
      }

      if(!this.legacy) {
        // ensure proof was performed for a valid purpose
        const {valid, error} = await purpose.validate(
          proof, {document, suite: this, verificationMethod,
            documentLoader, expansionMap});
        if(!valid) {
          throw error;
        }
      }

      return {verified: true};
    } catch(error) {
      return {verified: false, error};
    }
  }

  async canonize(input, {documentLoader, expansionMap, skipExpansion}) {
    const options = {
      algorithm: 'URDNA2015',
      format: 'application/n-quads',
      documentLoader,
      expansionMap,
      skipExpansion
    };
    return jsonld.canonize(input, options);
  }

  async canonizeProof(proof, {documentLoader, expansionMap, skipExpansion}) {
    // `jws`,`signatureValue`,`proofValue` must not be included in the proof
    // options
    proof = {...proof};
    delete proof.jws;
    delete proof.signatureValue;
    delete proof.proofValue;
    return this.canonize(proof, {documentLoader, expansionMap, skipExpansion});
  }

  /**
   * @param document {object} to be signed/verified.
   * @param proof {object}
   * @param documentLoader {function}
   * @param expansionMap {function}
   *
   * @returns {Promise<{Uint8Array}>}.
   */
  async createVerifyData({document, proof, documentLoader, expansionMap}) {
    // concatenate hash of c14n proof options and hash of c14n document
    const c14nProofOptions = await this.canonizeProof(
      proof, {documentLoader, expansionMap});
    const c14nDocument = await this.canonize(
      document, {documentLoader, expansionMap});
    return util.concat(
      util.sha256(c14nProofOptions),
      util.sha256(c14nDocument));
  }

  /**
   * @param document {object} to be signed.
   * @param proof {object}
   * @param documentLoader {function}
   * @param expansionMap {function}
   */
  async getVerificationMethod({proof, documentLoader}) {
    let {verificationMethod} = proof;

    if(!verificationMethod) {
      // backwards compatibility support for `creator`
      const {creator} = proof;
      verificationMethod = creator;
    }

    if(typeof verificationMethod === 'object') {
      verificationMethod = verificationMethod.id;
    }

    if(!verificationMethod) {
      throw new Error('No "verificationMethod" or "creator" found in proof.');
    }

    const {'@graph': [framed]} = await jsonld.frame(verificationMethod, {
      '@context': constants.SECURITY_CONTEXT_URL,
      '@embed': '@always',
      id: verificationMethod
    }, {documentLoader});
    if(!framed) {
      throw new Error(`Verification method ${verificationMethod} not found.`);
    }

    // ensure verification method has not been revoked
    if(framed.revoked !== undefined) {
      throw new Error('The verification method has been revoked.');
    }

    return framed;
  }

  /**
   * @param verifyData {Uint8Array}.
   * @param document {object} to be signed.
   * @param proof {object}
   * @param documentLoader {function}
   * @param expansionMap {function}
   *
   * @returns {Promise<{object}>} the proof containing the signature value.
   */
  async sign() {
    throw new Error('Must be implemented by a derived class.');
  }

  /**
   * @param verifyData {Uint8Array}.
   * @param verificationMethod {object}.
   * @param document {object} to be signed.
   * @param proof {object}
   * @param documentLoader {function}
   * @param expansionMap {function}
   *
   * @returns {Promise<boolean>}
   */
  async verifySignature() {
    throw new Error('Must be implemented by a derived class.');
  }
};
