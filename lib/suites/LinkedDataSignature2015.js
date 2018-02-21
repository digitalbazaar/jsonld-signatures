/*
 * Copyright (c) 2017-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const constants = require('../constants');
const util = require('../util');
const LinkedDataSignature = require('./LinkedDataSignature');

module.exports = class LinkedDataSignature2015 extends LinkedDataSignature {
  constructor(injector, algorithm = 'LinkedDataSignature2015') {
    super(injector, algorithm);
  }

  async createProofNode(verifyData, options) {
    const proof = options.proof;
    proof.signatureValue = await this.createSignatureValue(verifyData, options);
    return proof;
  }

  async attachProofNode(input, proofNode, options) {
    // compact proof node to match input context
    const tmp = {
      'https://w3id.org/security#signature': proofNode
    };
    const jsonld = this.injector.use('jsonld');
    const ctx = jsonld.getValues(input, '@context');
    const opts = {expansionMap: options.expansionMap};
    if(options.documentLoader) {
      opts.documentLoader = options.documentLoader;
    }
    const compactProofNode = await jsonld.compact(tmp, ctx, opts);

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

  async createSignatureValue(verifyData, options) {
    // TODO: support `sign` function via options instead of `privateKeyPem`
    if(typeof options.privateKeyPem !== 'string') {
      throw new TypeError(
        '"options.privateKeyPem" must be a PEM formatted string.');
    }

    if(this.injector.env.nodejs) {
      // optimize using node libraries
      const crypto = this.injector.use('crypto');
      const signer = crypto.createSign('RSA-SHA256');
      signer.update(verifyData.data, verifyData.encoding);
      return signer.sign(options.privateKeyPem, 'base64');
    }

    // browser or other environment
    const forge = this.injector.use('forge');
    const privateKey = forge.pki.privateKeyFromPem(options.privateKeyPem);
    const md = forge.md.sha256.create();
    md.update(verifyData.data, verifyData.encoding);
    return forge.util.encode64(privateKey.sign(md));
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
    // option is used and implemented in the future

    // delete the existing signature(s) prior to canonicalization
    delete compacted.signature;

    const c14n = await this.canonize(compacted, options);

    let verifyData = '';
    const headers = {
      'http://purl.org/dc/elements/1.1/created': options.date,
      'https://w3id.org/security#domain': options.domain,
      'https://w3id.org/security#nonce': options.nonce
    };
    // add headers in lexicographical order
    const keys = Object.keys(headers).sort();
    for(let i = 0; i < keys.length; ++i) {
      const key = keys[i];
      const value = headers[key];
      if(!(value === null || value === undefined)) {
        verifyData += key + ': ' + value + '\n';
      }
    }
    verifyData += c14n;
    return {
      data: verifyData,
      encoding: 'utf8'
    };
  }

  async verifyProofNode(verifyData, proof, options) {
    const publicKeyPem = options.publicKey.publicKeyPem;
    if(typeof publicKeyPem !== 'string') {
      throw new TypeError(
        'Could not verify signature; invalid "publicKeyPem".');
    }

    if(this.injector.env.nodejs) {
      // optimize using node libraries
      const crypto = this.injector.use('crypto');
      const verifier = crypto.createVerify('RSA-SHA256');
      verifier.update(verifyData.data, verifyData.encoding);
      return verifier.verify(publicKeyPem, proof.signatureValue, 'base64');
    }

    // browser or other environment
    const forge = this.injector.use('forge');
    const publicKey = forge.pki.publicKeyFromPem(publicKeyPem);
    const md = forge.md.sha256.create();
    md.update(verifyData.data, verifyData.encoding);
    return publicKey.verify(
      md.digest().bytes(), forge.util.decode64(proof.signatureValue));
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
