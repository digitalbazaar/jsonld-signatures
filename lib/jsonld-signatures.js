/**
 * An implementation of the Linked Data Signatures specification for JSON-LD.
 * This library works in the browser and node.js.
 *
 * @author Dave Longley <dlongley@digitalbazaar.com>
 * @author David I. Lehn <dlehn@digitalbazaar.com>
 * @author Manu Sporny <msporny@digitalbazaar.com>
 *
 * BSD 3-Clause License
 * Copyright (c) 2014-2018 Digital Bazaar, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * Neither the name of the Digital Bazaar, Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
(function(global) {

'use strict';

const Injector = require('./Injector');
const util = require('./util');

// TODO: only require dynamically as needed or according to build
const suites = {
  EcdsaKoblitzSignature2016: require('./suites/EcdsaKoblitzSignature2016'),
  Ed25519Signature2018: require('./suites/Ed25519Signature2018'),
  LinkedDataSignature: require('./suites/LinkedDataSignature'),
  LinkedDataSignature2015: require('./suites/LinkedDataSignature2015'),
  GraphSignature2012: require('./suites/GraphSignature2012'),
  RsaSignature2018: require('./suites/RsaSignature2018')
};

// load locally embedded contexts
const contexts = require('./contexts');

// determine if using node.js or browser
const _nodejs = (
  typeof process !== 'undefined' && process.versions && process.versions.node);
const _browser = !_nodejs &&
  (typeof window !== 'undefined' || typeof self !== 'undefined');

/**
 * Attaches the JSON-LD Signatures API to the given object.
 *
 * @param api the object to attach the signatures API to.
 */
function wrap(api) {

const injector = new Injector();

/* API Constants */
const constants = require('./constants');
Object.assign(api, constants);

/* Core API */
api.suites = suites;

/**
 * Signs a JSON-LD document using a digital signature.
 *
 * @param input the JSON-LD document to be signed.
 * @param [options] options to use:
 *          algorithm the algorithm to use, eg: 'Ed25519Signature2018',
 *            'RsaSignature2018'.
 *          [privateKeyPem] A PEM-encoded private key.
 *          [privateKeyBase58] A base85-encoded (Bitcoin/IPFS alphabet)
 *            private key.
 *          [creator] the URL to the paired public key.
 *          [date] an optional date to override the signature date with.
 *          [domain] an optional domain to include in the signature.
 *          [nonce] an optional nonce to include in the signature.
 *          [expansionMap] a custom expansion map that is passed
 *            to the JSON-LD processor; by default a function that will
 *            throw an error when unmapped properties are detected in the
 *            input, use `false` to turn this off and allow unmapped
 *            properties to be dropped or use a custom function.
 *          [proof] a JSON-LD document with options to use for the `proof`
 *            node (e.g. `proofPurpose` or any other custom fields can be
 *            provided here using a context different from security-v2).
 *          [documentLoader(url, [callback(err, remoteDoc)])] the document
 *            loader.
 * @param callback(err, signedDocument) called once the operation completes.
 *
 * @return a Promise that resolves to the signed document.
 */
api.sign = util.callbackify(async function(input, options) {
  options = options || {};

  // no default algorithm; it must be specified
  if(!('algorithm' in options)) {
    throw new TypeError('"options.algorithm" must be specified.');
  }

  const SUPPORTED_ALGORITHMS = _getSupportedAlgorithms();

  const algorithm = options.algorithm;
  if(SUPPORTED_ALGORITHMS.indexOf(algorithm) === -1) {
    throw new Error(
      'Unsupported algorithm "' + algorithm + '"; ' +
      '"options.algorithm" must be one of: ' +
      JSON.stringify(SUPPORTED_ALGORITHMS));
  }

  options = _addEmbeddedContextDocumentLoader(options);

  // TODO: won't work with static analysis?
  // use signature suite
  //const Suite = require('./suites/' + algorithm);
  const Suite = suites[algorithm];
  return new Suite(injector).sign(input, options);
});

/**
 * Verifies a JSON-LD digitally-signed object.
 *
 * @param obj the JSON-LD object to verify.
 * @param [options] the options to use:
 *          [publicKey] a JSON-LD document providing the public
 *            key info or a function ((keyId, options, [(err, publicKey)]) that
 *            returns a Promise that resolves to such a document (or that
 *            accepts a node-style callback that will be passed it).
 *          [publicKeyOwner] a JSON-LD document providing the public key owner
 *            info including the list of valid keys for that owner or a
 *            function (owner, options, [(err, ownerDoc)]) that returns a
 *            Promise that resolves to such a document (or that accepts a
 *            node-style callback that will be passed it).
 *          [checkNonce(nonce, options, function(err, valid))] a callback to
 *            check if the nonce (null if none) used in the signature is valid.
 *          [checkDomain(domain, options, function(err, valid))] a callback
 *            to check if the domain used (null if none) is valid.
 *          [checkKey(key, options, function(err, trusted))] a callback to
 *            check if the key used to sign the message is trusted.
 *          [checkKeyOwner(owner, key, options, function(err, trusted))] a
 *            callback to check if the key's owner is trusted.
 *          [checkTimestamp]: check signature timestamp (default: false).
 *          [maxTimestampDelta]: signature must be created within a window of
 *            this many seconds (default: 15 minutes).
 *          [documentLoader(url, [callback(err, remoteDoc)])] the document
 *            loader.
 *          [id] the ID (full URL) of the node to check the signature of, if
 *            the input contains multiple signed nodes.
 * @param [callback(err, result)] called once the operation completes.
 *
 * @return a Promise that resolves to the verification result.
 */
api.verify = util.callbackify(async function(input, options) {
  // set default options
  options = Object.assign({}, options || {});

  // validate options
  if('checkNonce' in options &&
    !(options.checkNonce === false ||
    typeof options.checkNonce === 'function')) {
    throw new TypeError(
      '"options.checkNonce" must be `false` or a function.');
  }
  if('checkDomain' in options &&
    !(options.checkDomain === false ||
    typeof options.checkDomain === 'string' ||
    typeof options.checkDomain === 'function')) {
    throw new TypeError(
      '"options.checkDomain" must be `false`, a string, or a function.');
  }
  if('checkTimestamp' in options &&
    !(options.checkTimestamp === false ||
    typeof options.checkTimestamp === 'function')) {
    throw new TypeError(
      '"options.checkTimestamp" must be `false` or a function.');
  }

  // backwards compatibility, massage `getPublicKey` and `getPublicKeyOwner`
  // options into `publicKey` and `publicKeyOwner`
  if('getPublicKey' in options) {
    options.publicKey = options.getPublicKey;
  }
  if('getPublicKeyOwner' in options) {
    options.publicKeyOwner = options.getPublicKeyOwner;
  }

  options = _addEmbeddedContextDocumentLoader(options);

  // TODO: frame before getting signature, not just compact? considerations:
  // 1. named-graph framing support is required to avoid merging data and
  //    invalidating the signature
  // 2. JSON-only inputs will fail compaction -- so perhaps this library
  //    should require the signature to be at the top?
  /*
  const frame = {
    '@context': constants.SECURITY_CONTEXT_URL,
    proof: {},
    signature: {
      type: algorithm,
      created: {},
      creator: {},
      signatureValue: {}
    }
  };
  if(options.id) {
    frame.id = options.id;
  }
  */
  // compact to get signature types
  const jsonld = injector.use('jsonld');
  const opts = {};
  if(options.documentLoader) {
    opts.documentLoader = options.documentLoader;
  }
  const framed = await jsonld.compact(
    input, constants.SECURITY_CONTEXT_URL, opts);

  // ensure there is at least one `proof` or `signature`
  const proofs = jsonld.getValues(framed, 'signature')
    .map(doc => ({property: 'signature', doc}))
    .concat(jsonld.getValues(framed, 'proof')
      .map(doc => ({property: 'proof', doc})));
  if(proofs.length === 0) {
    throw new Error('No signature found.');
  }

  // TODO: this only works for set signatures; add support for chained
  // signatures

  // create a promise for each signature to be verified
  const SUPPORTED_ALGORITHMS = _getSupportedAlgorithms();
  const results = await Promise.all(proofs.map(proof => (async () => {
    try {
      const algorithm = jsonld.getValues(proof.doc, 'type')[0] || '';
      if(SUPPORTED_ALGORITHMS.indexOf(algorithm) === -1) {
        throw new Error(
          'Unsupported signature algorithm "' + algorithm +
          '"; ' + 'supported algorithms are: ' +
          JSON.stringify(SUPPORTED_ALGORITHMS));
      }

      // copy the framed object and place a single signature on each copy
      const f = util.deepClone(framed);
      f[proof.property] = proof.doc;
      // TODO: won't work with static analysis?
      // use signature suite
      //const Suite = require('./suites/' + algorithm);
      const Suite = suites[algorithm];
      const verified = await new Suite(injector).verify(
        f, Object.assign({}, options, {framed}));
      return {verified};
    } catch(e) {
      return {verified: false, error: e};
    }
  })()));

  // ensure results include public key identifiers
  results.forEach((result, i) => {
    if(proofs[i].doc.creator) {
      result.publicKey = proofs[i].doc.creator;
    }
  });

  return {
    keyResults: results,
    verified: results.every(r => r.verified)
  };
});

function _getSupportedAlgorithms() {
  // every suite is supported except the base class
  return Object.keys(api.suites).filter(s => s !== 'LinkedDataSignature');
}

function _addEmbeddedContextDocumentLoader(options) {
  options = Object.assign({}, options);
  if(!options.documentLoader) {
    const jsonld = injector.use('jsonld');
    const documentLoader = jsonld.documentLoader;
    options.documentLoader = async url => {
      if(url in contexts) {
        return {
          contextUrl: null,
          documentUrl: url,
          document: contexts[url]
        };
      }
      return documentLoader(url);
    };
  }
  return options;
}

/* Helper functions */
const Helper = require('./Helper');
const helper = new Helper(injector);

// expose for helper functions
api.getPublicKey = util.callbackify(helper.getPublicKey.bind(helper));
api.checkKey = util.callbackify(helper.checkKey.bind(helper));
api.getJsonLd = util.callbackify(helper.getJsonLd.bind(helper));

// expose injector API
api.use = injector.use.bind(injector);

// reexpose API as `.promises` for backwards compatability
api.promises = api;

// expose base64 functions for testing
api._encodeBase64Url = util.encodeBase64Url;
api._decodeBase64Url = util.decodeBase64Url;

return api;

} // end wrap

// used to generate a new verifier API instance
const factory = function() {
  return wrap(function() {return factory();});
};
wrap(factory);

if(_nodejs) {
  // export nodejs API
  module.exports = factory;
} else if(typeof define === 'function' && define.amd) {
  // export AMD API
  define([], function() {
    return factory;
  });
} else if(_browser) {
  // export simple browser API
  if(typeof global.jsigs === 'undefined') {
    global.jsigs = {};
  }
  wrap(global.jsigs);
}

})(typeof window !== 'undefined' ? window : this);
