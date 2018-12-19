/**
 * An implementation of the Linked Data Signatures specification for JSON-LD.
 * This library works in the browser and node.js.
 *
 * @author Dave Longley <dlongley@digitalbazaar.com>
 * @author David I. Lehn <dlehn@digitalbazaar.com>
 * @author Manu Sporny <msporny@digitalbazaar.com>
 * @author Ganesh Annan <gannan@digitalbazaar.com>
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

const {suites, getSuite, getSupportedAlgorithms} = require('./suites');

// load locally embedded contexts
const contexts = require('./contexts');

/**
 * Attaches the JSON-LD Signatures API to the given object.
 *
 * @param api the object to attach the signatures API to.
 */
/* eslint-disable indent */
function wrap(api) {

const injector = new Injector();

/* API Constants */
const constants = require('./constants');
Object.assign(api, constants);

/* Core API */
const ppInjector = new Injector({useDefault: false});
api.proofPurposes = {
  use: ppInjector.use.bind(ppInjector)
};
api.suites = suites;

/**
 * Signs a JSON-LD document using a digital signature.
 *
 * @param input {object|string} Object to be signed, either a string URL
 *   (resolved to an object by `jsonld.expand()`) or a plain object (JSON-LD
 *   doc).
 * @param options {object} Options hashmap
 *
 * Either a `suite` or an `algorithm` option is required:
 *
 * @param [options.suite] {LinkedDataSignature} Injected signature suite
 * @param [options.algorithm] {string} Algorithm to use,
 *   eg: 'Ed25519Signature2018', 'RsaSignature2018', used to construct the
 *   suite if not passed in.
 *
 * Optional key material (if not passed along in `suite` above):
 *
 * @param [privateKeyPem] {string} A PEM-encoded private key, for RSA sigs
 * @param [privateKeyBase58] {string} A base85-encoded (Bitcoin/IPFS alphabet)
 *   private key, for Ed25519 sigs.
 * @param [options.creator] {string} A key id URL to the paired public key.
 *
 * Optional (but highly recommended) Proof Purpose params:
 *
 * @param [options.purpose] {object} define proofPurpose and additional options.
 *   WARNING: Not providing this will result in the legacy behavior of checking
 *   only signatures without a proofPurpose, which can lead to confused deputy
 *   attacks.
 * @param [options.proof] {object} a JSON-LD document with options to use for
 *   the `proof` node (e.g. `proofPurpose` or any other custom fields can be
 *   provided here using a context different from security-v2).
 * @param [options.proofPurpose] {string} proofPurpose the proofPurpose to use.
 *   (e.g. 'CredentialIssuance')
 * @param [options.purposeParameters] {object} additional named parameters that
 *   will be passed to the proofPurpose handler.
 *
 * Advanced optional parameters and overrides:
 *
 * @param [options.date] {string|Date} Initialized to `now` if not passed
 * @param [options.domain] {string} Domain to include in the signature
 * @param [options.nonce] {string} Nonce to include in the signature.
 * @param [options.documentLoader] {function} Custom document loader,
 *   documentLoader(url, [callback(err, remoteDoc)])
 * @param [options.expansionMap] {function} A custom expansion map that is
 *   passed to the JSON-LD processor; by default a function that will throw
 *   an error when unmapped properties are detected in the input, use `false`
 *   to turn this off and allow unmapped properties to be dropped or use a
 *   custom function.

 * @param [options.callback] {function} Optional Node style callback,
 *   `callback(err, signedDocument)` called once the operation completes, if not
 *   using Promises.
 *
 * @return {Promise<object>} Resolves with the signed input document, with
 *   the signature in the top-level `proof` property.
 */
api.sign = util.callbackify(async function sign(input, options = {}) {
  options = _addEmbeddedContextDocumentLoader(options);

  const suite = options.suite ||
    getSuite({algorithm: options.algorithm, injector});

  const {purpose, proofPurposeHandler, purposeParameters} =
    getProofPurposeHandler({options, injector});

  return suite.sign(
    input,
    {...options, purpose, proofPurposeHandler, purposeParameters});
});

/**
 * @param options
 * @param [options.purpose]
 * @param [options.purposeParameters]
 * @param injector
 * @throws {Error} On unsupported proof purpose handler
 * @private
 * @returns {{purpose: *, proofPurposeHandler: *, purposeParameters: *}}
 */
function getProofPurposeHandler({options, injector}) {
  // instantiate a proofPurpose handler
  const {purpose, purposeParameters} = options;
  let proofPurposeHandler;
  if(purpose) {
    const ProofPurposeHandler = api.proofPurposes.use(purpose);
    if(!ProofPurposeHandler) {
      throw new Error(`Unsupported proof purpose handler "${purpose}".`);
    }
    proofPurposeHandler = new ProofPurposeHandler(injector);
  }
  return {purpose, proofPurposeHandler, purposeParameters};
}

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
 *          {Object} [purpose] define proofPurpose and additional options.
 *            If provided, only proofs matching this proofPurpose's URI will
 *            be checked, but will be checked against the additional
 *            verification steps relevant to the proofPurpose.
 *            Not providing this will result in the legacy behavior
 *            of checking only signatures without a proofPurpose.  Not
 *            recommended... this can lead to confused deputy attacks.
 *            {string} proofPurpose the proofPurpose to use.
 *                (e.g. CredentialIssuance)
 *              {...*} additional named parameters that will be passed to the
 *                proofPurpose handler.
 * @param [callback(err, result)] called once the operation completes.
 *
 * @return a Promise that resolves to the verification result.
 */
api.verify = util.callbackify(async function verify(input, options) {
  // set default options
  options = {...options};

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
  _validateProofPurpose(options.purpose);
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
    input,
    constants.SECURITY_CONTEXT_URL,
    opts);

  // ensure there is at least one `proof` or `signature`
  let proofs = jsonld.getValues(framed, 'signature')
    .map(doc => ({property: 'signature', doc}))
    .concat(jsonld.getValues(framed, 'proof')
    .map(doc => ({property: 'proof', doc})));
  if(proofs.length === 0) {
    throw new Error('No signature found.');
  }

  // Filter proofs to only those with the expected proofpurpose
  const {purpose, purposeParameters} = options;

  let proofPurposeHandler;
  if(purpose) {
    const ProofPurposeHandler = api.proofPurposes.use(purpose);
    proofPurposeHandler = new ProofPurposeHandler(injector);

    // if a purpose has been specified, proofs *must* include a proof with the
    // specified `proofPurpose`
    proofs = proofs.filter(async ({doc: proof}) => {
      const proofPurposeUri = await _getExpandedProofPurpose({
        proof, jsonldOpts: opts});
      return proofPurposeUri === proofPurposeHandler.uri;
    });

    if(proofs.length === 0) {
      const error = new Error(
        'No proofs matched the required proofPurpose "' +
        proofPurposeHandler.uri + '".');
      return {error, verified: false};
    }
  }

  // TODO: this only works for set signatures; add support for chained
  // signatures

  // create a promise for each signature to be verified
  const SUPPORTED_ALGORITHMS = getSupportedAlgorithms();
  const results = await Promise.all(proofs.map(async proof => {
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
        f, {...options, purpose, proofPurposeHandler, purposeParameters});
      return {verified};
    } catch(e) {
      return {verified: false, error: e};
    }
  }));

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

function _validateProofPurpose(purpose) {
  if(!purpose) {
    // TODO: Enable error in the next major release
    // throw new Error(`Please provide 'purpose' of the proof to verify.`);
    return;
  }
  try {
    const ProofPurposeHandler = api.proofPurposes.use(purpose);
    // when not in the node environment, an uknown purpose causes the injector
    // to return undefined
    if(!ProofPurposeHandler) {
      throw new Error(`Unsupported proof purpose "${purpose}".`);
    }
  } catch(e) {
    // when in the node environment, an uknown purpose causes the injector
    // to return an error from `require` that it can't find the module
    if(e.message === `Cannot find module '${purpose}'`) {
      throw new Error(`Unsupported proof purpose "${purpose}".`);
    }
    throw e;
  }
}

async function _getExpandedProofPurpose({proof, jsonldOpts}) {
  const {proofPurpose} = proof;
  if(!proofPurpose) {
    throw new Error('"proofPurpose" is not defined.');
  }
  const jsonld = injector.use('jsonld');

  const expanded = await jsonld.expand({
    proofPurpose,
    '@context': constants.SECURITY_CONTEXT_URL}, jsonldOpts);
  return expanded[0]['https://w3id.org/security#proofPurpose'][0]['@id'];
}

function _addEmbeddedContextDocumentLoader(options) {
  options = {...options};
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

// register itself using the injector
injector.use('jsonld-signatures', api);

// reexpose API as `.promises` for backwards compatability
api.promises = api;

// expose base64 functions for testing
api._encodeBase64Url = util.encodeBase64Url;
api._decodeBase64Url = util.decodeBase64Url;

// expose ProofPurposeHandler base class
api.ProofPurposeHandler = require('./proof-purpose/ProofPurposeHandler');

return api;

} // end wrap

// used to generate a new verifier API instance
const factory = function() {
  return wrap(function() {return factory();});
};
wrap(factory);

const {nodejs, browser} = require('./env');

if(nodejs) {
  // export nodejs API
  module.exports = factory;
} else if(typeof define === 'function' && define.amd) {
  // export AMD API
  define([], function() {
    return factory;
  });
} else if(browser) {
  // export simple browser API
  if(typeof global.jsigs === 'undefined') {
    global.jsigs = {};
  }
  wrap(global.jsigs);
}

})(typeof window !== 'undefined' ? window : this);
