/*!
 * Copyright (c) 2010-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

/* Core API */
const api = {};
module.exports = api;

/* API Constants */
const constants = require('./constants');
Object.assign(api, constants);

// TODO: support `ProofChain`
const ProofSet = require('./ProofSet');
const VerificationError = require('./VerificationError');

/**
 * Cryptographically signs the provided document by adding a `proof` section,
 * based on the provided suite and proof purpose.
 *
 * @param {object|string} document - The document to be signed, either a string URL
 *  (resolved to an object via the given `documentLoader`) or a plain object
 *  (JSON-LD document).
 *
 * @param {LinkedDataSignature} suite - The linked data signature cryptographic
 *   suite, containing private key material, with which to sign the document.
 * @param {ProofPurpose} purpose - A proof purpose instance that will
 *   match proofs to be verified and ensure they were created according to
 *   the appropriate purpose.
 *
 * Advanced optional parameters and overrides:
 *
 * @param {function} [documentLoader]  - A custom document loader,
 *   `Promise<RemoteDocument> documentLoader(url)`.
 * @param {function} [expansionMap] - A custom expansion map that is
 *   passed to the JSON-LD processor; by default a function that will throw
 *   an error when unmapped properties are detected in the input, use `false`
 *   to turn this off and allow unmapped properties to be dropped or use a
 *   custom function.
 * @param {boolean} [compactProof=true] - Indicates that this method cannot
 *   assume that the incoming document has defined all proof terms in the
 *   same way as the `constants.SECURITY_CONTEXT_URL` JSON-LD `@context`.
 *   This means that this method must compact any found proofs to this
 *   context for internal and extension processing; this is the default
 *   behavior. To override this behavior and optimize away this step because
 *   the caller knows that the input document's JSON-LD `@context` defines
 *   the proof terms in the same way, set this flag to `false`.
 *
 * @returns {Promise<object>} Resolves with signed document.
 */
api.sign = async function sign(document, {
  suite, purpose, documentLoader, expansionMap, compactProof} = {}) {
  try {
    return await new ProofSet().add(
      document, {suite, purpose, documentLoader, expansionMap, compactProof});
  } catch(e) {
    if(!documentLoader && e.name === 'jsonld.InvalidUrl') {
      const {details: {url}} = e;
      const err = new Error(
        `A URL "${url}" could not be fetched; you need to pass ` +
        '"documentLoader" or resolve the URL before calling "sign".');
      err.cause = e;
      throw err;
    }
    throw e;
  }
};

/**
 * Verifies the linked data signature on the provided document.
 *
 * @param {object|string} document - The document with one or more proofs to be
 *   verified, either a string URL (resolved to an object via the given
 *   `documentLoader`) or a plain object (JSON-LD document).
 *
 * @param {LinkedDataSignature|LinkedDataSignature[]} suite -
 *   Acceptable signature suite instances for verifying the proof(s).
 *
 * @param {ProofPurpose} purpose - A proof purpose instance that will
 *   match proofs to be verified and ensure they were created according to
 *   the appropriate purpose.
 *
 * Advanced optional parameters and overrides:
 *
 * @param {function} [documentLoader]  - A custom document loader,
 *   `Promise<RemoteDocument> documentLoader(url)`.
 * @param {function} [expansionMap] - A custom expansion map that is
 *   passed to the JSON-LD processor; by default a function that will throw
 *   an error when unmapped properties are detected in the input, use `false`
 *   to turn this off and allow unmapped properties to be dropped or use a
 *   custom function.
 * @param {boolean} [compactProof=true] - Indicates that this method cannot
 *   assume that the incoming document has defined all proof terms in the
 *   same way as the `constants.SECURITY_CONTEXT_URL` JSON-LD `@context`.
 *   This means that this method must compact any found proofs to this
 *   context for internal and extension processing; this is the default
 *   behavior. To override this behavior and optimize away this step because
 *   the caller knows that the input document's JSON-LD `@context` defines
 *   the proof terms in the same way, set this flag to `false`.
 *
 * @return {Promise<{verified: boolean, results: Array, error: VerificationError}>}
 *   resolves with an object with a `verified` boolean property that is `true`
 *   if at least one proof matching the given purpose and suite verifies and
 *   `false` otherwise; a `results` property with an array of detailed results;
 *   if `false` an `error` property will be present, with `error.errors`
 *   containing all of the errors that occurred during the verification process.
 */
api.verify = async function verify(document, {
  suite, purpose, documentLoader, expansionMap, compactProof} = {}) {
  const result = await new ProofSet().verify(
    document, {suite, purpose, documentLoader, expansionMap, compactProof});
  const {error} = result;
  if(error) {
    if(!documentLoader && error.name === 'jsonld.InvalidUrl') {
      const {details: {url}} = error;
      const urlError = new Error(
        `A URL "${url}" could not be fetched; you need to pass ` +
        '"documentLoader" or resolve the URL before calling "verify".');
      result.error = new VerificationError(urlError);
    } else {
      result.error = new VerificationError(error);
    }
  }
  return result;
};

// expose suite classes
api.suites = require('./suites').suites;

// expose ProofPurpose classes to enable extensions
api.purposes = require('./purposes').purposes;

// expose LDKeyPair classes
Object.assign(api, require('crypto-ld'));

// expose document loader helpers
Object.assign(api, require('./documentLoader'));
