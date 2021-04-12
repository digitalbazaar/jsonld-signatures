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
 * @param {object} document - The JSON-LD document to be signed.
 *
 * @param {object} options - Options hashmap.
 * @param {LinkedDataSignature} options.suite - The linked data signature
 *   cryptographic suite, containing private key material, with which to sign
 *   the document.
 *
 * @param {ProofPurpose} purpose - A proof purpose instance that will
 *   match proofs to be verified and ensure they were created according to
 *   the appropriate purpose.
 *
 * @param {function} documentLoader  - A secure document loader (it is
 *   recommended to use one that provides static known documents, instead of
 *   fetching from the web) for returning contexts, controller documents, keys,
 *   and other relevant URLs needed for the proof.
 *
 * Advanced optional parameters and overrides:
 *
 * @param {function} [options.expansionMap] - A custom expansion map that is
 *   passed to the JSON-LD processor; by default a function that will throw
 *   an error when unmapped properties are detected in the input, use `false`
 *   to turn this off and allow unmapped properties to be dropped or use a
 *   custom function.
 * @param {boolean} [options.addSuiteContext=true] - Toggles the default
 *   behavior of each signature suite enforcing the presence of its own
 *   `@context` (if it is not present, it's added to the context list).
 *
 * @returns {Promise<object>} Resolves with signed document.
 */
api.sign = async function sign(document, {
  suite, purpose, documentLoader, expansionMap, addSuiteContext = true
} = {}) {
  if(typeof document !== 'object') {
    throw new TypeError('The "document" parameter must be an object.');
  }
  // Ensure document contains the signature suite specific context URL
  // or throw an error (in case an advanced user overrides the `addSuiteContext`
  // flag to false).
  suite.ensureSuiteContext({document, addSuiteContext});

  try {
    return await new ProofSet().add(
      document, {suite, purpose, documentLoader, expansionMap});
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
 * @param {object} document - The JSON-LD document with one or more proofs to be
 *   verified.
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
 *
 * @return {Promise<{verified: boolean, results: Array,
 *   error: VerificationError}>}
 *   resolves with an object with a `verified` boolean property that is `true`
 *   if at least one proof matching the given purpose and suite verifies and
 *   `false` otherwise; a `results` property with an array of detailed results;
 *   if `false` an `error` property will be present, with `error.errors`
 *   containing all of the errors that occurred during the verification process.
 */
api.verify = async function verify(document, {
  suite, purpose, documentLoader, expansionMap} = {}) {
  if(typeof document !== 'object') {
    throw new TypeError('The "document" parameter must be an object.');
  }
  const result = await new ProofSet().verify(
    document, {suite, purpose, documentLoader, expansionMap});
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

// expose document loader helpers
Object.assign(api, require('./documentLoader'));

