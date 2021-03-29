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
 * @param {object|string} document - The document to be signed, either a string
 *  URL (resolved to an object via the given `documentLoader`) or a plain
 *  object (JSON-LD document).
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
 *
 * @returns {Promise<object>} Resolves with signed document.
 */
api.sign = async function sign(document, {
  suite, purpose, documentLoader, expansionMap
} = {}) {
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

/* eslint-disable max-len */
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
 *
 * @return {Promise<{verified: boolean, results: Array,
 *   error: VerificationError}>}
 *   resolves with an object with a `verified` boolean property that is `true`
 *   if at least one proof matching the given purpose and suite verifies and
 *   `false` otherwise; a `results` property with an array of detailed results;
 *   if `false` an `error` property will be present, with `error.errors`
 *   containing all of the errors that occurred during the verification process.
 */
/* eslint-enable */
api.verify = async function verify(document, {
  scope, suite, purpose, documentLoader, expansionMap, compactProof} = {}) {

  let result = {};

  // "proof" verification
  if (Array.isArray(scope) && scope.includes('proof')) {
    result = await new ProofSet().verify(
      document, {suite, purpose, documentLoader, expansionMap, compactProof});
  }

  const errors = [];

  const {error} = result;
  if (error) {
    if (!documentLoader && error.name === 'jsonld.InvalidUrl') {
      const { details: { url } } = error;
      const urlError = new Error(
        `A URL "${url}" could not be fetched; you need to pass ` +
        '"documentLoader" or resolve the URL before calling "verify".');
      errors.push(urlError);
    } else {
      errors.push(...(Array.isArray(error) ? error : [error]));
    }
  }

  const NBF_SKEW = 300;
  const now = Math.floor(Date.now() / 1000);

  // "issuanceDate" verification // Spherity's logic
  if (Array.isArray(scope) && scope.includes('issuanceDate')) {
   
    const nowSkewed = now + NBF_SKEW;
    const nbf = +new Date(document.issuanceDate) / 1000;
    if (nbf > nowSkewed) {
      const issError = new Error(`JSON-LD is not valid before "issuanceDate": ${new Date(nbf * 1000)}`);
      errors.push(issError);
    }
  }

  // "expirationDate" verification // Spherity's logic
  if (Array.isArray(scope) && scope.includes('expirationDate')) {
    if (document.expirationDate) {
      const exp = +new Date(document.expirationDate) / 1000;
      if (exp <= now - NBF_SKEW) {
        const expError = new Error(
          `JSON-LD has expired: expirationDate: ${new Date(document.expirationDate)} <= now: ${new Date(now * 1000)}`
        );
        errors.push(expError);
      }
    } else {
      const noExpError = new Error('A "expirationDate" property is required for expiration date verification.');
      errors.push(noExpError);
    }
  }

  if (errors.length > 0) {
    result.error = new VerificationError(errors);
  }

  return result;
};
// api.verify = async function verify(document, {
//   suite, purpose, documentLoader, expansionMap} = {}) {
//   const result = await new ProofSet().verify(
//     document, {suite, purpose, documentLoader, expansionMap});
//   const {error} = result;
//   if(error) {
//     if(!documentLoader && error.name === 'jsonld.InvalidUrl') {
//       const {details: {url}} = error;
//       const urlError = new Error(
//         `A URL "${url}" could not be fetched; you need to pass ` +
//         '"documentLoader" or resolve the URL before calling "verify".');
//       result.error = new VerificationError(urlError);
//     } else {
//       result.error = new VerificationError(error);
//     }
//   }
//   return result;
// };

// expose suite classes
api.suites = require('./suites').suites;

// expose ProofPurpose classes to enable extensions
api.purposes = require('./purposes').purposes;

// expose document loader helpers
Object.assign(api, require('./documentLoader'));
