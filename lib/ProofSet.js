/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const constants = require('./constants');
const jsonld = require('jsonld');
const {extendContextLoader, strictDocumentLoader} = require('./documentLoader');
const {serializeError} = require('serialize-error');
const strictExpansionMap = require('./expansionMap');

module.exports = class ProofSet {
  /**
   * Adds a Linked Data proof to a document. If the document contains other
   * proofs, the new proof will be appended to the existing set of proofs.
   *
   * Important note: This method assumes that the term `proof` in the given
   * document has the same definition as the `https://w3id.org/security/v2`
   * JSON-LD @context.
   *
   * @param document {object|string} Object to be signed, either a string URL
   *   (resolved via the given `documentLoader`) or a plain object (JSON-LD
   *   document).
   * @param options {object} Options hashmap.
   *
   * A `suite` option is required:
   *
   * @param options.suite {LinkedDataSignature} a signature suite instance
   *   that will create the proof.
   *
   * A `purpose` option is required:
   *
   * @param options.purpose {ProofPurpose} a proof purpose instance that will
   *   augment the proof with information describing its intended purpose.
   *
   * Advanced optional parameters and overrides:
   *
   * @param [documentLoader] {function} a custom document loader,
   *   `Promise<RemoteDocument> documentLoader(url)`.
   * @param [expansionMap] {function} A custom expansion map that is
   *   passed to the JSON-LD processor; by default a function that will throw
   *   an error when unmapped properties are detected in the input, use `false`
   *   to turn this off and allow unmapped properties to be dropped or use a
   *   custom function.
   *
   * @return {Promise<object>} resolves with the signed document, with
   *   the signature in the top-level `proof` property.
   */
  async add(document, {suite, purpose, documentLoader, expansionMap} = {}) {
    if(!suite) {
      throw new TypeError('"options.suite" is required.');
    }
    if(!purpose) {
      throw new TypeError('"options.purpose" is required.');
    }

    if(documentLoader) {
      documentLoader = extendContextLoader(documentLoader);
    } else {
      documentLoader = strictDocumentLoader;
    }
    if(expansionMap !== false) {
      expansionMap = strictExpansionMap;
    }

    if(typeof document === 'string') {
      // fetch document
      document = await documentLoader(document);
    }

    // preprocess document to prepare to remove existing proofs
    // let input;
    // shallow copy document to allow removal of existing proofs
    const input = {...document};

    delete input.proof;

    // create the new proof (suites MUST output a proof using the security-v2
    // `@context`)
    const proof = await suite.createProof({
      document: input, purpose, documentLoader, expansionMap
    });

    jsonld.addValue(document, 'proof', proof);

    return document;
  }

  /**
   * Verifies Linked Data proof(s) on a document. The proofs to be verified
   * must match the given proof purpose.
   *
   * Important note: This method assumes that the term `proof` in the given
   * document has the same definition as the `https://w3id.org/security/v2`
   * JSON-LD @context.
   *
   * @param {object|string} document - Object with one or more proofs to be
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
   * @param {function} [documentLoader]  a custom document loader,
   *   `Promise<RemoteDocument> documentLoader(url)`.
   * @param {function} [expansionMap] - A custom expansion map that is
   *   passed to the JSON-LD processor; by default a function that will throw
   *   an error when unmapped properties are detected in the input, use `false`
   *   to turn this off and allow unmapped properties to be dropped or use a
   *   custom function.
   *
   * @return {Promise<{verified: boolean, results: Array, error: *}>} resolves
   *   with an object with a `verified`boolean property that is `true` if at
   *   least one proof matching the given purpose and suite verifies and `false`
   *   otherwise; a `results` property with an array of detailed results;
   *   if `false` an `error` property will be present.
   */
  async verify(document, {suite, purpose, documentLoader, expansionMap} = {}) {
    if(!suite) {
      throw new TypeError('"options.suite" is required.');
    }
    if(!purpose) {
      throw new TypeError('"options.purpose" is required.');
    }
    const suites = Array.isArray(suite) ? suite : [suite];
    if(suites.length === 0) {
      throw new TypeError('At least one suite is required.');
    }

    if(documentLoader) {
      documentLoader = extendContextLoader(documentLoader);
    } else {
      documentLoader = strictDocumentLoader;
    }
    if(expansionMap !== false) {
      expansionMap = strictExpansionMap;
    }

    try {
      if(typeof document === 'string') {
        // fetch document
        document = await documentLoader(document);
      } else {
        // TODO: consider in-place editing to optimize when `compactProof`
        // is `false`

        // shallow copy to allow for removal of proof set prior to canonize
        document = {...document};
      }

      // get proofs from document
      const {proofSet, document: doc} = await _getProofs({
        document, documentLoader, expansionMap
      });
      document = doc;

      // verify proofs
      const results = await _verify({
        document, suites, proofSet, purpose, documentLoader, expansionMap
      });
      if(results.length === 0) {
        throw new Error(
          'Could not verify any proofs; no proofs matched the required ' +
          'suite and purpose.');
      }

      // combine results
      const verified = results.some(r => r.verified);
      if(!verified) {
        const errors = [].concat(
          ...results.filter(r => r.error).map(r => r.error));
        const result = {verified, results};
        if(errors.length > 0) {
          result.error = errors;
        }
        return result;
      }
      return {verified, results};
    } catch(error) {
      _addToJSON(error);
      return {verified: false, error};
    }
  }
};

async function _getProofs({document}) {
  // handle document preprocessing to find proofs
  let proofSet;
  proofSet = jsonld.getValues(document, 'proof');
  delete document.proof;

  if(proofSet.length === 0) {
    // no possible matches
    throw new Error('No matching proofs found in the given document.');
  }

  // shallow copy proofs and add document context or SECURITY_CONTEXT_URL
  const context = document['@context'] || constants.SECURITY_CONTEXT_URL;
  proofSet = proofSet.map(proof => ({
    '@context': context,
    ...proof
  }));

  return {proofSet, document};
}

async function _verify({
  document, suites, proofSet, purpose, documentLoader, expansionMap
}) {
  // filter out matching proofs
  const result = await Promise.all(proofSet.map(proof =>
    purpose.match(proof, {document, documentLoader, expansionMap})));
  const matches = proofSet.filter((value, index) => result[index]);
  if(matches.length === 0) {
    // no matches, nothing to verify
    return [];
  }

  // verify each matching proof
  return (await Promise.all(matches.map(async proof => {
    for(const s of suites) {
      if(await s.matchProof({proof, document, documentLoader, expansionMap})) {
        return s.verifyProof({
          proof, document, purpose, documentLoader, expansionMap
        }).catch(error => ({verified: false, error}));
      }
    }
  }))).map((r, i) => {
    if(!r) {
      return null;
    }
    if(r.error) {
      _addToJSON(r.error);
    }
    return {proof: matches[i], ...r};
  }).filter(r => r);
}

// add a `toJSON` method to an error which allows for errors in validation
// reports to be serialized properly by `JSON.stringify`.
function _addToJSON(error) {
  Object.defineProperty(error, 'toJSON', {
    value: function() {
      return serializeError(this);
    },
    configurable: true,
    writable: true
  });
}
