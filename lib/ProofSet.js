/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const constants = require('./constants');
const jsonld = require('jsonld');
const {extendContextLoader, strictDocumentLoader} = require('./documentLoader');
const {serializeError} = require('serialize-error');

module.exports = class ProofSet {
  /**
   * Adds a Linked Data proof to a document. If the document contains other
   * proofs, the new proof will be appended to the existing set of proofs.
   *
   * Important note: This method assumes that the term `proof` in the given
   * document has the same definition as the `https://w3id.org/security/v2`
   * JSON-LD @context.
   *
   * @param document {object} - JSON-LD Document to be signed.
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
   *
   * @return {Promise<object>} resolves with the signed document, with
   *   the signature in the top-level `proof` property.
   */
  async add(document, {suite, purpose, documentLoader} = {}) {
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

    // shallow copy document to allow removal of existing proofs
    const input = {...document};
    delete input.proof;

    // get existing proof set, if any
    const proofSet = _getProofs({document});

    // create the new proof
    const proof = await suite.createProof({
      document: input, purpose, proofSet, documentLoader
    });

    jsonld.addValue(document, 'proof', proof);

    return document;
  }

  /**
   * Derives a new Linked Data document with a new `proof` from an existing
   * document with an existing proof set.
   *
   * Important note: This method assumes that the term `proof` in the given
   * document has the same definition as the `https://w3id.org/security/v2`
   * JSON-LD @context.
   *
   * @param document {object} - JSON-LD Document from which to derive a proof.
   * @param options {object} Options hashmap.
   *
   * A `suite` option is required:
   *
   * @param options.suite {LinkedDataSignature} a signature suite instance
   *   that will derive the new document and new `proof`.
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
   *
   * @return {Promise<object>} resolves with the new document, with a new
   *   top-level `proof` property.
   */
  async derive(document, {suite, purpose, documentLoader} = {}) {
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

    // shallow copy document to allow removal of existing proofs
    const input = {...document};
    delete input.proof;

    // get existing proof set, if any
    const proofSet = _getProofs({document});

    // create the new document and proof
    const newDocument = await suite.derive({
      document: input, purpose, proofSet, documentLoader
    });

    return newDocument;
  }

  /**
   * Verifies Linked Data proof(s) on a document. The proofs to be verified
   * must match the given proof purpose.
   *
   * Important note: This method assumes that the term `proof` in the given
   * document has the same definition as the `https://w3id.org/security/v2`
   * JSON-LD @context.
   *
   * @param {object} document - The JSON-LD document with one or more proofs to
   *   be verified.
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
   *
   * @return {Promise<{verified: boolean, results: Array, error: *}>} resolves
   *   with an object with a `verified`boolean property that is `true` if at
   *   least one proof matching the given purpose and suite verifies and `false`
   *   otherwise; a `results` property with an array of detailed results;
   *   if `false` an `error` property will be present.
   */
  async verify(document, {suite, purpose, documentLoader} = {}) {
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

    try {
      // shallow copy to allow for removal of proof set prior to canonize
      document = {...document};

      // get proofs from document
      const proofSet = _getProofs({document});
      if(proofSet.length === 0) {
        // no possible matches
        throw new Error('No matching proofs found in the given document.');
      }
      // clear proofs from shallow copy
      delete document.proof;

      // verify proofs
      const results = await _verify(
        {document, suites, proofSet, purpose, documentLoader});
      if(results.length === 0) {
        const error = new Error(
          'Did not verify any proofs; insufficient proofs matched the ' +
          'acceptable suite(s) and required purpose(s).');
        error.name = 'NotFoundError';
        throw error;
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
      _makeSerializable(error);
      return {verified: false, error};
    }
  }
};

function _getProofs({document}) {
  // handle document preprocessing to find proofs
  let proofSet;
  proofSet = jsonld.getValues(document, 'proof');

  // shallow copy proofs and add document context or SECURITY_CONTEXT_URL
  const context = document['@context'] || constants.SECURITY_CONTEXT_URL;
  proofSet = proofSet.map(proof => {
    const {cryptosuite} = proof;
    // JCS Data Integrity Suites require unmodified proofs
    if(cryptosuite?.includes?.('-jcs-')) {
      return proof;
    }
    return {'@context': context, ...proof};
  });

  return proofSet;
}

async function _verify({
  document, suites, proofSet, purpose, documentLoader
}) {
  // map each purpose to at least one proof to verify
  const purposes = Array.isArray(purpose) ? purpose : [purpose];
  const purposeToProofs = new Map();
  const proofToSuite = new Map();
  const suiteMatchQueue = new Map();
  await Promise.all(purposes.map(purpose => _matchProofSet({
    purposeToProofs, proofToSuite, purpose, proofSet, suites,
    suiteMatchQueue, document, documentLoader
  })));

  // every purpose must have at least one matching proof or verify will fail
  if(purposeToProofs.size < purposes.length) {
    // insufficient proofs to verify, so don't bother verifying any
    return [];
  }

  // verify every proof in `proofToSuite`; these proofs matched a purpose
  const verifyResults = new Map();
  await Promise.all([...proofToSuite.entries()].map(async ([proof, suite]) => {
    let result;
    try {
      // create backwards-compatible deferred proof purpose to capture
      // verification method from old-style suites
      let vm;
      const purpose = {
        async validate(proof, {verificationMethod}) {
          vm = verificationMethod;
          return {valid: true};
        }
      };
      const {verified, verificationMethod, error} = await suite.verifyProof(
        {proof, document, purpose, proofSet, documentLoader});
      if(!vm) {
        vm = verificationMethod;
      }
      result = {proof, verified, verificationMethod: vm, error};
    } catch(error) {
      result = {proof, verified: false, error};
    }

    if(result.error) {
      // ensure error is serializable
      _makeSerializable(result.error);
    }

    verifyResults.set(proof, result);
  }));

  // validate proof against each purpose that matched it
  await Promise.all([...purposeToProofs.entries()].map(
    async ([purpose, proofs]) => {
      for(const proof of proofs) {
        const result = verifyResults.get(proof);
        if(!result.verified) {
          // if proof was not verified, so not bother validating purpose
          continue;
        }

        // validate purpose
        const {verificationMethod} = result;
        const suite = proofToSuite.get(proof);
        let purposeResult;
        try {
          purposeResult = await purpose.validate(proof, {
            document, suite, verificationMethod, documentLoader
          });
        } catch(error) {
          purposeResult = {valid: false, error};
        }

        // add `purposeResult` to verification result regardless of validity
        // to ensure that all purposes are represented
        if(result.purposeResult) {
          if(Array.isArray(result.purposeResult)) {
            result.purposeResult.push(purposeResult);
          } else {
            result.purposeResult = [result.purposeResult, purposeResult];
          }
        } else {
          result.purposeResult = purposeResult;
        }

        if(!purposeResult.valid) {
          // ensure error is serializable
          _makeSerializable(purposeResult.error);

          // if no top level error set yet, set it
          if(!result.error) {
            result.verified = false;
            result.error = purposeResult.error;
          }
        }
      }
    }));

  return [...verifyResults.values()];
}

// add a `toJSON` method to an error which allows for errors in validation
// reports to be serialized properly by `JSON.stringify`.
function _makeSerializable(error) {
  Object.defineProperty(error, 'toJSON', {
    value: function() {
      return serializeError(this);
    },
    configurable: true,
    writable: true
  });
}

async function _matchProofSet({
  purposeToProofs, proofToSuite, purpose, proofSet, suites,
  suiteMatchQueue, document, documentLoader
}) {
  for(const proof of proofSet) {
    // first check if the proof matches the purpose; if it doesn't continue
    if(!await purpose.match(proof, {document, documentLoader})) {
      continue;
    }

    // next, find the suite that can verify the proof; if found, `matched`
    // will be set to `true` and the proof will be added to `purposeToProofs`
    // and `proofToSuite` to be processed -- otherwise it will not be; if
    // no proofs are added for a given purpose, an exception will be thrown
    let matched = false;
    for(const s of suites) {
      // `matchingProofs` is a map of promises that resolve to whether a
      // proof matches a suite; multiple purposes and suites may be checked
      // in parallel so a promise queue is used to prevent duplicate work
      let matchingProofs = suiteMatchQueue.get(s);
      if(!matchingProofs) {
        suiteMatchQueue.set(s, matchingProofs = new Map());
      }
      let promise = matchingProofs.get(proof);
      if(!promise) {
        promise = s.matchProof({proof, document, documentLoader});
        matchingProofs.set(proof, promise);
      }
      if(await promise) {
        // found the matching suite for the proof; there should only be one
        // suite that can verify a particular proof; add the proof to the
        // map of proofs to be verified along with the matching suite
        matched = true;
        proofToSuite.set(proof, s);
        break;
      }
    }

    if(matched) {
      // note proof was a match for the purpose and an acceptable suite; it
      // will need to be verified by the suite and then validated against the
      // purpose
      const matches = purposeToProofs.get(purpose);
      if(matches) {
        matches.push(proof);
      } else {
        purposeToProofs.set(purpose, [proof]);
      }
    }
  }
}
