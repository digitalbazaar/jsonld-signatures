/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const constants = require('../constants');
const jsonld = require('jsonld');
const ProofPurpose = require('./ProofPurpose');

// DID documents can be specially optimized
const DID_CONTEXT_V1 = 'https://www.w3.org/ns/did/v1';
// verification relationship terms that are known to appear in DID documents
const DID_VR_TERMS = [
  'assertionMethod',
  'authentication',
  'capabilityInvocation',
  'capabilityDelegation',
  'keyAgreement',
  'verificationMethod'
];

module.exports = class ControllerProofPurpose extends ProofPurpose {
  /**
   * Creates a proof purpose that will validate whether or not the verification
   * method in a proof was authorized by its declared controller for the
   * proof's purpose.
   *
   * @param term {string} the `proofPurpose` term, as defined in the
   *    SECURITY_CONTEXT_URL `@context` or a URI if not defined in such.
   * @param [controller] {object} the description of the controller, if it
   *   is not to be dereferenced via a `documentLoader`.
   * @param [date] {string or Date or integer} the expected date for
   *   the creation of the proof.
   * @param [maxTimestampDelta] {integer} a maximum number of seconds that
   *   the date on the signature can deviate from, defaults to `Infinity`.
   */
  constructor({term, controller, date, maxTimestampDelta = Infinity} = {}) {
    super({term, date, maxTimestampDelta});
    if(controller !== undefined) {
      if(typeof controller !== 'object') {
        throw new TypeError('"controller" must be an object.');
      }
      this.controller = controller;
    }
    this._termDefinedByDIDContext = DID_VR_TERMS.includes(term);
  }

  /**
   * Validates the purpose of a proof. This method is called during
   * proof verification, after the proof value has been checked against the
   * given verification method (e.g. in the case of a digital signature, the
   * signature has been cryptographically verified against the public key).
   *
   * @param proof
   * @param verificationMethod
   * @param documentLoader
   * @param expansionMap
   *
   * @throws {Error} If verification method not authorized by controller
   * @throws {Error} If proof's created timestamp is out of range
   *
   * @returns {Promise<{valid: boolean, error: Error}>}
   */
  async validate(proof, {verificationMethod, documentLoader, expansionMap}) {
    try {
      const result = await super.validate(
        proof, {verificationMethod, documentLoader, expansionMap});
      if(!result.valid) {
        throw result.error;
      }

      const {id: verificationId} = verificationMethod;
      const {term, _termDefinedByDIDContext} = this;

      // if no `controller` specified, use verification method's
      if(this.controller) {
        result.controller = this.controller;
      } else {
        const {controller} = verificationMethod;
        let controllerId;
        if(controller) {
          if(typeof controller === 'object') {
            controllerId = controller.id;
          } else if(typeof controller !== 'string') {
            throw new TypeError(
              '"controller" must be a string representing a URL.');
          } else {
            controllerId = controller;
          }
        }

        // apply optimization to controller documents that are DID documents;
        // if `term` is one of those defined by the DID context
        let {document} = await documentLoader(controllerId);
        const mustFrame = !(_termDefinedByDIDContext &&
          document['@context'] === DID_CONTEXT_V1 ||
          (Array.isArray(document['@context']) &&
          document['@context'][0] === DID_CONTEXT_V1));
        if(mustFrame) {
          // Note: `expansionMap` is intentionally not passed; we can safely
          // drop properties here and must allow for it
          document = await jsonld.frame(document, {
            '@context': constants.SECURITY_CONTEXT_URL,
            id: controllerId,
            // this term must be in the JSON-LD controller document or
            // verification will fail
            [term]: {
              '@embed': '@never',
              id: verificationId
            }
          }, {documentLoader, compactToRelative: false});
        }
        result.controller = document;
      }

      const verificationMethods = jsonld.getValues(result.controller, term);
      result.valid = verificationMethods.some(vm =>
        vm === verificationId ||
        (typeof vm === 'object' && vm.id === verificationId));
      if(!result.valid) {
        throw new Error(
          `Verification method "${verificationMethod.id}" not authorized ` +
          `by controller for proof purpose "${this.term}".`);
      }
      return result;
    } catch(error) {
      return {valid: false, error};
    }
  }
};
