/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const constants = require('../constants');
const jsonld = require('jsonld');
const ProofPurpose = require('./ProofPurpose');

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
  }

  async validate(proof, {verificationMethod, documentLoader, expansionMap}) {
    try {
      const result = await super.validate(
        proof, {verificationMethod, documentLoader, expansionMap});
      if(!result.valid) {
        throw result.error;
      }

      const {id: verificationId} = verificationMethod;

      // if no `controller` specified, use verification method's
      if(this.controller) {
        result.controller = this.controller;
      } else {
        // support legacy `owner` property
        const {controller, owner} = verificationMethod;
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
        } else if(owner) {
          if(typeof owner === 'object') {
            controllerId = owner.id;
          } else if(typeof owner !== 'string') {
            throw new TypeError(
              '"owner" must be a string representing a URL.');
          } else {
            controllerId = owner;
          }
        }
        // Note: `expansionMap` is intentionally not passed; we can safely drop
        // properties here and must allow for it
        const {'@graph': [framed = {}]} = await jsonld.frame(controllerId, {
          '@context': constants.SECURITY_CONTEXT_URL,
          id: controllerId,
          // the term should be in the json-ld object the controllerId resolves
          // to.
          [this.term]: {
            '@embed': '@never',
            id: verificationId
          }
        }, {documentLoader, compactToRelative: false});
        result.controller = framed;
      }
      const verificationMethods = jsonld.getValues(
        result.controller, this.term);
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
