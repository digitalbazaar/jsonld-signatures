/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const constants = require('../constants');
const jsonld = require('jsonld');
const ProofPurpose = require('./ProofPurpose');

module.exports = class ControllerProofPurpose extends ProofPurpose {
  constructor({term, controller} = {}) {
    super({term});
    if(controller !== undefined) {
      if(typeof controller !== 'object') {
        throw new TypeError('"controller" must be an object.');
      }
      this.controller = controller;
    }
  }

  async validate(proof, {verificationMethod, documentLoader, expansionMap}) {
    try {
      const {id: verificationId} = verificationMethod;
      const result = {};

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
          }
          controllerId = controller;
        } else if(owner) {
          if(typeof owner === 'object') {
            controllerId = owner.id;
          } else if(typeof owner !== 'string') {
            throw new TypeError(
              '"owner" must be a string representing a URL.');
          }
          controllerId = owner;
        }

        const {'@graph': [framed = {}]} = await jsonld.frame(controllerId, {
          '@context': constants.SECURITY_CONTEXT_URL,
          id: controllerId,
          [this.term]: {
            '@embed': '@never',
            id: verificationId
          }
        }, {documentLoader, expansionMap, compactToRelative: false});
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
