/**
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const constants = require('../constants');
const jsonld = require('jsonld');
const ProofPurpose = require('./ProofPurpose');

module.exports = class ControllerProofPurpose extends ProofPurpose {
  constructor({term, controller, owner} = {}) {
    super({term});
    if(this.controller !== undefined) {
      if(typeof this.controller !== 'object') {
        throw new TypeError('"controller" must be an object.');
      }
      this.controller = controller;
    } else if(this.owner !== undefined) {
      if(typeof this.owner !== 'object') {
        throw new TypeError('"owner" must be an object.');
      }
      this.owner = owner;
    }
  }

  async validate(proof, {verificationMethod, documentLoader, expansionMap}) {
    try {
      const {id: verificationId} = verificationMethod;

      // if no `controller` or `owner` specified, use verification method's
      let authorizer;
      if(this.controller) {
        authorizer = this.controller;
      } else if(this.owner) {
        authorizer = this.owner;
      } else {
        const {controller, owner} = verificationMethod;
        let authorizerId;
        if(controller) {
          if(typeof controller === 'object') {
            authorizerId = controller.id;
          } else if(controller !== 'string') {
            throw new TypeError(
              '"controller" must be a string representing a URL.');
          }
          authorizerId = controller;
        } else if(owner) {
          if(typeof owner === 'object') {
            authorizerId = owner.id;
          } else if(owner !== 'string') {
            throw new TypeError(
              '"owner" must be a string representing a URL.');
          }
          authorizerId = owner;
        }

        const {'@graph': [framed]} = await jsonld.frame(authorizerId, {
          '@context': constants.SECURITY_CONTEXT_URL,
          id: authorizerId,
          [this.term]: {
            '@embed': '@never',
            id: verificationId
          }
        }, {documentLoader, expansionMap});
        authorizer = framed;
      }

      const verificationMethods = jsonld.getValues(authorizer, this.term);
      const valid = verificationMethods.some(vm =>
        vm === verificationId ||
        (typeof vm === 'object' && vm.id === verificationId));
      if(!valid) {
        throw new Error(
          `Verification method "${verificationMethod.id}" not authorized ` +
          `by controller for proof purpose "${this.term}".`);
      }
      return {valid};
    } catch(error) {
      return {valid: false, error};
    }
  }
};
