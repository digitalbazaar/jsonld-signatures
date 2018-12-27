/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const api = {};
module.exports = api;

// TODO: only require dynamically as needed or according to build
api.purposes = {
  AuthenticationProofPurpose: require('./purposes/AuthenticationProofPurpose'),
  ControllerProofPurpose: require('./purposes/ControllerProofPurpose'),
  ProofPurpose: require('./purposes/ProofPurpose'),
  PublicKeyProofPurpose: require('./purposes/PublicKeyProofPurpose')
};
