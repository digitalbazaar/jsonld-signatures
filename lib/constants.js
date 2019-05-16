/*!
 * Copyright (c) 2017-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {constants: securityConstants} = require('security-context');

module.exports = {
  SECURITY_CONTEXT_URL: securityConstants.SECURITY_CONTEXT_V2_URL,
  SECURITY_CONTEXT_V1_URL: securityConstants.SECURITY_CONTEXT_V1_URL,
  SECURITY_CONTEXT_V2_URL: securityConstants.SECURITY_CONTEXT_V2_URL,
  SECURITY_PROOF_URL: 'https://w3id.org/security#proof',
  SECURITY_SIGNATURE_URL: 'https://w3id.org/security#signature'
};
