/*
 * Copyright (c) 2017-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const constants = require('./constants');
const {contexts: securityContexts} = require('@digitalbazaar/security-context');

module.exports = new Map([
  [constants.SECURITY_CONTEXT_V1_URL,
    securityContexts.get(constants.SECURITY_CONTEXT_V1_URL)],
  [constants.SECURITY_CONTEXT_V2_URL,
    securityContexts.get(constants.SECURITY_CONTEXT_V2_URL)]
]);
