/*
 * Copyright (c) 2017-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const constants = require('./constants');
const {contexts: securityContexts} = require('security-context');

module.exports = {
  [constants.SECURITY_CONTEXT_V1_URL]:
    securityContexts.get(constants.SECURITY_CONTEXT_V1_URL),
  [constants.SECURITY_CONTEXT_V2_URL]:
    securityContexts.get(constants.SECURITY_CONTEXT_V2_URL)
};
