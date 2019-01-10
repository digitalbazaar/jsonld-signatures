/*
 * Copyright (c) 2017-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const constants = require('./constants');
const {v1: securityContextV1, v2: securityContextV2} =
  require('security-context');

module.exports = {
  [constants.SECURITY_CONTEXT_V1_URL]: securityContextV1,
  [constants.SECURITY_CONTEXT_V2_URL]: securityContextV2
};
