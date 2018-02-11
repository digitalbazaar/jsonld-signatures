/*
 * Copyright (c) 2017-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const constants = require('./constants');

module.exports = {
  [constants.SECURITY_CONTEXT_V1_URL]: require('./contexts/security-v1'),
  [constants.SECURITY_CONTEXT_V2_URL]: require('./contexts/security-v2')
};
