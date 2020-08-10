/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const api = {};
module.exports = api;

// TODO: only require dynamically as needed or according to build
api.suites = {
  LinkedDataProof: require('./suites/LinkedDataProof'),
  LinkedDataSignature: require('./suites/LinkedDataSignature')
};
