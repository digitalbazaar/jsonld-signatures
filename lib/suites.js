/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const api = {};
module.exports = api;

// TODO: only require dynamically as needed or according to build
api.suites = {
  EcdsaKoblitzSignature2016: require('./suites/EcdsaKoblitzSignature2016'),
  Ed25519Signature2018: require('./suites/Ed25519Signature2018'),
  LinkedDataProof: require('./suites/LinkedDataProof'),
  LinkedDataSignature: require('./suites/LinkedDataSignature'),
  LinkedDataSignature2015: require('./suites/LinkedDataSignature2015'),
  GraphSignature2012: require('./suites/GraphSignature2012'),
  RsaSignature2018: require('./suites/RsaSignature2018')
};
