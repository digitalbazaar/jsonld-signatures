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
  LinkedDataSignature: require('./suites/LinkedDataSignature'),
  LinkedDataSignature2015: require('./suites/LinkedDataSignature2015'),
  GraphSignature2012: require('./suites/GraphSignature2012'),
  RsaSignature2018: require('./suites/RsaSignature2018')
};

/**
 * @param algorithm {string}
 * @param injector {Injector}
 * @throws {Error} On unsupported algorithm
 * @returns {Suite} Suite instance for given algorithm
 */
api.getSuite = ({algorithm, injector}) => {
  // no default algorithm; it must be specified
  if(!algorithm) {
    throw new TypeError('"options.algorithm" must be specified.');
  }

  const SUPPORTED_ALGORITHMS = api.getSupportedAlgorithms();

  if(SUPPORTED_ALGORITHMS.indexOf(algorithm) === -1) {
    throw new Error(
      'Unsupported algorithm "' + algorithm + '"; ' +
      '"options.algorithm" must be one of: ' +
      JSON.stringify(SUPPORTED_ALGORITHMS));
  }

  const Suite = api.suites[algorithm];
  return new Suite(injector);
};

api.getSupportedAlgorithms = () => {
  // every suite is supported except the base class
  return Object.keys(api.suites).filter(s => s !== 'LinkedDataSignature');
};
