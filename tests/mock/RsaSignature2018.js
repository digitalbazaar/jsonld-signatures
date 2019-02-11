/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const constants = require('../../lib/constants');
const {NOOP_PROOF_PURPOSE_URI} = require('./noop-purpose');
const {nonSecurityContextTestDoc, securityContextTestDoc} =
  require('./test-document');
const {controllers, publicKeys, privateKeys} = require('./keys');
const {RSAKeyPair} = require('crypto-ld');

const mock = {};
module.exports = mock;

mock.nonSecurityContextSigned = {
  ...nonSecurityContextTestDoc,
  'https://w3id.org/security#proof': {
    '@graph': {
      '@type': 'https://w3id.org/security#RsaSignature2018',
      'http://purl.org/dc/terms/created': {
        '@type': 'http://www.w3.org/2001/XMLSchema#dateTime',
        '@value': '2018-02-22T15:16:04Z'
      },
      'http://purl.org/dc/terms/creator': {
        '@id': publicKeys.alice.id
      },
      'https://w3id.org/security#jws':
        'eyJhbGciOiJQUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19' +
        '..' +
        'dJBMvvFAIC00nSGB6Tn0XKbbF9XrsaJZREWvR2aONYTQQxnyXirtXnlewJMB' +
        'Bn2h9hfcGZrvnC1b6PgWmukzFJ1IiH1dWgnDIS81BH-IxXnPkbuYDeySorc4' +
        'QU9MJxdVkY5EL4HYbcIfwKj6X4LBQ2_ZHZIu1jdqLcRZqHcsDF5KKylKc1TH' +
        'n5VRWy5WhYg_gBnyWny8E6Qkrze53MR7OuAmmNJ1m1nN8SxDrG6a08L78J0-' +
        'Fbas5OjAQz3c17GY8mVuDPOBIOVjMEghBlgl3nOi1ysxbRGhHLEK4s0KKbeR' +
        'ogZdgt1DkQxDFxxn41QWDw_mmMCjs9qxg0zcZzqEJw',
      'https://w3id.org/security#proofPurpose': {
        '@id': NOOP_PROOF_PURPOSE_URI
      }
    }
  }
};

mock.securityContextSigned = {
  ...securityContextTestDoc,
  'proof': {
    'type': 'RsaSignature2018',
    'created': '2018-02-22T15:16:04Z',
    'creator': publicKeys.alice.id,
    'jws':
      'eyJhbGciOiJQUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19' +
      '..' +
      'dJBMvvFAIC00nSGB6Tn0XKbbF9XrsaJZREWvR2aONYTQQxnyXirtXnlewJMB' +
      'Bn2h9hfcGZrvnC1b6PgWmukzFJ1IiH1dWgnDIS81BH-IxXnPkbuYDeySorc4' +
      'QU9MJxdVkY5EL4HYbcIfwKj6X4LBQ2_ZHZIu1jdqLcRZqHcsDF5KKylKc1TH' +
      'n5VRWy5WhYg_gBnyWny8E6Qkrze53MR7OuAmmNJ1m1nN8SxDrG6a08L78J0-' +
      'Fbas5OjAQz3c17GY8mVuDPOBIOVjMEghBlgl3nOi1ysxbRGhHLEK4s0KKbeR' +
      'ogZdgt1DkQxDFxxn41QWDw_mmMCjs9qxg0zcZzqEJw',
    'proofPurpose': NOOP_PROOF_PURPOSE_URI
  }
};

mock.securityContextInvalidSignature = {
  ...securityContextTestDoc,
  'proof': {
    'type': 'RsaSignature2018',
    'created': '2018-02-22T15:16:04Z',
    'creator': publicKeys.alice.id,
    'jws':
      'eyJhbGciOiJQUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19' +
      '..' +
      'DJBMvvFAIC00nSGB6Tn0XKbbF9XrsaJZREWvR2aONYTQQxnyXirtXnlewJMB' +
      'Bn2h9hfcGZrvnC1b6PgWmukzFJ1IiH1dWgnDIS81BH-IxXnPkbuYDeySorc4' +
      'QU9MJxdVkY5EL4HYbcIfwKj6X4LBQ2_ZHZIu1jdqLcRZqHcsDF5KKylKc1TH' +
      'n5VRWy5WhYg_gBnyWny8E6Qkrze53MR7OuAmmNJ1m1nN8SxDrG6a08L78J0-' +
      'Fbas5OjAQz3c17GY8mVuDPOBIOVjMEghBlgl3nOi1ysxbRGhHLEK4s0KKbeR' +
      'ogZdgt1DkQxDFxxn41QWDw_mmMCjs9qxg0zcZzqEJw',
    'proofPurpose': NOOP_PROOF_PURPOSE_URI
  }
};

mock.parameters = {};

mock.parameters.sign = {
  creator: publicKeys.alice.id,
  date: '2018-02-22T15:16:04Z',
  key: new RSAKeyPair({
    privateKeyPem: privateKeys.alice.privateKeyPem,
    ...publicKeys.alice
  })
};

mock.parameters.verify = {
  creator: publicKeys.alice.id,
  date: '2018-02-22T15:16:04Z'
};

mock.parameters.verifyWithPassedKey = mock.parameters.sign;

mock.parameters.authenticationController = {
  '@context': constants.SECURITY_CONTEXT_URL,
  id: controllers.alice.id,
  authentication: publicKeys.alice.id
};

mock.parameters.assertionController = {
  '@context': constants.SECURITY_CONTEXT_URL,
  id: controllers.alice.id,
  assertionMethod: publicKeys.alice.id
};
