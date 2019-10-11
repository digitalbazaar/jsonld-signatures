/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const constants = require('../../lib/constants');
const {Ed25519KeyPair} = require('crypto-ld');
const {NOOP_PROOF_PURPOSE_URI} = require('./noop-purpose');
const {nonSecurityContextTestDoc, securityContextTestDoc} =
  require('./test-document');
const {controllers, publicKeys, privateKeys} = require('./keys');

const mock = {};
module.exports = mock;

mock.nonSecurityContextSigned = {
  ...nonSecurityContextTestDoc,
  'https://w3id.org/security#proof': {
    '@graph': {
      '@type': 'https://w3id.org/security#Ed25519Signature2018',
      'http://purl.org/dc/terms/created': {
        '@type': 'http://www.w3.org/2001/XMLSchema#dateTime',
        '@value': '2018-02-13T21:26:08Z'
      },
      'http://purl.org/dc/terms/creator': {
        '@id': publicKeys.carol.id
      },
      'https://w3id.org/security#jws':
        'eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19' +
        '..' +
        'UNcNI6x6KDA_hHux2RLM8_i9aoZY34GwcZevOjkSh22WoNB4FcP6dNgf2nKzX' +
        'XJIr-IqUnEwMYeD36fc8jv1AA',
      'https://w3id.org/security#proofPurpose': {
        '@id': NOOP_PROOF_PURPOSE_URI
      }
    }
  }
};

mock.securityContextSigned = {
  ...securityContextTestDoc,
  proof: {
    type: 'Ed25519Signature2018',
    created: '2018-02-13T21:26:08Z',
    creator: publicKeys.carol.id,
    jws:
      'eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19' +
      '..' +
      'UNcNI6x6KDA_hHux2RLM8_i9aoZY34GwcZevOjkSh22WoNB4FcP6dNgf2nKzX' +
      'XJIr-IqUnEwMYeD36fc8jv1AA',
    proofPurpose: NOOP_PROOF_PURPOSE_URI
  }
};

mock.securityContextInvalidSignature = {
  ...securityContextTestDoc,
  proof: {
    type: 'Ed25519Signature2018',
    created: '2018-02-13T21:26:08Z',
    creator: publicKeys.carol.id,
    jws:
      'eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19' +
      '..' +
      'ANcNI6x6KDA_hHux2RLM8_i9aoZY34GwcZevOjkSh22WoNB4FcP6dNgf2nKzX' +
      'XJIr-IqUnEwMYeD36fc8jv1AA',
    proofPurpose: NOOP_PROOF_PURPOSE_URI
  }
};

mock.parameters = {};

mock.parameters.sign = {
  creator: publicKeys.carol.id,
  date: '2018-02-13T21:26:08Z',
  key: new Ed25519KeyPair({
    privateKeyBase58: privateKeys.carol.privateKeyBase58,
    ...publicKeys.carol
  })
};

mock.parameters.verify = {
  creator: publicKeys.carol.id,
  date: '2018-02-13T21:26:08Z'
};

mock.parameters.verifyWithPassedKey = mock.parameters.sign;

mock.parameters.authenticationController = {
  '@context': constants.SECURITY_CONTEXT_URL,
  id: controllers.carol.id,
  authentication: publicKeys.carol.id
};

mock.parameters.assertionController = {
  '@context': constants.SECURITY_CONTEXT_URL,
  id: controllers.carol.id,
  assertionMethod: publicKeys.carol.id
};
