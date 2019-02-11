/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {nonSecurityContextTestDoc, securityContextTestDoc} =
  require('./test-document');
const {publicKeys, privateKeys} = require('./keys');

const mock = {};
module.exports = mock;

mock.nonSecurityContextSigned = {
  ...nonSecurityContextTestDoc,
  'https://w3id.org/security#signature': {
    '@type': 'https://w3id.org/security#EcdsaKoblitzSignature2016',
    'http://purl.org/dc/terms/created': {
      '@type': 'http://www.w3.org/2001/XMLSchema#dateTime',
      '@value': '2017-03-25T22:01:04Z'
    },
    'http://purl.org/dc/terms/creator': {
      '@id': publicKeys.aliceBtc.id
    },
    'https://w3id.org/security#signatureValue':
      'IOoF0rMmpcdxNZFoirTpRMCyLr8kGHLqXFl7v+m3naetCx+OLNhVY/6SCUwDGZf' +
      'Fs4yPXeAl6Tj1WgtLIHOVZmw='
  }
};

mock.securityContextSigned = {
  ...securityContextTestDoc,
  'signature': {
    'type': 'EcdsaKoblitzSignature2016',
    'created': '2017-03-25T22:01:04Z',
    'creator': publicKeys.aliceBtc.id,
    'signatureValue':
      'IOoF0rMmpcdxNZFoirTpRMCyLr8kGHLqXFl7v+m3naetCx+OLNhVY/6SCUwDGZf' +
      'Fs4yPXeAl6Tj1WgtLIHOVZmw='
  }
};

mock.securityContextInvalidSignature = {
  ...securityContextTestDoc,
  'signature': {
    'type': 'EcdsaKoblitzSignature2016',
    'created': '2017-03-25T22:01:04Z',
    'creator': publicKeys.aliceBtc.id,
    'signatureValue':
      'IOoF0rMmpcdxNZFoirTpRMCyLr8kGHLqXFl7v+m3naetCx+OLNhVY/6SCUwDGZf' +
      'Fs4yPXeAl6Tj1WgtLIHOVZma='
  }
};

mock.parameters = {};

mock.parameters.sign = {
  creator: publicKeys.aliceBtc.id,
  date: '2017-03-25T22:01:04Z',
  privateKeyWif: privateKeys.aliceBtc.privateKeyWif,
  publicKeyWif: privateKeys.aliceBtc.publicKeyWif
};

mock.parameters.verify = {
  creator: publicKeys.aliceBtc.id,
  date: '2017-03-25T22:01:04Z'
};

mock.parameters.verifyWithPassedKey = mock.parameters.sign;
