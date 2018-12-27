/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const mock = {};
module.exports = mock;

({
  nonSecurityContextTestDoc: mock.nonSecurityContextTestDoc,
  securityContextTestDoc: mock.securityContextTestDoc
} = require('./test-document'));

({
  controllers: mock.controllers,
  publicKeys: mock.publicKeys,
  privateKeys: mock.privateKeys,
} = require('./keys'));

mock.testLoader = require('./test-loader');

({
  NOOP_PROOF_PURPOSE_URI: mock.NOOP_PROOF_PURPOSE_URI,
  NoOpProofPurpose: mock.NoOpProofPurpose
} = require('./noop-purpose'));

mock.suites = {
  EcdsaKoblitzSignature2016: require('./EcdsaKoblitzSignature2016'),
  Ed25519Signature2018: require('./Ed25519Signature2018'),
  GraphSignature2012: require('./GraphSignature2012'),
  LinkedDataSignature2015: require('./LinkedDataSignature2015'),
  RsaSignature2018: require('./RsaSignature2018')
};
