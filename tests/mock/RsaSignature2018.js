/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {NOOP_PROOF_PURPOSE_URI} = require('./noop-purpose');
const {nonSecurityContextTestDoc, securityContextTestDoc} =
  require('./test-document');
const {publicKeys, privateKeys} = require('./keys');
const {RSAKeyPair} = require('../../lib/suites/LDKeyPair');

const mock = {};
module.exports = mock;

mock.nonSecurityContextSigned = {
  ...nonSecurityContextTestDoc,
  "proof": {
    "@type": "https://w3id.org/security#RsaSignature2018",
    "http://purl.org/dc/terms/created": {
      "@type": "http://www.w3.org/2001/XMLSchema#dateTime",
      "@value": "2018-02-22T15:16:04Z"
    },
    "http://purl.org/dc/terms/creator": {
      "@id": publicKeys.alice.id
    },
    "https://w3id.org/security#jws":
      "eyJhbGciOiJQUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19" +
      ".." +
      "KbIsIghAzxk5cs2uBYGO60RgV342Fppcz5AYy9u-BgbEbRwBlh0sB3wCvbKL" +
      "eUlMyccltvqLUvhJTiW0mrM9TC-JAk4-Cr0zIQ9zrZ2g3SAHEe5hxT5dpCEg" +
      "PB8uIZZV3XqxDgJRWgd1BvrA3hqHMqqh3CTh85KNa8wZqlTnjkM",
    "https://w3id.org/security#proofPurpose": {
      "@id": NOOP_PROOF_PURPOSE_URI
    }
  }
};

mock.securityContextSigned = {
  ...securityContextTestDoc,
  "proof": {
    "type": "RsaSignature2018",
    "created": "2018-02-22T15:16:04Z",
    "creator": publicKeys.alice.id,
    "jws":
      "eyJhbGciOiJQUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19" +
      ".." +
      "KbIsIghAzxk5cs2uBYGO60RgV342Fppcz5AYy9u-BgbEbRwBlh0sB3wCvbKL" +
      "eUlMyccltvqLUvhJTiW0mrM9TC-JAk4-Cr0zIQ9zrZ2g3SAHEe5hxT5dpCEg" +
      "PB8uIZZV3XqxDgJRWgd1BvrA3hqHMqqh3CTh85KNa8wZqlTnjkM",
    "proofPurpose": NOOP_PROOF_PURPOSE_URI
  }
};

mock.securityContextInvalidSignature = {
  ...securityContextTestDoc,
  "proof": {
    "type": "RsaSignature2018",
    "created": "2018-02-22T15:16:04Z",
    "creator": publicKeys.alice.id,
    "jws":
      "eyJhbGciOiJQUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19" +
      ".." +
      "AbIsIghAzxk5cs2uBYGO60RgV342Fppcz5AYy9u-BgbEbRwBlh0sB3wCvbKL" +
      "eUlMyccltvqLUvhJTiW0mrM9TC-JAk4-Cr0zIQ9zrZ2g3SAHEe5hxT5dpCEg" +
      "PB8uIZZV3XqxDgJRWgd1BvrA3hqHMqqh3CTh85KNa8wZqlTnjkM",
    "proofPurpose": NOOP_PROOF_PURPOSE_URI
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
