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
  "signature": {
    "@type": "https://w3id.org/security#LinkedDataSignature2015",
    "http://purl.org/dc/terms/created": {
      "@type": "http://www.w3.org/2001/XMLSchema#dateTime",
      "@value": "2018-02-22T15:16:04Z"
    },
    "http://purl.org/dc/terms/creator": {
      "@id": "https://example.com/i/alice/keys/1"
    },
    "https://w3id.org/security#signatureValue":
      "Ah67DfRQVUMpwjnlEo+q3q+LAjA9wN74qDHmhTM28+tW+sRO3qQkp4ipqy+NUt" +
      "zakDnagmAIULfqoBENkk32HPM66N7xDwzcx3JPAmaHk4TNSAb98ozLohQvbN8h" +
      "Wc3S7TvBVK8ylhKa59ys6YT4DXzQw71LlYxfUjasnp4hTf4="
  }
};

mock.securityContextSigned = {
  ...securityContextTestDoc,
  "signature": {
    "type": "LinkedDataSignature2015",
    "created": "2018-02-22T15:16:04Z",
    "creator": "https://example.com/i/alice/keys/1",
    "signatureValue":
      "Ah67DfRQVUMpwjnlEo+q3q+LAjA9wN74qDHmhTM28+tW+sRO3qQkp4ipqy+NUt" +
      "zakDnagmAIULfqoBENkk32HPM66N7xDwzcx3JPAmaHk4TNSAb98ozLohQvbN8h" +
      "Wc3S7TvBVK8ylhKa59ys6YT4DXzQw71LlYxfUjasnp4hTf4="
  }
};

mock.securityContextInvalidSignature = {
  ...securityContextTestDoc,
  "signature": {
    "type": "LinkedDataSignature2015",
    "created": "2018-02-22T15:16:04Z",
    "creator": "https://example.com/i/alice/keys/1",
    "signatureValue":
      "Bh67DfRQVUMpwjnlEo+q3q+LAjA9wN74qDHmhTM28+tW+sRO3qQkp4ipqy+NUt" +
      "zakDnagmAIULfqoBENkk32HPM66N7xDwzcx3JPAmaHk4TNSAb98ozLohQvbN8h" +
      "Wc3S7TvBVK8ylhKa59ys6YT4DXzQw71LlYxfUjasnp4hTf4="
  }
};

mock.parameters = {};

mock.parameters.sign = {
  creator: publicKeys.alice.id,
  date: '2018-02-22T15:16:04Z',
  privateKeyPem: privateKeys.alice.privateKeyPem,
  publicKeyPem: privateKeys.alice.publicKeyPem
};

mock.parameters.verify = {
  creator: publicKeys.alice.id,
  date: '2018-02-22T15:16:04Z'
};

mock.parameters.verifyWithPassedKey = mock.parameters.sign;
