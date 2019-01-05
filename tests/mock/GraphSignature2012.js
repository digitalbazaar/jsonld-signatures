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
  "https://w3id.org/security#signature": {
    "@type": "https://w3id.org/security#GraphSignature2012",
    "http://purl.org/dc/terms/created": {
      "@type": "http://www.w3.org/2001/XMLSchema#dateTime",
      "@value": "2018-02-22T15:16:04Z"
    },
    "http://purl.org/dc/terms/creator": {
      "@id": "https://example.com/i/alice/keys/1"
    },
    "https://w3id.org/security#signatureValue":
      "JCsAA1dvXCNR7Ey3qLc4mLAy8JvdE0RSklNTWlIMqVZ8hrCpVSRoq86sJd4HS" +
      "eRFaor6YwwOiLZ4yQbNPvxkS4b85vlTrivz4OrLPi8XKT4ArUZUreHPEcaHmU" +
      "6rIVnt3ySwOwMqSjfjzRrpxkoZzQbBnqFbqojF1hul1XuTT6AvFiwXyHY3z2w" +
      "qAJeetILLzIZoSDnpSrUKEEyZ/erfS7t/BXuSbmGjRm9p/MYXLSHk6oWI7Ydb" +
      "i8xXhpb4sIOdnCK3EES6CTGVdwWE7gJUPZ8lcGHhLo4fqGrVhqbAuWXvfBow4" +
      "YWDjiXgvJsVbeDRV1WM+abFMpvBRuvAn8ej2A=="
  }
};

mock.securityContextSigned = {
  ...securityContextTestDoc,
  "signature": {
    "type": "GraphSignature2012",
    "created": "2018-02-22T15:16:04Z",
    "creator": "https://example.com/i/alice/keys/1",
    "signatureValue":
      "JCsAA1dvXCNR7Ey3qLc4mLAy8JvdE0RSklNTWlIMqVZ8hrCpVSRoq86sJd4HS" +
      "eRFaor6YwwOiLZ4yQbNPvxkS4b85vlTrivz4OrLPi8XKT4ArUZUreHPEcaHmU" +
      "6rIVnt3ySwOwMqSjfjzRrpxkoZzQbBnqFbqojF1hul1XuTT6AvFiwXyHY3z2w" +
      "qAJeetILLzIZoSDnpSrUKEEyZ/erfS7t/BXuSbmGjRm9p/MYXLSHk6oWI7Ydb" +
      "i8xXhpb4sIOdnCK3EES6CTGVdwWE7gJUPZ8lcGHhLo4fqGrVhqbAuWXvfBow4" +
      "YWDjiXgvJsVbeDRV1WM+abFMpvBRuvAn8ej2A=="
  }
};

mock.securityContextInvalidSignature = {
  ...securityContextTestDoc,
  "signature": {
    "type": "GraphSignature2012",
    "created": "2018-02-22T15:16:04Z",
    "creator": "https://example.com/i/alice/keys/1",
    "signatureValue":
      "jCsAA1dvXCNR7Ey3qLc4mLAy8JvdE0RSklNTWlIMqVZ8hrCpVSRoq86sJd4HS" +
      "eRFaor6YwwOiLZ4yQbNPvxkS4b85vlTrivz4OrLPi8XKT4ArUZUreHPEcaHmU" +
      "6rIVnt3ySwOwMqSjfjzRrpxkoZzQbBnqFbqojF1hul1XuTT6AvFiwXyHY3z2w" +
      "qAJeetILLzIZoSDnpSrUKEEyZ/erfS7t/BXuSbmGjRm9p/MYXLSHk6oWI7Ydb" +
      "i8xXhpb4sIOdnCK3EES6CTGVdwWE7gJUPZ8lcGHhLo4fqGrVhqbAuWXvfBow4" +
      "YWDjiXgvJsVbeDRV1WM+abFMpvBRuvAn8ej2A=="
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
  date: '2018-12-26T18:08:04Z'
};

mock.parameters.verifyWithPassedKey = mock.parameters.sign;
