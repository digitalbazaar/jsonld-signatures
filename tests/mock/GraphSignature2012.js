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
    "@type": "https://w3id.org/security#GraphSignature2012",
    "http://purl.org/dc/terms/created": {
      "@type": "http://www.w3.org/2001/XMLSchema#dateTime",
      "@value": "2018-02-22T15:16:04Z"
    },
    "http://purl.org/dc/terms/creator": {
      "@id": "https://example.com/i/alice/keys/1"
    },
    "https://w3id.org/security#signatureValue":
      "BQC/V/0kPugo3fYJlDtu1DdeJwJvjfrdLOwC8cCA6HlXA/DTnfJrOyrki/ors" +
      "Cxiy3/oPr1y7oTRn6ZD7uuvT9cAB5zWiSqHxVrTL7gPff4FaJK+lvhsFKdlEj" +
      "0IoFG7Sr2DD6Y5bW01fqcHeeRoPZpUl3nl0oo3Rk8/UAlBE88="
  }
};

mock.securityContextSigned = {
  ...securityContextTestDoc,
  "signature": {
    "type": "GraphSignature2012",
    "created": "2018-02-22T15:16:04Z",
    "creator": "https://example.com/i/alice/keys/1",
    "signatureValue":
      "BQC/V/0kPugo3fYJlDtu1DdeJwJvjfrdLOwC8cCA6HlXA/DTnfJrOyrki/ors" +
      "Cxiy3/oPr1y7oTRn6ZD7uuvT9cAB5zWiSqHxVrTL7gPff4FaJK+lvhsFKdlEj" +
      "0IoFG7Sr2DD6Y5bW01fqcHeeRoPZpUl3nl0oo3Rk8/UAlBE88="
  }
};

mock.securityContextInvalidSignature = {
  ...securityContextTestDoc,
  "signature": {
    "type": "GraphSignature2012",
    "created": "2018-02-22T15:16:04Z",
    "creator": "https://example.com/i/alice/keys/1",
    "signatureValue":
      "CQC/V/0kPugo3fYJlDtu1DdeJwJvjfrdLOwC8cCA6HlXA/DTnfJrOyrki/ors" +
      "Cxiy3/oPr1y7oTRn6ZD7uuvT9cAB5zWiSqHxVrTL7gPff4FaJK+lvhsFKdlEj" +
      "0IoFG7Sr2DD6Y5bW01fqcHeeRoPZpUl3nl0oo3Rk8/UAlBE88="
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
