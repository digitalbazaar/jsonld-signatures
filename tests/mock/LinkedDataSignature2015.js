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
    "@type": "https://w3id.org/security#LinkedDataSignature2015",
    "http://purl.org/dc/terms/created": {
      "@type": "http://www.w3.org/2001/XMLSchema#dateTime",
      "@value": "2018-02-22T15:16:04Z"
    },
    "http://purl.org/dc/terms/creator": {
      "@id": "https://example.com/i/alice/keys/1"
    },
    "https://w3id.org/security#signatureValue":
      "hztABpsP4e/emXsUYFUQ8HstjrgMfbMXbVcUhfYBHCCYuIgfsmTTOT4uaL5zwF" +
      "EpkSBNxskB46IAnqdkIYU2KF+7pDyBbIe7GMm60zIAavmIsAcxh034ENJreUgX" +
      "eIQhpx/ZPKcQCBPwDHrbxXiBxS/VmkvJLbtjfy0qj96f6Gc2AvaB43ZHwO88TV" +
      "lzxQFa8gnJt2embI41u4Gz7+jmx2yc/1lEH/iOmm1g3OTmnJu3OmvLGvygLogu" +
      "n17ueUbTA1Fam2H78V1UI/E90i/PY3Doy1VGDkdLsW8UJGTZOVSpmf0acqik91" +
      "pS1OuHcvyzN+HdRolszzdkrORzM8mxmg=="
  }
};

mock.securityContextSigned = {
  ...securityContextTestDoc,
  "signature": {
    "type": "LinkedDataSignature2015",
    "created": "2018-02-22T15:16:04Z",
    "creator": "https://example.com/i/alice/keys/1",
    "signatureValue":
      "hztABpsP4e/emXsUYFUQ8HstjrgMfbMXbVcUhfYBHCCYuIgfsmTTOT4uaL5zwF" +
      "EpkSBNxskB46IAnqdkIYU2KF+7pDyBbIe7GMm60zIAavmIsAcxh034ENJreUgX" +
      "eIQhpx/ZPKcQCBPwDHrbxXiBxS/VmkvJLbtjfy0qj96f6Gc2AvaB43ZHwO88TV" +
      "lzxQFa8gnJt2embI41u4Gz7+jmx2yc/1lEH/iOmm1g3OTmnJu3OmvLGvygLogu" +
      "n17ueUbTA1Fam2H78V1UI/E90i/PY3Doy1VGDkdLsW8UJGTZOVSpmf0acqik91" +
      "pS1OuHcvyzN+HdRolszzdkrORzM8mxmg=="
  }
};

mock.securityContextInvalidSignature = {
  ...securityContextTestDoc,
  "signature": {
    "type": "LinkedDataSignature2015",
    "created": "2018-02-22T15:16:04Z",
    "creator": "https://example.com/i/alice/keys/1",
    "signatureValue":
      "HztABpsP4e/emXsUYFUQ8HstjrgMfbMXbVcUhfYBHCCYuIgfsmTTOT4uaL5zwF" +
      "EpkSBNxskB46IAnqdkIYU2KF+7pDyBbIe7GMm60zIAavmIsAcxh034ENJreUgX" +
      "eIQhpx/ZPKcQCBPwDHrbxXiBxS/VmkvJLbtjfy0qj96f6Gc2AvaB43ZHwO88TV" +
      "lzxQFa8gnJt2embI41u4Gz7+jmx2yc/1lEH/iOmm1g3OTmnJu3OmvLGvygLogu" +
      "n17ueUbTA1Fam2H78V1UI/E90i/PY3Doy1VGDkdLsW8UJGTZOVSpmf0acqik91" +
      "pS1OuHcvyzN+HdRolszzdkrORzM8mxmg=="
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
