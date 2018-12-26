/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const constants = require('../../lib/constants');

const mock = {};
module.exports = mock;

mock.nonSecurityContextTestDoc = {
  '@context': {
    '@version': 1.1,
    schema: 'http://schema.org/',
    name: 'schema:name',
    homepage: 'schema:url',
    image: 'schema:image',
    signature: {
      '@id': 'https://w3id.org/security#signature',
      '@type': '@id'
    },
    proof: {
      '@id': 'https://w3id.org/security#proof',
      '@type': '@id',
      '@container': '@graph'
    }
  },
  name: 'Manu Sporny',
  homepage: 'https://manu.sporny.org/',
  image: 'https://manu.sporny.org/images/manu.png'
};

mock.securityContextTestDoc = {
  ...mock.nonSecurityContextTestDoc,
  '@context': [
    {'@version': 1.1},
    mock.nonSecurityContextTestDoc['@context'],
    constants.SECURITY_CONTEXT_URL]
};
