/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const constants = require('../../lib/constants');

const mock = {};
module.exports = mock;

mock.nonSecurityContextTestDoc = {
  '@context': {
    schema: 'http://schema.org/',
    name: 'schema:name',
    homepage: 'schema:url',
    image: 'schema:image'
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
