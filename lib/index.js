/*!
 * Copyright (c) 2010-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

if(require('semver').gte(process.version, '8.0.0')) {
  module.exports = require('./jsonld-signatures');
} else {
  module.exports = require('../dist/node6/lib/jsonld-signatures');
}
