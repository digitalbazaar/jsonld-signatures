/**
 * Node.js test runner for jsonld-signatures.
 *
 * @author Dave Longley
 * @author David I. Lehn
 *
 * Copyright (c) 2011-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

// support async/await tests in node6
if(!require('semver').gte(process.version, '8.6.0')) {
  require('babel-register')({
    presets: ['node6-es6']
  });
}

const assert = require('chai').assert;
const common = require('./test-common');
const constants = require('../lib/constants');
const jsigs = require('..');
const mock = require('./mock-data');
const {suites} = require('../lib/suites');
const util = require('../lib/util');

const options = {
  assert,
  constants,
  jsigs,
  mock,
  suites,
  util,
  nodejs: true
};

common(options).then(() => {
  run();
}).catch(err => {
  console.error(err);
});

process.on('unhandledRejection', (reason, p) => {
  console.error('Unhandled Rejection at:', p, 'reason:', reason);
});
