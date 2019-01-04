/**
 * Karma test runner for jsonld-signatures.
 *
 * Use environment vars to control, set via karma.conf.js/webpack:
 *
 * Set dirs, manifests, or js to run:
 *   JSONLD_TESTS="r1 r2 ..."
 * Output an EARL report:
 *   EARL=filename
 * Bail with tests fail:
 *   BAIL=true
 *
 * Copyright (c) 2011-2018 Digital Bazaar, Inc. All rights reserved.
 */
// FIXME: hack to ensure delay is set first
//mocha.setup({delay: true, ui: 'bdd'});

// test suite compatibility
require('core-js/fn/string/ends-with');
require('core-js/fn/string/starts-with');

// jsonld compatibility
require('core-js/fn/array/from');
require('core-js/fn/array/includes');
require('core-js/fn/map');
require('core-js/fn/object/assign');
require('core-js/fn/promise');
require('core-js/fn/set');
require('core-js/fn/symbol');
// loaded from karma.conf.js as of babel@7
//require('regenerator-runtime/runtime');

const assert = require('chai').assert;
const common = require('./test-common');
const constants = require('../lib/constants');
const jsigs = require('..');
const mock = require('./mock/mock');
const {suites} = require('../lib/suites');
const util = require('../lib/util');

const options = {
  assert,
  constants,
  jsigs,
  mock,
  suites,
  util,
  nodejs: false
};

common(options).catch(err => {
  console.error(err);
});
