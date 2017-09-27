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
 * @author Dave Longley
 * @author David I. Lehn
 *
 * Copyright (c) 2011-2017 Digital Bazaar, Inc. All rights reserved.
 */
// FIXME: hack to ensure delay is set first
//mocha.setup({delay: true, ui: 'bdd'});

// jsonld compatibility
//require('core-js/fn/array/includes');
//require('core-js/fn/object/assign');
require('core-js/fn/promise');
require('regenerator-runtime/runtime');

const assert = require('chai').assert;
const common = require('./test-common');
const jsigs = require('..');
const jsonld = require('../node_modules/jsonld/dist/jsonld.js');
const jws = require('jws');

//var system = require('system');
const forge = require('../node_modules/node-forge');
window.forge = forge;
const bitcoreMessage = require(
  '../node_modules/bitcore-message/dist/bitcore-message.js');
window.bitcoreMessage = bitcoreMessage;

jsigs.promises({api: jsigs.promises});

const options = {
  assert: assert,
  jsigs: jsigs,
  jsonld: jsonld,
  jws: jws,
  nodejs: false
};

common(options).then(() => {
  //run();
}).then(() => {
  // FIXME: karma phantomjs does not expose this API
  if(window.phantom && window.phantom.exit) {
    phantom.exit(0);
  }
}).catch(err => {
  console.error(err);
  // FIXME: karma phantomjs does not expose this API
  if(window.phantom && window.phantom.exit) {
    phantom.exit(1);
  }
});
