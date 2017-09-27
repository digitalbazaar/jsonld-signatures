/**
 * Node.js test runner for jsonld-signatures.
 *
 * @author Dave Longley
 * @author David I. Lehn
 *
 * Copyright (c) 2011-2017 Digital Bazaar, Inc. All rights reserved.
 */
const assert = require('chai').assert;
const common = require('./test-common');
const jsonld = require('../node_modules/jsonld');
const jsigs = require('..');
const jws = require('../node_modules/jws');

const options = {
  assert: assert,
  jsigs: jsigs,
  jsonld: jsonld,
  jws: jws,
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
