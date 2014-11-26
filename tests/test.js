/**
 * Test runner for JSON-LD Signatures library.
 *
 * @author Dave Longley <dlongley@digitalbazaar.com>
 * @author Manu Sporny <msporny@digitalbazaar.com>
 *
 * Copyright (c) 2014 Digital Bazaar, Inc. All rights reserved.
 */
(function() {

'use strict';

// detect node.js (vs. phantomJS)
var _nodejs = (typeof process !== 'undefined' &&
  process.versions && process.versions.node);

if(_nodejs) {
  var _jsdir = getEnv().JSDIR || 'lib';
  var fs = require('fs');
  var path = require('path');
  var jsonld = require('jsonld');
  var jsigs = require('../' + _jsdir + '/jsonld-signatures')(jsonld);
  var assert = require('assert');
  var program = require('commander');
  program
    .option('--bail', 'Bail when a test fails')
    .parse(process.argv);
} else {
  var fs = require('fs');
  var system = require('system');
  require('./setImmediate');
  var _jsdir = getEnv().JSDIR || 'lib';
  require('jsonld');
  var jsigs = require('../' + _jsdir + '/jsonld-signatures')(jsonld);
  jsigs = jsigsjs;
  window.Promise = require('es6-promise').Promise;
  var assert = require('chai').assert;
  require('mocha/mocha');
  require('mocha-phantomjs/lib/mocha-phantomjs/core_extensions');
  var program = {};
  for(var i = 0; i < system.args.length; ++i) {
    var arg = system.args[i];
    if(arg.indexOf('--') === 0) {
      var argname = arg.substr(2);
      switch(argname) {
      default:
        program[argname] = true;
      }
    }
  }

  mocha.setup({
    reporter: 'spec',
    ui: 'bdd'
  });
}

// run tests
describe('JSON-LD Signatures', function() {
  it('should successfully verify a local signed document', function(done) {
    var signedDoc = {};
    jsigs.verify(signedDoc, function(err, verified) {
      assert.isTrue(verified, 'signature verification failed');
      done();
    });
  });
});

if(!_nodejs) {
  mocha.run(function() {
    phantom.exit();
  });
}

})();
