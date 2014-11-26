/**
 * An implementation of the Linked Data Signatures specification for JSON-LD. 
 * This library works in the browser and node.js.
 *
 * @author Dave Longley <dlongley@digitalbazaar.com>
 * @author David I. Lehn <dlehn@digitalbazaar.com>
 * @author Manu Sporny <msporny@digitalbazaar.com>
 *
 * BSD 3-Clause License
 * Copyright (c) 2014 Digital Bazaar, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * Neither the name of the Digital Bazaar, Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
(function(global) {

'use strict';

// determine if using node.js or browser
var _nodejs = (
  typeof process !== 'undefined' && process.versions && process.versions.node);
var _browser = !_nodejs &&
  (typeof window !== 'undefined' || typeof self !== 'undefined');

/**
 * Attaches the JSON-LD Signatures API to the given object.
 *
 * @param api the object to attach the signatures API to.
 * @param [options] the options to use:
 *          [inject] the dependencies to inject, available global defaults will
 *            be used otherwise.
 *            [forge] forge API.
 *            [jsonld] jsonld.js API; a secure document loader must be
 *              configured.
 *            [_] underscore API.
 *          [checkCertificates] true to check TLS/SSL certificate validity,
 *            false to disable checking (NOT SAFE!).
 *          [disableLocalFraming] true to disable framing of local
 *            documents based on the given local base URI (default: false).
 *          [localBaseUri] must be given if disabling local framing.
 */
function wrap(api, options) {

// handle dependency injection
options = options || {};
var inject = options.inject || {};
var forge = inject.forge || global.forge;
var jsonld = inject.jsonld || global.jsonldjs;
var _ = inject._ || global._;
var checkCertificates = options.checkCertificates || true;

// if dependencies not loaded and using node, load them
if(_nodejs) {
  if(!forge) {
    forge = require('node-forge');
  }
  if(!jsonld) {
    // locally configure jsonld
    jsonld = require('jsonld')();
    jsonld.useDocumentLoader('node', {secure: checkCertificates});
  }
  if(!_){
    _ = require('underscore');
  }
}

/**
 * Attempts to verify a signed JSON-LD document.
 *
 * @param doc the signed document (JSON-LD object) or URL to the document to
 *          verify.
 *
 * @return a promise that resolves to a results object with the parameters
 *           used during verification, any errors, and any tests that were run.
 */
api.verify = function(doc) {
  return new jsonld.Promise(function(resolve, reject) {
    resolve('not implemented');
  });
};

return api;

} // end wrap

// used to generate a new verifier API instance
var factory = function(inject) {
  return wrap(function() {return factory();}, inject);
};
wrap(factory);

if(_nodejs) {
  // export nodejs API
  module.exports = factory;
} else if(typeof define === 'function' && define.amd) {
  // export AMD API
  define([], function() {
    return factory;
  });
} else if(_browser) {
  // export simple browser API
  if(typeof global.jsigs === 'undefined') {
    global.jsigs = {};
  }
  wrap(global.jsigs);
}

})(this);