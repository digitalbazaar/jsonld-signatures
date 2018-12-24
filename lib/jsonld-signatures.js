/**
 * An implementation of the Linked Data Signatures specification for JSON-LD.
 * This library works in the browser and node.js.
 *
 * BSD 3-Clause License
 * Copyright (c) 2014-2018 Digital Bazaar, Inc.
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
/* eslint-disable indent */
(function(global) {

'use strict';

const util = require('./util');

/* Core API */
const api = {};

/* API Constants */
const constants = require('./constants');
Object.assign(api, constants);

// TODO: support `ProofChain`
const ProofSet = require('./ProofSet');

api.sign = util.callbackify(async function sign(document, {
  suite, purpose, documentLoader, expansionMap} = {}) {
  return new ProofSet().add(
    document, {suite, purpose, documentLoader, expansionMap});
});

api.verify = util.callbackify(async function verify(document, {
  suite, purpose, documentLoader, expansionMap} = {}) {
  return new ProofSet().verify(
    document, {suite, purpose, documentLoader, expansionMap});
});

/* Helper functions */
const Helper = require('./Helper');
const helper = new Helper();

// expose for helper functions
api.getPublicKey = util.callbackify(helper.getPublicKey.bind(helper));
api.checkKey = util.callbackify(helper.checkKey.bind(helper));
api.getJsonLd = util.callbackify(helper.getJsonLd.bind(helper));

// reexpose API as `.promises` for backwards compatability
api.promises = api;

// expose base64 functions for testing
api._encodeBase64Url = util.encodeBase64Url;
api._decodeBase64Url = util.decodeBase64Url;

// expose ProofPurposeHandler base class
api.ProofPurposeHandler = require('./proof-purpose/ProofPurposeHandler');

const {nodejs, browser} = require('./env');

if(nodejs) {
  // export nodejs API
  module.exports = api;
} else if(typeof define === 'function' && define.amd) {
  // export AMD API
  define([], function() {
    return api;
  });
} else if(browser) {
  // export simple browser API
  if(typeof global.jsigs === 'undefined') {
    global.jsigs = api;
  }
}

})(typeof window !== 'undefined' ? window : this);
