/*!
 * Copyright (c) 2010-2018 Digital Bazaar, Inc. All rights reserved.
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

// expose base64 functions for testing
api._encodeBase64Url = util.encodeBase64Url;
api._decodeBase64Url = util.decodeBase64Url;

// expose ProofPurpose classes to enable extensions
api.ControllerProofPurpose = require('./proof-purpose/ControllerProofPurpose');
api.ProofPurpose = require('./proof-purpose/ProofPurpose');
api.PublicKeyProofPurpose = require('./proof-purpose/PublicKeyProofPurpose');

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
