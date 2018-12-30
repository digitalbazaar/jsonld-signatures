/*!
 * Copyright (c) 2010-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

/* Core API */
const api = {};
module.exports = api;

/* API Constants */
const constants = require('./constants');
Object.assign(api, constants);

// TODO: support `ProofChain`
const ProofSet = require('./ProofSet');

api.sign = async function sign(document, {
  suite, purpose, documentLoader, expansionMap, compactProof} = {}) {
  return new ProofSet().add(
    document, {suite, purpose, documentLoader, expansionMap, compactProof});
};

api.verify = async function verify(document, {
  suite, purpose, documentLoader, expansionMap, compactProof} = {}) {
  return new ProofSet().verify(
    document, {suite, purpose, documentLoader, expansionMap, compactProof});
};

// expose suite classes
api.suites = require('./suites').suites;

// expose ProofPurpose classes to enable extensions
api.purposes = require('./purposes').purposes;

// expose LDKeyPair classes
Object.assign(api, require('./LDKeyPair'));
