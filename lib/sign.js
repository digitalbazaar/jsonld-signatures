/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const ProofSet = require('./ProofSet');

const api = {};
module.exports = api;

api.sign = async function sign(document, {
  suite, purpose, documentLoader, expansionMap} = {}) {
  return new ProofSet().add(
    document, {suite, purpose, documentLoader, expansionMap});
};
