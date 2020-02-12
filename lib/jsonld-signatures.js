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
const VerificationError = require('./VerificationError');

api.sign = async function sign(document, {
  suite, purpose, documentLoader, expansionMap, compactProof} = {}) {
  try {
    return await new ProofSet().add(
      document, {suite, purpose, documentLoader, expansionMap, compactProof});
  } catch(e) {
    if(!documentLoader && e.name === 'jsonld.InvalidUrl') {
      const {details: {url}} = e;
      const err = new Error(
        `A URL "${url}" could not be fetched; you need to pass ` +
        '"documentLoader" or resolve the URL before calling "sign".');
      err.cause = e;
      throw err;
    }
    throw e;
  }
};

api.verify = async function verify(document, {
  suite, purpose, documentLoader, expansionMap, compactProof} = {}) {
  const result = await new ProofSet().verify(
    document, {suite, purpose, documentLoader, expansionMap, compactProof});
  const {error} = result;
  if(error) {
    if(!documentLoader && error.name === 'jsonld.InvalidUrl') {
      const {details: {url}} = error;
      const urlError = new Error(
        `A URL "${url}" could not be fetched; you need to pass ` +
        '"documentLoader" or resolve the URL before calling "verify".');
      result.error = new VerificationError(urlError);
    } else {
      result.error = new VerificationError(error);
    }
  }
  return result;
};

// expose suite classes
api.suites = require('./suites').suites;

// expose ProofPurpose classes to enable extensions
api.purposes = require('./purposes').purposes;

// expose LDKeyPair classes
Object.assign(api, require('crypto-ld'));

// expose document loader helpers
Object.assign(api, require('./documentLoader'));
