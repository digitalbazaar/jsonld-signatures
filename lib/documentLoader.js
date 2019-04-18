/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

// load locally embedded contexts
const contexts = require('./contexts');

/**
 * documentLoader is a set of methods used to fetch jsonld documents.
 * Most of these methods are there to ensure jsonld contexts are loaded
 * correctly.
 * @module documentLoader
 */
const api = {};
module.exports = api;

api.extendContextLoader = documentLoader => {
  /**
   * extendContextLoader takes in an documentLoader. It then
   * returns a function that accepts a url. If the url is in the context
   * cache, it returns the security context
   * otherwise it uses the curried documentLoader
   * to fetch a jsonld document from a remote source.
   *
   * @param {Function} documentLoader - A function that fetches a document.
   * @see [node example]{@link https://github.com/digitalbazaar/jsonld.js/blob/master/lib/documentLoaders/node.js}
   * @see [xhr example]{@link https://github.com/digitalbazaar/jsonld.js/blob/master/lib/documentLoaders/xhr.js}
   *
   * @returns {Function} A function that accepts a url to a jsonld document.
   */
  return async url => {
    const context = contexts[url];
    if(context !== undefined) {
      return {
        contextUrl: null,
        documentUrl: url,
        document: context
      };
    }
    return documentLoader(url);
  };
};

api.strictDocumentLoader = api.extendContextLoader(url => {
  /**
   * strictDocumentLoader can be used to ensure functions that need
   * a documentLoader throw an error if no documentLoader is provided.
   *
   * @param {string} url - A valid url to a jsonld document.
   *
   * @throws {Error} Always throws an error.
   * @return {undefined} This function should always throw an error.
   */
  throw new Error(`${url} not found.`);
});
