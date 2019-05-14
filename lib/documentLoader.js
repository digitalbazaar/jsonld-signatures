/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';
/*eslint max-len: ["error", { "ignoreComments": true }]*/

// load locally embedded contexts
const contexts = require('./contexts');

/**
 * A utility module that provides a set of functions for using or
 * extending jsonld-signature's built-in JSON-LD document loader.
 * Documents stored at urls are usually dereferenced via https requests
 * while DIDs can be dereferenced by a variety of means.
 * Most of these methods are there to ensure jsonld contexts are loaded
 * from an in-memory, immutable copy of the context
 * document to ensure content integrity.
 * @module documentLoader
 * @see https://www.w3.org/TR/json-ld11-api/#loaddocumentcallback
 */
const api = {};
module.exports = api;

api.extendContextLoader = documentLoader => {
  /**
   * extendContextLoader takes in a documentLoader. It then
   * returns a function that accepts a url. If the url is in the context
   * map, it returns a copy of an in-memory, immutable context document
   * otherwise it uses the curried documentLoader
   * to fetch a jsonld document from a remote source.
   *
   * @param {Function} documentLoader - A function that fetches a document.
   * @see [node documentLoader example]{@link https://github.com/digitalbazaar/jsonld.js/blob/master/lib/documentLoaders/node.js}
   * @see [xhr documentLoader example]{@link https://github.com/digitalbazaar/jsonld.js/blob/master/lib/documentLoaders/xhr.js}
   *
   * @returns {Function} A function that accepts a
   * url then fetches a jsonld document.
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
   * strictDocumentLoader if the url for a context is in the context map
   * this returns a copy of an in-memory, immutable context document
   * it throws an error. This ensures no network
   * calls are made so the only documents that can
   * be loaded are locally available contexts.
   * @see documentLoader.extendContextLoader
   *
   * @param {string} url - A valid url to a jsonld context.
   *
   * @throws {Error} Always throws an error if the
   * url is not in the context map
   * (i.e., not a URL for a locally available context document).
   * @return {Object} A JSON-LD RemoteDocument
   * that is a copy of a locally available context.
   */
  throw new Error(`${url} not found.`);
});
