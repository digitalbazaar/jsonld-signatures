/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

/*eslint max-len: ["error", { "ignoreComments": true }]*/

// load locally embedded contexts
const contexts = require('./contexts');

/**
 * This is a utility module that provides a set of functions for using or
 * extending jsonld-signature's built-in JSON-LD document loader.
 * @see https://www.w3.org/TR/json-ld11-api/#loaddocumentcallback
 */
const api = {};
module.exports = api;

api.extendContextLoader = documentLoader => {
  /**
   * extendContextLoader extends another JSON-LD document loader.
   * Given a document loader to extend, this method will return a
   * new document loader that will first check for a URL in
   * jsonld-signature's built-in context map and, if not found,
   * it will fall back to using the passed document loader.
   * This utility method can be used to ensure that any local,
   * in-memory, immutable context documents provided by
   * jsonld-signatures will be used prior to using another
   * document loader to load other documents.
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
   * strictDocumentLoader extends extendContextLoader.
   * ensuring no network calls are made so the only documents
   * available are the built-in contexts.
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
