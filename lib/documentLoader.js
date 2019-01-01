/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

// load locally embedded contexts
const contexts = require('./contexts');

const api = {};
module.exports = api;

api.extendContextLoader = documentLoader => {
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
  throw new Error(`${url} not found.`);
});
