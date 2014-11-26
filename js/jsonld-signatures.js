/**
 * An implementation of the Linked Data Signatures specification for JSON-LD. 
 * This library works in the browser and node.js.
 *
 * @author Dave Longley
 * @author Manu Sporny
 * @author David I. Lehn
 *
 * BSD 3-Clause License
 * Copyright (c) 2011-2014 Digital Bazaar, Inc.
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
(function(jsonld) {

// determine if in-browser or using node.js
var _nodejs = (
  typeof process !== 'undefined' && process.versions && process.versions.node);
var _browser = !_nodejs &&
  (typeof window !== 'undefined' || typeof self !== 'undefined');
if(_browser) {
  if(typeof global === 'undefined') {
    if(typeof window !== 'undefined') {
      global = window;
    } else if(typeof self !== 'undefined') {
      global = self;
    } else if(typeof $ !== 'undefined') {
      global = $;
    }
  }
}

// attaches the Linked Data Signatures API for JSON-LD to the given object
var wrapper = function(jsigs) {

/* Core API */

/**
 * Verifies a JSON-LD signature.
 *
 * @param input the signed JSON-LD document.
 * @param [options] options to use:
 *          [publicKey] A JSON-LD document containing the public key info. If
 *            this is not provided, it will be fetched by checking the 
 *            cache first and then attempting to retrieve it via the Web.
 *          [publicKeyOwner] A JSON-LD document containing the public key owner
 *            info, which must also include a set of keys. If this is not 
 *            provided, it will be fetched by checking the cache first and 
 *            then attempting to retrieve it via the Web.
 *          [documentLoader(url, callback(err, remoteDoc))] the document loader.
 * @param callback(err, compacted, ctx) called once the operation completes.
 */
jsigs.verify = function(input, options, callback) {
  callback('Not implemented');
};

/* Promises API */

/**
 * Creates a new promises API object.
 *
 * @param [options] the options to use:
 *          [api] an object to attach the API to.
 *          [version] 'jsonld-signatures-1.0' to output a standard Linked Data 
 *            Signatures 1.0 promises API, 'jsigs' to output the same with 
 *            augmented proprietary methods (default: 'jsigs')
 *
 * @return the promises API object.
 */
jsigs.promises = function(options) {
  options = options || {};
  var slice = Array.prototype.slice;
  var promisify = jsonld.promisify;

  // handle 'api' option as version, set defaults
  var api = options.api || {};
  var version = options.version || 'jsigs';
  if(typeof options.api === 'string') {
    if(!options.version) {
      version = options.api;
    }
    api = {};
  }

  api.verify = function(input, options) {
    if(arguments.length < 2) {
      throw new TypeError('Could not verify, too few arguments.');
    }
    return promisify.apply(null, [jsigs.verify].concat(slice.call(arguments)));
  };

  try {
    jsigs.Promise = global.Promise || require('es6-promise').Promise;
  } catch(e) {
    var f = function() {
      throw new Error('Unable to find a Promise implementation.');
    };
    for(var method in api) {
      api[method] = f;
    }
  }

  return api;
};

/* WebIDL API */

function JsonLdSignaturesProcessor() {}
JsonLdSignaturesProcessor.prototype = 
  jsigs.promises({version: 'jsonld-signatures-1.0'});
JsonLdSignaturesProcessor.prototype.toString = function() {
  if(this instanceof JsonLdSignaturesProcessor) {
    return '[object JsonLdSignaturesProcessor]';
  }
  return '[object JsonLdSignaturesProcessorPrototype]';
};
jsigs.JsonLdSignaturesProcessor = JsonLdSignaturesProcessor;

// IE8 has Object.defineProperty but it only
// works on DOM nodes -- so feature detection
// requires try/catch :-(
var canDefineProperty = !!Object.defineProperty;
if(canDefineProperty) {
  try {
    Object.defineProperty({}, 'x', {});
  } catch(e) {
    canDefineProperty = false;
  }
}

if(canDefineProperty) {
  Object.defineProperty(JsonLdSignaturesProcessor, 'prototype', {
    writable: false,
    enumerable: false
  });
  Object.defineProperty(JsonLdSignaturesProcessor.prototype, 'constructor', {
    writable: true,
    enumerable: false,
    configurable: true,
    value: JsonLdSignaturesProcessor
  });
}

// setup browser global JsonLdProcessor
if(_browser && typeof global.JsonLdSignaturesProcessor === 'undefined') {
  if(canDefineProperty) {
    Object.defineProperty(global, 'JsonLdSignaturesProcessor', {
      writable: true,
      enumerable: false,
      configurable: true,
      value: JsonLdSignaturesProcessor
    });
  } else {
    global.JsonLdSignaturesProcessor = JsonLdSignaturesProcessor;
  }
}

/**
 * Constructs a new JSON-LD Signatures Processor.
 */
var Processor = function() {};

/**
 * Recursively compacts an element using the given active context. All values
 * must be in expanded form before this method is called.
 *
 * @param activeCtx the active context to use.
 * @param activeProperty the compacted property associated with the element
 *          to compact, null for none.
 * @param element the element to compact.
 * @param options the compaction options.
 *
 * @return the compacted value.
 */
Processor.prototype.verify = function(input, options, callback) {
  // FIXME: Implement

  // only primitives remain which are already compact
  callback('Not implemented');
};

// end of jsigs API factory
return jsigs;
};

// external APIs:

// used to generate a new JSON-LD Signatures API instance
var factory = function() {
  return wrapper(function() {
    return factory();
  });
};
// the shared global jsigs API instance
wrapper(factory);

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
  if(typeof jsigs === 'undefined') {
    jsigs = factory;
  }
}

})();
