/**
 * An implementation of the Linked Data Signatures specification for JSON-LD. 
 * This library works in the browser and node.js.
 *
 * @author Dave Longley <dlongley@digitalbazaar.com>
 * @author David I. Lehn <dlehn@digitalbazaar.com>
 * @author Manu Sporny <msporny@digitalbazaar.com>
 *
 * BSD 3-Clause License
 * Copyright (c) 2014 Digital Bazaar, Inc.
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
(function(global) {

'use strict';

// determine if using node.js or browser
var _nodejs = (
  typeof process !== 'undefined' && process.versions && process.versions.node);
var _browser = !_nodejs &&
  (typeof window !== 'undefined' || typeof self !== 'undefined');

/**
 * Attaches the JSON-LD Signatures API to the given object.
 *
 * @param api the object to attach the signatures API to.
 * @param [options] the options to use:
 *          [inject] the dependencies to inject, available global defaults will
 *            be used otherwise.
 *            [async] async API.
 *            [forge] forge API.
 *            [jsonld] jsonld.js API; a secure document loader must be
 *              configured.
 *            [_] underscore API.
 *          [checkCertificates] true to check TLS/SSL certificate validity,
 *            false to disable checking (NOT SAFE!).
 *          [disableLocalFraming] true to disable framing of local
 *            documents based on the given local base URI (default: false).
 *          [localBaseUri] must be given if disabling local framing.
 */
function wrap(api, options) {

// handle dependency injection
options = options || {};
var inject = options.inject || {};
var async = inject.async || global.async;
var crypto = inject.crypto || global.crypto;
var forge = inject.forge || global.forge;
var jsonld = inject.jsonld || global.jsonldjs;
var _ = inject._ || global._;
var checkCertificates = options.checkCertificates || true;

// if dependencies not loaded and using node, load them
if(_nodejs) {
  if(!async) {
    async = require('async');
  }
  if(!crypto) {
    crypto = require('crypto');
  }
  if(!forge) {
    forge = require('node-forge');
  }
  if(!jsonld) {
    // locally configure jsonld
    jsonld = require('jsonld')();
    jsonld.useDocumentLoader('node', {secure: checkCertificates});
  }
  if(!_){
    _ = require('underscore');
  }
}

/* API Constants */

api.SECURITY_CONTEXT_URL = 'https://w3id.org/security/v1';

/* Core API */

/**
 * Signs a JSON-LD document using a digital signature.
 *
 * @param input the JSON-LD document to be signed.
 * @param [options] options to use:
 *          privateKeyPem A PEM-encoded private key.
 *          creator the URL to the paired public key.
 *          [date] an optional date to override the signature date with.
 *          [domain] an optional domain to include in the signature.
 *          [nonce] an optional nonce to include in the signature.
 *          [documentLoader(url, callback(err, remoteDoc))] the document loader.
 * @param callback(err, signedDocument) called once the operation completes.
 */
api.sign = function(input, options, callback) {
  callback = callback || options;
  if(!callback) {
    options = {};
  }
  var privateKeyPem = options.privateKeyPem;
  var creator = options.creator;
  var date = options.date || new Date();
  var domain = options.domain || null;
  var nonce = options.nonce || null;
  var output = _deepClone(input);

  if(typeof privateKeyPem !== 'string') {
    return callback(new TypeError(
      '[jsig.sign] options.privateKeyPem must be a PEM formatted string.'));
  }
  if(typeof creator !== 'string') {
    return callback(new TypeError(
      '[jsig.sign] options.creator must be a URL string.'));
  }
  if(domain && typeof domain !== 'string') {
    return callback(new TypeError(
      '[jsig.sign] options.domain must be a string.'));
  }
  if(nonce && typeof nonce !== 'string') {
    return callback(new TypeError(
      '[jsig.sign] options.nonce must be a string.'));
  }

  // create W3C-formatted date
  if(typeof date !== 'string') {
    date = _w3cDate(date);
  }

  async.auto({
    normalize: function(callback) {
      jsonld.normalize(output, {format: 'application/nquads'}, callback);
    },
    sign: ['normalize', function(callback, results) {
      var normalized = results.normalize;
      if(normalized.length === 0) {
        var inputJson = '';
        
        try {
          inputJson = JSON.stringify(input, null, 2);
        } catch(err) {
          inputJson = 'JSON stringification error: ' + err;
        }
        
        return callback(new Error('[jsig.sign] ' +
          'The data to sign is empty. This error may be caused because ' +
          'a "@context" was not supplied in the input which would cause ' +
          'any terms or prefixes to be undefined. ' +
          'Input:\n' + inputJson));
      }
      
      _createSignature(normalized, {privateKeyPem: privateKeyPem, 
        date: date, nonce: nonce, domain: domain}, callback);
    }]
  }, function(err, results) {
    if(err) {
      return callback(err);
    }

    // create signature info
    var signature = {
      type: 'GraphSignature2012',
      creator: creator,
      created: date,
      signatureValue: results.sign
    };
    if(domain !== null) {
      signature.domain = domain;
    }
    if(nonce !== null) {
      signature.nonce = nonce;
    }
    // TODO: support multiple signatures
    output.signature = signature;
    jsonld.addValue(
      output, '@context', api.SECURITY_CONTEXT_URL, {allowDuplicate: false});
    callback(null, output);
  });
};

/**
 * Verifies a JSON-LD document containing a digital signature.
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
 * @param callback(err, verified) called once the operation completes.
 */
api.verify = function(input, options, callback) {
  callback = callback || options;
  if(!callback) {
    options = {};
  }
  
  callback('Not implemented');
};

/* Helper functions */
var _createSignature = null;

if(_nodejs) {
  _createSignature = function(normalized, options, callback) {
    // generate base64-encoded signature
    var signer = crypto.createSign('RSA-SHA256');
    if(options.nonce !== null) {
      signer.update(options.nonce);
    }
    signer.update(options.date);
    signer.update(normalized);
    if(options.domain !== null) {
      signer.update('@' + options.domain);
    }
    var signature = signer.sign(options.privateKeyPem, 'base64');
    callback(null, signature);
  };
} else if(_browser) {
  _createSignature = function(normalized, options, callback) {
    // FIXME: Implement signature creation in browser using forge
    callback('not implemented');
  }; 
}


/**
 * Clones a value. If the value is an array or an object it will be deep cloned.
 *
 * @param value the value to clone.
 *
 * @return the cloned value.
 */
function _deepClone(value) {
  if(value && typeof value === 'object') {
    var rval = Array.isArray(value) ? new Array(value.length) : {};
    for(var i in value) {
      rval[i] = _deepClone(value[i]);
    }
    return rval;
  }
  return value;
}

/**
 * Converts the given date into W3C datetime format (eg: 2011-03-09T21:55:41Z).
 *
 * @param date the date to convert.
 *
 * @return the date in W3C datetime format.
 */
function _w3cDate(date) {
  if(date === undefined || date === null) {
    date = new Date();
  } else if(typeof date === 'number' || typeof date === 'string') {
    date = new Date(date);
  }
  
  return date.getUTCFullYear() + '-' +
    _zeroFill(date.getUTCMonth() + 1) + '-' +
    _zeroFill(date.getUTCDate())  + 'T' +
    _zeroFill(date.getUTCHours()) + ':' +
    _zeroFill(date.getUTCMinutes()) + ':' +
    _zeroFill(date.getUTCSeconds()) + 'Z';
}

function _zeroFill(num) {
  return (num < 10) ? '0' + num : '' + num;
}

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
api.promises = function(options) {
  options = options || {};
  var slice = Array.prototype.slice;
  var promisify = jsonld.promisify;

  // handle 'api' option as version, set defaults
  var papi = options.api || {};
  var version = options.version || 'jsigs';
  if(typeof options.api === 'string') {
    if(!options.version) {
      version = options.api;
    }
    papi = {};
  }

  papi.verify = function(input, options) {
    if(arguments.length < 2) {
      throw new TypeError('Could not verify, too few arguments.');
    }
    return promisify.apply(null, [api.verify].concat(slice.call(arguments)));
  };

  try {
    api.Promise = global.Promise || require('es6-promise').Promise;
  } catch(e) {
    var f = function() {
      throw new Error('Unable to find a Promise implementation.');
    };
    for(var method in api) {
      papi[method] = f;
    }
  }

  return papi;
};

return api;

} // end wrap

// used to generate a new verifier API instance
var factory = function(inject) {
  return wrap(function() {return factory();}, inject);
};
wrap(factory);

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
  if(typeof global.jsigs === 'undefined') {
    global.jsigs = {};
  }
  wrap(global.jsigs);
}

})(this);