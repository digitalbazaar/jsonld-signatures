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
 *.now
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
 * Verifies a JSON-LD digitally-signed object.
 *
 * @param obj the JSON-LD object to verify.
 * @param [options] the options to use.
 *          [publicKey] the JSON-LD document providing the public key info.
 *          [publicKeyOwner] the JSON-LD document providing the public key
 *            owner info including the list of valid keys for that owner.
 *          [checkNonce(nonce, options, function(err, valid))] a callback to
 *            check if the nonce (null if none) used in the signature is valid.
 *          [checkDomain(domain, options, function(err, valid))] a callback
 *            to check if the domain used (null if none) is valid.
 *          [checkKey(key, options, function(err, trusted))] a callback to
 *            check if the key used to sign the message is trusted.
 *          [checkKeyOwner(owner, key, options, function(err, trusted))] a
 *            callback to check if the key's owner is trusted.
 *          [checkTimestamp]: check signature timestamp (default: true).
 *          [maxTimestampDelta]: signature must be created within a window of
 *            this many seconds (default: 15 minutes).
 * @param callback(err, verified) called once the operation completes.
 */
api.verify = function(input, options, callback) {
  if(typeof options === 'function') {
    callback = options;
    options = {};
  }

  var checkTimestamp = (
    'checkTimestamp' in options ? options.checkTimestamp : true);
  var maxTimestampDelta = (
    'maxTimestampDelta' in options ? options.maxTimestampDelta : (15 * 60));

  async.auto({
    // FIXME: add support for multiple signatures
    //      : for many signers of an object, can just check all sigs
    //      : for signed sigs, need to recurse?
    // FIXME: add support for different signature types
    //      : frame with signatures to get types, then reframe to get
    //      : correct structure for each type.
    frame: function(callback) {
      // frame message to retrieve signature
      var frame = {
        '@context': api.SECURITY_CONTEXT_URL,
        signature: {
          type: 'GraphSignature2012',
          created: {},
          creator: {},
          signatureValue: {}
        }
      };
      jsonld.frame(input, frame, function(err, framed) {
        if(err) {
          return callback(err);
        }
        var graphs = framed['@graph'];
        if(graphs.length === 0) {
          return callback(new Error('[jsigs.verify] ' +
            'No signed data found in the provided input.'));
        }
        if(graphs.length > 1) {
          return callback(new Error('[jsigs.verify] ' +
            'More than one signed graph found.'));
        }
        var graph = graphs[0];
        // copy the top level framed data context
        graph['@context'] = framed['@context'];
        var signature = graph.signature;
        if(!signature) {
          return callback(new Error('[jsigs.verify] ' +
            'The message is not digitally signed using a known algorithm.'));
        }
        callback(null, graph);
      });
    },
    checkNonce: ['frame', function(callback, results) {
      var signature = results.frame.signature;
      var cb = function(err, valid) {
        if(err) {
          return callback(err);
        }
        if(!valid) {
          return callback(new Error('[jsigs.verify] ' +
            'The message nonce is invalid.'));
        }
        callback();
      };
      if(!options.checkNonce) {
        return cb(
          null, (signature.nonce === null || signature.nonce === undefined));
      }
      options.checkNonce(signature.nonce, options, cb);
    }],
    checkDomain: ['frame', function(callback, results) {
      var signature = results.frame.signature;
      var cb = function(err, valid) {
        if(err) {
          return callback(err);
        }
        if(!valid) {
          return callback(new Error('[jsigs.verify] ' +
            'The message domain is invalid.'));
        }
        callback();
      };
      if(!options.checkDomain) {
        return cb(
          null, (signature.domain === null || signature.domain === undefined));
      }
      options.checkDomain(signature.domain, options, cb);
    }],
    checkDate: ['frame', function(callback, results) {
      if(!checkTimestamp) {
        return callback();
      }

      // ensure signature timestamp within a valid range
      var now = +new Date();
      var delta = maxTimestampDelta * 1000;
      try {
        var signature = results.frame.signature;
        var created = Date.parse(signature.created);
        if(created < (now - delta) || created > (now + delta)) {
          throw new Error('[jsigs.verify] ' +
            'The message digital signature timestamp is out of range.');
        }
      } catch(ex) {
        return callback(ex);
      }
      callback();
    }],
    getPublicKey: ['frame', function(callback, results) {
      var signature = results.frame.signature;

      if(options.publicKey) {
        return callback(null, options.publicKey);
      }

      api.getPublicKey(signature.creator, options, callback);
    }],
    checkKey: ['getPublicKey', function(callback, results) {
      if('revoked' in results.getPublicKey) {
        return callback(new Error('[jsigs.verify] ' +
          'The message was signed with a key that has been revoked.'));
      }
      var cb = function(err, trusted) {
        if(err) {
          return callback(err);
        }
        if(!trusted) {
          throw new Error('[jsigs.verify] ' +
            'The message was not signed with a trusted key.');
        }
        callback();
      };
      if(options.checkKey) {
        return options.checkKey(results.getPublicKey, options, cb);
      }
      api.checkKey(results.getPublicKey, options, cb);
    }],
    normalize: ['checkNonce', 'checkDate', 'checkKey',
      function(callback, results) {
      // remove signature property from object
      var result = results.frame;
      var signature = result.signature;
      delete result.signature;

      jsonld.normalize(
        result, {format: 'application/nquads'}, function(err, normalized) {
        if(err) {
          return callback(err);
        }
        callback(null, {data: normalized, signature: signature});
      });
    }],
    verifySignature: ['normalize', function(callback, results) {
      var key = results.getPublicKey;
      var signature = results.normalize.signature;

      _verifySignature(results.normalize.data, signature.signatureValue, {
        publicKeyPem: key.publicKeyPem,
        nonce: signature.nonce,
        created: signature.created,
        domain: signature.domain
      }, callback);
    }]
  }, function(err, results) {
    callback(err, results.verifySignature);
  });
};

/* Helper functions */

/**
 * Gets a remote public key.
 *
 * @param id the ID for the public key.
 * @param [options] the options to use.
 *          [request] any options to pass to jsigs.getJsonLd.
 * @param callback(err, key) called once the operation completes.
 */
api.getPublicKey = function(id, options, callback) {
  if(typeof options === 'function') {
    callback = options;
    options = {};
  }
  options = options || {};

  api.getJsonLd(id, options.request, function(err, key) {
    if(err) {
      return callback(err);
    }

    // FIXME: improve validation
    if(!('publicKeyPem' in key)) {
      return callback(new Error('[payswarm.getPublicKey] ' +
        'Could not get public key. Unknown format.'));
    }

    callback(null, key);
  });
};

/**
 * Checks to see if the given key is trusted.
 *
 * @param key the public key to check.
 * @param [options] the options to use.
 *          [publicKeyOwner] the JSON-LD document describing the public key
 *            owner.
 *          [checkKeyOwner(owner, key)] a custom method to return whether
 *            or not the key owner is trusted.
 *          [request] any options to pass to payswarm.getJsonLd.
 * @param callback(err, trusted) called once the operation completes.
 */
api.checkKey = function(key, options, callback) {
  if(typeof options === 'function') {
    callback = options;
    options = {};
  }
  options = options || {};
  async.auto({
    getOwner: function(callback) {
      if(options.publicKeyOwner) {
        return callback(null, options.publicKeyOwner);
      }
      api.getJsonLd(key.owner, options.request, callback);
    },
    frameOwner: ['getOwner', function(callback, results) {
      var frame = {
        '@context': api.SECURITY_CONTEXT_URL,
        publicKey: {'@embed': false}
      };
      jsonld.frame(results.getOwner, frame, function(err, framed) {
        if(err) {
          return callback(err);
        }
        callback(null, framed['@graph']);
      });
    }],
    checkOwner: ['frameOwner', function(callback, results) {
      // find specific owner of key
      var owner;
      var owners = results.frameOwner;
      for(var i = 0; i < owners.length; ++i) {
        if(jsonld.hasValue(owners[i], 'publicKey', key['@id'])) {
          owner = owners[i];
          break;
        }
      }
      if(!owner) {
        return callback(new Error('[jsigs.verify] ' +
          'The public key is not owned by its declared owner.'));
      }
      if(!options.checkKeyOwner) {
        return callback();
      }
      options.checkKeyOwner(owner, key, options, function(err, trusted) {
        if(err) {
          return callback(err);
        }
        if(!trusted) {
          return callback(new Error('[jsigs.verify] ' +
            'The owner of the public key is not trusted.'));
        }
      });
    }]
  }, function(err) {
    callback(err, !err && true);
  });
};

/**
 * Retrieves a JSON-LD object over HTTP. To implement caching, override
 * this method.
 *
 * @param url the URL to HTTP GET.
 * @param [options] the options to pass to the underlying document loader;
 *          see jsonld.documentLoaders.node for details.
 * @param callback(err, result) called once the operation completes.
 */
api.getJsonLd = function(url, options, callback) {
  if(typeof options === 'function') {
    callback = options;
    options = {};
  }
  var documentLoader = jsonld.documentLoaders.node(options);
  documentLoader(url, function(err, result) {
    if(err) {
      return callback(err);
    }
    // ensure result is parsed
    if(typeof result.document === 'string') {
      try {
        result.document = JSON.parse(result.document);
      } catch(e) {
        return callback(e);
      }
    }
    if(!result.document) {
      return callback(new Error(
        '[jsigs.getJsonLd] No JSON-LD found at "' + url + '".'));
    }
    // compact w/context URL from link header
    if(result.contextUrl) {
      return jsonld.compact(
        result.document, result.contextUrl, {expandContext: result.contextUrl},
        callback);
    }
    callback(null, result.document);
  });
};

/**
 * Implements the node.js/browser-specific code for creating a digital
 * signature.
 *
 * @param input the data to sign.
 * @param [options] options to use:
 *          privateKeyPem A PEM-encoded private key.
 *          [date] an optional date to override the signature date with.
 *          [domain] an optional domain to include in the signature.
 *          [nonce] an optional nonce to include in the signature.
 * @param callback(err, signature) called once the operation completes.
 */
var _createSignature = null;
if(_nodejs) {
  _createSignature = function(input, options, callback) {
    // generate base64-encoded signature
    var signer = crypto.createSign('RSA-SHA256');
    if(options.nonce !== null) {
      signer.update(options.nonce);
    }
    signer.update(options.date);

    signer.update(input);
    if(options.domain !== null) {
      signer.update('@' + options.domain);
    }
    var signature = signer.sign(options.privateKeyPem, 'base64');
    callback(null, signature);
  };
} else if(_browser) {
  _createSignature = function(input, options, callback) {
    // FIXME: Implement signature creation in browser using forge
    callback('not implemented');
  };
}

/**
 * Implements the node.js/browser-specific code for creating a digital
 * signature.
 *
 * @param input the data associated with the signature.
 * @param signature the base-64 encoded signature on the data.
 * @param [options] options to use:
 *          publicKeyPem A PEM-encoded public key.
 *          [date] an optional date to override the signature date with.
 *          [domain] an optional domain to include in the signature.
 *          [nonce] an optional nonce to include in the signature.
 * @param callback(err, valid) called once the operation completes.
 */
var _verifySignature = null;
if(_nodejs) {
  _verifySignature = function(input, signature, options, callback) {
    var verifier = crypto.createVerify('RSA-SHA256');
    if(options.nonce) {
      verifier.update(options.nonce);
    }
    verifier.update(options.created);
    verifier.update(input);
    if(options.domain) {
      verifier.update('@' + options.domain);
    }

    var verified = verifier.verify(options.publicKeyPem, signature, 'base64');
    if(!verified) {
      return callback(new Error('[jsigs.verify] ' +
        'The digital signature on the message is invalid.'));
    }
    callback(null, verified);
  };
} else if(_browser) {
  _verifySignature = function(input, options, callback) {
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
    var rval;
    if(Array.isArray(value)) {
      rval = new Array(value.length);
      for(var i = 0; i < rval.length; i++) {
        rval[i] = _deepClone(value[i]);
      }
    } else {
      rval = {};
      for(var j in value) {
        rval[j] = _deepClone(value[j]);
      }
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

})(typeof window !== 'undefined' ? window : this);
