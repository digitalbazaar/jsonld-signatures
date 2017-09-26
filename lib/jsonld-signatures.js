/**
 * An implementation of the Linked Data Signatures specification for JSON-LD.
 * This library works in the browser and node.js.
 *
 * @author Dave Longley <dlongley@digitalbazaar.com>
 * @author David I. Lehn <dlehn@digitalbazaar.com>
 * @author Manu Sporny <msporny@digitalbazaar.com>
 *
 * BSD 3-Clause License
 * Copyright (c) 2014-2017 Digital Bazaar, Inc.
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
 *          [inject] *deprecated*, use `use` API instead; the dependencies to
 *              inject, available global defaults will be used otherwise.
 *            [forge] forge API.
 *            [jsonld] jsonld.js API; all remote documents will be loaded
 *              using jsonld.documentLoader by default, so ensure a secure
 *              document loader is configured.
 */
function wrap(api, options) {

options = options || {};
var libs = {};

/* API Constants */

api.SECURITY_CONTEXT_URL = 'https://w3id.org/security/v1';
api.SUPPORTED_ALGORITHMS = [
  'EcdsaKoblitzSignature2016',
  'GraphSignature2012',
  'LinkedDataSignature2015'
];

/* Core API */

// require Promises
try {
  if(!global.Promise) {
    global.Promise = require('es6-promise').Promise;
  }
  api.Promise = global.Promise;
} catch(e) {
  throw new Error('Unable to find a Promise implementation.');
}

/**
 * Allows injectables to be set or retrieved.
 *
 * @param name the name of the injectable to use (
 *          eg: `jsonld`, `jsonld-signatures`).
 * @param [injectable] the api to set for the injectable, only present for
 *          setter, omit for getter.
 *
 * @return the API for `name` if not using this method as a setter, otherwise
 *   undefined.
 */
api.use = function(name, injectable) {
  // setter mode
  if(injectable) {
    libs[name] = injectable;
    return;
  }

  // getter mode:

  // api not set yet, load default
  if(!libs[name]) {
    var requireAliases = {
      'forge': 'node-forge',
      'bitcoreMessage': 'bitcore-message'
    };
    var requireName = requireAliases[name] || name;
    libs[name] = global[name] || (_nodejs && require(requireName));
    if(name === 'jsonld') {
      if(_nodejs) {
        // locally configure jsonld
        libs[name] = libs[name]();
        libs[name].useDocumentLoader('node', {secure: true, strictSSL: true});
      }
    }
  }
  return libs[name];
};

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
 *          [algorithm] the algorithm to use, eg: 'GraphSignature2012',
 *            'LinkedDataSignature2015' (default: 'GraphSignature2012').
 *          [expansionMap] a custom expansion map that is passed
 *            to the JSON-LD processor; by default a function that will
 *            throw an error when unmapped properties are detected in the
 *            input, use `false` to turn this off and allow unmapped
 *            properties to be dropped or use a custom function.
 * @param callback(err, signedDocument) called once the operation completes.
 */
api.sign = function(input, options, callback) {
  callback = callback || options;
  if(!callback) {
    options = {};
  }
  var privateKeyPem = options.privateKeyPem;
  var privateKeyWif = options.privateKeyWif;
  var creator = options.creator;
  var date = options.date || new Date();
  var domain = options.domain || null;
  var nonce = options.nonce || null;
  var algorithm = options.algorithm || 'GraphSignature2012';

  if(api.SUPPORTED_ALGORITHMS.indexOf(algorithm) === -1) {
    return callback(new Error(
      '[jsigs.sign] Unsupported algorithm "' + algorithm + '"; ' +
      'options.algorithm must be one of: ' +
      JSON.stringify(api.SUPPORTED_ALGORITHMS)));
  }

  if(algorithm === 'EcdsaKoblitzSignature2016') {
    if(typeof privateKeyWif !== 'string') {
      return callback(new TypeError(
        '[jsig.sign] options.privateKeyWif must be a base 58 formatted ' +
        'string.'));
    }
  } else if(typeof privateKeyPem !== 'string') {
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

  var jsonld = api.use('jsonld');

  var normalizeAlgorithm;
  if(algorithm === 'GraphSignature2012') {
    normalizeAlgorithm = 'URGNA2012';
  } else {
    normalizeAlgorithm = 'URDNA2015';
  }

  // TODO: callbackify top-level function and ONLY use promises internally
  var _callback = function(err, result) {
    _invokeCallback(callback, err, result);
  };

  // used to save existing signatures to be added back after signing
  var previousSignature;

  // TODO: frame before getting signature, not just compact? considerations:
  // should the assumption be that the signature is on the top-level object
  // and thus framing is unnecessary?

  var expansionMap;
  if(typeof options.expansionMap === 'function') {
    expansionMap = options.expansionMap;
  } else if(options.expansionMap !== false) {
    expansionMap = function(info) {
      if(info.unmappedProperty) {
        throw new Error('[jsigs.sign] The property "' +
           info.unmappedProperty + '" in the input ' +
          'was not defined in the context.');
      }
    };
  }

  jsonld.promises.compact(
    input, api.SECURITY_CONTEXT_URL, {expansionMap: expansionMap})
    .then(function(compacted) {
      // capture existing signature(s)
      previousSignature = compacted.signature;
      // delete the existing signature(s)
      delete compacted.signature;
      // normalize
      return jsonld.promises.normalize(
        compacted, {
          algorithm: normalizeAlgorithm, format: 'application/nquads'
        });
    })
    // sign
    .then(function(normalized) {
      if(normalized.length === 0) {
        var inputJson = '';
        try {
          inputJson = JSON.stringify(input, null, 2);
        } catch(err) {
          inputJson = 'JSON stringification error: ' + err;
        }
        throw new Error('[jsig.sign] ' +
          'The data to sign is empty. This error may be because a ' +
          '"@context" was not supplied in the input thereby causing ' +
          'any terms or prefixes to be undefined. ' +
          'Input:\n' + inputJson);
      }

      return _createSignature(normalized, {
        algorithm: algorithm,
        privateKeyPem: privateKeyPem,
        privateKeyWif: privateKeyWif,
        date: date,
        nonce: nonce,
        domain: domain
      });
    })
    // compact
    .then(function(signatureValue) {
      // create signature info
      var signature = {
        '@context': api.SECURITY_CONTEXT_URL,
        type: algorithm,
        creator: creator,
        created: date,
        signatureValue: signatureValue
      };
      if(domain !== null) {
        signature.domain = domain;
      }
      if(nonce !== null) {
        signature.nonce = nonce;
      }
      var tmp = {
        'https://w3id.org/security#signature': signature
      };
      var ctx = jsonld.getValues(input, '@context');
      return jsonld.promises.compact(tmp, ctx);
    })
    // add signature
    .then(function(compacted) {
      var output = _deepClone(input);
      delete compacted['@context'];
      var signatureKey = Object.keys(compacted)[0];

      if(previousSignature) {
        output.signature = previousSignature;
      }
      jsonld.addValue(output, signatureKey, compacted[signatureKey]);
      return output;
    })
    .then(_callback.bind(null, null), _callback);
};

/**
 * Verifies a JSON-LD digitally-signed object.
 *
 * @param obj the JSON-LD object to verify.
 * @param [options] the options to use:
 *          [publicKey] DEPRECATED - the JSON-LD document providing the public
 *            key info.
 *          [publicKeyOwner] DEPRECATED - the JSON-LD document providing the
 *            public key owner info including the list of valid keys for that
 *            owner.
 *          [getPublicKey(keyId, options, function(err, publicKey))] a
 *            callback to retrieve the JSON-LD document providing the public
 *            key info.
 *          [getPublicKeyOwner(owner, options, function(err, ownerDoc))]
 *            a callback to retrieve the JSON-LD document providing the
 *            public key owner info including the list of valid keys for that
 *            owner.
 *          [checkNonce(nonce, options, function(err, valid))] a callback to
 *            check if the nonce (null if none) used in the signature is valid.
 *          [checkDomain(domain, options, function(err, valid))] a callback
 *            to check if the domain used (null if none) is valid.
 *          [checkKey(key, options, function(err, trusted))] a callback to
 *            check if the key used to sign the message is trusted.
 *          [checkKeyOwner(owner, key, options, function(err, trusted))] a
 *            callback to check if the key's owner is trusted.
 *          [checkTimestamp]: check signature timestamp (default: false).
 *          [maxTimestampDelta]: signature must be created within a window of
 *            this many seconds (default: 15 minutes).
 *          [documentLoader(url, callback(err, remoteDoc))] the document loader.
 *          [id] the ID (full URL) of the node to check the signature of, if
 *            the input contains multiple signed nodes.
 * @param callback(err, verified) called once the operation completes.
 */
api.verify = function(input, options, callback) {
  if(typeof options === 'function') {
    callback = options;
    options = {};
  }
  options = options || {};
  var jsonld = api.use('jsonld');

  // TODO: frame before getting signature, not just compact? considerations:
  // should the assumption be that the signature is on the top-level object
  // and thus framing is unnecessary?

  // TODO: callbackify top-level function and ONLY use promises internally
  var _callback = function(err, result) {
    _invokeCallback(callback, err, result);
  };

  // compact to get signature and types
  jsonld.promises.compact(input, api.SECURITY_CONTEXT_URL)
    .then(function(compacted) {
      var signature = jsonld.getValues(compacted, 'signature')[0] || null;
      if(!signature) {
        throw new Error('[jsigs.verify] No signature found.');
      }
      var algorithm = jsonld.getValues(signature, 'type')[0] || '';
      if(api.SUPPORTED_ALGORITHMS.indexOf(algorithm) === -1) {
        throw new Error(
          '[jsigs.verify] Unsupported signature algorithm "' + algorithm +
          '"; ' + 'supported algorithms are: ' +
          JSON.stringify(api.SUPPORTED_ALGORITHMS));
      }
      return _verify(algorithm, input, options);
    })
    .then(_callback.bind(null, null), _callback);
};

/* Helper functions */

/**
 * Gets a remote public key.
 *
 * @param id the ID for the public key.
 * @param [options] the options to use:
 *          [documentLoader(url, callback(err, remoteDoc))] the document loader.
 * @param callback(err, key) called once the operation completes.
 */
api.getPublicKey = function(id, options, callback) {
  if(typeof options === 'function') {
    callback = options;
    options = {};
  }
  options = options || {};

  // TODO: callbackify top-level function and ONLY use promises internally
  var _callback = function(err, result) {
    _invokeCallback(callback, err, result);
  };

  api.getJsonLd(id, options, function(err, key) {
    if(err) {
      return callback(err);
    }

    // frame key to validate it
    var frame = {
      '@context': api.SECURITY_CONTEXT_URL,
      type: 'CryptographicKey',
      owner: {'@embed': '@never'}
    };
    var jsonld = api.use('jsonld');
    return jsonld.promises.frame(key, frame)
      .then(function(framed) {
        // FIXME: improve validation
        if(!framed['@graph'][0]) {
          throw new Error('[jsigs.verify] ' +
            'The public key is not a CryptographicKey.');
        }
        // FIXME: other key formats are acceptable, no?
        if(!('publicKeyPem' in framed['@graph'][0])) {
          throw new Error('[jsigs.getPublicKey] ' +
            'Could not get public key. Unknown format.');
        }
        framed['@graph'][0]['@context'] = framed['@context'];
        return framed['@graph'][0];
      }).then(_callback.bind(null, null), _callback);
  });
};

/**
 * Checks to see if the given key is trusted.
 *
 * @param key the public key to check.
 * @param [options] the options to use:
 *          [publicKeyOwner] the JSON-LD document describing the public key
 *            owner.
 *          [checkKeyOwner(owner, key)] a custom method to return whether
 *            or not the key owner is trusted.
 *          [documentLoader(url, callback(err, remoteDoc))] the document loader.
 * @param callback(err, trusted) called once the operation completes.
 */
api.checkKey = function(key, options, callback) {
  if(!(key && typeof key === 'object')) {
    throw new TypeError('`key` must be an object.');
  }
  if(typeof options === 'function') {
    callback = options;
    options = {};
  }
  options = options || {};
  var jsonld = api.use('jsonld');

  // TODO: callbackify top-level function and ONLY use promises internally
  var _callback = function(err, result) {
    _invokeCallback(callback, err, result);
  };

  // frame key
  var frame = {
    '@context': api.SECURITY_CONTEXT_URL,
    type: 'CryptographicKey',
    owner: {'@embed': '@never'}
  };
  var _framedKey;
  jsonld.promises.frame(key, frame).then(function(framed) {
    if(!framed['@graph'][0]) {
      throw new Error('[jsigs.verify] ' +
        'The public key is not a CryptographicKey.');
    }
    if(!framed['@graph'][0].owner) {
      throw new Error('[jsigs.verify] ' +
        'The public key has no specified owner.');
    }
    framed['@graph'][0]['@context'] = framed['@context'];
    return framed['@graph'][0];
  }).then(function(framedKey) {
    _framedKey = framedKey;

    // get framed owner
    if(options.publicKeyOwner && !options.getPublicKeyOwner) {
      options.getPublicKeyOwner =
        _createPublicKeyOwnerGetter(options.publicKeyOwner);
    }
    var getOwner = _normalizeAsyncFn(
      options.getPublicKeyOwner || api.getJsonLd, 2);
    return getOwner(framedKey.owner, options);
  }).then(function(owner) {
    // frame owner
    var frame = {
      '@context': api.SECURITY_CONTEXT_URL,
      '@requireAll': false,
      publicKey: {'@embed': '@never'},
      authenticationCredential: {'@embed': '@never'}
    };
    return jsonld.promises.frame(owner, frame).then(function(framed) {
      return framed['@graph'];
    });
  }).then(function(owners) {
    // check owner...

    // find specific owner of key
    var owner;
    for(var i = 0; i < owners.length; ++i) {
      if(jsonld.hasValue(owners[i], 'publicKey', _framedKey.id) ||
        jsonld.hasValue(owners[i], 'authenticationCredential', _framedKey.id)) {
        owner = owners[i];
        break;
      }
    }
    if(!owner) {
      throw new Error('[jsigs.verify] ' +
        'The public key is not owned by its declared owner.');
    }
    if(!options.checkKeyOwner) {
      return true;
    }
    return _promisify(options.checkKeyOwner, owner, key, options)
      .then(function(trusted) {
        if(!trusted) {
          throw new Error('[jsigs.verify] ' +
            'The owner of the public key is not trusted.');
        }
        return true;
      });
    })
  .then(_callback.bind(null, null), _callback);
};

/**
 * Retrieves a JSON-LD object over HTTP. To implement caching, override
 * this method.
 *
 * @param url the URL to HTTP GET.
 * @param [options] the options to use.
 *          [documentLoader(url, callback(err, remoteDoc))] the document loader.
 * @param callback(err, result) called once the operation completes.
 */
api.getJsonLd = function(url, options, callback) {
  if(typeof options === 'function') {
    callback = options;
    options = {};
  }
  options = options || {};
  var jsonld = api.use('jsonld');

  var documentLoader = options.documentLoader || jsonld.documentLoader;
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

// handle dependency injection
(function() {
  var inject = options.inject || {};
  for(var name in inject) {
    api.use(name, inject[name]);
  }
})();

function _verify(algorithm, input, options) {
  var checkTimestamp = (
    'checkTimestamp' in options ? options.checkTimestamp : false);
  var maxTimestampDelta = (
    'maxTimestampDelta' in options ? options.maxTimestampDelta : (15 * 60));
  var jsonld = api.use('jsonld');

  // FIXME: add support for signed sigs, need to recurse?

  // first frame message to retrieve signature
  // TODO: `frame` also needs to be run for other algorithms once
  // any named graph issues are sorted out with the framing algorithm
  var framePromise;

  if(algorithm === 'GraphSignature2012') {
    var frame = {
      '@context': api.SECURITY_CONTEXT_URL,
      signature: {
        type: algorithm,
        created: {},
        creator: {},
        signatureValue: {}
      }
    };
    if(options.id) {
      frame.id = options.id;
    }
    framePromise = jsonld.promises.frame(input, frame).then(function(framed) {
      var graphs = framed['@graph'];
      if(graphs.length === 0) {
        throw new Error('[jsigs.verify] ' +
          'No signed data found in the provided input.');
      }
      if(graphs.length > 1) {
        throw new Error('[jsigs.verify] ' +
          'More than one signed graph found.');
      }
      var graph = graphs[0];
      // copy the top level framed data context
      graph['@context'] = framed['@context'];
      var signature = graph.signature;
      if(!signature) {
        throw new Error('[jsigs.verify] ' +
          'The message is not digitally signed using a known algorithm.');
      }
      return graph;
    });
  } else {
    // TODO: remove and use `frame` once named graph issues with framing
    // are sorted out
    framePromise = jsonld.promises.compact(input, api.SECURITY_CONTEXT_URL);
  }

  return framePromise.then(function(framed) {
    var signatures = [].concat(framed.signature);

    // create a promise for each signature to be verified
    var p = signatures.map(function(s) {
      // copy the framed object and place a single signature on each copy
      var f = _deepClone(framed);
      f.signature = s;
      return verifySingleSignature(f);
    });
    return Promise.all(p).then(function(results) {
      var signatureMap = {keyResults: []};
      var allVerified = true;
      for(var i = 0; i < results.length; i++) {
        if(!results[i].verified) {
          allVerified = false;
          break;
        }
      }
      signatureMap.verified = allVerified;
      signatureMap.keyResults = results.map(function(result, index) {
        result.publicKey = signatures[index].creator;
        return result;
      });
      return signatureMap;
    });
  });

  function verifySingleSignature(framed) {
    var signature = framed.signature;
    return Promise.all([
      // framed
      Promise.resolve(framed),
      // check nonce
      new Promise(function(resolve, reject) {
        var cb = function(err, valid) {
          if(err) {
            return reject(err);
          }
          if(!valid) {
            return reject(new Error('[jsigs.verify] ' +
              'The message nonce is invalid.'));
          }
          resolve();
        };
        if(!options.checkNonce) {
          return cb(
            null, (signature.nonce === null || signature.nonce === undefined));
        }
        options.checkNonce(signature.nonce, options, cb);
      }),
      // check domain
      new Promise(function(resolve, reject) {
        var cb = function(err, valid) {
          if(err) {
            return reject(err);
          }
          if(!valid) {
            return reject(new Error('[jsigs.verify] ' +
              'The message domain is invalid.'));
          }
          resolve();
        };
        if(!options.checkDomain) {
          return cb(
            null, (signature.domain === null ||
              signature.domain === undefined));
        }
        options.checkDomain(signature.domain, options, cb);
      }),
      // check date
      new Promise(function(resolve, reject) {
        if(!checkTimestamp) {
          return resolve();
        }

        // ensure signature timestamp within a valid range
        var now = new Date().getTime();
        var delta = maxTimestampDelta * 1000;
        try {
          var created = Date.parse(signature.created);
          if(created < (now - delta) || created > (now + delta)) {
            throw new Error('[jsigs.verify] ' +
              'The message digital signature timestamp is out of range.');
          }
        } catch(ex) {
          return reject(ex);
        }
        resolve();
      }),
      // get public key
      new Promise(function(resolve, reject) {
        if(options.publicKey && !options.getPublicKey) {
          options.getPublicKey = _createPublicKeyGetter(options.publicKey);
        }
        // TODO: `api.getPublicKey` should already be normalized
        var getPublicKey = _normalizeAsyncFn(
          options.getPublicKey || api.getPublicKey, 2);
        return getPublicKey(signature.creator, options).then(resolve, reject);
      })
    ]).then(function(results) {
      var framed = results[0];
      var publicKey = results[4];

      // check key
      return new Promise(function(resolve, reject) {
        if('revoked' in publicKey) {
          return reject(new Error('[jsigs.verify] ' +
            'The message was signed with a key that has been revoked.'));
        }
        var cb = function(err, trusted) {
          if(err) {
            return reject(err);
          }
          if(!trusted) {
            return reject(new Error('[jsigs.verify] ' +
              'The message was not signed with a trusted key.'));
          }
          resolve();
        };
        if(options.checkKey) {
          return options.checkKey(publicKey, options, cb);
        }
        api.checkKey(publicKey, options, cb);
      }).then(function() {
        return {
          framed: framed,
          publicKey: publicKey
        };
      });
    }).then(function(results) {
      // normalize...
      // remove signature property from object
      var framed = results.framed;
      var signature = framed.signature;
      delete framed.signature;
      var normalizeAlgorithm = (algorithm === 'GraphSignature2012' ?
        'URGNA2012' : 'URDNA2015');
      return jsonld.promises.normalize(
        framed, {algorithm: normalizeAlgorithm, format: 'application/nquads'})
        .then(function(normalized) {
          return {
            normalized: normalized,
            signature: signature,
            publicKey: results.publicKey
          };
        });
    }).then(function(results) {
      // verify signature
      var key = results.publicKey;
      var signature = results.signature;
      return _verifySignature(results.normalized, signature.signatureValue, {
        algorithm: algorithm,
        publicKeyPem: key.publicKeyPem,
        publicKeyWif: key.publicKeyWif,
        nonce: signature.nonce,
        date: signature.created,
        domain: signature.domain
      });
    }).then(function(verified) {
      return {verified: verified};
    }).catch(function(err) {
      return {
        verified: false,
        error: err.toString()
      };
    });
  }
}

/**
 * Implements the node.js/browser-specific code for creating a digital
 * signature.
 *
 * @param input the data to sign.
 * @param options options to use:
 *          algorithm 'GraphSignature2012' or 'LinkedDataSignature2015'.
 *          privateKeyPem A PEM-encoded private key.
 *          [date] an optional date to override the signature date with.
 *          [domain] an optional domain to include in the signature.
 *          [nonce] an optional nonce to include in the signature.
 *
 * @return a Promise that resolves to the signature or rejects with an error.
 */
var _createSignature = function(input, options) {
  var signature, privateKey;

  if(options.algorithm === 'EcdsaKoblitzSignature2016') {
    // works same in any environment
    var bitcoreMessage = api.use('bitcoreMessage');
    var bitcore = bitcoreMessage.Bitcore;
    privateKey = bitcore.PrivateKey.fromWIF(options.privateKeyWif);
    var message = bitcoreMessage(_getDataToHash(input, options));
    signature = message.sign(privateKey);
    return Promise.resolve(signature);
  }

  if(_nodejs) {
    // optimize using node libraries
    var crypto = api.use('crypto');
    var signer = crypto.createSign('RSA-SHA256');
    signer.update(_getDataToHash(input, options), 'utf8');
    signature = signer.sign(options.privateKeyPem, 'base64');
    return Promise.resolve(signature);
  }

  // browser or other environment
  var forge = api.use('forge');
  privateKey = forge.pki.privateKeyFromPem(options.privateKeyPem);
  var md = forge.md.sha256.create();
  md.update(_getDataToHash(input, options), 'utf8');
  signature = forge.util.encode64(privateKey.sign(md));
  return Promise.resolve(signature);
};

/**
 * Implements the node.js/browser-specific code for creating a digital
 * signature.
 *
 * @param input the data associated with the signature.
 * @param signature the base-64 encoded signature on the data.
 * @param options options to use:
 *          algorithm 'GraphSignature2012' or 'LinkedDataSignature2015'.
 *          publicKeyPem A PEM-encoded public key.
 *          [date] an optional date to override the signature date with.
 *          [domain] an optional domain to include in the signature.
 *          [nonce] an optional nonce to include in the signature.
 *
 * @return a Promise that resolves to a `true` when verified and `false`
 *           when not or rejects with an error.
 */
var _verifySignature = function(input, signature, options) {
  var verified;

  if(options.algorithm === 'EcdsaKoblitzSignature2016') {
    // works same in any environment
    var bitcoreMessage = api.use('bitcoreMessage');
    var message = bitcoreMessage(_getDataToHash(input, options));
    verified = message.verify(options.publicKeyWif, signature);
    return Promise.resolve(verified);
  }

  if(_nodejs) {
    // optimize using node libraries
    var crypto = api.use('crypto');
    var verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(_getDataToHash(input, options), 'utf8');
    verified = verifier.verify(options.publicKeyPem, signature, 'base64');
    return Promise.resolve(verified);
  }

  // browser or other environment
  var forge = api.use('forge');
  var publicKey = forge.pki.publicKeyFromPem(options.publicKeyPem);
  var md = forge.md.sha256.create();
  md.update(_getDataToHash(input, options), 'utf8');
  verified = publicKey.verify(
    md.digest().bytes(), forge.util.decode64(signature));
  return Promise.resolve(verified);
};

function _createPublicKeyGetter(publicKey) {
  return function(keyId, options) {
    if(keyId !== publicKey.id) {
      return Promise.reject(new Error('PublicKey not found.'));
    }
    return Promise.resolve(publicKey);
  };
}

function _createPublicKeyOwnerGetter(publicKeyOwner) {
  return function(owner, options) {
    if(owner !== publicKeyOwner.id) {
      return Promise.reject(new Error('PublicKey owner not found.'));
    }
    return Promise.resolve(publicKeyOwner);
  };
}

function _getDataToHash(input, options) {
  var toHash = '';
  if(options.algorithm === 'GraphSignature2012') {
    if(options.nonce !== null && options.nonce !== undefined) {
      toHash += options.nonce;
    }
    toHash += options.date;
    toHash += input;
    if(options.domain !== null && options.domain !== undefined) {
      toHash += '@' + options.domain;
    }
  } else {
    var headers = {
      'http://purl.org/dc/elements/1.1/created': options.date,
      'https://w3id.org/security#domain': options.domain,
      'https://w3id.org/security#nonce': options.nonce
    };
    // add headers in lexicographical order
    var keys = Object.keys(headers).sort();
    for(var i = 0; i < keys.length; ++i) {
      var key = keys[i];
      var value = headers[key];
      if(value !== null && value !== undefined) {
        toHash += key + ': ' + value + '\n';
      }
    }
    toHash += input;
  }
  return toHash;
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
    _zeroFill(date.getUTCDate()) + 'T' +
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

  // handle 'api' option as version, set defaults
  var papi = options.api || {};
  if(typeof options.api === 'string') {
    papi = {};
  }

  papi.sign = function() {
    if(arguments.length < 2) {
      throw new TypeError('Could not sign, too few arguments.');
    }
    return _promisify.apply(null, [api.sign].concat(slice.call(arguments)));
  };

  papi.verify = function() {
    if(arguments.length < 2) {
      throw new TypeError('Could not verify, too few arguments.');
    }
    return _promisify.apply(null, [api.verify].concat(slice.call(arguments)));
  };

  return papi;
};

/**
 * Converts a node.js async op into a promise w/boxed resolved value(s).
 *
 * @param op the operation to convert.
 *
 * @return the promise.
 */
function _promisify(op) {
  var args = Array.prototype.slice.call(arguments, 1);
  return new Promise(function(resolve, reject) {
    op.apply(null, args.concat(function(err, value) {
      if(!err) {
        resolve(value);
      } else {
        reject(err);
      }
    }));
  });
}

function _normalizeAsyncFn(fn, promiseFnLength) {
  // ensure promise-based function can be called with a callback
  if(fn.length <= promiseFnLength) {
    return _callbackify(fn);
  }

  // ensure callback-based function will return a Promise
  var normalized = function() {
    var callback = arguments[promiseFnLength];
    var args = Array.prototype.slice.call(arguments);
    if(typeof callback === 'function') {
      args.pop();
    }
    return new Promise(function(resolve, reject) {
      args.push(function(err, result) {
        if(typeof callback === 'function') {
          return _invokeCallback(callback, err, result);
        } else if(err) {
          reject(err);
        } else {
          resolve(result);
        }
      });
      try {
        fn.apply(null, args);
      } catch(e) {
        if(typeof callback === 'function') {
          return _invokeCallback(callback, e);
        }
        reject(e);
      }
    });
  };

  // create a function that uses the `promiseFnLength` number of arguments
  var args = [];
  for(var i = 0; i < promiseFnLength; ++i) {
    args.push('a' + i);
  }
  var rval;
  eval('rval = function(' + args.join(',') + ') { ' +
    'return normalized.apply(null, arguments); };');
  return rval;
}

function _callbackify(fn) {
  return function() {
    var args = Array.prototype.slice.call(arguments);
    var callback = args[args.length - 1];
    if(typeof callback === 'function') {
      args.pop();
    }
    return fn.apply(null, args).then(
      // success
      function(result) {
        if(typeof callback === 'function') {
          return _invokeCallback(callback, null, result);
        }
        return result;
      },
      // error
      function(e) {
        if(typeof callback === 'function') {
          return _invokeCallback(callback, e);
        }
        throw e;
      });
  };
}

function _invokeCallback(callback, err, result) {
  // execute on next tick to prevent "unhandled rejected promise"
  // and simulate what would have happened in a promiseless API
  var jsonld = api.use('jsonld');
  jsonld.nextTick(function() { callback(err, result); });
}

// extend default promises call w/promise API
try {
  api.promises({api: api.promises});
} catch(e) {}

return api;

} // end wrap

// used to generate a new verifier API instance
var factory = function(options) {
  return wrap(function() {return factory();}, options);
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
