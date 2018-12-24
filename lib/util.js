/*
 * Copyright (c) 2017-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const env = require('./env');
const forge = require('node-forge');

const api = {};
module.exports = api;

// FIXME: remove `setImmediate` and `nextTick`

// define setImmediate and nextTick
//// nextTick implementation with browser-compatible fallback ////
// from https://github.com/caolan/async/blob/master/lib/async.js

// capture the global reference to guard against fakeTimer mocks
const _setImmediate = typeof setImmediate === 'function' && setImmediate;

const _delay = _setImmediate ?
  // not a direct alias (for IE10 compatibility)
  fn => _setImmediate(fn) :
  fn => setTimeout(fn, 0);

if(typeof process === 'object' && typeof process.nextTick === 'function') {
  api.nextTick = process.nextTick;
} else {
  api.nextTick = _delay;
}
api.setImmediate = _setImmediate ? _delay : api.nextTick;

api.createJws = createJwsFactory();

// FIXME: remove `deepClone`

/**
 * Clones a value. If the value is an array or an object it will be deep cloned.
 *
 * @param value the value to clone.
 *
 * @return the cloned value.
 */
api.deepClone = value => {
  if(value && typeof value === 'object') {
    let rval;
    if(Array.isArray(value)) {
      rval = new Array(value.length);
      for(let i = 0; i < rval.length; ++i) {
        rval[i] = api.deepClone(value[i]);
      }
    } else {
      rval = {};
      for(const j in value) {
        rval[j] = api.deepClone(value[j]);
      }
    }
    return rval;
  }
  return value;
};

/**
 * Converts the given date into W3C datetime format (eg: 2011-03-09T21:55:41Z).
 *
 * @param date the date to convert.
 *
 * @return the date in W3C datetime format.
 */
api.w3cDate = date => {
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
};

api.callbackify = fn => {
  return async function(...args) {
    const callback = args[args.length - 1];
    if(typeof callback === 'function') {
      args.pop();
    }

    let result;
    try {
      result = await fn.apply(null, args);
    } catch(e) {
      if(typeof callback === 'function') {
        return _invokeCallback(callback, e);
      }
      throw e;
    }

    if(typeof callback === 'function') {
      return _invokeCallback(callback, null, result);
    }

    return result;
  };
};

api.normalizeAsyncFn = (fn, promiseFnLength) => {
  // ensure promise-based function can be called with a callback
  if(fn.length <= promiseFnLength) {
    return api.callbackify(fn);
  }

  // ensure callback-based function will return a Promise
  return async function(...args) {
    const callback = arguments[promiseFnLength];
    if(typeof callback === 'function') {
      args.pop();
    }
    return new Promise((resolve, reject) => {
      args.push((err, result) => {
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
};

function _invokeCallback(callback, err, result) {
  // execute on next tick to prevent "unhandled rejected promise"
  // and simulate what would have happened in a promiseless API
  api.nextTick(() => callback(err, result));
}

function _zeroFill(num) {
  return (num < 10) ? '0' + num : '' + num;
}

/**
 * Encodes input according to the "Base64url Encoding" format as specified
 * in JSON Web Signature (JWS) RFC7517. A URL safe character set is used and
 * trailing '=', line breaks, whitespace, and other characters are omitted.
 *
 * @param data {Uint8Array} the data to encode.
 *
 * @return {String} the encoded value.
 */
api.encodeBase64Url = base64urlEncodeFactory();

/**
 * Decodes input according to the "Base64url Encoding" format as specified
 * in JSON Web Signature (JWS) RFC7517. A URL safe character set is used and
 * trailing '=', line breaks, whitespace, and other characters are omitted.
 *
 * @param string {String} the string to decode.
 *
 * @return {Uint8Array} the decoded value.
 */
api.decodeBase64Url = base64urlDecodeFactory();

/**
 * Decodes input according to the "Base64url Encoding" format as specified
 * in JSON Web Signature (JWS) RFC7517. A URL safe character set is used and
 * trailing '=', line breaks, whitespace, and other characters are omitted.
 *
 * @param string {String} the string to decode.
 *
 * @return {String} the decoded value as a string.
 */
api.decodeBase64UrlToString = base64urlDecodeToStringFactory();

/**
 * Hashes a string of data using SHA-256.
 *
 * @param string {String} the string to hash.
 * @param encoding {String} the string's encoding (e.g. 'utf8').
 *
 * @return {Uint8Array} the hash digest.
 */
api.sha256 = sha256Factory();

/**
 * Concatenates two Uint8Arrays.
 *
 * @param b1 {Uint8Array}.
 * @param b2 {Uint8Array}.
 *
 * @return {Uint8Array} the result.
 */
api.concat = concatFactory();

/**
 * Converts a string to a Uint8Array.
 *
 * @param string {String}.
 * @param encoding {String}, e.g. 'utf8'.
 *
 * @return {Uint8Array} the result.
 */
api.stringToBytes = stringToBytesFactory();

function stringToBytesFactory() {
  if(env.nodejs) {
    return (string, encoding) => {
      const buffer = Buffer.from(string, encoding);
      return new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.length);
    };
  }
  return (string, encoding) => {
    const buffer = new forge.util.ByteBuffer(string, encoding);
    return forge.util.binary.raw.decode(buffer.getBytes());
  };
}

function concatFactory() {
  if(env.nodejs) {
    return (b1, b2) => {
      const buffer = Buffer.concat([
        Buffer.from(b1.buffer, b1.byteOffset, b1.length),
        Buffer.from(b2.buffer, b2.byteOffset, b2.length)]);
      return new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.length);
    };
  }
  return (b1, b2) => {
    const rval = new Uint8Array(b1.length + b2.length);
    rval.set(b1, 0);
    rval.set(b2, b1.length);
    return rval;
  };
}

function sha256Factory() {
  if(env.nodejs) {
    const crypto = require('crypto');
    return (string, encoding) => {
      const hash = crypto.createHash('sha256');
      hash.update(string, encoding);
      const buffer = hash.digest();
      return new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.length);
    };
  }
  return (string, encoding) => {
    const md = forge.md.sha256.create();
    md.update(string, encoding || 'utf8');
    const buffer = md.digest();
    return forge.util.binary.raw.decode(buffer.getBytes());
  };
}

function createJwsFactory() {
  if(env.nodejs) {
    return ({encodedHeader, verifyData}) => {
      const buffer = Buffer.concat([
        Buffer.from(encodedHeader + '.', 'utf8'),
        Buffer.from(verifyData.buffer, verifyData.byteOffset, verifyData.length)
      ]);
      return new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.length);
    };
  }
  return ({encodedHeader, verifyData}) => {
    const buffer = new forge.util.ByteBuffer(encodedHeader + '.', 'utf8');
    const binaryString = forge.util.binary.raw.encode(verifyData);
    buffer.putBytes(binaryString);
    return forge.util.binary.raw.decode(buffer.getBytes());
  };
}

function base64urlEncodeFactory() {
  if(env.nodejs) {
    const base64url = require('base64url');
    return data => {
      if(typeof data === 'string') {
        return base64url(data);
      }
      return base64url(Buffer.from(data.buffer, data.byteOffset, data.length));
    };
  }
  return data => {
    let binaryString;
    if(typeof data === 'string') {
      binaryString = forge.util.encodeUtf8(data);
    } else {
      binaryString = forge.util.binary.raw.encode(data);
    }
    const enc = forge.util.encode64(binaryString);
    return enc.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  };
}

function base64urlDecodeFactory() {
  if(env.nodejs) {
    const base64url = require('base64url');
    return string => {
      const buffer = base64url.toBuffer(string);
      return new Uint8Array(buffer.buffer, buffer.offset, buffer.length);
    };
  }
  return string => {
    // FIXME: forge supports alternative alphabets now -- use that instead?
    // convert to regular base64 encoding and then decode
    let base64 = string.replace(/-/g, '+').replace(/_/g, '/');
    const mod4 = base64.length % 4;
    if(mod4 === 0) {
      // pass
    } else if(mod4 === 2) {
      base64 = base64 + '==';
    } else if(mod4 === 3) {
      base64 = base64 + '=';
    } else {
      throw new Error('Illegal base64 string.');
    }
    return forge.util.binary.base64.decode(base64);
  };
}

function base64urlDecodeToStringFactory() {
  if(env.nodejs) {
    const base64url = require('base64url');
    return string => base64url.decode(string);
  }
  return string => {
    // FIXME: forge supports alternative alphabets now -- use that instead?
    // convert to regular base64 encoding and then decode
    let base64 = string.replace(/-/g, '+').replace(/_/g, '/');
    const mod4 = base64.length % 4;
    if(mod4 === 0) {
      // pass
    } else if(mod4 === 2) {
      base64 = base64 + '==';
    } else if(mod4 === 3) {
      base64 = base64 + '=';
    } else {
      throw new Error('Illegal base64 string.');
    }
    const binaryString = forge.util.decode64(base64);
    return forge.util.decodeUtf8(binaryString);
  };
}
