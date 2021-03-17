/*
 * Copyright (c) 2017-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const env = require('./env');
const forge = require('node-forge');

const api = {};
module.exports = api;

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
  const str = date.toISOString();
  return str.substr(0, str.length - 5) + 'Z';
};

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
