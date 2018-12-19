/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

// determine if using node.js or browser
const nodejs = (
  typeof process !== 'undefined' && process.versions && process.versions.node);
const browser = !nodejs &&
  (typeof window !== 'undefined' || typeof self !== 'undefined');

module.exports = {
  nodejs,
  browser
};
