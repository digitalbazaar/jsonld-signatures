/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
module.exports = {
  root: true,
  env: {
    node: true
  },
  extends: [
    'digitalbazaar',
    // 'digitalbazaar/jsdoc'
  ],
  ignorePatterns: ['node_modules', 'dist'],
  rules: {
    'jsdoc/check-examples': 0,
    'jsdoc/require-description-complete-sentence': 0
  }
};
