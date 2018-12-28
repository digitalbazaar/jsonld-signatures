/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const ControllerProofPurpose = require('./ControllerProofPurpose');

module.exports = class AssertionProofPurpose extends ControllerProofPurpose {
  constructor({
    term = 'assertionMethod', controller,
    date, maxTimestampDelta = Infinity} = {}) {
    super({term, controller, date, maxTimestampDelta});
  }
};
