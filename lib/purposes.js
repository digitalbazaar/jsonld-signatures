/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const Injector = require('./Injector');

const api = {};
module.exports = api;

const injector = new Injector({useDefault: false});
api.proofPurposes = {
  use: injector.use.bind(injector)
};
