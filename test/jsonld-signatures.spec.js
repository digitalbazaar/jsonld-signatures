/*!
 * Copyright (c) 2020-2021 Digital Bazaar, Inc. All rights reserved.
 */
const chai = require('chai');
chai.should();
const {expect} = chai;

const jsigs = require('../lib/jsonld-signatures');

/**
 * NOTE: The existing test suite has been extracted to each individual signature
 * suite's repository.
 *
 * Test coverage of this package currently depends on indirect testing through
 * other test suites.
 */
describe('jsonld-signatures', () => {
  it('should exist', async () => {
    expect(jsigs).to.exist;
  });
});
