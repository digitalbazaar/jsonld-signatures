/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
const chai = require('chai');
chai.use(require('dirty-chai'));
chai.should();
const {expect} = chai;

const jsigs = require('../../');

describe('jsonld-signatures', () => {
  it('should exist', async () => {
    expect(jsigs).to.exist();
  });
});
