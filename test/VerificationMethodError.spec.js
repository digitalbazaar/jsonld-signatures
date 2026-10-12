/*!
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */
const chai = require('chai');
chai.should();
const {expect} = chai;

const jsigs = require('../lib/jsonld-signatures');
const {LinkedDataSignature} = jsigs.suites;
const {ControllerProofPurpose} = jsigs.purposes;
const {VerificationMethodError} = jsigs;

const DID_CONTEXT_V1 = 'https://www.w3.org/ns/did/v1';
const CONTROLLER = 'did:example:1234';
const KEY_ID = `${CONTROLLER}#key-1`;

function loaderFor(documents) {
  return jsigs.extendContextLoader(async url => {
    const document = documents[url];
    if(!document) {
      throw new Error(`NotFoundError: "${url}"`);
    }
    return {contextUrl: null, documentUrl: url, document};
  });
}

describe('VerificationMethodError', () => {
  it('should be exported', () => {
    expect(VerificationMethodError).to.be.a('function');
    const error = new VerificationMethodError({
      message: 'test', code: 'notFound', verificationMethod: KEY_ID
    });
    error.should.be.instanceof(Error);
    error.name.should.equal('VerificationMethodError');
    error.code.should.equal('notFound');
    error.verificationMethod.should.equal(KEY_ID);
    error.message.should.equal('test');
  });

  describe('LinkedDataSignature.getVerificationMethod', () => {
    it('should throw "notFound" when the method is not framed', async () => {
      const suite = new LinkedDataSignature({
        type: 'TestSignature', contextUrl: 'https://example.com/ctx'
      });
      const documentLoader = loaderFor({
        [KEY_ID]: {
          '@context': jsigs.SECURITY_CONTEXT_URL,
          id: `${CONTROLLER}#other-key`,
          controller: CONTROLLER
        }
      });
      let error;
      try {
        await suite.getVerificationMethod({
          proof: {verificationMethod: KEY_ID}, documentLoader
        });
      } catch(e) {
        error = e;
      }
      expect(error).to.exist;
      error.name.should.equal('VerificationMethodError');
      error.code.should.equal('notFound');
      error.verificationMethod.should.equal(KEY_ID);
      error.message.should.equal(`Verification method ${KEY_ID} not found.`);
    });
  });

  describe('ControllerProofPurpose.validate', () => {
    const proof = {proofPurpose: 'assertionMethod'};

    it('should throw "notAuthorized" when not listed by controller',
      async () => {
        const purpose = new ControllerProofPurpose({term: 'assertionMethod'});
        const documentLoader = loaderFor({
          [CONTROLLER]: {
            '@context': DID_CONTEXT_V1,
            id: CONTROLLER,
            assertionMethod: [`${CONTROLLER}#other-key`]
          }
        });
        const {valid, error} = await purpose.validate(proof, {
          verificationMethod: {id: KEY_ID, controller: CONTROLLER},
          documentLoader
        });
        valid.should.equal(false);
        error.name.should.equal('VerificationMethodError');
        error.code.should.equal('notAuthorized');
        error.verificationMethod.should.equal(KEY_ID);
        error.message.should.equal(
          `Verification method "${KEY_ID}" not authorized by controller ` +
          'for proof purpose "assertionMethod".');
      });

    it('should throw "invalidId" when the method id is not a string',
      async () => {
        const purpose = new ControllerProofPurpose({term: 'assertionMethod'});
        const {valid, error} = await purpose.validate(proof, {
          verificationMethod: {id: 42, controller: CONTROLLER},
          documentLoader: loaderFor({})
        });
        valid.should.equal(false);
        error.name.should.equal('VerificationMethodError');
        error.code.should.equal('invalidId');
        expect(error.verificationMethod).to.be.undefined;
        error.message.should.equal(
          'Verification method ID "42" must be a string.');
      });
  });
});
