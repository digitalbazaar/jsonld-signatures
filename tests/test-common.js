/*!
 * Copyright (c) 2014-2018 Digital Bazaar, Inc. All rights reserved.
 */
/* eslint-disable indent */
module.exports = async function(options) {

'use strict';

const {assert, constants, jsigs, mock, suites, util} = options;
const {PublicKeyProofPurpose} = jsigs.purposes;
const {LinkedDataProof} = jsigs.suites;
const {NoOpProofPurpose} = mock;

// helper:
function clone(obj) {
  return JSON.parse(JSON.stringify(obj));
}

const {testLoader} = mock;

// run tests
describe('JSON-LD Signatures', () => {
  context('util', () => {
    it('should base64url encode', async () => {
      const inputs = [
        '',
        '1',
        '12',
        '123',
        '1234',
        '12345',
        [],
        [97],
        [97, 98],
        [97, 98, 99],
        [97, 98, 99, 100],
        [97, 98, 99, 100, 101],
        [0xc3, 0xbb, 0xc3, 0xb0, 0x00],
        [0xc3, 0xbb, 0xc3, 0xb0],
        [0xc3, 0xbb]
      ];
      inputs.forEach(function(input) {
        input = new Uint8Array(input);
        const enc = util.encodeBase64Url(input);
        const dec = util.decodeBase64Url(enc);
        /*
        console.log('E', input, '|', Buffer.from(input));
        console.log('  enc', enc, '|', Buffer.from(enc));
        console.log('  dec', dec, '|', Buffer.from(dec));
        */
        assert.equal(enc.indexOf('+'), -1);
        assert.equal(enc.indexOf('/'), -1);
        assert.equal(enc.indexOf('='), -1);
        assert.equal(input.length, dec.length);
        for(let i = 0; i < input.length; ++i) {
          assert.equal(input[i], dec[i]);
        }
      });
    });

    it('should base64url decode', async () => {
      const inputs = [
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_',
        '_-E',
        '_-E=',
        'AA',
        'eA',
        'eA=',
        'eA==',
      ];
      inputs.forEach(input => {
        const dec = util.decodeBase64Url(input);
        const enc = util.encodeBase64Url(dec);
        /*
        console.log('D', input, '|', Buffer.from(input));
        console.log('  dec', dec, '|', Buffer.from(dec));
        console.log('  enc', enc, '|', Buffer.from(enc));
        */
        assert.equal(input.replace(/=/g, ''), enc);
      });
    });
  });

  context('common', () => {
    it('should fail to sign a document when missing a suite', async () => {
      const testDoc = clone(mock.securityContextTestDoc);
      let err;
      try {
        await jsigs.sign(testDoc);
      } catch(e) {
        err = e;
      }
      assert.exists(err);
      assert.equal(err.message, '"options.suite" is required.');
    });

    it('should fail to sign a document when missing a purpose', async () => {
      const testDoc = clone(mock.securityContextTestDoc);
      let err;
      try {
        await jsigs.sign(testDoc, {
          suite: new suites.Ed25519Signature2018()
        });
      } catch(e) {
        err = e;
      }
      assert.exists(err);
      assert.equal(err.message, '"options.purpose" is required.');
    });

    it('should fail to verify a document when missing a suite', async () => {
      const testDoc = clone(mock.securityContextTestDoc);
      let err;
      try {
        await jsigs.verify(testDoc);
      } catch(e) {
        err = e;
      }
      assert.exists(err);
      assert.equal(err.message, '"options.suite" is required.');
    });

    it('should fail to verify a document when missing a purpose', async () => {
      const testDoc = clone(mock.securityContextTestDoc);
      let err;
      try {
        await jsigs.verify(testDoc, {
          suite: new suites.Ed25519Signature2018()
        });
      } catch(e) {
        err = e;
      }
      assert.exists(err);
      assert.equal(err.message, '"options.purpose" is required.');
    });
  });

  context('custom suite', () => {
    class CustomSuite extends LinkedDataProof {
      constructor() {
        super({type: 'example:CustomSuite'});
      }
      async createProof() {
        return {
          '@context': constants.SECURITY_CONTEXT_URL,
          type: this.type
        };
      }
      async verifyProof() {
        return {verified: true};
      }
    }

    it('should sign a document with a custom suite', async () => {
      const testDoc = clone(mock.securityContextTestDoc);
      const signed = await jsigs.sign(testDoc, {
        documentLoader: testLoader,
        suite: new CustomSuite(),
        purpose: new NoOpProofPurpose()
      });
      const expected = clone(mock.securityContextTestDoc);
      expected.proof = {type: 'example:CustomSuite'};
      assert.deepEqual(signed, expected);
    });

    it('should verify a document with a custom suite', async () => {
      const signed = clone(mock.securityContextTestDoc);
      signed.proof = {type: 'example:CustomSuite'};
      const result = await jsigs.verify(signed, {
        documentLoader: testLoader,
        suite: new CustomSuite(),
        purpose: new NoOpProofPurpose()
      });
      const expected = {
        verified: true,
        results: [{
          proof: {
            '@context': constants.SECURITY_CONTEXT_URL,
            ...signed.proof
          },
          verified: true
        }]
      };
      assert.deepEqual(result, expected);
    });
  });

  const suitesToTest = [
    'Ed25519Signature2018',
    'RsaSignature2018',
    'EcdsaKoblitzSignature2016',
    'LinkedDataSignature2015',
    'GraphSignature2012'
  ];

  for(const suiteName of suitesToTest) {
    // FIXME: still need to test:
    // custom signer and verifier for jws signature
    // custom suite
    // ...once above is added, copy and do each w/callback API

    const pseudorandom = ['EcdsaKoblitzSignature2016', 'RsaSignature2018'];

    context(suiteName + ' w/promise API', () => {
      it('should sign a document w/security context', async () => {
        const Suite = suites[suiteName];
        const suite = new Suite(mock.suites[suiteName].parameters.sign);
        const testDoc = clone(mock.securityContextTestDoc);
        const signed = await jsigs.sign(testDoc, {
          documentLoader: testLoader,
          suite,
          purpose: suite.legacy ?
            new PublicKeyProofPurpose() : new NoOpProofPurpose()
        });
        let expected = mock.suites[suiteName].securityContextSigned;
        if(pseudorandom.includes(suiteName)) {
          expected = clone(expected);
          if(suite.legacy) {
            expected.signature.signatureValue = signed.signature.signatureValue;
          } else {
            expected.proof.jws = signed.proof.jws;
          }
        }
        assert.deepEqual(signed, expected);
      });

      it('should sign a document w/o security context', async () => {
        const Suite = suites[suiteName];
        const suite = new Suite(mock.suites[suiteName].parameters.sign);
        const testDoc = clone(mock.nonSecurityContextTestDoc);
        const signed = await jsigs.sign(testDoc, {
          documentLoader: testLoader,
          suite,
          purpose: suite.legacy ?
            new PublicKeyProofPurpose() : new NoOpProofPurpose()
        });
        let expected = mock.suites[suiteName].nonSecurityContextSigned;
        if(pseudorandom.includes(suiteName)) {
          expected = clone(expected);
          if(suite.legacy) {
            expected.signature['https://w3id.org/security#signatureValue'] =
              signed.signature['https://w3id.org/security#signatureValue'];
          } else {
            expected.proof['https://w3id.org/security#jws'] =
              signed.proof['https://w3id.org/security#jws'];
          }
        }
        assert.deepEqual(signed, expected);
      });

      it('should verify a document w/security context', async () => {
        const Suite = suites[suiteName];
        const suite = new Suite(mock.suites[suiteName].parameters.verify);
        const signed = mock.suites[suiteName].securityContextSigned;
        const result = await jsigs.verify(signed, {
          documentLoader: testLoader,
          suite,
          purpose: suite.legacy ?
            new PublicKeyProofPurpose() : new NoOpProofPurpose()
        });
        const property = suite.legacy ? 'signature' : 'proof';
        const expected = {
          verified: true,
          results: [{
            proof: {
              '@context': constants.SECURITY_CONTEXT_URL,
              ...signed[property]
            },
            verified: true
          }]
        };
        assert.deepEqual(result, expected);
      });

      it('should verify a document w/o security context', async () => {
        const Suite = suites[suiteName];
        const suite = new Suite(mock.suites[suiteName].parameters.verify);
        const signed = mock.suites[suiteName].nonSecurityContextSigned;
        const result = await jsigs.verify(signed, {
          documentLoader: testLoader,
          suite,
          purpose: suite.legacy ?
            new PublicKeyProofPurpose() : new NoOpProofPurpose()
        });
        const property = suite.legacy ? 'signature' : 'proof';
        const expected = {
          verified: true,
          results: [{
            proof: {
              '@context': constants.SECURITY_CONTEXT_URL,
              ...mock.suites[suiteName].securityContextSigned[property]
            },
            verified: true
          }]
        };
        assert.deepEqual(result, expected);
      });

      it('should verify a document w/security context w/passed key',
        async () => {
        const Suite = suites[suiteName];
        const suite = new Suite(
          mock.suites[suiteName].parameters.verifyWithPassedKey);
        const signed = mock.suites[suiteName].securityContextSigned;
        const result = await jsigs.verify(signed, {
          documentLoader: testLoader,
          suite,
          purpose: suite.legacy ?
            new PublicKeyProofPurpose() : new NoOpProofPurpose()
        });
        const property = suite.legacy ? 'signature' : 'proof';
        const expected = {
          verified: true,
          results: [{
            proof: {
              '@context': constants.SECURITY_CONTEXT_URL,
              ...signed[property]
            },
            verified: true
          }]
        };
        assert.deepEqual(result, expected);
      });

      it('should verify a document w/o security context w/passed key',
        async () => {
        const Suite = suites[suiteName];
        const suite = new Suite(
          mock.suites[suiteName].parameters.verifyWithPassedKey);
        const signed = mock.suites[suiteName].nonSecurityContextSigned;
        const result = await jsigs.verify(signed, {
          documentLoader: testLoader,
          suite,
          purpose: suite.legacy ?
            new PublicKeyProofPurpose() : new NoOpProofPurpose()
        });
        const property = suite.legacy ? 'signature' : 'proof';
        const expected = {
          verified: true,
          results: [{
            proof: {
              '@context': constants.SECURITY_CONTEXT_URL,
              ...mock.suites[suiteName].securityContextSigned[property]
            },
            verified: true
          }]
        };
        assert.deepEqual(result, expected);
      });

      it('should detect an invalid signature', async () => {
        const Suite = suites[suiteName];
        const suite = new Suite(mock.suites[suiteName].parameters.verify);
        const signed = mock.suites[suiteName].securityContextInvalidSignature;
        const result = await jsigs.verify(signed, {
          documentLoader: testLoader,
          suite,
          purpose: suite.legacy ?
            new PublicKeyProofPurpose() : new NoOpProofPurpose()
        });
        const property = suite.legacy ? 'signature' : 'proof';
        const expected = {
          verified: false,
          results: [{
            proof: {
              '@context': constants.SECURITY_CONTEXT_URL,
              ...signed[property]
            },
            verified: false
          }]
        };
        assert.isFalse(result.verified);
        assert.isArray(result.results);
        assert.equal(result.results.length, expected.results.length);
        assert.deepEqual(result.results[0].proof, expected.results[0].proof);
        assert.equal(result.results[0].verified, expected.results[0].verified);
        assert.equal(
          result.results[0].error.message,
          'Invalid signature.');
      });

      it('should detect an expired date', async () => {
        const Suite = suites[suiteName];
        const suite = new Suite({
          ...mock.suites[suiteName].parameters.verify,
          date: new Date('01-01-1970'),
          maxTimestampDelta: 0
        });
        const signed = mock.suites[suiteName].securityContextSigned;
        const result = await jsigs.verify(signed, {
          documentLoader: testLoader,
          suite,
          purpose: suite.legacy ?
            new PublicKeyProofPurpose() : new NoOpProofPurpose()
        });
        const property = suite.legacy ? 'signature' : 'proof';
        const expected = {
          verified: false,
          results: [{
            proof: {
              '@context': constants.SECURITY_CONTEXT_URL,
              ...signed[property]
            },
            verified: false
          }]
        };
        assert.isFalse(result.verified);
        assert.isArray(result.results);
        assert.equal(result.results.length, expected.results.length);
        assert.deepEqual(result.results[0].proof, expected.results[0].proof);
        assert.equal(result.results[0].verified, expected.results[0].verified);
        assert.equal(
          result.results[0].error.message,
          'The proof\'s created timestamp is out of range.');
      });

      it('should sign a document with multiple signatures', async () => {
        const Suite = suites[suiteName];
        const suite = new Suite(mock.suites[suiteName].parameters.sign);
        const testDoc = clone(mock.suites[suiteName].securityContextSigned);
        const signed = await jsigs.sign(testDoc, {
          documentLoader: testLoader,
          suite,
          purpose: suite.legacy ?
            new PublicKeyProofPurpose() : new NoOpProofPurpose()
        });
        const property = suite.legacy ? 'signature' : 'proof';
        assert.isArray(signed[property]);
        assert.equal(signed[property].length, 2);
        const expected = clone(mock.suites[suiteName].securityContextSigned);
        expected[property] = [expected[property], clone(expected[property])];
        if(suite.legacy) {
          expected[property][1].signatureValue =
            signed[property][1].signatureValue;
        } else {
          expected[property][1].jws = signed[property][1].jws;
        }
        assert.deepEqual(signed, expected);
      });

      it('should verify a document with multiple set signatures', async () => {
        const Suite = suites[suiteName];
        const suite = new Suite(mock.suites[suiteName].parameters.verify);
        const testDoc = clone(mock.suites[suiteName].securityContextSigned);
        const property = suite.legacy ? 'signature' : 'proof';
        testDoc[property] = [testDoc[property], clone(testDoc[property])];
        const result = await jsigs.verify(testDoc, {
          documentLoader: testLoader,
          suite,
          purpose: suite.legacy ?
            new PublicKeyProofPurpose() : new NoOpProofPurpose()
        });
        const expected = {
          verified: true,
          results: [{
            proof: {
              '@context': constants.SECURITY_CONTEXT_URL,
              ...mock.suites[suiteName].securityContextSigned[property]
            },
            verified: true
          }, {
            proof: {
              '@context': constants.SECURITY_CONTEXT_URL,
              ...mock.suites[suiteName].securityContextSigned[property]
            },
            verified: true
          }]
        };
        assert.deepEqual(result, expected);
      });
    });
  }
});

};
