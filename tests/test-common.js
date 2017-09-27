/**
 * Test runner for JSON-LD Signatures library.
 *
 * @author Dave Longley <dlongley@digitalbazaar.com>
 * @author Manu Sporny <msporny@digitalbazaar.com>
 *
 * Copyright (c) 2014-2017 Digital Bazaar, Inc. All rights reserved.
 */

module.exports = function(options) {

'use strict';

const assert = options.assert;
const jsonld = options.jsonld;
const jsigs = options.jsigs;
const jws = options.jws;

var testLoader = function(url, callback) {
  if(url === 'https://w3id.org/security/v1') {
    return callback(null, {
      contextUrl: null,
      document: securityContext,
      documentUrl: 'https://web-payments.org/contexts/security-v1.jsonld'
    });
  }
  if(url === testPublicKeyUrl) {
    return callback(null, {
      contextUrl: null,
      document: testPublicKey,
      documentUrl: testPublicKeyUrl
    });
  }
  if(url === testPublicKeyUrl2) {
    return callback(null, {
      contextUrl: null,
      document: testPublicKey2,
      documentUrl: testPublicKeyUrl2
    });
  }
  if(url === testPublicKeyOwner.id) {
    return callback(null, {
      contextUrl: null,
      document: testPublicKeyOwner,
      documentUrl: testPublicKeyOwner.id
    });
  }
  if(url === testPublicKeyOwner2.id) {
    return callback(null, {
      contextUrl: null,
      document: testPublicKeyOwner2,
      documentUrl: testPublicKeyOwner2.id
    });
  }
};

// setup
jsonld.documentLoader = testLoader;
jsigs.use('jsonld', jsonld);

// helper:
function clone(obj) {
  return JSON.parse(JSON.stringify(obj));
}

// run tests
describe('JSON-LD Signatures', function() {
  context('common', function() {
    const forge = jsigs.use('forge');

    var testDocument = {
      '@context': {
        schema: 'http://schema.org/',
        name: 'schema:name',
        homepage: 'schema:url',
        image: 'schema:image'
      },
      name: 'Manu Sporny',
      homepage: 'https://manu.sporny.org/',
      image: 'https://manu.sporny.org/images/manu.png'
    };

    var testBadDocument = clone(testDocument);
    testBadDocument['https://w3id.org/security#signature'] = {
      '@type': 'https://w3id.org/security#BogusSignature3000',
      'http://purl.org/dc/terms/created': {
        '@type': 'http://www.w3.org/2001/XMLSchema#dateTime',
        '@value': '2017-03-25T22:01:04Z'
      },
      'http://purl.org/dc/terms/creator': {
        '@id': 'test:1234'
      },
      'https://w3id.org/security#signatureValue': 'test'
    };

    it('should fail sign with unknown algorithm', function(done) {
      jsigs.sign(testDocument, {
        algorithm: 'BogusSignature3000',
        privateKeyPem: '',
        creator: ''
      }, function(err, signedDocument) {
        assert(err);
        done();
      });
    });

    it('should fail verify with unknown algorithm', function(done) {
      jsigs.verify(testBadDocument, {}, function(err, result) {
        assert.ifError(err);
        assert.equal(result.verified, false, 'signature verification passed');
        done();
      });
    });

    it('should base64url encode', function(done) {
      var inputs = [
        '',
        '1',
        '12',
        '123',
        '1234',
        '12345',
        Buffer.from([0xc3,0xbb,0xc3,0xb0,0x00]).toString(),
        Buffer.from([0xc3,0xbb,0xc3,0xb0]).toString(),
        Buffer.from([0xc3,0xbb]).toString()
      ];
      inputs.forEach(function(input) {
        var enc = jsigs._encodeBase64Url(input, {forge});
        var dec = jsigs._decodeBase64Url(enc, {forge});
        /*
        console.log('E', input, '|', Buffer.from(input));
        console.log('  enc', enc, '|', Buffer.from(enc));
        console.log('  dec', dec, '|', Buffer.from(dec));
        */
        assert.equal(enc.indexOf('+'), -1);
        assert.equal(enc.indexOf('/'), -1);
        assert.equal(enc.indexOf('='), -1);
        assert.equal(input, dec);
      });
      done()
    });

    it('should base64url decode', function(done) {
      var inputs = [
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_',
        '_-E',
        '_-E=',
        'AA',
        'eA',
        'eA=',
        'eA==',
      ];
      inputs.forEach(function(input) {
        var dec = jsigs._decodeBase64Url(input, {forge});
        var enc = jsigs._encodeBase64Url(dec, {forge});
        /*
        console.log('D', input, '|', Buffer.from(input));
        console.log('  dec', dec, '|', Buffer.from(dec));
        console.log('  enc', enc, '|', Buffer.from(enc));
        */
        assert.equal(input.replace(/=/g, ''), enc);
      });
      done()
    });
  });

  context('with NO security context', function() {
    // the test document that will be signed
    var testDocument = {
      '@context': {
        schema: 'http://schema.org/',
        name: 'schema:name',
        homepage: 'schema:url',
        image: 'schema:image'
      },
      name: 'Manu Sporny',
      homepage: 'https://manu.sporny.org/',
      image: 'https://manu.sporny.org/images/manu.png'
    };
    var testDocumentSigned = {};

    describe('signing and verify Graph2012', function() {
      it('should successfully sign a local document', function(done) {
        jsigs.sign(testDocument, {
          algorithm: 'GraphSignature2012',
          privateKeyPem: testPrivateKeyPem,
          creator: testPublicKeyUrl
        }, function(err, signedDocument) {
          assert.ifError(err);
          assert.notEqual(
            signedDocument['https://w3id.org/security#signature'], undefined,
            'signature was not created');
          assert.equal(
            signedDocument['https://w3id.org/security#signature']
              ['http://purl.org/dc/terms/creator']['@id'], testPublicKeyUrl,
            'creator key for signature is wrong');
          testDocumentSigned = signedDocument;
          done();
        });
      });

      it('should successfully verify a local signed document', function(done) {
        jsigs.verify(testDocumentSigned, {
          publicKey: testPublicKey,
          publicKeyOwner: testPublicKeyOwner
        }, function(err, result) {
          assert.ifError(err);
          assert.equal(result.verified, true, 'signature verification failed');
          done();
        });
      });

      it('should successfully sign a local document w/promises API',
        function(done) {
          jsigs.promises.sign(testDocument, {
            algorithm: 'GraphSignature2012',
            privateKeyPem: testPrivateKeyPem,
            creator: testPublicKeyUrl
          }).then(function(signedDocument) {
            assert.notEqual(
              signedDocument['https://w3id.org/security#signature'], undefined,
              'signature was not created');
            assert.equal(
              signedDocument['https://w3id.org/security#signature']
                ['http://purl.org/dc/terms/creator']['@id'], testPublicKeyUrl,
              'creator key for signature is wrong');
            testDocumentSigned = signedDocument;
          }).catch(function(err) {
            assert.ifError(err);
          }).then(done, done);
        });

      it('should successfully verify a local signed document w/promises API',
        function(done) {
          jsigs.promises.verify(testDocumentSigned, {
            publicKey: testPublicKey,
            publicKeyOwner: testPublicKeyOwner
          }).then(function(result) {
            assert.equal(
              result.verified, true, 'signature verification failed');
          }).catch(function(err) {
            assert.ifError(err);
          }).then(done, done);
        });

    });

    describe('signing and verify LinkedDataSignature2015', function() {
      describe('single signature', function() {
        it('should successfully sign a local document', function(done) {
          jsigs.sign(testDocument, {
            algorithm: 'LinkedDataSignature2015',
            privateKeyPem: testPrivateKeyPem,
            creator: testPublicKeyUrl
          }, function(err, signedDocument) {
            assert.ifError(err);
            assert.notEqual(
              signedDocument['https://w3id.org/security#signature'], undefined,
              'signature was not created');
            assert.equal(
              signedDocument['https://w3id.org/security#signature']
                ['http://purl.org/dc/terms/creator']['@id'], testPublicKeyUrl,
              'creator key for signature is wrong');
            testDocumentSigned = signedDocument;
            done();
          });
        });

        it('should successfully verify a local signed document',
          function(done) {
            jsigs.verify(testDocumentSigned, {
              publicKey: testPublicKey,
              publicKeyOwner: testPublicKeyOwner
            }, function(err, result) {
              assert.ifError(err);
              assert.equal(result.keyResults[0].error, undefined);
              assert.equal(
                result.verified, true, 'signature verification failed');
              done();
            });
          });

        it('verify local document using getPublicKey and getPublicKeyOwner',
          function(done) {
            jsigs.sign(testDocument, {
              algorithm: 'LinkedDataSignature2015',
              privateKeyPem: testPrivateKeyPem3,
              creator: testPublicKeyUrl3
            }, function(err, signedDocument) {
              assert.ifError(err);
              jsigs.verify(signedDocument, {
                getPublicKey: _publicKeyGetter,
                getPublicKeyOwner: _publicKeyOwnerGetter
              }, function(err, result) {
                assert.ifError(err);
                assert.equal(result.keyResults[0].error, undefined);
                assert.isTrue(result.verified, 'signature verification failed');
                done();
              });
            });
          });

        it('should successfully sign a local document w/promises API',
          function(done) {
            jsigs.sign(testDocument, {
              algorithm: 'LinkedDataSignature2015',
              privateKeyPem: testPrivateKeyPem,
              creator: testPublicKeyUrl
            }).then(function(signedDocument) {
              assert.notEqual(
                signedDocument['https://w3id.org/security#signature'],
                undefined, 'signature was not created');
              assert.equal(
                signedDocument['https://w3id.org/security#signature']
                  ['http://purl.org/dc/terms/creator']['@id'], testPublicKeyUrl,
                'creator key for signature is wrong');
              testDocumentSigned = signedDocument;
            }).catch(function(err) {
              assert.ifError(err);
            }).then(done, done);
          });

        it('should successfully verify a local signed document w/promises API',
          function(done) {
            jsigs.verify(testDocumentSigned, {
              publicKey: testPublicKey,
              publicKeyOwner: testPublicKeyOwner
            }).then(function(result) {
              assert.equal(
                result.verified, true, 'signature verification failed');
            }).catch(function(err) {
              assert.ifError(err);
            }).then(done, done);
          });

        it('verify local document using getPublicKey and getPublicKeyOwner ' +
          'w/Promises API',function(done) {
          jsigs.sign(testDocument, {
            algorithm: 'LinkedDataSignature2015',
            privateKeyPem: testPrivateKeyPem3,
            creator: testPublicKeyUrl3
          }).then(function(signedDocument) {
            return jsigs.promises.verify(signedDocument, {
              getPublicKey: _publicKeyGetterPromise,
              getPublicKeyOwner: _publicKeyOwnerGetterPromise});
          }).then(function(result) {
            assert.equal(result.keyResults[0].error, undefined);
            assert.isTrue(result.verified, 'signature verification failed');
          }).then(done, done);
        });
      }); // end single signature

      describe('multiple signatures', function() {
        it('should successfully sign a local document', function(done) {
          jsigs.sign(testDocument, {
            algorithm: 'LinkedDataSignature2015',
            privateKeyPem: testPrivateKeyPem,
            creator: testPublicKeyUrl
          }, function(err, signedDocument) {
            // add a second signature
            jsigs.sign(signedDocument, {
              algorithm: 'LinkedDataSignature2015',
              privateKeyPem: testPrivateKeyPem2,
              creator: testPublicKeyUrl2
            }, function(err, signedDocument) {
              assert.ifError(err);
              assert.notEqual(
                signedDocument['https://w3id.org/security#signature'],
                undefined, 'signature was not created');
              assert.isArray(
                signedDocument['https://w3id.org/security#signature']);
              assert.equal(
                signedDocument['https://w3id.org/security#signature'].length,
                2);
              assert.equal(
                signedDocument['https://w3id.org/security#signature'][0]
                  ['http://purl.org/dc/terms/creator']['@id'],
                testPublicKeyUrl,
                'creator key for the first signature is wrong');
              assert.equal(
                signedDocument['https://w3id.org/security#signature'][1]
                  ['http://purl.org/dc/terms/creator']['@id'],
                testPublicKeyUrl2,
                'creator key for the second signature is wrong');
              testDocumentSigned = signedDocument;
              done();
            });
          });
        });
        it('should successfully verify a local signed document',
          function(done) {
            jsigs.verify(testDocumentSigned, {}, function(err, result) {
              assert.ifError(err);
              assert.equal(result.keyResults[0].error, undefined);
              assert.isBoolean(result.verified);
              assert.isTrue(result.verified,'signature verification failed');
              assert.isArray(result.keyResults);
              assert.equal(result.keyResults.length, 2);
              assert.isObject(result.keyResults[0]);
              assert.isObject(result.keyResults[1]);
              assert.isBoolean(result.keyResults[0].verified);
              assert.isTrue(result.keyResults[0].verified);
              assert.equal(result.keyResults[0].publicKey, testPublicKeyUrl);
              assert.isBoolean(result.keyResults[1].verified);
              assert.isTrue(result.keyResults[1].verified);
              assert.equal(result.keyResults[1].publicKey, testPublicKeyUrl2);
              done();
            });
          });
        it('return error when publicKey and publicKeyOwner options are used',
          function(done) {
            jsigs.verify(testDocumentSigned, {
              publicKey: testPublicKey,
              publicKeyOwner: testPublicKeyOwner
            }, function(err, result) {
              assert.ifError(err);
              assert.equal(result.keyResults[0].error, undefined);
              assert.notEqual(result.keyResults[1].error, undefined);
              assert.isFalse(result.verified);
              assert.isArray(result.keyResults);
              assert.equal(result.keyResults.length, 2);
              assert.isObject(result.keyResults[0]);
              assert.isObject(result.keyResults[1]);
              assert.isBoolean(result.keyResults[0].verified);
              assert.isTrue(result.keyResults[0].verified);
              assert.equal(result.keyResults[0].publicKey, testPublicKeyUrl);
              assert.isBoolean(result.keyResults[1].verified);
              assert.isFalse(result.keyResults[1].verified);
              assert.equal(
                result.keyResults[1].error.toString(),
                'Error: Public key not found.');
              assert.equal(result.keyResults[1].publicKey, testPublicKeyUrl2);
              done();
            });
          });
        it('should successfully sign a local document w/promises API',
          function(done) {
            jsigs.sign(testDocument, {
              algorithm: 'LinkedDataSignature2015',
              privateKeyPem: testPrivateKeyPem,
              creator: testPublicKeyUrl
            }).then(function(signedDocument) {
              return jsigs.sign(signedDocument, {
                algorithm: 'LinkedDataSignature2015',
                privateKeyPem: testPrivateKeyPem2,
                creator: testPublicKeyUrl2
              });
            }).then(function(signedDocument) {
              assert.notEqual(
                signedDocument['https://w3id.org/security#signature'],
                undefined, 'signature was not created');
              assert(Array.isArray(
                signedDocument['https://w3id.org/security#signature']));
              assert.equal(
                signedDocument['https://w3id.org/security#signature'].length,
                2);
              assert.equal(
                signedDocument['https://w3id.org/security#signature'][0]
                  ['http://purl.org/dc/terms/creator']['@id'], testPublicKeyUrl,
                'creator key for the first signature is wrong');
              assert.equal(
                signedDocument['https://w3id.org/security#signature'][1]
                  ['http://purl.org/dc/terms/creator']['@id'],
                testPublicKeyUrl2,
                'creator key for the second signature is wrong');
              testDocumentSigned = signedDocument;
            }).catch(function(err) {
              assert.ifError(err);
            }).then(done, done);
          });
        it('should successfully verify a local signed document w/promises API',
          function(done) {
            jsigs.verify(testDocumentSigned, {})
              .then(function(result) {
                assert.isBoolean(result.verified);
                assert.isTrue(result.verified,'signature verification failed');
                assert.isArray(result.keyResults);
                assert.equal(result.keyResults.length, 2);
                assert.isObject(result.keyResults[0]);
                assert.isObject(result.keyResults[1]);
                assert.isBoolean(result.keyResults[0].verified);
                assert.isTrue(result.keyResults[0].verified);
                assert.equal(result.keyResults[0].publicKey, testPublicKeyUrl);
                assert.isBoolean(result.keyResults[1].verified);
                assert.isTrue(result.keyResults[1].verified);
                assert.equal(result.keyResults[1].publicKey, testPublicKeyUrl2);
              }).catch(function(err) {
                assert.ifError(err);
              }).then(done, done);
          });
      }); // end multiple signatures
    }); // end signing and verify Graph2015

    describe('signing and verify EcdsaKoblitzSignature2016', function() {

      var testDocument;
      var testDocumentSigned;
      var testPrivateKeyWif;
      var testPublicKeyWif;
      var testPublicKeyFriendly;
      var testPublicKeyBtc;
      var testPublicKeyBtcOwner;
      var invalidPublicKeyWif;
      var testDocumentSignedAltered;

      beforeEach(function() {
        testDocument = {
          '@context': {
            schema: 'http://schema.org/',
            name: 'schema:name',
            homepage: 'schema:url',
            image: 'schema:image'
          },
          name: 'Manu Sporny',
          homepage: 'https://manu.sporny.org/',
          image: 'https://manu.sporny.org/images/manu.png'
        };

        testDocumentSigned = clone(testDocument);
        testDocumentSigned["https://w3id.org/security#signature"] = {
          "@type": "https://w3id.org/security#EcdsaKoblitzSignature2016",
          "http://purl.org/dc/terms/created": {
            "@type": "http://www.w3.org/2001/XMLSchema#dateTime",
            "@value": "2017-03-25T22:01:04Z"
          },
          "http://purl.org/dc/terms/creator": {
            "@id": "ecdsa-koblitz-pubkey:1LGpGhGK8whX23ZNdxrgtjKrek9rP4xWER"
          },
          "https://w3id.org/security#signatureValue":
            "IOoF0rMmpcdxNZFoirTpRMCyLr8kGHLqXFl7v+m3naetCx+OLNhVY/6SCUwDGZf" +
            "Fs4yPXeAl6Tj1WgtLIHOVZmw="
        };
        testDocumentSignedAltered = clone(testDocumentSigned);
        testDocumentSignedAltered.name = 'Manu Spornoneous';

        testPrivateKeyWif =
          'L4mEi7eEdTNNFQEWaa7JhUKAbtHdVvByGAqvpJKC53mfiqunjBjw';
        testPublicKeyWif = '1LGpGhGK8whX23ZNdxrgtjKrek9rP4xWER';
        testPublicKeyFriendly = 'ecdsa-koblitz-pubkey:' + testPublicKeyWif;

        testPublicKeyBtc = {
          '@context': jsigs.SECURITY_CONTEXT_URL,
          id: testPublicKeyFriendly,
          type: 'CryptographicKey',
          owner: 'https://example.com/i/alice',
          publicKeyWif: testPublicKeyWif
        };

        testPublicKeyBtcOwner = {
          '@context': jsigs.SECURITY_CONTEXT_URL,
          id: 'https://example.com/i/alice',
          publicKey: [testPublicKeyFriendly]
        };

        invalidPublicKeyWif = '1BHdCBqQ1GQLfHVEnoXtYf44T97aEHodwe';
      });

      it('should successfully sign a local document', function(done) {
        jsigs.sign(testDocument, {
          algorithm: 'EcdsaKoblitzSignature2016',
          privateKeyWif: testPrivateKeyWif,
          creator: testPublicKeyFriendly
        }, function(err, signedDocument) {
          assert.ifError(err);
          assert.notEqual(
            signedDocument['https://w3id.org/security#signature'], undefined,
            'signature was not created');
          assert.equal(
            signedDocument['https://w3id.org/security#signature']
              ['http://purl.org/dc/terms/creator']['@id'],
            testPublicKeyFriendly,
            'creator key for signature is wrong');
          done();
        });
      });

      it('should successfully verify a local signed document', function(done) {
        jsigs.verify(testDocumentSigned, {
          publicKey: testPublicKeyBtc,
          publicKeyOwner: testPublicKeyBtcOwner,
          // timestamp is quite old, do not check it, it is used to ensure
          // a static document is being checked
          checkTimestamp: false
        }, function(err, result) {
          assert.ifError(err);
          assert.equal(result.verified, true, 'signature verification failed');
          done();
        });
      });

      it('verify should return false if the document was signed by a ' +
        'different private key', function(done) {
        testPublicKeyBtc.publicKeyWif = invalidPublicKeyWif;

        jsigs.verify(testDocumentSigned, {
          publicKey: testPublicKeyBtc,
          publicKeyOwner: testPublicKeyBtcOwner,
          // timestamp is quite old, do not check it, it is used to ensure
          // a static document is being checked
          checkTimestamp: false
        }, function(err, result) {
          assert.ifError(err);
          assert.equal(
            result.verified, false,
            'signature verification should have failed');
          done();
        });
      });

      it('verify returns false if the document was altered after signing',
        function(done) {
          jsigs.verify(testDocumentSignedAltered, {
            publicKey: testPublicKeyBtc,
            publicKeyOwner: testPublicKeyBtcOwner,
            // timestamp is quite old, do not check it, it is used to ensure
            // a static document is being checked
            checkTimestamp: false
          }, function(err, result) {
            assert.ifError(err);
            assert.equal(
              result.verified, false,
              'signature verification should have failed');
            done();
          });
        });

      it('should successfully sign a local document' +
        ' w/promises API', function(done) {
        jsigs.promises.sign(testDocument, {
          algorithm: 'EcdsaKoblitzSignature2016',
          privateKeyWif: testPrivateKeyWif,
          creator: testPublicKeyFriendly
        }).then(function(signedDocument) {
          assert.notEqual(
            signedDocument['https://w3id.org/security#signature'], undefined,
            'signature was not created');
          assert.equal(
            signedDocument['https://w3id.org/security#signature']
              ['http://purl.org/dc/terms/creator']['@id'],
            testPublicKeyFriendly, 'creator key for signature is wrong');
        }).then(done, done);
      });

      it('should successfully verify a local signed document' +
        ' w/promises API', function(done) {
        jsigs.promises.verify(testDocumentSigned, {
          publicKey: testPublicKeyBtc,
          publicKeyOwner: testPublicKeyBtcOwner,
          // timestamp is quite old, do not check it, it is used to ensure
          // a static document is being checked
          checkTimestamp: false
        }).then(function(result) {
          assert.equal(result.verified, true, 'signature verification failed');
        }).then(done, done);
      });

      it('verify should return false if the document was signed by' +
        ' a different private key w/promises API', function(done) {
        testPublicKeyBtc.publicKeyWif = invalidPublicKeyWif;

        jsigs.promises.verify(testDocumentSigned, {
          publicKey: testPublicKeyBtc,
          publicKeyOwner: testPublicKeyBtcOwner,
          // timestamp is quite old, do not check it, it is used to ensure
          // a static document is being checked
          checkTimestamp: false
        }).then(function(result) {
          assert.equal(result.verified, false,
            'signature verification should have failed but did not');
        }).then(done, done);
      });
    });

    describe('signing and verify RsaSignature2017', function() {

      var testDocument;
      var testDocumentSigned;
      var testDocumentSignedAltered;
      var testInvalidPublicKey;

      beforeEach(function() {
        testDocument = {
          '@context': {
            schema: 'http://schema.org/',
            name: 'schema:name',
            homepage: 'schema:url',
            image: 'schema:image'
          },
          name: 'Manu Sporny',
          homepage: 'https://manu.sporny.org/',
          image: 'https://manu.sporny.org/images/manu.png'
        };

        testDocumentSigned = clone(testDocument);
        testDocumentSigned["https://w3id.org/security#signature"] = {
          "@type": "https://w3id.org/security#RsaSignature2017",
          "http://purl.org/dc/terms/created": {
            "@type": "http://www.w3.org/2001/XMLSchema#dateTime",
            "@value": "2017-09-27T03:12:26Z"
          },
          "http://purl.org/dc/terms/creator": {
            "@id": testPublicKeyUrl
          },
          "https://w3id.org/security#signatureValue":
            "eyJhbGciOiJSUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19" +
            ".." +
            "Vewb2R5LWN2T5_8lFTE6hYqu7MyrUaIBCLE55DDGGtEUFZOfFnW0sxft5TiEdm" +
            "BIYhYveNY9LTAqhRLTIzYG2ZOi9WpMI3DsfApEuz9GkZLIkPC0rQZVMW9ssP17" +
            "Cxiim9imGA5dyHn2pZ98C_Cd_ptqHMFyjKHluKhG4HpfNaM"
        };
        testDocumentSignedAltered = clone(testDocumentSigned);
        testDocumentSignedAltered.name = 'Manu Spornoneous';

        testInvalidPublicKey = clone(testPublicKey);
        testInvalidPublicKey.id = testPublicKeyUrl2;
      });

      it('should successfully sign a local document', function(done) {
        jsigs.sign(testDocument, {
          algorithm: 'RsaSignature2017',
          creator: testPublicKeyUrl,
          privateKeyPem: testPrivateKeyPem,
        }, function(err, signedDocument) {
          assert.ifError(err);
          assert.notEqual(
            signedDocument['https://w3id.org/security#signature'], undefined,
            'signature was not created');
          assert.equal(
            signedDocument['https://w3id.org/security#signature']
              ['http://purl.org/dc/terms/creator']['@id'],
            testPublicKeyUrl,
            'creator key for signature is wrong');
          done();
        });
      });

      it('should successfully verify a local signed document', function(done) {
        jsigs.verify(testDocumentSigned, {
          publicKey: testPublicKey,
          publicKeyOwner: testPublicKeyOwner,
          // timestamp is quite old, do not check it, it is used to ensure
          // a static document is being checked
          checkTimestamp: false
        }, function(err, result) {
          assert.ifError(err);
          assert.equal(result.verified, true, 'signature verification failed');
          done();
        });
      });

      it('verify should return false if the document was signed by a ' +
        'different private key', function(done) {
        jsigs.verify(testDocumentSigned, {
          publicKey: testInvalidPublicKey,
          publicKeyOwner: testPublicKeyOwner,
          // timestamp is quite old, do not check it, it is used to ensure
          // a static document is being checked
          checkTimestamp: false
        }, function(err, result) {
          assert.ifError(err);
          assert.equal(
            result.verified, false,
            'signature verification should have failed');
          done();
        });
      });

      it('verify returns false if the document was altered after signing',
        function(done) {
          jsigs.verify(testDocumentSignedAltered, {
            publicKey: testPublicKey,
            publicKeyOwner: testPublicKeyOwner,
            // timestamp is quite old, do not check it, it is used to ensure
            // a static document is being checked
            checkTimestamp: false
          }, function(err, result) {
            assert.ifError(err);
            assert.equal(
              result.verified, false,
              'signature verification should have failed');
            done();
          });
        });

      it('should successfully sign a local document' +
        ' w/promises API', function(done) {
        jsigs.sign(testDocument, {
          algorithm: 'RsaSignature2017',
          privateKeyPem: testPrivateKeyPem,
          creator: testPublicKeyUrl
        }).then(function(signedDocument) {
          assert.notEqual(
            signedDocument['https://w3id.org/security#signature'], undefined,
            'signature was not created');
          assert.equal(
            signedDocument['https://w3id.org/security#signature']
              ['http://purl.org/dc/terms/creator']['@id'],
            testPublicKeyUrl, 'creator key for signature is wrong');
        }).then(done, done);
      });

      it('should successfully verify a local signed document' +
        ' w/promises API', function(done) {
        jsigs.verify(testDocumentSigned, {
          publicKey: testPublicKey,
          publicKeyOwner: testPublicKeyOwner,
          // timestamp is quite old, do not check it, it is used to ensure
          // a static document is being checked
          checkTimestamp: false
        }).then(function(result) {
          assert.equal(result.verified, true, 'signature verification failed');
        }).then(done, done);
      });

      it('verify should return false if the document was signed by' +
        ' a different private key w/promises API', function(done) {
        jsigs.verify(testDocumentSigned, {
          publicKey: testInvalidPublicKey,
          publicKeyOwner: testPublicKeyOwner,
          // timestamp is quite old, do not check it, it is used to ensure
          // a static document is being checked
          checkTimestamp: false
        }).then(function(result) {
          assert.equal(result.verified, false,
            'signature verification should have failed but did not');
        }).then(done, done);
      });
    });
  });

  context('with security context', function() {
    // the test document that will be signed
    var testDocument = {
      '@context': [{
        schema: 'http://schema.org/',
        name: 'schema:name',
        homepage: 'schema:url',
        image: 'schema:image'
      }, jsigs.SECURITY_CONTEXT_URL],
      name: 'Manu Sporny',
      homepage: 'https://manu.sporny.org/',
      image: 'https://manu.sporny.org/images/manu.png'
    };
    var testDocumentSigned = {};

    describe(
      'signing and verify GraphSignature2012 w/security context', function() {
        it('should successfully sign a local document', function(done) {
          jsigs.sign(testDocument, {
            algorithm: 'GraphSignature2012',
            privateKeyPem: testPrivateKeyPem,
            creator: testPublicKeyUrl
          }, function(err, signedDocument) {
            assert.ifError(err);
            assert.notEqual(signedDocument.signature, undefined,
              'signature was not created');
            assert.equal(signedDocument.signature.creator, testPublicKeyUrl,
              'creator key for signature is wrong');
            testDocumentSigned = signedDocument;
            done();
          });
        });

        it('should successfully verify a local signed document',
          function(done) {
            jsigs.verify(testDocumentSigned, {
              publicKey: testPublicKey,
              publicKeyOwner: testPublicKeyOwner
            }, function(err, result) {
              assert.ifError(err);
              assert.equal(
                result.verified, true, 'signature verification failed');
              done();
            });
          });

        it('should successfully sign a local document w/promises API',
          function(done) {
            jsigs.promises.sign(testDocument, {
              algorithm: 'GraphSignature2012',
              privateKeyPem: testPrivateKeyPem,
              creator: testPublicKeyUrl
            }).then(function(signedDocument) {
              assert.notEqual(signedDocument.signature, undefined,
                'signature was not created');
              assert.equal(signedDocument.signature.creator, testPublicKeyUrl,
                'creator key for signature is wrong');
              testDocumentSigned = signedDocument;
            }).catch(function(err) {
              assert.ifError(err);
            }).then(done, done);
          });

        it('should successfully verify a local signed document w/promises API',
          function(done) {
            jsigs.promises.verify(testDocumentSigned, {
              publicKey: testPublicKey,
              publicKeyOwner: testPublicKeyOwner
            }).then(function(result) {
              assert.equal(
                result.verified, true, 'signature verification failed');
            }).catch(function(err) {
              assert.ifError(err);
            }).then(done, done);
          });

      });

    describe(
      'signing and verify LinkedDataSignature2015 w/security context',
      function() {
        it('should successfully sign a local document', function(done) {
          jsigs.sign(testDocument, {
            algorithm: 'LinkedDataSignature2015',
            privateKeyPem: testPrivateKeyPem,
            creator: testPublicKeyUrl
          }, function(err, signedDocument) {
            assert.ifError(err);
            assert.notEqual(signedDocument.signature, undefined,
              'signature was not created');
            assert.equal(signedDocument.signature.creator, testPublicKeyUrl,
              'creator key for signature is wrong');
            testDocumentSigned = signedDocument;
            done();
          });
        });

        it('should successfully verify a local signed document',
          function(done) {
            jsigs.verify(testDocumentSigned, {
              publicKey: testPublicKey,
              publicKeyOwner: testPublicKeyOwner
            }, function(err, result) {
              assert.ifError(err);
              assert.equal(
                result.verified, true, 'signature verification failed');
              done();
            });
          });

        it('should successfully sign a local document w/promises',
          function(done) {
            jsigs.promises.sign(testDocument, {
              algorithm: 'LinkedDataSignature2015',
              privateKeyPem: testPrivateKeyPem,
              creator: testPublicKeyUrl
            }).then(function(signedDocument) {
              assert.notEqual(signedDocument.signature, undefined,
                'signature was not created');
              assert.equal(signedDocument.signature.creator, testPublicKeyUrl,
                'creator key for signature is wrong');
              testDocumentSigned = signedDocument;
            }).catch(function(err) {
              assert.ifError(err);
            }).then(done, done);
          });

        it('should successfully verify a local signed document w/promises',
          function(done) {
            jsigs.promises.verify(testDocumentSigned, {
              publicKey: testPublicKey,
              publicKeyOwner: testPublicKeyOwner
            }).then(function(result) {
              assert.equal(
                result.verified, true, 'signature verification failed');
            }).catch(function(err) {
              assert.ifError(err);
            }).then(done, done);
          });

        it('should fail to sign with unmapped terms', function(done) {
          var testDocumentWithUnmappedTerms = clone(testDocument);
          testDocumentWithUnmappedTerms.foo = 'bar';

          jsigs.sign(testDocumentWithUnmappedTerms, {
            algorithm: 'LinkedDataSignature2015',
            privateKeyPem: testPrivateKeyPem,
            creator: testPublicKeyUrl
          }, function(err) {
            assert.exists(err);
            const message = (err.details && err.details.cause) ?
              err.details.cause.message : err.message;
            assert.equal(message,
              'The property "foo" in the input ' +
              'was not defined in the context.');
            done();
          });
        });

        it('should sign with unmapped terms', function(done) {
          var testDocumentWithUnmappedTerms = clone(testDocument);
          testDocumentWithUnmappedTerms.foo = 'bar';

          jsigs.sign(testDocumentWithUnmappedTerms, {
            algorithm: 'LinkedDataSignature2015',
            privateKeyPem: testPrivateKeyPem,
            creator: testPublicKeyUrl,
            expansionMap: false
          }, function(err) {
            assert.ifError(err);
            done();
          });
        });

      });

    describe('signing and verify EcdsaKoblitzSignature2016', function() {
      var testDocument;
      var testDocumentSigned;
      var testPrivateKeyWif;
      var testPublicKeyWif;
      var testPublicKeyFriendly;
      var testPublicKeyBtc;
      var testPublicKeyBtcOwner;
      var invalidPublicKeyWif;
      var testDocumentSignedAltered;

      beforeEach(function() {
        testDocument = {
          '@context': [{
            schema: 'http://schema.org/',
            name: 'schema:name',
            homepage: 'schema:url',
            image: 'schema:image'
          }, jsigs.SECURITY_CONTEXT_URL],
          name: 'Manu Sporny',
          homepage: 'https://manu.sporny.org/',
          image: 'https://manu.sporny.org/images/manu.png'
        };

        testDocumentSigned = clone(testDocument);
        testDocumentSigned["https://w3id.org/security#signature"] = {
          "@type": "EcdsaKoblitzSignature2016",
          "http://purl.org/dc/terms/created": {
            "@type": "http://www.w3.org/2001/XMLSchema#dateTime",
            "@value": "2017-03-25T22:01:04Z"
          },
          "http://purl.org/dc/terms/creator": {
            "@id": "ecdsa-koblitz-pubkey:1LGpGhGK8whX23ZNdxrgtjKrek9rP4xWER"
          },
          "https://w3id.org/security#signatureValue":
            "IOoF0rMmpcdxNZFoirTpRMCyLr8kGHLqXFl7v+m3naetCx+OLNhVY/6SCUwDGZf" +
            "Fs4yPXeAl6Tj1WgtLIHOVZmw="
        };
        testDocumentSignedAltered = clone(testDocumentSigned);
        testDocumentSignedAltered.name = 'Manu Spornoneous';

        testPrivateKeyWif =
          'L4mEi7eEdTNNFQEWaa7JhUKAbtHdVvByGAqvpJKC53mfiqunjBjw';
        testPublicKeyWif = '1LGpGhGK8whX23ZNdxrgtjKrek9rP4xWER';
        testPublicKeyFriendly = 'ecdsa-koblitz-pubkey:' + testPublicKeyWif;

        testPublicKeyBtc = {
          '@context': jsigs.SECURITY_CONTEXT_URL,
          id: testPublicKeyFriendly,
          type: 'CryptographicKey',
          owner: 'https://example.com/i/alice',
          publicKeyWif: testPublicKeyWif
        };

        testPublicKeyBtcOwner = {
          '@context': jsigs.SECURITY_CONTEXT_URL,
          id: 'https://example.com/i/alice',
          publicKey: [testPublicKeyFriendly]
        };

        invalidPublicKeyWif = '1BHdCBqQ1GQLfHVEnoXtYf44T97aEHodwe';
      });

      it('should successfully sign a local document', function(done) {
        jsigs.sign(testDocument, {
          algorithm: 'EcdsaKoblitzSignature2016',
          privateKeyWif: testPrivateKeyWif,
          creator: testPublicKeyFriendly
        }, function(err, signedDocument) {
          assert.ifError(err);
          assert.notEqual(
            signedDocument.signature, undefined, 'signature was not created');
          assert.equal(
            signedDocument.signature.creator, testPublicKeyFriendly,
            'creator key for signature is wrong');
          done();
        });
      });

      it('should successfully verify a local signed document', function(done) {
        jsigs.verify(testDocumentSigned, {
          publicKey: testPublicKeyBtc,
          publicKeyOwner: testPublicKeyBtcOwner,
          // timestamp is quite old, do not check it, it is used to ensure
          // a static document is being checked
          checkTimestamp: false
        }, function(err, result) {
          assert.ifError(err);
          assert.equal(result.verified, true, 'signature verification failed');
          done();
        });
      });

      it('verify should return false if the document was signed by a ' +
        'different private key', function(done) {
        testPublicKeyBtc.publicKeyWif = invalidPublicKeyWif;

        jsigs.verify(testDocumentSigned, {
          publicKey: testPublicKeyBtc,
          publicKeyOwner: testPublicKeyBtcOwner,
          // timestamp is quite old, do not check it, it is used to ensure
          // a static document is being checked
          checkTimestamp: false
        }, function(err, result) {
          assert.ifError(err);
          assert.equal(
            result.verified, false,
            'signature verification should have failed');
          done();
        });
      });

      it('should successfully sign a local document' +
        ' w/promises API', function(done) {
        jsigs.promises.sign(testDocument, {
          algorithm: 'EcdsaKoblitzSignature2016',
          privateKeyWif: testPrivateKeyWif,
          creator: testPublicKeyFriendly
        }).then(function(signedDocument) {
          assert.notEqual(signedDocument.signature, undefined,
            'signature was not created');
          assert.equal(signedDocument.signature.creator, testPublicKeyFriendly,
            'creator key for signature is wrong');
          testDocumentSigned = signedDocument;
        }).then(done, done);
      });

      it('should successfully verify a local signed document' +
        ' w/promises API', function(done) {
        jsigs.promises.verify(testDocumentSigned, {
          publicKey: testPublicKeyBtc,
          publicKeyOwner: testPublicKeyBtcOwner,
          // timestamp is quite old, do not check it, it is used to ensure
          // a static document is being checked
          checkTimestamp: false
        }).then(function(result) {
          assert.equal(result.verified, true, 'signature verification failed');
        }).then(done, done);
      });

      it('verify should return false if the document was signed by' +
        ' a different private key w/promises API', function(done) {
        testPublicKeyBtc.publicKeyWif = invalidPublicKeyWif;

        jsigs.promises.verify(testDocumentSigned, {
          publicKey: testPublicKeyBtc,
          publicKeyOwner: testPublicKeyBtcOwner,
          // timestamp is quite old, do not check it, it is used to ensure
          // a static document is being checked
          checkTimestamp: false
        }).then(function(result) {
          assert.equal(result.verified, false,
            'signature verification should have failed but did not');
        }).then(done, done);
      });

      it('verify should return false if the document was altered after' +
        ' signing w/promises API', function(done) {
        jsigs.promises.verify(testDocumentSignedAltered, {
          publicKey: testPublicKeyBtc,
          publicKeyOwner: testPublicKeyBtcOwner,
          // timestamp is quite old, do not check it, it is used to ensure
          // a static document is being checked
          checkTimestamp: false
        }).then(function(result) {
          assert.equal(result.verified, false,
            'signature verification should have failed but did not');
        }).then(done, done);
      });
    });
  });
});

// the security context that is used when loading https://w3id.org/security/v1
var securityContext = {
  "@context": {
    "id": "@id",
    "type": "@type",

    "dc": "http://purl.org/dc/terms/",
    "sec": "https://w3id.org/security#",
    "xsd": "http://www.w3.org/2001/XMLSchema#",

    "EcdsaKoblitzSignature2016": "sec:EcdsaKoblitzSignature2016",
    "EncryptedMessage": "sec:EncryptedMessage",
    "GraphSignature2012": "sec:GraphSignature2012",
    "LinkedDataSignature2015": "sec:LinkedDataSignature2015",
    "LinkedDataSignature2016": "sec:LinkedDataSignature2016",
    "RsaSignature2017": "sec:RsaSignature2017",
    "CryptographicKey": "sec:Key",

    "authenticationTag": "sec:authenticationTag",
    "canonicalizationAlgorithm": "sec:canonicalizationAlgorithm",
    "cipherAlgorithm": "sec:cipherAlgorithm",
    "cipherData": "sec:cipherData",
    "cipherKey": "sec:cipherKey",
    "created": {"@id": "dc:created", "@type": "xsd:dateTime"},
    "creator": {"@id": "dc:creator", "@type": "@id"},
    "digestAlgorithm": "sec:digestAlgorithm",
    "digestValue": "sec:digestValue",
    "domain": "sec:domain",
    "encryptionKey": "sec:encryptionKey",
    "expiration": {"@id": "sec:expiration", "@type": "xsd:dateTime"},
    "expires": {"@id": "sec:expiration", "@type": "xsd:dateTime"},
    "initializationVector": "sec:initializationVector",
    "iterationCount": "sec:iterationCount",
    "nonce": "sec:nonce",
    "normalizationAlgorithm": "sec:normalizationAlgorithm",
    "owner": {"@id": "sec:owner", "@type": "@id"},
    "password": "sec:password",
    "privateKey": {"@id": "sec:privateKey", "@type": "@id"},
    "privateKeyPem": "sec:privateKeyPem",
    "publicKey": {"@id": "sec:publicKey", "@type": "@id"},
    "publicKeyPem": "sec:publicKeyPem",
    "publicKeyService": {"@id": "sec:publicKeyService", "@type": "@id"},
    "revoked": {"@id": "sec:revoked", "@type": "xsd:dateTime"},
    "salt": "sec:salt",
    "signature": "sec:signature",
    "signatureAlgorithm": "sec:signingAlgorithm",
    "signatureValue": "sec:signatureValue"
  }
};

var testPublicKeyUrl = 'https://example.com/i/alice/keys/1';
var testPublicKeyUrl2 = 'https://example.com/i/bob/keys/1';
var testPublicKeyUrl3 = 'https://example.com/i/sally/keys/1';
var testPublicKeyPem =
  '-----BEGIN PUBLIC KEY-----\n' +
  'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC4R1AmYYyE47FMZgo708NhFU+t\n' +
  '+VWn133PYGt/WYmD5BnKj679YiUmyrC3hX6oZfo4eVpOkycxZvGgXCLQGuDp45Xf\n' +
  'Zkdsjqs3o62En4YjlHWxgeGmkiRqGfZ3sJ3u5WZ2xwapdZY3/2T/oOV5ri8SktTv\n' +
  'mVGCyhwFuJC/NbJMEwIDAQAB\n' +
  '-----END PUBLIC KEY-----';
var testPrivateKeyPem = '-----BEGIN RSA PRIVATE KEY-----\n' +
  'MIICWwIBAAKBgQC4R1AmYYyE47FMZgo708NhFU+t+VWn133PYGt/WYmD5BnKj679\n' +
  'YiUmyrC3hX6oZfo4eVpOkycxZvGgXCLQGuDp45XfZkdsjqs3o62En4YjlHWxgeGm\n' +
  'kiRqGfZ3sJ3u5WZ2xwapdZY3/2T/oOV5ri8SktTvmVGCyhwFuJC/NbJMEwIDAQAB\n' +
  'AoGAZXNdPMQXiFGSGm1S1P0QYzJIW48ZCP4p1TFP/RxeCK5bRJk1zWlq6qBMCb0E\n' +
  'rdD2oICupvN8cEYsYAxZXhhuGWZ60vggbqTTa+4LXB+SGCbKMX711ZoQHdY7rnaF\n' +
  'b/Udf4wTLD1yAslx1TrHkV56OfuJcEdWC7JWqyNXQoxedwECQQDZvcEmBT/Sol/S\n' +
  'AT5ZSsgXm6xCrEl4K26Vyw3M5UShRSlgk12gfqqSpdeP5Z7jdV/t5+vD89OJVfaa\n' +
  'Tw4h9BibAkEA2Khe03oYQzqP1V4YyV3QeC4yl5fCBr8HRyOMC4qHHKQqBp2VDUyu\n' +
  'RBJhTqqf1ErzUBkXseawNxtyuPmPrMSl6QJAQOgfu4W1EMT2a1OTkmqIWwE8yGMz\n' +
  'Q28u99gftQRjAO/s9az4K++WSUDGkU6RnpxOjEymKzNzy2ykpjsKq3RoIQJAA+XL\n' +
  'huxsYVE9Yy5FLeI1LORP3rBJOkvXeq0mCNMeKSK+6s2M7+dQP0NBYuPo6i3LAMbi\n' +
  'yT2IMAWbY76Bmi8TeQJAfdLJGwiDNIhTVYHxvDz79ANzgRAd1kPKPddJZ/w7Gfhm\n' +
  '8Mezti8HCizDxPb+H8HlJMSkfoHx1veWkdLaPWRFrA==\n' +
  '-----END RSA PRIVATE KEY-----';
var testPublicKeyPem2 =
  '-----BEGIN PUBLIC KEY-----\n' +
  'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwlsOUSgEA9NZdtxFmra5\n' +
  'tbdQQkcLcOTqLNBjXm275/Vdoz5Bcwfipty3As2b2nxJt8I9co4lmE4wsDHp5dyu\n' +
  '34SFKn4/Y9SQzQWAvmkSBkgcRXCBS91cakW7Wx3O9/Yr66hSO7pAbt2TEW3Jf3Xl\n' +
  '3NZcnCDpNCYc40UOWRh0pmMMeyKMedHki6rWD6fgT/0Qm+LeN7E9Aelqy/5OwW38\n' +
  'aKXCuf6J9J2bBzGTc9nof7Ordnllz/XS7dLm6qNT3lkx+VMFOa9L1JXo77p7DI+L\n' +
  'z7CnswIQ8Yq9ukZZzjLvX6RN1pEB9CW9rvU9r2k2VPN8bTY3yXjolo1s6bG69lc3\n' +
  'vQIDAQAB\n' +
  '-----END PUBLIC KEY-----';
var testPrivateKeyPem2 = '-----BEGIN RSA PRIVATE KEY-----\r\n' +
  'MIIEpQIBAAKCAQEAwlsOUSgEA9NZdtxFmra5tbdQQkcLcOTqLNBjXm275/Vdoz5B\n' +
  'cwfipty3As2b2nxJt8I9co4lmE4wsDHp5dyu34SFKn4/Y9SQzQWAvmkSBkgcRXCB\n' +
  'S91cakW7Wx3O9/Yr66hSO7pAbt2TEW3Jf3Xl3NZcnCDpNCYc40UOWRh0pmMMeyKM\n' +
  'edHki6rWD6fgT/0Qm+LeN7E9Aelqy/5OwW38aKXCuf6J9J2bBzGTc9nof7Ordnll\n' +
  'z/XS7dLm6qNT3lkx+VMFOa9L1JXo77p7DI+Lz7CnswIQ8Yq9ukZZzjLvX6RN1pEB\n' +
  '9CW9rvU9r2k2VPN8bTY3yXjolo1s6bG69lc3vQIDAQABAoIBAC68FIpBVA3TcYza\n' +
  'VMZqL+fZR6xYRxEDiqfyCCL5whh58OVDIBvYBpFXO46qAFMeVd+hDoOQWMvx6VVE\n' +
  '+1hxo39N73OTXgzUXWlfbGDdBR+LkXjFH+ItPX60e+PiHBWWFWOaWwPPupSuJSIo\n' +
  'wy4qHHbo+OX2J/2JOKMRxOx5q/siI+vrzYKEdRU+P338vWpvlBK9GiodIY29t71Z\n' +
  'qTV+2eA1v5rmDK/pa8+WXUNKyKrIZQ8qxdf8LbD/1QkspvCqcyQ+XTl+qkRM8hp8\n' +
  'ONfhLFPrIN0BOonwGNh9u9bsYGZGmoV8YzdgJoNJ1jWRyuKhO9Px5hQmnixuBdkO\n' +
  'XcdkOiECgYEA/y5vsNeUgwTkolYSIs2QqHuLqxZZ1U5JyPKVipuqgrSgAV20A3Ah\n' +
  'Bvnp+GpqrConLrvjoYKRCWf9IRI+MfxFiLTgKdWxc6PlDXAFpaSZAgYVBTRudgd/\n' +
  'CLpr7fC1w9rx5S/VHaDu89aLBTsSHjQBIKZaWhmFM00Y+tqkxtqrBjkCgYEAwvqq\n' +
  '3/MbOZHEOXjDzbwsZPg+8q8eyBE0bPzp4tjxBPvxnWqwhC3NoKhZP/E2gojVDgdH\n' +
  'ZvsEO+o8JXH2DKFBEXc80c77Gl8hhiRsFab1rIRl7vCUjgNksu1ChzXnvwJuRAB4\n' +
  'mFHsuxJi83kRQD8HqgIfuDnsS5kl6gpvAlel3aUCgYEAjBxjFyZHVOkK4FeB/boB\n' +
  'A4FSXs4W5RfnS35mvYRbSwkCEb3xaTHX8Iyn+s3zZDSA7xgbFEMsf42pXs81dxyc\n' +
  '0UL/EflTRbtnuMkZUKnfmUzdnc38GLJk/dXeDPdt1ewRhVWOHoaOrTPPgT+94veK\n' +
  '5vJwCaiZimF6pcIHV2gZH4ECgYEAmcq4b07FIaKdYSulXijX54h7tlZ09B/F91WC\n' +
  'ciDl8yV6zcyykH/EWr2PMEVl1o5xZtBM/KhwDYZTjMGX7xxeQ5WGjoMxQvrYaYNf\n' +
  'EbEQxNPlxxNSSbXZftxwBlB5jAsxyEeK17J/BIubKypKdh+BPxLPzDM78+FHq5Qx\n' +
  'PWq+9NUCgYEAqm0LdhkoqdKgbkU/rgNjX3CgINQ/OhbUGpqq78EAbw/90MCXGdOB\n' +
  '5pxB4HwKFtDPNtquIQ3UCIVVCJlDZfW7mJJQ9LkD21uqwxXOf1uPH2cb651yeLqd\n' +
  'TSz1b9F4+GFdKxjk8JKywWAD2fIamcx2W0Wfgfyvr6Kd+kJrkyWn+ZM=\n' +
  '-----END RSA PRIVATE KEY-----';
var testPublicKeyPem3 =
  '-----BEGIN PUBLIC KEY-----\n' +
  'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwIjS6bkpr+xR/+JCL0KF\n' +
  '24ZOHEmX/4ASBhSfKh0vGb5plKFuAOumNj5y/CzdgkqenhtcbrMunHuzPqYdTUJB\n' +
  'NXDqpVzXh7bZDHDjFcHgHcU8xxCvchL9EDKyFP39JJG9/sTr6SEkKz8OH48lZoFh\n' +
  'GsXvsYTCMKJRZ0+vECTvEb2gd6OGhXwQqPk402Kk0hMq/5LjceUaxDfcBDJ8WYim\n' +
  'BWy9YO+xeEu3nFrPk2I1aMFDdD6vHO7l7P6tMAY/U+H1wrsDPuv3A/stalSHjZyh\n' +
  'DaBD1ZoEtAk03kOSvwLQb2LI3kAwYqoNApNsLVI+U9HsP/UuKk2/3kZS8Oa70b97\n' +
  'RwIDAQAB\n' +
  '-----END PUBLIC KEY-----';
var testPrivateKeyPem3 = '-----BEGIN RSA PRIVATE KEY-----\r\n' +
  'MIIEogIBAAKCAQEAwIjS6bkpr+xR/+JCL0KF24ZOHEmX/4ASBhSfKh0vGb5plKFu\n' +
  'AOumNj5y/CzdgkqenhtcbrMunHuzPqYdTUJBNXDqpVzXh7bZDHDjFcHgHcU8xxCv\n' +
  'chL9EDKyFP39JJG9/sTr6SEkKz8OH48lZoFhGsXvsYTCMKJRZ0+vECTvEb2gd6OG\n' +
  'hXwQqPk402Kk0hMq/5LjceUaxDfcBDJ8WYimBWy9YO+xeEu3nFrPk2I1aMFDdD6v\n' +
  'HO7l7P6tMAY/U+H1wrsDPuv3A/stalSHjZyhDaBD1ZoEtAk03kOSvwLQb2LI3kAw\n' +
  'YqoNApNsLVI+U9HsP/UuKk2/3kZS8Oa70b97RwIDAQABAoIBADJKCr0drjPTSD/L\n' +
  '+3mYqJoEZJai6l7ENvD7pe88HDdfMvitiawX4Rw+B46ysVD86J1njCcmCkC5VsJA\n' +
  'ZVruuVWaHs/+hhVevyauvcHLGBzujcd5Jjpnl04Jz9YH2X0ZzESlbvE/xNC+8ZNw\n' +
  'slYp6REzLj5x7L8DRrvzZkiTPRamuiDQrxr6d27TWPZIAwfPYuoy/OMx9hMgZyKk\n' +
  'pxsAvMmVRyy2NZK428oU5rwF/mWsURS05oWyBqicgaeWlqJ9swnak1OnF5z0N196\n' +
  'fU4bVHjtyAMS/DCNI+4qjpg7G+PPUfK4RXtJ/0AC0ZRDu35khXeI5u1U3F5Ks6ms\n' +
  'XUTQDhECgYEA/gltTiKTlZhGxx9K1P5DQ+ZFHns+NsonbBS1i9Io6dFK0QfS4xOa\n' +
  'TjP1nOKFIlB1TS2kqOylkxbS/Jf1bzSOk/rwIFfDnE0q4zIfiGEnlmnqefmJ4Qac\n' +
  'LXsfwTQ4WiHuQcqOMlM3PgWm8r1zhPQaY2yFXzgCBpsD82cLcaPa8R0CgYEAwgW5\n' +
  'US/UBB+j8OLyjeDgZvhvIfsgL8hREaS3U+Uk72ei+UT2XhjdV4mVyiQ3N5cTHyXC\n' +
  'vkamozmp90zHSnAyjDq+GNt04A1n3nz45VKNlstG/NfrqP5QCfCjEwiJfuclD2+q\n' +
  'VRrpbHbWBJ9B/8e+andl5rixNoI72n44n/k7NLMCgYB/6HM20kYJHoEUpXbiQ5vO\n' +
  'xlSrAlbS83ph+xNl8U1UXWMUWKIgX7BkC9lxQsTSADzvvTmZLH45z1YwhLq5YXcg\n' +
  'n0rkngwJ2PjtKEGkQ3bRT0cWX0TDHrboV4QnnYl6KHd0fO6X/DpmaiYjNqzBlr7q\n' +
  'rKuCxAqRFOAqYAntEBmfKQKBgDjYNnhL3AEtR/nudAQPa4+fn+fDzKVTOjVCHhgt\n' +
  'XYnqwjvn8YqWHFtmSwWDYM4frBGHHaxjxLSz01FKJGVxw82D9GgR/Accxl7QHJgL\n' +
  'fMI+Ylj35eqIP+j5oL2V1brhe+Eu5Se0D8mgc4m9IzgOTIKi4q8bU4hV1bVpH6v2\n' +
  '+FqzAoGAHM2v90bEbN/TNFv7OODWeK7HBRKBNigMVktXBpfCAFOm+cSfMlsoQTr3\n' +
  '4xiV0oxUFjPHA6qt0hGsk7/0P1Pe15Kg5n6+w2JzFpN5ix7DWus57PBKbMUkE64y\n' +
  'KBFLr5ANLqWLaVrSw5Uep1s5VvXyOrltUN/1SUoCoNZuM/FakRc=\n' +
  '-----END RSA PRIVATE KEY-----';

var testPublicKey = {
  '@context': jsigs.SECURITY_CONTEXT_URL,
  id: testPublicKeyUrl,
  type: 'CryptographicKey',
  owner: 'https://example.com/i/alice',
  publicKeyPem: testPublicKeyPem
};
var testPublicKeyOwner = {
  '@context': jsigs.SECURITY_CONTEXT_URL,
  id: 'https://example.com/i/alice',
  publicKey: [testPublicKey]
};
var testPublicKey2 = {
  '@context': jsigs.SECURITY_CONTEXT_URL,
  id: testPublicKeyUrl2,
  type: 'CryptographicKey',
  owner: 'https://example.com/i/bob',
  publicKeyPem: testPublicKeyPem2
};
var testPublicKeyOwner2 = {
  '@context': jsigs.SECURITY_CONTEXT_URL,
  id: 'https://example.com/i/bob',
  publicKey: [testPublicKey2]
};
var testPublicKey3 = {
  '@context': jsigs.SECURITY_CONTEXT_URL,
  id: testPublicKeyUrl3,
  type: 'CryptographicKey',
  owner: 'https://example.com/i/sally',
  publicKeyPem: testPublicKeyPem3
};
var testPublicKeyOwner3 = {
  '@context': jsigs.SECURITY_CONTEXT_URL,
  id: 'https://example.com/i/sally',
  publicKey: [testPublicKey3]
};
var getterDocs = {};
getterDocs[testPublicKey3.id] = testPublicKey3;
getterDocs[testPublicKeyOwner3.id] = testPublicKeyOwner3;

function _publicKeyGetter(keyId, options, callback) {
  return getterDocs[keyId] ? callback(null, getterDocs[keyId]) :
    callback(new Error('PublicKey not found.'));
}

function _publicKeyOwnerGetter(owner, options, callback) {
  return getterDocs[owner] ? callback(null, getterDocs[owner]) :
    callback(new Error('PublicKey owner not found.'));
}

function _publicKeyGetterPromise(keyId) {
  return getterDocs[keyId] ? Promise.resolve(getterDocs[keyId]) :
    Promise.resolve(new Error('PublicKey not found.'));
}

function _publicKeyOwnerGetterPromise(owner) {
  return getterDocs[owner] ? Promise.resolve(getterDocs[owner]) :
    Promise.reject(new Error('PublicKey owner not found.'));
}

return Promise.resolve();

};
