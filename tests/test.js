/**
 * Test runner for JSON-LD Signatures library.
 *
 * @author Dave Longley <dlongley@digitalbazaar.com>
 * @author Manu Sporny <msporny@digitalbazaar.com>
 *
 * Copyright (c) 2014-2017 Digital Bazaar, Inc. All rights reserved.
 */
/* globals jsonldjs */
(function() {

'use strict';

// detect node.js (vs. phantomJS)
var _nodejs = (typeof process !== 'undefined' &&
  process.versions && process.versions.node);

var _jsdir, jsonld, jsigs, assert, program;

if(_nodejs) {
  if(!global.Promise) {
    global.Promise = require('es6-promise').Promise;
  }
  _jsdir = process.env.JSDIR || 'lib';
  jsonld = require('../node_modules/jsonld');
  jsigs = require('../' + _jsdir + '/jsonld-signatures')();
  assert = require('assert');
  program = require('commander');
  program
    .option('--bail', 'Bail when a test fails')
    .parse(process.argv);
} else {
  if(!window.Promise) {
    window.Promise = require('es6-promise').Promise;
  }
  var system = require('system');
  require('./bind');
  require('./setImmediate');
  _jsdir = system.env.JSDIR || 'lib';
  var forge = require('../node_modules/node-forge');
  window.forge = forge;
  var bitcoreMessage = require(
    '../node_modules/bitcore-message/dist/bitcore-message.js');
  window.bitcoreMessage = bitcoreMessage;
  require('../node_modules/jsonld');
  jsonld = jsonldjs;
  require('../' + _jsdir + '/jsonld-signatures');
  jsigs = window.jsigs;
  assert = require('chai').assert;
  require('mocha/mocha');
  require('mocha-phantomjs/lib/mocha-phantomjs/core_extensions');

  // PhantomJS is really bad at doing XHRs, so we have to fake the network
  // fetch of the JSON-LD Contexts
  var contextLoader = function(url, callback) {
    if(url === 'https://w3id.org/security/v1') {
      callback(null, {
        contextUrl: null,
        document: securityContext,
        documentUrl: 'https://web-payments.org/contexts/security-v1.jsonld'
      });
    }
  };
  jsonld.documentLoader = contextLoader;

  program = {};
  for(var i = 0; i < system.args.length; ++i) {
    var arg = system.args[i];
    if(arg.indexOf('--') === 0) {
      var argname = arg.substr(2);
      switch(argname) {
      default:
        program[argname] = true;
      }
    }
  }

  mocha.setup({
    reporter: 'spec',
    ui: 'bdd'
  });
}

// helper:
function clone(obj) {
  return JSON.parse(JSON.stringify(obj));
}

// run tests
describe('JSON-LD Signatures', function() {
  var testPublicKeyUrl = 'https://example.com/i/alice/keys/1';
  var testPublicKeyUrl2 = 'https://example.com/i/bob/keys/1';
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
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwyD/b26ez7OQB0bwvd4K\n' +
    'gyzlRaLOxyZyEFYZi9DqphK+NKtYnqGHfk2Qi2xanCVj2IrxJetvEWNFnoS1JgI4\n' +
    'BdnN2/D3yJfr4Di/nuppB3EYBu/auKuiuFrQhR5gPeNM6NAwD7HUQ1XKaSk2iow8\n' +
    'IJHEHe+4bIiUht7V+rN6iUi0oOYW+mjbaLLKcUR/ngdX3DXZs99Jx+hDwd28s1su\n' +
    'zWB9N29NiFaqg2RwqFELCSav9gx+nYb0zj5ltVGIIgNp2ibYO+nVQ3zmhE+O8zFc\n' +
    'l5c0l72XnEQn5eKZ5gJHPn4ZDpykO/NKZRj+hDRIxApDHmg0wYRJovtqJ6v5AZkh\n' +
    'ywIDAQAB\n' +
    '-----END PUBLIC KEY-----';
  var testPrivateKeyPem2 = '-----BEGIN RSA PRIVATE KEY-----\r\n' +
    'MIIEowIBAAKCAQEAwyD/b26ez7OQB0bwvd4KgyzlRaLOxyZyEFYZi9DqphK+NKtY\n' +
    'nqGHfk2Qi2xanCVj2IrxJetvEWNFnoS1JgI4BdnN2/D3yJfr4Di/nuppB3EYBu/a\n' +
    'uKuiuFrQhR5gPeNM6NAwD7HUQ1XKaSk2iow8IJHEHe+4bIiUht7V+rN6iUi0oOYW\n' +
    '+mjbaLLKcUR/ngdX3DXZs99Jx+hDwd28s1suzWB9N29NiFaqg2RwqFELCSav9gx+\n' +
    'nYb0zj5ltVGIIgNp2ibYO+nVQ3zmhE+O8zFcl5c0l72XnEQn5eKZ5gJHPn4ZDpyk\n' +
    'O/NKZRj+hDRIxApDHmg0wYRJovtqJ6v5AZkhywIDAQABAoIBAGHxrkXAwPaAq0r7\n' +
    '0Nt9GMm/P1Y04pYUNiz9CtWjiCTUQ6UsXM9DRT+gr21Mdi7qlbOcCm9+PcH8knV/\n' +
    'J25srrJBIZPE4JtPppZl5cle4Flb6zOQMbmAba0b6I7pMGXgMjqqRXWbTXB/H5qp\n' +
    'lTb2LTgr8sUUDv5rkCIiuEWe0WMWuzGoeFuh4kYAUGu91Qh9q9GDEgZ7C7CoonsH\n' +
    'O15CD1LxfE7Jcfabjx0qSjelcmIkXijtji3NhBaS784hJomjxuL2sjsOAdaxfFfB\n' +
    '5kHa4YjJ05gWRuz6mIBMGN/Dvpexz1SZnbudmxA2moFXUzj2rV1CzopERnWC3vHz\n' +
    'HnkCLAECgYEA4ZK5VDnX/AljCu5Ps57wfK6Cy+C3tbY4/PXEGtoF34FeE8i+xg3v\n' +
    'yiQfqzqSnC9n37R111k3oFxUABYpjC1eJdI46pKqMwNJ/px0jiZU5PyawXBbaA4M\n' +
    'jaiKPcYoEHS4bWeYbiEVtr/MEGWpdCSAhW7KLDxtRW3ZEIf1ZFxwy98CgYEA3XMA\n' +
    'muA8t7cyr7qgnp/QuLHRKKU7W/Jl6eGwnhIhp8mDSg2GMFF0xwcqEV3u6k8b8oS8\n' +
    'E6E7BPk1DjRwydE0FCpQYNKV0kbFrw44J56IhMZ6PJobt/9Dg15uFBAwo6YImqsu\n' +
    'J38CwRwysunb2nkcXmcGSKrLrhetJenIYf+Mp5UCgYAzVhQNghiQiIZc332OEHcE\n' +
    'uSaVRbApj64Ki9g0kDfT9Po3IHGiW1ueMnhunKbvGq7WL5i+CNTrDvgjCOgtucl6\n' +
    'bAx9/iDz+SSm6G5yR3D8qCyEJ5D17nSW7KuBgY5uqFGsvG3pamgprh7AAJL/FquV\n' +
    'MnCafqoTqftDkt2bGJqnGwKBgCpHKnZnGTB56VNjbgbavB6G1EfOQ+bqAEsGq5GC\n' +
    'JKrD7izVKClRY9obpAxswpA5Sjyi2sVkor/wVBDCMkZVinvPGElj6vaaTGN/c3kc\n' +
    '6zNuMSggw+n88gbCoIF0FdUofbwJsmYX+Y6ks4k03KR5OtFLGggFk51JJ+V1HKyY\n' +
    '/WGBAoGBAJH23ZK1AUmv/c8X+wifjjLLmhoJgL3OcyjFiaJsKFpbTYR2m8WxWlQr\n' +
    'I6uT8jR2jQVWZoEWSuIV7ciekihFa7k/R0YevmAZt3h6KHYfqJvjaLHLAcxYNE2T\n' +
    '54pu8qaIrQ9kBM7vOBrQtK4s8glzDC6VLThEO1FyrZVehshoue9f\n' +
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
    id: testPublicKeyUrl,
    type: 'CryptographicKey',
    owner: 'https://example.com/i/bob',
    publicKeyPem: testPublicKeyPem2
  };
  var testPublicKeyOwner2 = {
    '@context': jsigs.SECURITY_CONTEXT_URL,
    id: 'https://example.com/i/bob',
    publicKey: [testPublicKey2]
  };

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
        function() {
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
          });
        });

      it('should successfully verify a local signed document w/promises API',
        function() {
          jsigs.promises.verify(testDocumentSigned, {
            publicKey: testPublicKey,
            publicKeyOwner: testPublicKeyOwner
          }).then(function(result) {
            assert.equal(
              result.verified, true, 'signature verification failed');
          }).catch(function(err) {
            assert.ifError(err);
          });
        });

    });

    describe('signing and verify Graph2015', function() {
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
              assert.equal(
                result.verified, true, 'signature verification failed');
              done();
            });
          });

        it('should successfully sign a local document w/promises API',
          function() {
            jsigs.promises.sign(testDocument, {
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
            });
          });

        it('should successfully verify a local signed document w/promises API',
          function() {
            jsigs.promises.verify(testDocumentSigned, {
              publicKey: testPublicKey,
              publicKeyOwner: testPublicKeyOwner
            }).then(function(result) {
              assert.equal(
                result.verified, true, 'signature verification failed');
            }).catch(function(err) {
              assert.ifError(err);
            });
          });
      }); // end single signature

      describe.only('multiple signatures', function() {
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
              assert.equal(
                signedDocument['https://w3id.org/security#signature'].length,
                2);
              assert.equal(
                signedDocument['https://w3id.org/security#signature'][0]
                  ['http://purl.org/dc/terms/creator']['@id'], testPublicKeyUrl,
                'creator key for signature is wrong');
              assert.equal(
                signedDocument['https://w3id.org/security#signature'][1]
                  ['http://purl.org/dc/terms/creator']['@id'],
                testPublicKeyUrl2,'creator key for signature is wrong');
              done();
            });
          });
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
          publicKeyOwner: testPublicKeyBtcOwner
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
          publicKeyOwner: testPublicKeyBtcOwner
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
            publicKeyOwner: testPublicKeyBtcOwner
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
        }).then(done).catch(done);
      });

      it('should successfully verify a local signed document' +
        ' w/promises API', function() {
        jsigs.promises.verify(testDocumentSigned, {
          publicKey: testPublicKeyBtc,
          publicKeyOwner: testPublicKeyBtcOwner
        }).then(function(result) {
          assert.equal(result.verified, true, 'signature verification failed');
        });
      });

      it('verify should return false if the document was signed by' +
        ' a different private key w/promises API', function() {
        testPublicKeyBtc.publicKeyWif = invalidPublicKeyWif;

        jsigs.promises.verify(testDocumentSigned, {
          publicKey: testPublicKeyBtc,
          publicKeyOwner: testPublicKeyBtcOwner
        }).then(function(result) {
          assert.equal(result.verified, false,
            'signature verification should have failed but did not');
        });
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
          function() {
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
            });
          });

        it('should successfully verify a local signed document w/promises API',
          function() {
            jsigs.promises.verify(testDocumentSigned, {
              publicKey: testPublicKey,
              publicKeyOwner: testPublicKeyOwner
            }).then(function(result) {
              assert.equal(
                result.verified, true, 'signature verification failed');
            }).catch(function(err) {
              assert.ifError(err);
            });
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
          function() {
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
            });
          });

        it('should successfully verify a local signed document w/promises',
          function() {
            jsigs.promises.verify(testDocumentSigned, {
              publicKey: testPublicKey,
              publicKeyOwner: testPublicKeyOwner
            }).then(function(result) {
              assert.equal(
                result.verified, true, 'signature verification failed');
            }).catch(function(err) {
              assert.ifError(err);
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
          publicKeyOwner: testPublicKeyBtcOwner
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
          publicKeyOwner: testPublicKeyBtcOwner
        }, function(err, result) {
          assert.ifError(err);
          assert.equal(
            result.verified, false,
            'signature verification should have failed');
          done();
        });
      });

      it('should successfully sign a local document' +
        ' w/promises API', function() {
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
        });
      });

      it('should successfully verify a local signed document' +
        ' w/promises API', function() {
        jsigs.promises.verify(testDocumentSigned, {
          publicKey: testPublicKeyBtc,
          publicKeyOwner: testPublicKeyBtcOwner
        }).then(function(result) {
          assert.equal(result.verified, true, 'signature verification failed');
        });
      });

      it('verify should return false if the document was signed by' +
        ' a different private key w/promises API', function() {
        testPublicKeyBtc.publicKeyWif = invalidPublicKeyWif;

        jsigs.promises.verify(testDocumentSigned, {
          publicKey: testPublicKeyBtc,
          publicKeyOwner: testPublicKeyBtcOwner
        }).then(function(result) {
          assert.equal(result.verified, false,
            'signature verification should have failed but did not');
        });
      });

      it('verify should return false if the document was altered after' +
        ' signing w/promises API', function() {
        jsigs.promises.verify(testDocumentSignedAltered, {
          publicKey: testPublicKeyBtc,
          publicKeyOwner: testPublicKeyBtcOwner
        }).then(function(result) {
          assert.equal(result.verified, false,
            'signature verification should have failed but did not');
        });
      });

    });

  });
});

if(!_nodejs) {
  mocha.run(function() {
    phantom.exit();
  });
}

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

})();
