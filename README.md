jsonld-signatures
=================

[![Build Status][travis-ci-png]][travis-ci-site]
[travis-ci-png]: https://travis-ci.org/digitalbazaar/jsonld-signatures.png?branch=master
[travis-ci-site]: https://travis-ci.org/digitalbazaar/jsonld-signatures

An implementation of the Linked Data Signatures specification for JSON-LD.
This software works in all modern browsers as well as node.js.

Introduction
------------

In node.js, include the library like this:
```js
var jsonld = require('jsonld');
var jsig = require('jsonld-signatures');
jsig.use('jsonld', jsonld);
```

In a browser environment, include the library like this:

You will need to bower install jsonld-signatures and then serve it and
its dependencies from your server and include each via a script tag, or other
mechanism, in the order: es6-promise, async, jsonld, forge, jsonld-signatures.

Here are some examples on using the library:

```js
// to generate the next two lines, run the following command:
//
// openssl genrsa -out key.pem; cat key.pem; openssl rsa -in key.pem -pubout -out pubkey.pem; cat pubkey.pem; rm key.pem pubkey.pem
//
// for an example of how to specify these keys, look at [key-example]:
var testPublicKeyPem = "-----BEGIN PUBLIC KEY-----\r\n...";
var testPrivateKeyPem = "-----BEGIN PRIVATE KEY-----\r\n...";

// specify the public key object
var testPublicKey = {
  '@context': jsig.SECURITY_CONTEXT_URL,
  '@id': 'https://example.com/i/alice/keys/1',
  owner: 'https://example.com/i/alice',
  publicKeyPem: testPublicKeyPem
};

// specify the public key owner object
var testPublicKeyOwner = {
  "@context": jsig.SECURITY_CONTEXT_URL,
  '@id': 'https://example.com/i/alice',
  publicKey: [testPublicKey]
};

// create the JSON-LD document that should be signed
var testDocument = {
  "@context": {
    schema: 'http://schema.org/',
    name: 'schema:name',
    homepage: 'schema:url',
    image: 'schema:image'
  },
  name: 'Manu Sporny',
  homepage: 'https://manu.sporny.org/',
  image: 'https://manu.sporny.org/images/manu.png'
};

// sign the document and then verify the signed document
jsig.sign(testDocument, {
  privateKeyPem: testPrivateKeyPem,
  creator: 'https://example.com/i/alice/keys/1'
}, function(err, signedDocument) {
  if(err) {
    return console.log('Signing error:', err);
  }
  console.log('Signed document:', signedDocument);

  // verify the signed document
  jsig.verify(signedDocument, {
    publicKey: testPublicKey,
    publicKeyOwner: testPublicKeyOwner,
  }, function(err, verified) {
    if(err) {
      return console.log('Signature verification error:', err);
    }
    console.log('Signature is valid:', verified);
  });
});

// verification
var sign = jsig.promises.sign(testDocument, {
  privateKeyPem: testPrivateKeyPem,
  creator: 'https://example.com/i/alice/keys/1'
});
sign.then(function(signedDocument) {...}, function(err) {...});

var verify = jsig.promises.verify(signedDocument, {
  publicKey: testPublicKey,
  publicKeyOwner: testPublicKeyOwner
});
verify.then(function(verified) {...}, function(err) {...});
```

Commercial Support
------------------

Commercial support for this library is available upon request from
Digital Bazaar: support@digitalbazaar.com

Source
------

The source code for the JavaScript implementation of the JSON-LD Signatures API
is available at:

https://github.com/digitalbazaar/jsonld-signatures

Tests
-----

This library includes a sample testing utility which may be used to verify
that changes to the processor maintain the correct output.

To run the sample tests you will need to get the test suite files by cloning
the [jsonld-signatures repository][jsonld-signatures] hosted on GitHub.

https://github.com/digitalbazaar/jsonld-signatures/

Run the tests using the following command:

    npm run test

The standard tests will run node and browser tests. Just one type can also
be run:

    npm run test-node
    npm run test-browser

Code coverage of node tests can be generated in `coverage/`:

    npm run coverage

[jsonld-signatures]: https://github.com/digitalbazaar/jsonld-signatures/
[key-example]: https://github.com/digitalbazaar/jsonld-signatures/blob/44f1f67db2cfb0b166b7d5f63c40e10cc4642416/tests/test.js#L73
