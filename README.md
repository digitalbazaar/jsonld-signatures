jsonld-signatures
=================

[![Build Status][travis-ci-png]][travis-ci-site]
[travis-ci-png]: https://travis-ci.org/digitalbazaar/jsonld-signatures.png?branch=master
[travis-ci-site]: https://travis-ci.org/digitalbazaar/jsonld-signatures

An implementation of the Linked Data Signatures specification for JSON-LD. 
This software works in all modern browsers as well as node.js.

Introduction
------------

Here are some examples on using the library:

```js
var signedDoc = {
  "name": "Manu Sporny",
  "url": "http://manu.sporny.org/",
  "image": "http://manu.sporny.org/images/manu.png"
  "signature": {
    
  }
};

// verify a signed JSON-LD document
jsigs.verify(signedDoc, function(err, verified) {
  // should print 'Signed document verified: true' to the console
  console.log('Signed document verified:', verified);
});

// verify a signed JSON-LD document at a particular URL
jsigs.verify('http://example.org/signedDoc',...);

// use the promises API
var promises = jsigs.promises;

// verification
var promise = promises.verify(signedDoc);
promise.then(function(verified) {...}, function(err) {...});
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

    make test

The standard tests will run node and browser tests. Just one type can also
be run:

    make test-node
    make test-browser

Code coverage of node tests can be generated in `coverage/`:

    make test-coverage

The Mocha output reporter can be changed to min, dot, list, nyan, etc:

    make test REPORTER=dot

[jsonld-signatures]: https://github.com/digitalbazaar/jsonld-signatures/