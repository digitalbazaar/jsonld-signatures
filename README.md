jsonld-signatures
=================

[![Build Status](https://travis-ci.org/digitalbazaar/jsonld-signatures.png?branch=master)](https://travis-ci.org/digitalbazaar/jsonld-signatures)

An implementation of the Linked Data Signatures specification for JSON-LD.
This software works in all modern browsers as well as node.js via [npm](https://www.npmjs.com/package/jsonld-signatures).

Introduction
------------

A Linked Data Signature proof is created (or verified) by specifying a
signature suite and a proof purpose.

The signature suite performs the cryptographic operation required to sign (or
verify) a digital signature and includes information in a proof such as the
`verificationMethod` identifier (aka `creator`) and the date the proof was
created (aka `created`).

The proof purpose indicates why the proof was created and what its intended use
is. This information can also be used to make sure that the
`verificationMethod` was authorized for the stated purpose in the proof. Using
a proof purpose helps to encourage people to authorize certain cryptographic
keys (verification methods) for explicit purposes rather than granting them
ambient authority. This approach can help prevent people from accidentally
signing documents for reasons they did not intend.

This library provides base classes for signature suites and proof purposes
so that custom extensions can be written. It also provides some commonly
used signature suites and proof purposes.

This library also supports legacy signature suites such as `GraphSignature2012`,
`LinkedDataSignature2015`, and `EcdsaKoblitzSignature2016`. These signature
suites must be used with a `PublicKeyProofPurpose` instance as the proof
purpose as they were created before extensible proof purposes were possible.

During verification, the key and key controller information must be discovered.
This library allows for the key and key controller information to be looked up
via a `documentLoader` or it can be provided directly to the API via the
signature suite or proof purpose, respectively.

Install with npm:

```
npm install jsonld-signatures
```

In Node.js, include the library like this:
```js
const jsigs = require('jsonld-signatures');
```

In a browser environment, include `jsonld`, `forge`, and
`dist/jsonld-signatures.min.js` via script tag or other mechanism.

Examples
--------

```js
// to generate the next two lines, run the following command:
//
// openssl genrsa -out key.pem; cat key.pem; openssl rsa -in key.pem -pubout -out pubkey.pem; cat pubkey.pem; rm key.pem pubkey.pem
//
// for an example of how to specify these keys, look at [key-example]:
const publicKeyPem = "-----BEGIN PUBLIC KEY-----\r\n...";
const privateKeyPem = "-----BEGIN PRIVATE KEY-----\r\n...";
```

Signing and verifying a simple assertion:

```js
// specify the public key object
const publicKey = {
  '@context': jsigs.SECURITY_CONTEXT_URL,
  id: 'https://example.com/i/alice/keys/1',
  controller: 'https://example.com/i/alice',
  publicKeyPem
};

// specify the public key controller object
const controller = {
  '@context': jsigs.SECURITY_CONTEXT_URL,
  id: 'https://example.com/i/alice',
  publicKey: [publicKey]
  // this authorizes this key to be used for making assertions
  assertionMethod: [publicKey.id]
};

// create the JSON-LD document that should be signed
const doc = {
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

// sign the document as a simple assertion
const {RsaSignature2018} = jsigs.suites;
const {AuthenticationProofPurpose} = jsigs.purposes;
const {RSAKeyPair} = jsigs;
const signed = await jsigs.sign(doc, {
  suite: new RsaSignature2018({
    verificationMethod: publicKey.id,
    key: new RSAKeyPair({privateKeyPem})
  }),
  purpose: new AssertionProofPurpose()
});

console.log('Signed document:', signed);

// verify the signed document
const result = await jsigs.verify(signed, {
  suite: new RsaSignature2018({
    key: new RsaKeyPair(publicKey)
  }),
  purpose: new AssertionProofPurpose({
    controller
  })
});
if(result.verified) {
  console.log('Signature verified.');
} else {
  console.log('Signature verification error:', result.error);
}
```

Signing and verifying a document to authenticate to a website:

```js
const publicKeyBase58 = 'GycSSui454dpYRKiFdsQ5uaE8Gy3ac6dSMPcAoQsk8yq';
const privateKeyBase58 = '3Mmk4UzTRJTEtxaKk61LxtgUxAa2Dg36jF6Vog...SSiF';

// specify the public key object
const publicKey = {
  '@context': jsigs.SECURITY_CONTEXT_URL,
  id: 'https://example.com/i/alice/keys/2',
  controller: 'https://example.com/i/alice',
  publicKeyBase58
};

// specify the public key controller object
const controller = {
  '@context': jsigs.SECURITY_CONTEXT_URL,
  id: 'https://example.com/i/alice',
  publicKey: [publicKey]
  // this authorizes this key to be used for authenticating
  authentication: [publicKey.id]
};

// create the JSON-LD document that should be signed
const doc = {
  '@context': {
    schema: 'http://schema.org/',
    name: 'schema:action'
  },
  action: 'AuthenticateMe'
};

// sign the document for the purpose of authentication
const {Ed25519Signature2018} = jsigs.suites;
const {AuthenticationProofPurpose} = jsigs.purposes;
const {Ed25519KeyPair} = jsigs;
const signed = await jsigs.sign(doc, {
  suite: new Ed25519Signature2018({
    verificationMethod: publicKey.id,
    key: new Ed25519KeyPair({privateKeyPem})
  }),
  purpose: new AuthenticationProofPurpose({
    challenge: 'abc',
    domain: 'example.com'
  })
});

console.log('Signed document:', signed);

// verify the signed document
const result = await jsigs.verify(signed, {
  suite: new Ed25519Signature2018({
    key: new Ed25519KeyPair(publicKey)
  }),
  purpose: new AuthenticationProofPurpose({
    controller,
    challenge: 'abc',
    domain: 'example.com'
  })
});
if(result.verified) {
  console.log('Signature verified.');
} else {
  console.log('Signature verification error:', result.error);
}
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

Run the Node.js tests using the following command:

    npm run test

Run browser tests using PhantomJS using the following command:

    npm run test-karma

Run browser tests using a selection of browsers using the following command:

    npm run test-karma -- --browsers Firefox,Chrome,PhantomJS

Code coverage of node tests can be generated in `coverage/`:

    npm run coverage

[jsonld-signatures]: https://github.com/digitalbazaar/jsonld-signatures/
[key-example]: https://github.com/digitalbazaar/jsonld-signatures/blob/44f1f67db2cfb0b166b7d5f63c40e10cc4642416/tests/test.js#L73
