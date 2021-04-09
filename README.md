# JSON-LD Signatures _(jsonld-signatures)_

[![Build status](https://img.shields.io/github/workflow/status/digitalbazaar/jsonld-signatures/Node.js%20CI)](https://github.com/digitalbazaar/jsonld-signatures/actions?query=workflow%3A%22Node.js+CI%22)
[![Coverage status](https://img.shields.io/codecov/c/github/digitalbazaar/jsonld-signatures)](https://codecov.io/gh/digitalbazaar/jsonld-signatures)
[![Dependency Status](https://img.shields.io/david/digitalbazaar/jsonld-signatures.svg)](https://david-dm.org/digitalbazaar/jsonld-signatures)
[![NPM Version](https://img.shields.io/npm/v/jsonld-signatures.svg)](https://npm.im/jsonld-signatures)

> An implementation of the Linked Data Signatures specification for JSON-LD, for Node.js and browsers.

## Table of Contents

- [Background](#background)
- [Security](#security)
- [Install](#install)
- [Usage](#usage)
- [Contribute](#contribute)
- [Commercial Support](#commercial-support)
- [License](#license)

## Version Compatibility

`jsonld-signatures` **v9.0** is compatible with the following signature suites:

* [`ed25519-signature-2020`](https://github.com/digitalbazaar/ed25519-signature-2020)
  `>= 2.1.0`.

and the following related libraries:

* `crypto-ld` `>= 5.0.0` (and related key crypto suites such as 
  [`ed25519-verification-key-2020`](https://github.com/digitalbazaar/ed25519-verification-key-2020)
  `>= 2.1.0`).
* `vc-js` `>= 7.0` (currently, [branch `v7.x`](https://github.com/digitalbazaar/vc-js/pull/83))

## Background

A Linked Data Signature proof is created (or verified) by specifying a
signature suite and a proof purpose.

The signature suite performs the cryptographic operation required to sign (or
verify) a digital signature and includes information in a proof such as the
`verificationMethod` identifier, the proof's `controller`, and the date the
proof was created.

The proof purpose indicates why the proof was created and what its intended use
is. This information can also be used to make sure that the
`verificationMethod` was authorized for the stated purpose in the proof. Using
a proof purpose helps to encourage people to authorize certain cryptographic
keys (verification methods) for explicit purposes rather than granting them
ambient authority. This approach can help prevent people from accidentally
signing documents for reasons they did not intend.

This library provides base classes for signature suites and proof purposes
so that custom extensions can be written. It also provides some commonly
used proof purposes.

### Relationship to Verifiable Credentials

`jsonld-signatures` is a low-level library that is meant to sign _any_ JSON-LD
document.

One common use case for creating these signatures is for use with 
[Verifiable Credentials](https://w3c.github.io/vc-data-model) (VCs). If you're 
working with those, you should use a higher-level library that's specifically
made for that purpose, such as [`vc-js`](https://github.com/digitalbazaar/vc-js).
(Incidentally, `vc-js` uses this library, `jsonld-signatures`, under the hood.)

## Security

As with most security- and cryptography-related tools, the overall security of 
your system will largely depend on your design decisions (which key types you 
will use, where you'll store the private keys, what you put into your 
credentials, and so on).

### Document Loader

During verification, the key and key controller information must be discovered.
This library allows for the key and key controller information to be looked up
via a `documentLoader` or it can be provided directly to the API via the
signature suite or proof purpose, respectively.

This library's default `documentLoader` is very strict for security and content
integrity purposes. It will only load locally available copies of the context
documents that define the terms it uses internally. Any attempt to load any
other documents (including other contexts) will throw an error. If other
documents such as verification methods (e.g., public key documents), cannot
be provided directly to the API and thus need to be loaded, a custom document
loader must be passed. For the sake of clarity, the default document loader
will only load locally available copies of the following documents:

- https://w3id.org/security/v1
- https://w3id.org/security/v2

If you require other documents to be loaded then you will need to provide a
`documentLoader` that can provide them. jsonld.js provides both a node and browser
`documentLoader` you can use, however, depending on your use case, you may
increase security by using a custom `documentLoader` that is similarly strict
and will only load a subset of documents that is constrained by some technical,
security, or business rules.

## Install

- Node.js 12+ is required.

To install locally (for development):

```
git clone https://github.com/digitalbazaar/jsonld-signatures.git
cd jsonld-signatures
npm install
```

## Usage

`jsonld-signatures` (version `8.x` and above) is not meant for standalone use.
Instead, it's generally used through an individual _crypto suite_.
For detailed usage instructions, see the READMEs of the supported suites:

* [`Ed25519Signature2020`](https://github.com/digitalbazaar/ed25519-signature-2020) 
* [`Ed25519Signature2018`](https://github.com/digitalbazaar/ed25519-signature-2018)

Most of the usages with individual suites and key types will have elements in
common. You'll need to:

* Generate or import cryptographic keys to sign with (see
  the [`@digitalbazaar/crypto-ld >=v5.0`](https://github.com/digitalbazaar/crypto-ld))
  library), or use a secure `signer()` function provided by your secure
  cryptographic module.
* _Authorize_ those keys for the specific purpose you're using
  them for (see section on Proof Purpose below), using a Controller Document
  (such as a DID Document or similar).
* Pair those keys with a corresponding cryptographic Signature Suite.
  For greenfield development, we recommend the [`Ed25519Signature2020`](https://github.com/digitalbazaar/ed25519-signature-2020)
  suite, and for legacy/compatibility work, you can use 
  [`Ed25519Signature2018`](https://github.com/digitalbazaar/ed25519-signature-2018) suite.
  See also the [Choosing a Key Type](https://github.com/digitalbazaar/crypto-ld#choosing-a-key-type)
  section of `crypto-ld` documentation.
* Set up your `documentLoader` to fetch contexts and documents securely.
* Lastly, perform the `jsigs.sign()` or `jsigs.verify()` operations.

### Node.js Native Canonize Bindings

Specialized use cases may wish to use the native canonize bindings. This mode
can be enabled by setting the `useNativeCanonize` option to `true`. See the
[jsonld.js notes](https://github.com/digitalbazaar/jsonld.js#nodejs-native-canonize-bindings)
on this feature and note you should benchmark performance before using it.

## Contribute

See [the contribute file](https://github.com/digitalbazaar/bedrock/blob/master/CONTRIBUTING.md)!

PRs accepted.

If editing the Readme, please conform to the
[standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## Commercial Support

Commercial support for this library is available upon request from
Digital Bazaar: support@digitalbazaar.com

## License

[New BSD License (3-clause)](LICENSE) © Digital Bazaar
