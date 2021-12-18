# jsonld-signatures ChangeLog

## 9.3.1 - 2021-12-17

### Fixed
- Allow `expansionMap` overrides.

## 9.3.0 - 2021-07-10

### Added
- Add optimization for JSON-LD controller documents that are DID documents. When
  a controller ID resolves to a JSON-LD DID Document, then JSON-LD framing can
  be skipped when verifying verification method relationships if the verification
  relationship is one that is defined by the DID context.

## 9.2.1 - 2021-07-08

### Fixed
- Use the `size` method to get the number of entries in the `purposeToProofs` Map.

## 9.2.0 - 2021-07-02

### Added
- Support passing multiple purposes in a single verify call.
- Add `NotFoundError` name to error thrown when there are not enough proofs
  to match the passed supported suites and purposes during verification.
  LD suite implementations should not be relying the error message but can
  rely on the `name` property of the error instead.

### Changed
- `LinkedDataSignature` no longer calls `purpose.validate`; this function
  is instead called after `verifyProof()`. This removes the responsibility
  of calling this function from LD suite implementations and places it in
  the main verify call from within jsigs instead. LD suites will still be
  passed a dummy `purpose` in this version for backwards compatibility
  purposes that will successfully return a promise that resolves to
  `true` from `purpose.validate()`. Decoupling this from the suites both
  establishes a better separation of concerns and simplifies LD suites by
  reducing their responsibilities. LD suites are responsible for returing
  the `verificationMethod` used in their results so it can be passed to
  `purpose.validate()`.
- Add cache for hash of canonicalized document to enable its reuse when
  verifying multiple proofs on a single document.

## 9.1.1 - 2021-06-29

### Fixed
- Use `Map` to internally represent contexts instead of an object. This
  optimizes better w/ v8.

## 9.1.0 - 2021-06-29

### Changed
- Use `tag: 'static'` feature in `extendContextLoader`. This flag will inform
  the JSON-LD processor that the statically loaded contexts are, in fact,
  static and only need to be processed once.

## 9.0.2 - 2021-04-12

### Changed
- Move ensuring suite context to suite subclass. (Non-breaking change, added
  to support the 2018 signature suite.)

## 9.0.1 - 2021-04-09

These changes were intended to be released in v9.0.0, so, releasing them as
a patch.

### Changed
- **BREAKING**: Implement automatic adding of the suite context to the document
  to be signed, (if it's not present already).
- **BREAKING**: Remove the case where the `document` argument in `sign()` or
  `verify()` is a URL (instead of an object), since this is an unused feature,
  and a mixing of layers.

## 9.0.0 - 2021-04-06

### Changed
- **BREAKING**: Remove `verificationMethod` param from suite constructor. It
  is now strictly initialized from `key.id` or `signer.id`.
  Increase validation on either key or signer/verifier parameters.

### Fixed
- Add missing `signer` and `verifier` parameters to the `LinkedDataSignature`
  constructor. This issue caused `this.signer` in subclasses to be `undefined`.

## 8.0.2 - 2021-03-19

### Changed
- In ProofSet, use the document's context for proof before defaulting to
  security context.

## 8.0.1 - 2021-03-18

### Changed
- Update karma setup, remove babel.

## 8.0.0 - 2021-03-18

### Changed
- **BREAKING**: Only support Node.js >=12.
- **BREAKING**: Drop support for deprecated `owner` proof property.
- **BREAKING**: Drop support for deprecated `creator` proof property.

### Removed
- **BREAKING**: No longer shipping browser bundles. Due to splitting out suites
  into other packages, it becomes more practical to create browser bundles at
  the application level with modern tools.
- **BREAKING**: No longer exporting `crypto-ld` classes.
- **BREAKING**: Remove `PublicKeyProofPurpose`.
- **BREAKING**: Remove `GraphSignature2012` suite.
- **BREAKING**: Remove `LinkedDataSignature2015` suite.
- **BREAKING**: Remove bundled signature suites; all moved to external repos:
  - `JwsLinkedDataSignature` suite moved to https://github.com/digitalbazaar/jws-linked-data-signature
  - `RsaSignature2018` suite moved to https://github.com/digitalbazaar/rsa-signature-2018
  - `Ed25519Signature2018` suite moved to https://github.com/digitalbazaar/ed25519-signature-2018
- **BREAKING**: Remove `compactProof` parameter when signing and verifying. This
  means that going forward, documents are required to use the appropriate
  contexts for the proof that they're using (error will be thrown otherwise).

## 7.0.0 - 2021-02-11

### Changed
- **BREAKING**: Update to `jsonld@4.0.1` dep (uses JSON-LD 1.1).

## 6.0.0 - 2020-09-30

### Changed
- **BREAKING**: Drop support for Node.js v8.

## 5.2.0 - 2020-09-30

### Changed
- Use node-forge@0.10.0.

## 5.1.0 - 2020-05-05

### Changed
- Improve error handling when a JwsLinkedDataSignature is missing a "jws"
  property.

## 5.0.1 - 2020-02-27

### Fixed
- Re-publish to fix package.json version.

## 5.0.0 - 2020-02-14

### Removed
- **BREAKING**: ECDSA signature support.
  - Remove EcdsaKoblitzSignature2016 suite and tests.
  - Remove bitcore-message dependency.
  - Move feature to 'ecdsa-koblitz-signature-2016' package.

### Changed
  - **BREAKING**: `verify()`'s results.error is now always a
  `VerificationError` instance where `error.errors` is an array that includes
  all of the errors that occurred during the verification process.

### 4.6.0 - 2020-01-17

### Changed
- Update node-forge and jsonld dependencies.

### 4.5.1 - 2019-12-11

### Changed
- Required jsonld.js >= 2.0.1.

### 4.5.0 - 2019-12-09

### Changed
- Update jsonld.js dependency to 2.0.0.

### 4.4.0 - 2019-09-06

### Added
- Export `JwsLinkedDataSignature` in suites.

### Changed
- Use crypto-ld@3.7.0 with support for Node 12 native Ed25519 crypto.
- Update dependencies.

### 4.3.0 - 2019-09-03

### Changed
- Use security-context@4:
  - Add terms for EcdsaSecp256 signature suites.
  - Add terms for EcdsaSecp256 keys.
  - Add term DeriveSecretOperation.

## 4.2.1 - 2019-07-17

### Fixed
- Use crypto-ld@3.5.3 which properly specifies the Node.js engine.

## 4.2.0 - 2019-05-30

### Changed
- Replace local copies of security contexts with `security-context` module.

## 4.1.3 - 2019-05-22

### Fixed
- Handle compacting proofs that use a type-scoped proof term definition.

## 4.1.2 - 2019-05-08

### Changed
- Update local copy of security-v2 context.

## 4.1.1 - 2019-04-17

### Fixed
- Correct inconsistencies in the LinkedDataSignature APIs that allowed for
  optional `signer` and `verifier` parameters in some places, but required
  those parameters in other places.

## 4.1.0 - 2019-04-11

### Added
- Errors in proof verification reports now have a `toJSON` method that
  allows the errors to be serialized properly when the report is stringified
  using `JSON.stringify`.

## 4.0.2 - 2019-03-29

### Fixed
- Update webpack externals to also support amd and commonjs names.

## 4.0.1 - 2019-03-28

### Changed
- Updated local copy of security-v2 context.

## 4.0.0 - 2019-02-12

### Changed
- **NOTE**: Updated jsonld to 1.5.0. Dependency and code updates will be
  required to continue using the native canonize bindings. See the
  [jsonld.js 1.5.0 notes](https://github.com/digitalbazaar/jsonld.js/blob/master/CHANGELOG.md#150---2019-01-24).
- **BREAKING**: Updated crypto-ld to 3.0.0. The exposed APIs changed the key
  fingerprint output encodings.
- Switch to eslint.

### Added
- Expose `useNativeCanonize` option in constructors of suites that use
  rdf-canonize.

## 3.3.0 - 2019-01-22

### Changed
- JwsSignatures now default to `verificationMethod` term in the
  proof unless a legacy public key is being used. A legacy public key is
  one that has the deprecated `owner` property instead of the newer
  `controller` property.

## 3.2.0 - 2019-01-17

### Changed
- Use crypto-ld@2.

### Removed
- **BREAKING**: Remove Node.js 6.x support. If you need Node.js 6.x support
  please use the 2.x series or setup your own translation.

## 3.1.2 - 2019-01-08

### Fixed
- Fix ProofSet suite matching.
- Ensure proof verification method matches key if given.

## 3.1.1 - 2019-01-08

### Fixed
- Fix ProofSet proof matching.
- Use 2048-bit RSA keys in tests.

### Changed
- Improve usage of Babel features.

## 3.1.0 - 2019-01-04

### Fixed
- Move webpack-cli to dev dependency.

### Changed
- Update to Babel 7.

## 3.0.0 - 2019-01-03

### Added
- Add `compactProof` flag that can be set to `false` to enable skipping
  compaction of proof(s) when it is known that the input document's (for `sign`
  or `verify`) JSON-LD `@context` defines all applicable proof terms using the
  same definitions as the JSON-LD `@context` used internally by the library
  (i.e. the JSON-LD `@context` defined by `constants.SECURITY_CONTEXT_URL`).
  This flag should only be set to `false` by advanced users that have ensured
  their software systems have strictly validated the input to ensure that it
  is safe and cannot be misinterpreted. If these guarantees can be met, then
  setting this flag to `false` may be a useful optimization consideration.

### Changed
- **BREAKING**: `sign` and `verify` APIs require suites and proof purpose
  instances to be passed.

### Removed
- **BREAKING**: Removed API `wrap` and injector support.
- **BREAKING**: callback-based API is no longer supported.
- **BREAKING**: Removed exposed utility/helper functions.
- Karma PhantomJS support. Upstream deprecated PhantomJS and suggests headless
  Chrome or similar.

## 2.3.1 - 2018-09-05

### Changed
- Optimize `LinkedDataSignature` `createVerifyData` to remove
  one round of compaction and one round of expansion. This
  eliminates a total of four rounds (2x compaction, 2x expansion)
  for sign+verify processes as `createVerifyData` is used
  in both `sign` and `verify`.

## 2.3.0 - 2018-03-20

### Added
- Add in-browser support for ed25519.

## 2.2.2 - 2018-03-08

### Fixed
- Fix bug with explicitly passed `undefined` options.

## 2.2.1 - 2018-03-01

### Fixed
- Fix 1.0 compatibility issue with update of jsonld to 1.0.1.

## 2.2.0 - 2018-03-01

### Changed
- Update jsonld to 1.0.0.

## 2.1.5 - 2018-02-27

### Changed
- Use `chloride`, a faster and better maintained implementation
  of `Ed25519`.

## 2.1.4 - 2018-02-22

### Fixed
- Use RSASSA-PSS with `RsaSignature2018`, not RSASSA-PKCS1-v1_5. Uses
  PS256 JWS algorithm (sha256 for all hashing including mgf1 and
  a salt length that matches the digest length, i.e. 32 bytes).

## 2.1.3 - 2018-02-21

### Fixed
- Ensure `proofPurpose` property's objects are framed as
  application suites containing references to public keys
  not direct public keys.

## 2.1.2 - 2018-02-21

### Fixed
- Ensure key types are validated.

## 2.1.1 - 2018-02-14

### Fixed
- Ensure proof node is sanitized prior to use as verification
  data.
- Expose `sanitizeProofNode` for suite-specific override.

## 2.1.0 - 2018-02-14

### Added
- Expose `suites` on main API to allow for other libs to
  create plugins that extend them.

### Changed
- Do not require `creator` option.

### Fixed
- Only include `publicKey` in result if `creator` is present.
- Do not override `created` in `proof` option if `date` is not
  given in `options`.

## 2.0.1 - 2018-02-13

### Fixed
- Move cross-env to devDependencies.

## 2.0.0 - 2018-02-13

### Changed
- Add webpack support. Build and distribute bundles in `dist` directory.
- Add node6 support. Use babel to generate files in `dist/node6` directory.
  Used automatically at runtime.
- Use karma for browser testing.
- Use node and karma test setup files that use a common test file.
- **BREAKING**: `verify` now returns an object with `keyResults` and `verified`.

### Added
- Support for RsaSignature2018.
- Support for Ed25519Signature2018.
- Support for `proof` and `proofPurpose`.
- Support for attaching and verifying multiple proofs (signatures) as a set on
  a single document.
- Add embedded security JSON-LD contexts. These are automatically used unless a
  `documentLoader` option passed to `sign` or `verify` overrides this behavior.

### Removed
- **BREAKING**: Removed bower support. Use npm and the bundles in the `dist`
  directory.
- Remove grunt support in favor of package.json script targets.
- **BREAKING**: Removed deprecated options in `wrap` function. Use the `use`
  API instead.

## 1.2.1 - 2017-04-14

### Changed
- Add `key` validation in `checkKey` API.

## 1.2.0 - 2017-04-14

### Added
- EcdsaKoblitzSignature2016 signature algorithm.

## 1.1.x
- See git history for changes.
