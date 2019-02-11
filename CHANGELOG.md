# jsonld-signatures ChangeLog

### Changed
- Updated jsonld to 1.5.0.
- Switch to eslint.

### Added
- Expose `useNativeCanonize` option in constructors of suites that use
  rdf-canonize.

## 3.3.0 - 2019-01-22

### Changed
- JwsSignatures now default to `verificationMethod` term in the
  proof unless a legacy public key is being utilized. A legacy public key is
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
