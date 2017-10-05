# jsonld-signatures ChangeLog

### Changed
- Add webpack support. Build and distribute bundles in `dist` directory.
- Add node6 support. Use babel to generate files in `dist/node6` directory.
  Used automatically at runtime.
- Use karma for browser testing.
- Use node and karma test setup files that use a common test file.

### Removed
- **BREAKING**: Removed bower support. Use npm and the bundles in the `dist`
  directory.
- Remove grunt support in favor of package.json script targets.

## 1.2.1 - 2017-04-14

### Changed
- Add `key` validation in `checkKey` API.

## 1.2.0 - 2017-04-14

### Added
- EcdsaKoblitzSignature2016 signature algorithm.

## 1.1.x
- See git history for changes.
