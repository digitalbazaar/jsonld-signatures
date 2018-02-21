/*!
 * Copyright (c) 2017-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const constants = require('./constants');
const util = require('./util');

module.exports = class Helper {
  constructor(injector) {
    this.injector = injector;
  }

  /**
   * Gets a remote public key.
   *
   * @param id the ID for the public key.
   * @param [options] the options to use:
   *          [keyType] the expected key type (a term as compacted via the
   *            security-v2 context).
   *          [documentLoader(url, callback(err, remoteDoc))] the document
   *            loader.
   *
   * @return a Promise that resolves to a framed JSON-LD public key.
   */
  async getPublicKey(id, options) {
    options = options || {};

    // get key
    const key = await this.getJsonLd(id, options);

    // return framed key
    return this._frameKey(key, options);
  }

  /**
   * Checks to see if the given key is valid and trusted.
   *
   * @param key the public key to check.
   * @param [options] the options to use:
   *          [proof] the proof node, framed according to the security-v2
   *            context.
   *          [publicKeyOwner] the JSON-LD document describing the public key
   *            owner.
   *          [checkKeyOwner(owner, key)] a custom method to return whether
   *            or not the key owner is trusted.
   *          [documentLoader(url, callback(err, remoteDoc))] the document
   *            loader.
   *
   * @return a Promise that resolves to true if the key is trusted.
   */
  async checkKey(key, options) {
    if(!(key && typeof key === 'object')) {
      throw new TypeError('"key" must be an object.');
    }

    options = options || {};

    let {
      checkKeyOwner = () => true,
      publicKeyOwner: getPublicKeyOwner = this.getJsonLd.bind(this)
    } = options;

    if(typeof getPublicKeyOwner !== 'function') {
      const owner = getPublicKeyOwner;
      getPublicKeyOwner = ownerId => {
        if(ownerId !== owner.id) {
          throw new Error('Public key owner not found.');
        }
        return owner;
      };
    }
    checkKeyOwner = util.normalizeAsyncFn(checkKeyOwner, 3);
    getPublicKeyOwner = util.normalizeAsyncFn(getPublicKeyOwner, 2);

    // get framed key
    const framedKey = await this._frameKey(key, options);

    // get proof purpose
    const {proofPurpose = 'publicKey'} = options.proof || {};

    // get framed owners
    const owners = await getPublicKeyOwner(framedKey.owner, options);
    const framedOwners = await this._frameKeyOwners(
      owners, proofPurpose, options);

    // find specific owner of key
    let owner;
    const jsonld = this.injector.use('jsonld');
    for(let i = 0; i < framedOwners.length; ++i) {
      let keys;
      // direct access to public keys
      if(proofPurpose === 'publicKey') {
        keys = jsonld.getValues(framedOwners[i], proofPurpose);
      } else {
        // FIXME: apply known application suite rules and allow for custom
        //   functions to be passed to handle unknown ones

        // indirect access via application suites
        keys = jsonld.getValues(framedOwners[i], proofPurpose)
          .map(appSuite => appSuite.publicKey);
      }

      if(keys.some(key => typeof key === 'object' ?
        key.id === framedKey.id : key === framedKey.id)) {
        owner = framedOwners[i];
        break;
      }
    }
    if(!owner) {
      throw new Error('The public key is not owned by its declared owner.');
    }

    const isOwnerTrusted = checkKeyOwner(owner, key, options);
    if(!isOwnerTrusted) {
      throw new Error('The owner of the public key is not trusted.');
    }

    return true;
  }

  /**
   * Retrieves a JSON-LD document over HTTP. To implement caching, override
   * this method.
   *
   * @param url the URL to HTTP GET.
   * @param [options] the options to use.
   *          [documentLoader(url, callback(err, remoteDoc))] the document
   *          loader.
   *
   * @return a Promise that resolves to the JSON-LD document.
   */
  async getJsonLd(url, options) {
    options = options || {};

    const jsonld = this.injector.use('jsonld');
    const remoteDoc = await jsonld.get(url, options);

    // compact w/context URL from link header
    if(remoteDoc.contextUrl) {
      const opts = {expandContext: remoteDoc.contextUrl};
      if(options.documentLoader) {
        opts.documentLoader = options.documentLoader;
      }
      return jsonld.compact(remoteDoc.document, remoteDoc.contextUrl, opts);
    }

    return remoteDoc.document;
  }

  async _frameKey(key, options) {
    // `CryptographicKey` used here for backwards compatibility
    let requiredKeyType = 'CryptographicKey';
    if(options.keyType) {
      requiredKeyType = options.keyType;
    }

    const frame = {
      '@context': constants.SECURITY_CONTEXT_URL,
      type: requiredKeyType,
      owner: {'@embed': '@never'}
    };
    const jsonld = this.injector.use('jsonld');
    const opts = {};
    if(options.documentLoader) {
      opts.documentLoader = options.documentLoader;
    }
    const framed = await jsonld.frame(key, frame, opts);

    // FIXME: improve validation
    if(!framed['@graph'][0]) {
      throw new Error(`The public key is not a "${requiredKeyType}".`);
    }
    if(!framed['@graph'][0].owner) {
      throw new Error('The public key has no specified owner.');
    }
    framed['@graph'][0]['@context'] = framed['@context'];
    return framed['@graph'][0];
  }

  async _frameKeyOwners(owners, proofPurpose, options) {
    const frame = {
      '@context': constants.SECURITY_CONTEXT_URL,
      '@requireAll': false
    };
    if(proofPurpose === 'publicKey') {
      // direct access to public keys
      frame.publicKey = {'@embed': '@never'};
    } else {
      // indirect access to public keys via application suites
      frame[proofPurpose] = {
        '@embed': '@always',
        publicKey: {'@embed': '@never'}
      };
    }
    const jsonld = this.injector.use('jsonld');
    const opts = {};
    if(options.documentLoader) {
      opts.documentLoader = options.documentLoader;
    }
    const framed = await jsonld.frame(owners, frame, opts);
    return framed['@graph'];
  }

  async _frameAppSuite(owners, proofPurpose, options) {
    const frame = {
      '@context': constants.SECURITY_CONTEXT_URL,
      '@requireAll': false,
      [proofPurpose]: {'@embed': '@never'}
    };
    const jsonld = this.injector.use('jsonld');
    const opts = {};
    if(options.documentLoader) {
      opts.documentLoader = options.documentLoader;
    }
    const framed = await jsonld.frame(owners, frame, opts);
    return framed['@graph'];
  }
};
