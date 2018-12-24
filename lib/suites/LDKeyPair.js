/**
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const env = require('../env');
const forge = require('node-forge');

class LDKeyPair {
  publicNode({controller = this.controller, owner = this.owner} = {}) {
    const publicNode = {
      id: this.id,
      type: this.type
    };
    if(controller) {
      publicNode.controller = controller;
    }
    if(owner) {
      publicNode.owner = owner;
    }
    this.addEncodedPublicKey(publicNode);
    return publicNode;
  }
}

class Ed25519KeyPair extends LDKeyPair {
  constructor({
    privateKeyBase58, publicKeyBase58, id, type, controller, owner}) {
    super();
    this.privateKeyBase58 = privateKeyBase58;
    this.publicKeyBase58 = publicKeyBase58;
    this.id = id;
    this.type = type;
    this.controller = controller;
    this.owner = owner;
  }

  static async from(data) {
    const keyPair = new Ed25519KeyPair({
      publicKeyBase58: data.publicKeyBase58,
      id: data.id,
      type: data.type,
      controller: data.controller,
      owner: data.owner
    });
    return keyPair;
  }

  addEncodedPublicKey(publicKeyNode) {
    publicKeyNode.publicKeyBase58 = this.publicKeyBase58;
    return publicKeyNode;
  }

  signer() {
    return ed25519SignerFactory(this);
  }

  verifier() {
    return ed25519VerifierFactory(this);
  }
}

class RSAKeyPair extends LDKeyPair {
  constructor({
    privateKeyPem, publicKeyPem, id, type, controller, owner}) {
    super();
    this.privateKeyPem = privateKeyPem;
    this.publicKeyPem = publicKeyPem;
    this.id = id;
    this.type = type;
    this.controller = controller;
    this.owner = owner;
  }

  static async from(data) {
    const keyPair = new RSAKeyPair({
      publicKeyPem: data.publicKeyPem,
      id: data.id,
      type: data.type,
      controller: data.controller,
      owner: data.owner
    });
    return keyPair;
  }

  addEncodedPublicKey(publicKeyNode) {
    publicKeyNode.publicKeyPem = this.publicKeyPem;
    return publicKeyNode;
  }

  signer() {
    return rsaSignerFactory(this);
  }

  verifier() {
    return rsaVerifierFactory(this);
  }
}

function ed25519SignerFactory(key) {
  if(!key.privateKeyBase58) {
    return {
      async sign() {
        throw new Error('No private key to sign with.');
      }
    };
  }

  if(env.nodejs) {
    const chloride = require('chloride');
    const bs58 = require('bs58');
    const privateKey = bs58.decode(key.privateKeyBase58);
    return {
      async sign({data}) {
        return chloride.crypto_sign_detached(
          Buffer.from(data.buffer, data.byteOffset, data.length),
          privateKey);
      }
    };
  }
  const privateKey = forge.util.binary.base58.decode(key.privateKeyBase58);
  return {
    async sign({data}) {
      return forge.ed25519.sign({message: data, privateKey});
    }
  };
}

function ed25519VerifierFactory(key) {
  if(env.nodejs) {
    const chloride = require('chloride');
    const bs58 = require('bs58');
    const publicKey = bs58.decode(key.publicKeyBase58);
    return {
      async verify({data, signature}) {
        return chloride.crypto_sign_verify_detached(
          Buffer.from(signature.buffer, signature.byteOffset, signature.length),
          Buffer.from(data.buffer, data.byteOffset, data.length),
          publicKey);
      }
    };
  }
  const publicKey = forge.util.binary.base58.decode(key.publicKeyBase58);
  return {
    async verify({data, signature}) {
      return forge.ed25519.verify({message: data, signature, publicKey});
    }
  };
}

function rsaSignerFactory(key) {
  if(!key.privateKeyPem) {
    return {
      async sign() {
        throw new Error('No private key to sign with.');
      }
    };
  }

  // Note: Per rfc7518, the digest algorithm for PS256 is SHA-256,
  // https://tools.ietf.org/html/rfc7518

  // sign data using RSASSA-PSS where PSS uses a SHA-256 hash,
  // a SHA-256 based masking function MGF1, and a 32 byte salt to match
  // the hash size
  if(env.nodejs) {
    // node.js 8+
    const crypto = require('crypto');
    if('RSA_PKCS1_PSS_PADDING' in crypto.constants) {
      return {
        async sign({data}) {
          const signer = crypto.createSign('RSA-SHA256');
          signer.update(Buffer.from(data.buffer, data.byteOffset, data.length));
          const buffer = signer.sign({
            key: key.privateKeyPem,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
          });
          return new Uint8Array(
            buffer.buffer, buffer.byteOffset, buffer.length);
        }
      };
    }
  }

  // browser or other environment (including node 6.x)
  const privateKey = forge.pki.privateKeyFromPem(key.privateKeyPem);
  return {
    async sign({data}) {
      const pss = createPss();
      const md = forge.md.sha256.create();
      md.update(forge.util.binary.raw.encode(data), 'binary');
      const binaryString = privateKey.sign(md, pss);
      return forge.util.binary.raw.decode(binaryString);
    }
  };
}

function rsaVerifierFactory(key) {
  if(env.nodejs) {
    // node.js 8+
    const crypto = require('crypto');
    if('RSA_PKCS1_PSS_PADDING' in crypto.constants) {
      return {
        async verify({data, signature}) {
          const verifier = crypto.createVerify('RSA-SHA256');
          verifier.update(
            Buffer.from(data.buffer, data.byteOffset, data.length));
          return verifier.verify({
            key: key.publicKeyPem,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
          }, Buffer.from(
            signature.buffer, signature.byteOffset, signature.length));
        }
      };
    }
  }

  // browser or other environment (including node 6.x)
  const publicKey = forge.pki.publicKeyFromPem(key.publicKeyPem);
  return {
    async verify({data, signature}) {
      const pss = createPss();
      const md = forge.md.sha256.create();
      md.update(forge.util.binary.raw.decode(data), 'binary');
      return publicKey.verify(
        md.digest().bytes(),
        forge.util.binary.raw.decode(signature),
        pss);
    }
  };
}

function createPss() {
  const md = forge.md.sha256.create();
  return forge.pss.create({
    md,
    mgf: forge.mgf.mgf1.create(forge.md.sha256.create()),
    saltLength: md.digestLength
  });
}

module.exports = {
  LDKeyPair,
  Ed25519KeyPair,
  RSAKeyPair
};
