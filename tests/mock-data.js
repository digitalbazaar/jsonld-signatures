/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const constants = require('../lib/constants');
const ProofPurpose = require('../lib/proof-purpose/ProofPurpose');
const {Ed25519KeyPair, RSAKeyPair} = require('../lib/suites/LDKeyPair');

const mock = {};
module.exports = mock;

const controllers = mock.controllers = {};
const publicKeys = mock.publicKeys = {};
const privateKeys = mock.privateKeys = {};

publicKeys.alice = {
  '@context': constants.SECURITY_CONTEXT_URL,
  id: 'https://example.com/i/alice/keys/1',
  type: ['RsaVerificationKey2018'],
  owner: 'https://example.com/i/alice',
  publicKeyPem:
    '-----BEGIN PUBLIC KEY-----\n' +
    'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC4R1AmYYyE47FMZgo708NhFU+t\n' +
    '+VWn133PYGt/WYmD5BnKj679YiUmyrC3hX6oZfo4eVpOkycxZvGgXCLQGuDp45Xf\n' +
    'Zkdsjqs3o62En4YjlHWxgeGmkiRqGfZ3sJ3u5WZ2xwapdZY3/2T/oOV5ri8SktTv\n' +
    'mVGCyhwFuJC/NbJMEwIDAQAB\n' +
    '-----END PUBLIC KEY-----'
};
privateKeys.alice = {
  privateKeyPem:
    '-----BEGIN RSA PRIVATE KEY-----\n' +
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
    '-----END RSA PRIVATE KEY-----'
};
publicKeys.aliceBtc = {
  '@context': constants.SECURITY_CONTEXT_URL,
  id: 'ecdsa-koblitz-pubkey:1LGpGhGK8whX23ZNdxrgtjKrek9rP4xWER',
  type: 'CryptographicKey',
  owner: 'https://example.com/i/alice',
  publicKeyWif: '1LGpGhGK8whX23ZNdxrgtjKrek9rP4xWER'
};
privateKeys.aliceBtc = {
  privateKeyWif: 'L4mEi7eEdTNNFQEWaa7JhUKAbtHdVvByGAqvpJKC53mfiqunjBjw'
};
controllers.alice = {
  '@context': constants.SECURITY_CONTEXT_URL,
  id: publicKeys.alice.owner,
  publicKey: [publicKeys.alice, publicKeys.aliceBtc],
  'https://example.org/special-authentication': {
    publicKey: publicKeys.alice.id
  }
};

publicKeys.bob = {
  '@context': constants.SECURITY_CONTEXT_URL,
  id: 'https://example.com/i/bob/keys/1',
  type: ['RsaVerificationKey2018'],
  owner: 'https://example.com/i/bob',
  publicKeyPem:
    '-----BEGIN PUBLIC KEY-----\n' +
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwlsOUSgEA9NZdtxFmra5\n' +
    'tbdQQkcLcOTqLNBjXm275/Vdoz5Bcwfipty3As2b2nxJt8I9co4lmE4wsDHp5dyu\n' +
    '34SFKn4/Y9SQzQWAvmkSBkgcRXCBS91cakW7Wx3O9/Yr66hSO7pAbt2TEW3Jf3Xl\n' +
    '3NZcnCDpNCYc40UOWRh0pmMMeyKMedHki6rWD6fgT/0Qm+LeN7E9Aelqy/5OwW38\n' +
    'aKXCuf6J9J2bBzGTc9nof7Ordnllz/XS7dLm6qNT3lkx+VMFOa9L1JXo77p7DI+L\n' +
    'z7CnswIQ8Yq9ukZZzjLvX6RN1pEB9CW9rvU9r2k2VPN8bTY3yXjolo1s6bG69lc3\n' +
    'vQIDAQAB\n' +
    '-----END PUBLIC KEY-----'
};
privateKeys.bob = {
  privateKeyPem:
    '-----BEGIN RSA PRIVATE KEY-----\r\n' +
    'MIIEpQIBAAKCAQEAwlsOUSgEA9NZdtxFmra5tbdQQkcLcOTqLNBjXm275/Vdoz5B\n' +
    'cwfipty3As2b2nxJt8I9co4lmE4wsDHp5dyu34SFKn4/Y9SQzQWAvmkSBkgcRXCB\n' +
    'S91cakW7Wx3O9/Yr66hSO7pAbt2TEW3Jf3Xl3NZcnCDpNCYc40UOWRh0pmMMeyKM\n' +
    'edHki6rWD6fgT/0Qm+LeN7E9Aelqy/5OwW38aKXCuf6J9J2bBzGTc9nof7Ordnll\n' +
    'z/XS7dLm6qNT3lkx+VMFOa9L1JXo77p7DI+Lz7CnswIQ8Yq9ukZZzjLvX6RN1pEB\n' +
    '9CW9rvU9r2k2VPN8bTY3yXjolo1s6bG69lc3vQIDAQABAoIBAC68FIpBVA3TcYza\n' +
    'VMZqL+fZR6xYRxEDiqfyCCL5whh58OVDIBvYBpFXO46qAFMeVd+hDoOQWMvx6VVE\n' +
    '+1hxo39N73OTXgzUXWlfbGDdBR+LkXjFH+ItPX60e+PiHBWWFWOaWwPPupSuJSIo\n' +
    'wy4qHHbo+OX2J/2JOKMRxOx5q/siI+vrzYKEdRU+P338vWpvlBK9GiodIY29t71Z\n' +
    'qTV+2eA1v5rmDK/pa8+WXUNKyKrIZQ8qxdf8LbD/1QkspvCqcyQ+XTl+qkRM8hp8\n' +
    'ONfhLFPrIN0BOonwGNh9u9bsYGZGmoV8YzdgJoNJ1jWRyuKhO9Px5hQmnixuBdkO\n' +
    'XcdkOiECgYEA/y5vsNeUgwTkolYSIs2QqHuLqxZZ1U5JyPKVipuqgrSgAV20A3Ah\n' +
    'Bvnp+GpqrConLrvjoYKRCWf9IRI+MfxFiLTgKdWxc6PlDXAFpaSZAgYVBTRudgd/\n' +
    'CLpr7fC1w9rx5S/VHaDu89aLBTsSHjQBIKZaWhmFM00Y+tqkxtqrBjkCgYEAwvqq\n' +
    '3/MbOZHEOXjDzbwsZPg+8q8eyBE0bPzp4tjxBPvxnWqwhC3NoKhZP/E2gojVDgdH\n' +
    'ZvsEO+o8JXH2DKFBEXc80c77Gl8hhiRsFab1rIRl7vCUjgNksu1ChzXnvwJuRAB4\n' +
    'mFHsuxJi83kRQD8HqgIfuDnsS5kl6gpvAlel3aUCgYEAjBxjFyZHVOkK4FeB/boB\n' +
    'A4FSXs4W5RfnS35mvYRbSwkCEb3xaTHX8Iyn+s3zZDSA7xgbFEMsf42pXs81dxyc\n' +
    '0UL/EflTRbtnuMkZUKnfmUzdnc38GLJk/dXeDPdt1ewRhVWOHoaOrTPPgT+94veK\n' +
    '5vJwCaiZimF6pcIHV2gZH4ECgYEAmcq4b07FIaKdYSulXijX54h7tlZ09B/F91WC\n' +
    'ciDl8yV6zcyykH/EWr2PMEVl1o5xZtBM/KhwDYZTjMGX7xxeQ5WGjoMxQvrYaYNf\n' +
    'EbEQxNPlxxNSSbXZftxwBlB5jAsxyEeK17J/BIubKypKdh+BPxLPzDM78+FHq5Qx\n' +
    'PWq+9NUCgYEAqm0LdhkoqdKgbkU/rgNjX3CgINQ/OhbUGpqq78EAbw/90MCXGdOB\n' +
    '5pxB4HwKFtDPNtquIQ3UCIVVCJlDZfW7mJJQ9LkD21uqwxXOf1uPH2cb651yeLqd\n' +
    'TSz1b9F4+GFdKxjk8JKywWAD2fIamcx2W0Wfgfyvr6Kd+kJrkyWn+ZM=\n' +
    '-----END RSA PRIVATE KEY-----'
};
controllers.bob = {
  '@context': constants.SECURITY_CONTEXT_URL,
  id: publicKeys.bob.owner,
  publicKey: [publicKeys.bob]
};

publicKeys.sally = {
  '@context': constants.SECURITY_CONTEXT_URL,
  id: 'https://example.com/i/sally/keys/1',
  type: ['RsaVerificationKey2018'],
  owner: 'https://example.com/i/sally',
  publicKeyPem:
    '-----BEGIN PUBLIC KEY-----\n' +
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwIjS6bkpr+xR/+JCL0KF\n' +
    '24ZOHEmX/4ASBhSfKh0vGb5plKFuAOumNj5y/CzdgkqenhtcbrMunHuzPqYdTUJB\n' +
    'NXDqpVzXh7bZDHDjFcHgHcU8xxCvchL9EDKyFP39JJG9/sTr6SEkKz8OH48lZoFh\n' +
    'GsXvsYTCMKJRZ0+vECTvEb2gd6OGhXwQqPk402Kk0hMq/5LjceUaxDfcBDJ8WYim\n' +
    'BWy9YO+xeEu3nFrPk2I1aMFDdD6vHO7l7P6tMAY/U+H1wrsDPuv3A/stalSHjZyh\n' +
    'DaBD1ZoEtAk03kOSvwLQb2LI3kAwYqoNApNsLVI+U9HsP/UuKk2/3kZS8Oa70b97\n' +
    'RwIDAQAB\n' +
    '-----END PUBLIC KEY-----'
};
privateKeys.sally = {
  privateKeyPem:
    '-----BEGIN RSA PRIVATE KEY-----\r\n' +
    'MIIEogIBAAKCAQEAwIjS6bkpr+xR/+JCL0KF24ZOHEmX/4ASBhSfKh0vGb5plKFu\n' +
    'AOumNj5y/CzdgkqenhtcbrMunHuzPqYdTUJBNXDqpVzXh7bZDHDjFcHgHcU8xxCv\n' +
    'chL9EDKyFP39JJG9/sTr6SEkKz8OH48lZoFhGsXvsYTCMKJRZ0+vECTvEb2gd6OG\n' +
    'hXwQqPk402Kk0hMq/5LjceUaxDfcBDJ8WYimBWy9YO+xeEu3nFrPk2I1aMFDdD6v\n' +
    'HO7l7P6tMAY/U+H1wrsDPuv3A/stalSHjZyhDaBD1ZoEtAk03kOSvwLQb2LI3kAw\n' +
    'YqoNApNsLVI+U9HsP/UuKk2/3kZS8Oa70b97RwIDAQABAoIBADJKCr0drjPTSD/L\n' +
    '+3mYqJoEZJai6l7ENvD7pe88HDdfMvitiawX4Rw+B46ysVD86J1njCcmCkC5VsJA\n' +
    'ZVruuVWaHs/+hhVevyauvcHLGBzujcd5Jjpnl04Jz9YH2X0ZzESlbvE/xNC+8ZNw\n' +
    'slYp6REzLj5x7L8DRrvzZkiTPRamuiDQrxr6d27TWPZIAwfPYuoy/OMx9hMgZyKk\n' +
    'pxsAvMmVRyy2NZK428oU5rwF/mWsURS05oWyBqicgaeWlqJ9swnak1OnF5z0N196\n' +
    'fU4bVHjtyAMS/DCNI+4qjpg7G+PPUfK4RXtJ/0AC0ZRDu35khXeI5u1U3F5Ks6ms\n' +
    'XUTQDhECgYEA/gltTiKTlZhGxx9K1P5DQ+ZFHns+NsonbBS1i9Io6dFK0QfS4xOa\n' +
    'TjP1nOKFIlB1TS2kqOylkxbS/Jf1bzSOk/rwIFfDnE0q4zIfiGEnlmnqefmJ4Qac\n' +
    'LXsfwTQ4WiHuQcqOMlM3PgWm8r1zhPQaY2yFXzgCBpsD82cLcaPa8R0CgYEAwgW5\n' +
    'US/UBB+j8OLyjeDgZvhvIfsgL8hREaS3U+Uk72ei+UT2XhjdV4mVyiQ3N5cTHyXC\n' +
    'vkamozmp90zHSnAyjDq+GNt04A1n3nz45VKNlstG/NfrqP5QCfCjEwiJfuclD2+q\n' +
    'VRrpbHbWBJ9B/8e+andl5rixNoI72n44n/k7NLMCgYB/6HM20kYJHoEUpXbiQ5vO\n' +
    'xlSrAlbS83ph+xNl8U1UXWMUWKIgX7BkC9lxQsTSADzvvTmZLH45z1YwhLq5YXcg\n' +
    'n0rkngwJ2PjtKEGkQ3bRT0cWX0TDHrboV4QnnYl6KHd0fO6X/DpmaiYjNqzBlr7q\n' +
    'rKuCxAqRFOAqYAntEBmfKQKBgDjYNnhL3AEtR/nudAQPa4+fn+fDzKVTOjVCHhgt\n' +
    'XYnqwjvn8YqWHFtmSwWDYM4frBGHHaxjxLSz01FKJGVxw82D9GgR/Accxl7QHJgL\n' +
    'fMI+Ylj35eqIP+j5oL2V1brhe+Eu5Se0D8mgc4m9IzgOTIKi4q8bU4hV1bVpH6v2\n' +
    '+FqzAoGAHM2v90bEbN/TNFv7OODWeK7HBRKBNigMVktXBpfCAFOm+cSfMlsoQTr3\n' +
    '4xiV0oxUFjPHA6qt0hGsk7/0P1Pe15Kg5n6+w2JzFpN5ix7DWus57PBKbMUkE64y\n' +
    'KBFLr5ANLqWLaVrSw5Uep1s5VvXyOrltUN/1SUoCoNZuM/FakRc=\n' +
    '-----END RSA PRIVATE KEY-----'
};
controllers.sally = {
  '@context': constants.SECURITY_CONTEXT_URL,
  id: publicKeys.sally.owner,
  publicKey: [publicKeys.sally]
};

publicKeys.carol = {
  '@context': constants.SECURITY_CONTEXT_URL,
  id: 'https://example.com/i/carol/keys/1',
  type: ['Ed25519VerificationKey2018'],
  owner: 'https://example.com/i/carol',
  publicKeyBase58: 'GycSSui454dpYRKiFdsQ5uaE8Gy3ac6dSMPcAoQsk8yq'
};
privateKeys.carol = {
  privateKeyBase58:
    '3Mmk4UzTRJTEtxaKk61LxtgUxAa2Dg36jF6VogPtRiKvfpsQWKPCLesKSV182RMmvM' +
    'JKk6QErH3wgdHp8itkSSiF'
};
controllers.carol = {
  '@context': constants.SECURITY_CONTEXT_URL,
  id: publicKeys.carol.owner,
  publicKey: [publicKeys.carol],
  'https://example.org/special-authentication': {
    publicKey: publicKeys.carol.id
  }
};

const documents = {};
for(const key in publicKeys) {
  documents[publicKeys[key].id] = publicKeys[key];
}
for(const key in controllers) {
  documents[controllers[key].id] = controllers[key];
}

mock.testLoader = async url => {
  if(url in documents) {
    return {
      contextUrl: null,
      document: documents[url],
      documentUrl: url
    };
  }
  throw new Error(`Document "${url}" not found.`);
};

mock.NOOP_PROOF_PURPOSE_URI = 'https://example.org/special-authentication';

class NoOpProofPurpose extends ProofPurpose {
  constructor(options) {
    super(options);
    // if the value of `uri` is *not* defined in SECURITY_CONTEXT then it must
    // be in expanded form as demonstrated here
    this.uri = mock.NOOP_PROOF_PURPOSE_URI;
  }
  async validate() {
    return {valid: true};
  }
  // the proof provided here is compacted into the SECURITY_CONTEXT
  async update({proof}) {
    // TODO: We may not want to mutate the proof passed in
    proof.proofPurpose = this.uri;
    // the proof returned here *must* be compacted into the SECURITY_CONTEXT
    return proof;
  }
  async match() {
    return true;
  }
}

mock.NoOpProofPurpose = NoOpProofPurpose;

mock.nonSecurityContextTestDoc = {
  '@context': {
    '@version': 1.1,
    schema: 'http://schema.org/',
    name: 'schema:name',
    homepage: 'schema:url',
    image: 'schema:image',
    signature: {
      '@id': 'https://w3id.org/security#signature',
      '@type': '@id'
    },
    proof: {
      '@id': 'https://w3id.org/security#proof',
      '@type': '@id',
      '@container': '@graph'
    }
  },
  name: 'Manu Sporny',
  homepage: 'https://manu.sporny.org/',
  image: 'https://manu.sporny.org/images/manu.png'
};

mock.nonSecurityContextSigned = {};

mock.nonSecurityContextSigned.EcdsaKoblitzSignature2016 = {
  ...mock.nonSecurityContextTestDoc,
  "signature": {
    "@type": "https://w3id.org/security#EcdsaKoblitzSignature2016",
    "http://purl.org/dc/terms/created": {
      "@type": "http://www.w3.org/2001/XMLSchema#dateTime",
      "@value": "2017-03-25T22:01:04Z"
    },
    "http://purl.org/dc/terms/creator": {
      "@id": publicKeys.aliceBtc.id
    },
    "https://w3id.org/security#signatureValue":
      "IOoF0rMmpcdxNZFoirTpRMCyLr8kGHLqXFl7v+m3naetCx+OLNhVY/6SCUwDGZf" +
      "Fs4yPXeAl6Tj1WgtLIHOVZmw="
  }
};

mock.nonSecurityContextSigned.Ed25519Signature2018 = {
  ...mock.nonSecurityContextTestDoc,
  "proof": {
    "@type": "https://w3id.org/security#Ed25519Signature2018",
    "http://purl.org/dc/terms/created": {
      "@type": "http://www.w3.org/2001/XMLSchema#dateTime",
      "@value": "2018-02-13T21:26:08Z"
    },
    "http://purl.org/dc/terms/creator": {
      "@id": publicKeys.carol.id
    },
    "https://w3id.org/security#jws":
      "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19" +
      ".." +
      "UNcNI6x6KDA_hHux2RLM8_i9aoZY34GwcZevOjkSh22WoNB4FcP6dNgf2nKzX" +
      "XJIr-IqUnEwMYeD36fc8jv1AA",
    "https://w3id.org/security#proofPurpose": {
      "@id": mock.NOOP_PROOF_PURPOSE_URI
    }
  }
};

mock.nonSecurityContextSigned.RsaSignature2018 = {
  ...mock.nonSecurityContextTestDoc,
  "proof": {
    "@type": "https://w3id.org/security#RsaSignature2018",
    "http://purl.org/dc/terms/created": {
      "@type": "http://www.w3.org/2001/XMLSchema#dateTime",
      "@value": "2018-02-22T15:16:04Z"
    },
    "http://purl.org/dc/terms/creator": {
      "@id": publicKeys.alice.id
    },
    "https://w3id.org/security#jws":
      "eyJhbGciOiJQUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19" +
      ".." +
      "KbIsIghAzxk5cs2uBYGO60RgV342Fppcz5AYy9u-BgbEbRwBlh0sB3wCvbKL" +
      "eUlMyccltvqLUvhJTiW0mrM9TC-JAk4-Cr0zIQ9zrZ2g3SAHEe5hxT5dpCEg" +
      "PB8uIZZV3XqxDgJRWgd1BvrA3hqHMqqh3CTh85KNa8wZqlTnjkM",
    "https://w3id.org/security#proofPurpose": {
      "@id": mock.NOOP_PROOF_PURPOSE_URI
    }
  }
};

mock.nonSecurityContextSigned.LinkedDataSignature2015 = {
  ...mock.nonSecurityContextTestDoc,
  "signature": {
    "@type": "https://w3id.org/security#LinkedDataSignature2015",
    "http://purl.org/dc/terms/created": {
      "@type": "http://www.w3.org/2001/XMLSchema#dateTime",
      "@value": "2018-02-22T15:16:04Z"
    },
    "http://purl.org/dc/terms/creator": {
      "@id": "https://example.com/i/alice/keys/1"
    },
    "https://w3id.org/security#signatureValue":
      "Ah67DfRQVUMpwjnlEo+q3q+LAjA9wN74qDHmhTM28+tW+sRO3qQkp4ipqy+NUt" +
      "zakDnagmAIULfqoBENkk32HPM66N7xDwzcx3JPAmaHk4TNSAb98ozLohQvbN8h" +
      "Wc3S7TvBVK8ylhKa59ys6YT4DXzQw71LlYxfUjasnp4hTf4="
  }
};

mock.nonSecurityContextSigned.GraphSignature2012 = {
  ...mock.nonSecurityContextTestDoc,
  "signature": {
    "@type": "https://w3id.org/security#GraphSignature2012",
    "http://purl.org/dc/terms/created": {
      "@type": "http://www.w3.org/2001/XMLSchema#dateTime",
      "@value": "2018-02-22T15:16:04Z"
    },
    "http://purl.org/dc/terms/creator": {
      "@id": "https://example.com/i/alice/keys/1"
    },
    "https://w3id.org/security#signatureValue":
      "BQC/V/0kPugo3fYJlDtu1DdeJwJvjfrdLOwC8cCA6HlXA/DTnfJrOyrki/ors" +
      "Cxiy3/oPr1y7oTRn6ZD7uuvT9cAB5zWiSqHxVrTL7gPff4FaJK+lvhsFKdlEj" +
      "0IoFG7Sr2DD6Y5bW01fqcHeeRoPZpUl3nl0oo3Rk8/UAlBE88="
  }
};

mock.securityContextTestDoc = {
  ...mock.nonSecurityContextTestDoc,
  '@context': [
    {'@version': 1.1},
    mock.nonSecurityContextTestDoc['@context'],
    constants.SECURITY_CONTEXT_URL]
};

mock.securityContextSigned = {};

mock.securityContextSigned.EcdsaKoblitzSignature2016 = {
  ...mock.securityContextTestDoc,
  "signature": {
    "type": "EcdsaKoblitzSignature2016",
    "created": "2017-03-25T22:01:04Z",
    "creator": publicKeys.aliceBtc.id,
    "signatureValue":
      "IOoF0rMmpcdxNZFoirTpRMCyLr8kGHLqXFl7v+m3naetCx+OLNhVY/6SCUwDGZf" +
      "Fs4yPXeAl6Tj1WgtLIHOVZmw="
  }
};

mock.securityContextSigned.Ed25519Signature2018 = {
  ...mock.securityContextTestDoc,
  "proof": {
    "type": "Ed25519Signature2018",
    "created": "2018-02-13T21:26:08Z",
    "creator": publicKeys.carol.id,
    "jws":
      "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19" +
      ".." +
      "UNcNI6x6KDA_hHux2RLM8_i9aoZY34GwcZevOjkSh22WoNB4FcP6dNgf2nKzX" +
      "XJIr-IqUnEwMYeD36fc8jv1AA",
    "proofPurpose": mock.NOOP_PROOF_PURPOSE_URI
  }
};

mock.securityContextSigned.RsaSignature2018 = {
  ...mock.securityContextTestDoc,
  "proof": {
    "type": "RsaSignature2018",
    "created": "2018-02-22T15:16:04Z",
    "creator": publicKeys.alice.id,
    "jws":
      "eyJhbGciOiJQUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19" +
      ".." +
      "KbIsIghAzxk5cs2uBYGO60RgV342Fppcz5AYy9u-BgbEbRwBlh0sB3wCvbKL" +
      "eUlMyccltvqLUvhJTiW0mrM9TC-JAk4-Cr0zIQ9zrZ2g3SAHEe5hxT5dpCEg" +
      "PB8uIZZV3XqxDgJRWgd1BvrA3hqHMqqh3CTh85KNa8wZqlTnjkM",
    "proofPurpose": mock.NOOP_PROOF_PURPOSE_URI
  }
};

mock.securityContextSigned.LinkedDataSignature2015 = {
  ...mock.securityContextTestDoc,
  "signature": {
    "type": "LinkedDataSignature2015",
    "created": "2018-02-22T15:16:04Z",
    "creator": "https://example.com/i/alice/keys/1",
    "signatureValue":
      "Ah67DfRQVUMpwjnlEo+q3q+LAjA9wN74qDHmhTM28+tW+sRO3qQkp4ipqy+NUt" +
      "zakDnagmAIULfqoBENkk32HPM66N7xDwzcx3JPAmaHk4TNSAb98ozLohQvbN8h" +
      "Wc3S7TvBVK8ylhKa59ys6YT4DXzQw71LlYxfUjasnp4hTf4="
  }
};

mock.securityContextSigned.GraphSignature2012 = {
  ...mock.securityContextTestDoc,
  "signature": {
    "type": "GraphSignature2012",
    "created": "2018-02-22T15:16:04Z",
    "creator": "https://example.com/i/alice/keys/1",
    "signatureValue":
      "BQC/V/0kPugo3fYJlDtu1DdeJwJvjfrdLOwC8cCA6HlXA/DTnfJrOyrki/ors" +
      "Cxiy3/oPr1y7oTRn6ZD7uuvT9cAB5zWiSqHxVrTL7gPff4FaJK+lvhsFKdlEj" +
      "0IoFG7Sr2DD6Y5bW01fqcHeeRoPZpUl3nl0oo3Rk8/UAlBE88="
  }
};

mock.securityContextInvalidSignature = {};

mock.securityContextInvalidSignature.EcdsaKoblitzSignature2016 = {
  ...mock.securityContextTestDoc,
  "signature": {
    "type": "EcdsaKoblitzSignature2016",
    "created": "2017-03-25T22:01:04Z",
    "creator": publicKeys.aliceBtc.id,
    "signatureValue":
      "IOoF0rMmpcdxNZFoirTpRMCyLr8kGHLqXFl7v+m3naetCx+OLNhVY/6SCUwDGZf" +
      "Fs4yPXeAl6Tj1WgtLIHOVZma="
  }
};

mock.securityContextInvalidSignature.Ed25519Signature2018 = {
  ...mock.securityContextTestDoc,
  "proof": {
    "type": "Ed25519Signature2018",
    "created": "2018-02-13T21:26:08Z",
    "creator": publicKeys.carol.id,
    "jws":
      "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19" +
      ".." +
      "ANcNI6x6KDA_hHux2RLM8_i9aoZY34GwcZevOjkSh22WoNB4FcP6dNgf2nKzX" +
      "XJIr-IqUnEwMYeD36fc8jv1AA",
    "proofPurpose": mock.NOOP_PROOF_PURPOSE_URI
  }
};

mock.securityContextInvalidSignature.RsaSignature2018 = {
  ...mock.securityContextTestDoc,
  "proof": {
    "type": "RsaSignature2018",
    "created": "2018-02-22T15:16:04Z",
    "creator": publicKeys.alice.id,
    "jws":
      "eyJhbGciOiJQUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19" +
      ".." +
      "AbIsIghAzxk5cs2uBYGO60RgV342Fppcz5AYy9u-BgbEbRwBlh0sB3wCvbKL" +
      "eUlMyccltvqLUvhJTiW0mrM9TC-JAk4-Cr0zIQ9zrZ2g3SAHEe5hxT5dpCEg" +
      "PB8uIZZV3XqxDgJRWgd1BvrA3hqHMqqh3CTh85KNa8wZqlTnjkM",
    "proofPurpose": mock.NOOP_PROOF_PURPOSE_URI
  }
};

mock.securityContextInvalidSignature.LinkedDataSignature2015 = {
  ...mock.securityContextTestDoc,
  "signature": {
    "type": "LinkedDataSignature2015",
    "created": "2018-02-22T15:16:04Z",
    "creator": "https://example.com/i/alice/keys/1",
    "signatureValue":
      "Bh67DfRQVUMpwjnlEo+q3q+LAjA9wN74qDHmhTM28+tW+sRO3qQkp4ipqy+NUt" +
      "zakDnagmAIULfqoBENkk32HPM66N7xDwzcx3JPAmaHk4TNSAb98ozLohQvbN8h" +
      "Wc3S7TvBVK8ylhKa59ys6YT4DXzQw71LlYxfUjasnp4hTf4="
  }
};

mock.securityContextInvalidSignature.GraphSignature2012 = {
  ...mock.securityContextTestDoc,
  "signature": {
    "type": "GraphSignature2012",
    "created": "2018-02-22T15:16:04Z",
    "creator": "https://example.com/i/alice/keys/1",
    "signatureValue":
      "CQC/V/0kPugo3fYJlDtu1DdeJwJvjfrdLOwC8cCA6HlXA/DTnfJrOyrki/ors" +
      "Cxiy3/oPr1y7oTRn6ZD7uuvT9cAB5zWiSqHxVrTL7gPff4FaJK+lvhsFKdlEj" +
      "0IoFG7Sr2DD6Y5bW01fqcHeeRoPZpUl3nl0oo3Rk8/UAlBE88="
  }
};

mock.parameters = {};

mock.parameters.sign = {};
mock.parameters.verify = {};
mock.parameters.verifyWithPassedKey = mock.parameters.sign;

mock.parameters.sign.EcdsaKoblitzSignature2016 = {
  creator: publicKeys.aliceBtc.id,
  date: '2017-03-25T22:01:04Z',
  privateKeyWif: mock.privateKeys.aliceBtc.privateKeyWif,
  publicKeyWif: mock.privateKeys.aliceBtc.publicKeyWif
};

mock.parameters.sign.Ed25519Signature2018 = {
  creator: publicKeys.carol.id,
  date: '2018-02-13T21:26:08Z',
  key: new Ed25519KeyPair({
    privateKeyBase58: mock.privateKeys.carol.privateKeyBase58,
    ...mock.publicKeys.carol
  })
};

mock.parameters.sign.RsaSignature2018 = {
  creator: publicKeys.alice.id,
  date: '2018-02-22T15:16:04Z',
  key: new RSAKeyPair({
    privateKeyPem: mock.privateKeys.alice.privateKeyPem,
    ...mock.publicKeys.alice
  })
};

mock.parameters.sign.LinkedDataSignature2015 = {
  creator: publicKeys.alice.id,
  date: '2018-02-22T15:16:04Z',
  privateKeyPem: mock.privateKeys.alice.privateKeyPem,
  publicKeyPem: mock.privateKeys.alice.publicKeyPem
};

mock.parameters.sign.GraphSignature2012 = {
  creator: publicKeys.alice.id,
  date: '2018-02-22T15:16:04Z',
  privateKeyPem: mock.privateKeys.alice.privateKeyPem,
  publicKeyPem: mock.privateKeys.alice.publicKeyPem
};

mock.parameters.verify.EcdsaKoblitzSignature2016 = {
  creator: publicKeys.aliceBtc.id,
  date: '2017-03-25T22:01:04Z'
};

mock.parameters.verify.Ed25519Signature2018 = {
  creator: publicKeys.carol.id,
  date: '2018-02-13T21:26:08Z'
};

mock.parameters.verify.RsaSignature2018 = {
  creator: publicKeys.alice.id,
  date: '2018-02-22T15:16:04Z'
};

mock.parameters.verify.LinkedDataSignature2015 = {
  creator: publicKeys.alice.id,
  date: '2018-02-22T15:16:04Z'
};

mock.parameters.verify.GraphSignature2012 = {
  creator: publicKeys.alice.id,
  date: '2018-12-26T18:08:04Z'
};
