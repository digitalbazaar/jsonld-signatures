/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const constants = require('../lib/constants');
const ProofPurposeHandler = require('../lib/proof-purpose/ProofPurposeHandler');

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
controllers.alice = {
  '@context': constants.SECURITY_CONTEXT_URL,
  id: publicKeys.alice.owner,
  publicKey: [publicKeys.alice],
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
}

mock.NOOP_PROOF_PURPOSE_URI = 'https://example.org/special-authentication';

class NoOpProofPurpose extends ProofPurposeHandler {
  constructor(options) {
    super(options);
    // if the value of `uri` is *not* defined in SECURITY_CONTEXT then it must
    // be in expanded form as demonstrated here
    this.uri = mock.NOOP_PROOF_PURPOSE_URI;
  }
  async validate({document, proof, purposeParameters}) {
    return {valid: true};
  }
  // the proof provided here is compacted into the SECURITY_CONTEXT
  async updateProof({proof, purposeParameters}) {
    // TODO: We may not want to mutate the proof passed in
    proof.proofPurpose = this.uri;
    // the proof returned here *must* be compacted into the SECURITY_CONTEXT
    return proof;
  }
}

mock.NoOpProofPurpose = NoOpProofPurpose;
