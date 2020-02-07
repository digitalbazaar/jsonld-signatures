/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const constants = require('../../lib/constants');

const controllers = {};
const publicKeys = {};
const privateKeys = {};

module.exports = {controllers, publicKeys, privateKeys};

publicKeys.alice = {
  '@context': constants.SECURITY_CONTEXT_URL,
  id: 'https://example.com/i/alice/keys/1',
  type: ['RsaVerificationKey2018'],
  owner: 'https://example.com/i/alice',
  publicKeyPem:
    '-----BEGIN PUBLIC KEY-----\n' +
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAj+uWAsdsMZhH+DE9d0Je\n' +
    'keJ6GVlb8C0tnvT+wW9vNJhg/Zb3qsT0ENli7GLFvm8wSEt61Ng8Xt8M+ytCnqQP\n' +
    '+SqKGx5fdrCeEwR0G2tzsUo2B4/H3DEp45656hBKtu0ZeTl8ZgfCKlYdDttoDWmq\n' +
    'CH3SHrqcmzlVcX3pnE0ARkP2trHODQDpX1gFF7Ct/uRyEppplK2c/SkElVuAD5c3\n' +
    'JX2wx81dv7Ujhse7ZKX9UEJ1FmrSa/O3JjdOSa5/hK0/oRHmBDK46RMdr94S7/GU\n' +
    'z1I2akGMkSxzBMJEw9wXd01GJXw+Xv8TkFF5ae+iQ0I7hkrww8x+G9EQCRKylV8w\n' +
    'cwIDAQAB\n' +
    '-----END PUBLIC KEY-----'
};
privateKeys.alice = {
  privateKeyPem:
    '-----BEGIN RSA PRIVATE KEY-----\n' +
    'MIIEowIBAAKCAQEAj+uWAsdsMZhH+DE9d0JekeJ6GVlb8C0tnvT+wW9vNJhg/Zb3\n' +
    'qsT0ENli7GLFvm8wSEt61Ng8Xt8M+ytCnqQP+SqKGx5fdrCeEwR0G2tzsUo2B4/H\n' +
    '3DEp45656hBKtu0ZeTl8ZgfCKlYdDttoDWmqCH3SHrqcmzlVcX3pnE0ARkP2trHO\n' +
    'DQDpX1gFF7Ct/uRyEppplK2c/SkElVuAD5c3JX2wx81dv7Ujhse7ZKX9UEJ1FmrS\n' +
    'a/O3JjdOSa5/hK0/oRHmBDK46RMdr94S7/GUz1I2akGMkSxzBMJEw9wXd01GJXw+\n' +
    'Xv8TkFF5ae+iQ0I7hkrww8x+G9EQCRKylV8wcwIDAQABAoIBAFBNy65RR/WEWuQJ\n' +
    '1Zot1kbgb/ClA7/H9aS0X1Hfs9VNERFuo1MOAoFESwZLNrtDn1U3iJoq7cSiAMRF\n' +
    'Jy8NrDwDmHv5PpsjgZBq8744/pz2I5+kgohChnUTo/kOjiHzujsB8H+d5KFq21vm\n' +
    '4PBa/R0v14Z96dRS8XIaJ7em33hUradmuYQYNn9IgP5Y334DebTaTE4+yeFkR0z5\n' +
    'KLm78o/3uoH7+a2C2u2ERimaLO4mpqQXHtmzhulbW2aBIQsR8wGzrBH/AnIej+h/\n' +
    'FJ2CF1XrChq6a2k+Nu9mLRDKxHYN4uQq9qSB7js6p8ZSUC7HkOT6tge69uNn1jZZ\n' +
    'lpKLNQECgYEAwNtNRphFMA6oYLS5FaUY8l/Th66ToDMzVGK3DWXnoHA3vBU/1LW2\n' +
    'VPwV/PJVdTY5mXoERAI75QHCrLcdH07ppHusc6pFdzdVvO8Q5XnwUTfb6dcG7Ips\n' +
    'vniDd3AMWUFgbK2qNOOOeM7Qe0OPXNWzHHcmtL2uLOno8Y4J32cBwqMCgYEAvwqT\n' +
    'ECUjQmtoWHOWcO5M0SCv6YMBrigBY3Y8zFztDWltFhCKUT9WLAMOIHh5CKGnfLgG\n' +
    '4PV9kjTLEefxtUCqBm00SifkfRujfUQyZjfZIV9UBhSDceiM9phAK8JsTAKbop/h\n' +
    'FTDkknyqzsM7biLZjflGNWXvuwASKu0ssJjRh/ECgYBvsNJhNyCiw2pqj1+9lF8N\n' +
    'R8gXBVkD54MrtPv0q3bo6PSuXdQY2aAeOdx2INazSlMzeoHr7StI5qsbIfWgwy/3\n' +
    'DZUDa7JNZ+OkxwOPEv7F2sbm95xP858k9GCXFHJiYsV4S1+Ov9csSgJd0PO/PRg9\n' +
    'PRhShqPP6Sv6cVtwYZSYZwKBgHMa7Pb6WV9IletNYaSTgEc02ajpnVaQlh2WfRVp\n' +
    'HA9LqUV1G9HORp5oDNf1nn9b3y1fOA3M/Cbelkgop1LdLlSG8c2IcbwLrhrovzEl\n' +
    'jzbzWA39yCEWy/A8VdXH5DZ8D8gRaq248s9sPAIuUZ2Pc+N+ARZlX+cdKNUiaB3T\n' +
    'RdQRAoGBAIc/UaN3A8ya1+dZ5orrQkjuPQXB7+UzR128vzsKb3F8nt4F92bRMu3D\n' +
    'vBHZCT4QDhv4CCyYlu//LqVBQDdUo4BNayZmjK8J0XUQ/YY77CE35YRRqQAphvvz\n' +
    'fCwRbNd/EW88Pg8ioO1WWcIgmA0296qEBv079qOWqPQq/BbUjH/3\n' +
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

privateKeys.alex = {
  privateKeyPem: '-----BEGIN RSA PRIVATE KEY-----\r\n' +
   'MIIEpQIBAAKCAQEA0MG729HDdieuzyFT+vdgMXDjTdCniWv64evMXydjfaYlTsmd\r\n' +
   '1FfFQYJdrKJaFzB4y9vm37yKvsw7FJFymSzmk4T62yMqCIe19UNGHqk5TDVSKf0X\r\n' +
   'ZTZX+5i9qhQOaL7yFzzLunI8bNxAzJZ63cGWf4uJI+513SN9IKvh45vWlgsbZ/ek\r\n' +
   'ELHF0YXrupeTzQZMq4fl2/vQxPPmpooNXZ3Fud9DZLAyWhKg69u996XjYP0QcjkE\r\n' +
   '7H1PC1Um+CYDGe65pzBQlYlwgYtztK64kK3A2FGVQufyQ+19FlHTJTYdyy/zKtyE\r\n' +
   '2+22wuANiLkg9JQEWroRQaGBLCmjwaA+AMQmfQIDAQABAoIBAQCezfIZy93UgWWS\r\n' +
   '/jiDnzHXCphv9r2sZa9Js/YZoL4ntH+HCwr8oPRW3FRkYnEEWQRbmGJua2Bkurpq\r\n' +
   '8CZsbeLN8AhhMcPlD1AVTuMFqhgDaECj3nuwrAGMTOpjerRnbHJ/yOj2Ybaj3X2R\r\n' +
   '5Rt8nKrfRgfChMG2wyuJ8hd57W/1XQf0l5Zn3kdRBK5NzUp9fRBJxFEKag8z+Zij\r\n' +
   'X4ENJmR66gCNLlE87+XMhcyHoJJmmhijC1Hq5Ph4rAsHKN6AMWviW59EyViA2gAb\r\n' +
   'iwwNlmg0W9qYxsbcrApJo/PAncCiNLvOshr8CwCdY1k9WOvAxPgBtAtEEXoH/01r\r\n' +
   'SJQ/wSElAoGBAOlUoOn2CQztW+Wm9yyRXGjYxl5a/3Nn3JHCAKj37KX+4aknoIv2\r\n' +
   'LckuA6pJCbW1Q8VVP8OH1lj43wb3siHzmH2jM6f0GIbSVFn/Z0mfhSGHGRHOuJXK\r\n' +
   'AXurraSIoPKi5G1ZhMNQB8RBq/Os1LrRCJ9L8pWDQHhsGT9PIp9q7fGLAoGBAOUJ\r\n' +
   '6Ig/RG/V7NRfoqP8Lupi820Q0EdLL9Jnr6utKtPxaGFSi9MrmCJK+9YD1VWw9XZ8\r\n' +
   'pFxIkz8aNRPnJgAWT66SLLPiW7wsQezLqpcWprsvfpbusPpfMf6K7FSWHYJJVL1i\r\n' +
   'pS/MBdeDgl/DBJgfm4OrIuuodaKFvC7jJnUEQrkXAoGBAMPykzQHr7AQgVVKM1dV\r\n' +
   'N5LBQU2qA87qERzDHITJuA3rD51brwL7GZZSszdFIQddE23b2rGdGNAdKEcUqp7C\r\n' +
   'kHQqI05Pum02oyn1R8tXUJlIeDAxN2hrfXVbRnbfWrKJQ2XlgI35XpxdPkdkBD5j\r\n' +
   'H2ePg0g2MmUu+sDk90GDrhFjAoGBAIS//m/hw6fSZScemyTSyNp/KbogUafQ01Hv\r\n' +
   'WOl3P+iB9k7aSkLF9LKDpX2A0UiOfWcEjTsTsYyUgwkbI3JPfDWhcZl9bFAfksJN\r\n' +
   'tX1G2rKJr6SJijhDrrVrDdlk/IuEN0Jhh36xkP09svYQEXyebUOekGnoRO5C9zRx\r\n' +
   '4dtW8dlXAoGAZe/1usB8YV7fOdGCJJ/IBLXG5xbtoSVD8yM/HVllazfr6fKlGqPO\r\n' +
   'ORhqr5estS7IVwZjcArkqiwJeXXUYPt0m9Oasqf1+g3UibR2SFRs1ZCLq1hSIuwf\r\n' +
   '4/MYqzY1568+/4+QkLFkjdT18HbkL7cRZrYmAoonb1KeDEbh0THsFHw=\r\n' +
   '-----END RSA PRIVATE KEY-----\r\n'
};

publicKeys.alex = {
  '@context': constants.SECURITY_CONTEXT_URL,
  id: 'https://example.com/i/alex/keys/1',
  type: ['RsaVerificationKey2018'],
  // this test ensures that controller.id works
  controller: {id: 'https://example.com/i/alex'},
  publicKeyPem: '-----BEGIN PUBLIC KEY-----\r\n' +
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0MG729HDdieuzyFT+vdg\r\n' +
    'MXDjTdCniWv64evMXydjfaYlTsmd1FfFQYJdrKJaFzB4y9vm37yKvsw7FJFymSzm\r\n' +
    'k4T62yMqCIe19UNGHqk5TDVSKf0XZTZX+5i9qhQOaL7yFzzLunI8bNxAzJZ63cGW\r\n' +
    'f4uJI+513SN9IKvh45vWlgsbZ/ekELHF0YXrupeTzQZMq4fl2/vQxPPmpooNXZ3F\r\n' +
    'ud9DZLAyWhKg69u996XjYP0QcjkE7H1PC1Um+CYDGe65pzBQlYlwgYtztK64kK3A\r\n' +
    '2FGVQufyQ+19FlHTJTYdyy/zKtyE2+22wuANiLkg9JQEWroRQaGBLCmjwaA+AMQm\r\n' +
    'fQIDAQAB\r\n-----END PUBLIC KEY-----\r\n'
};

// RsaKey with an assertionMethod
controllers.alex = {
  '@context': constants.SECURITY_CONTEXT_URL,
  id: publicKeys.alex.controller.id,
  assertionMethod: [publicKeys.alex.id],
  publicKey: [publicKeys.alex]
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

publicKeys.ned = {
  '@context': constants.SECURITY_CONTEXT_URL,
  id: 'https://example.com/i/ned/keys/1',
  type: ['Ed25519VerificationKey2018'],
  // this test ensures that controller.id works
  controller: {id: 'https://example.com/i/ned'},
  publicKeyBase58: '39GT26rnBupnnwBhwqHxsCgqoMNYauRStTQCN5JNaPL7'
};

privateKeys.ned = {
  privateKeyBase58:
   '4EyMEq4hqVznTz1uNiuubvC4zach1G2mKMoeWdeN37jvTvCwinrmcBgyoJsgheC9oG' +
   'uVYVntB4K8ePdmyMfH12vX'
};

// controller with an assertionMethod on it
// that's publicKey is in the Ed25519 format.
controllers.ned = {
  '@context': constants.SECURITY_CONTEXT_URL,
  id: publicKeys.ned.controller.id,
  assertionMethod: [publicKeys.ned.id],
  publicKey: [publicKeys.ned]
};
