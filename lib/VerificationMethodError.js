/*!
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

/**
 * Thrown when a proof's verification method resolved but cannot back the
 * proof: it is not in the loaded document (`notFound`), the controller
 * document does not list it under the proof purpose's term (`notAuthorized`),
 * or its `id` is not a string (`invalidId`).
 */
class VerificationMethodError extends Error {
  /**
   * @param {object} options - Options hashmap.
   * @param {string} options.message - The error message.
   * @param {'notFound'|'notAuthorized'|'invalidId'} options.code - The
   *   machine-readable fault.
   * @param {string} [options.verificationMethod] - The verification method
   *   id, if known.
   */
  constructor({message, code, verificationMethod}) {
    super(message);
    this.name = 'VerificationMethodError';
    this.code = code;
    this.verificationMethod = verificationMethod;
  }
}
module.exports = VerificationMethodError;
