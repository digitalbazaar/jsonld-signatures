/**
 * Linked Data Signatures/Proofs
 *
 * @author Christopher Lemmer Webber
 *
 * @license BSD 3-Clause License
 * Copyright (c) 2018 Digital Bazaar, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * Neither the name of the Digital Bazaar, Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
'use strict';

const constants = require('../constants');
const ProofPurpose = require('./ProofPurpose.js');

const credentialsNs = constants.CREDENTIALS_CONTEXT_URL + '#';

const VerifiableCredentialUri = credentialsNs + 'VerifiableCredential';
const credentialIssuanceUri = credentialsNs + 'credentialIssuance';
const claimUri = credentialsNs + 'claim';

module.exports = class CredentialIssuance extends ProofPurpose {
  constructor(injector) {
    super(injector);
    // TODO: We need a more permanent URI for this.  Where would it go?
    this.uri = credentialIssuanceUri;
  }

  // The document's type MUST be VerifiableCredential
  // Only one field really MUST be present.
  async verify({document, proof, purpose}) {
    const jsonld = this.injector.use('jsonld');
    let error;
    if(!jsonld.hasValue(document['@type'], VerifiableCredentialUri)) {
      error = new Error(
        `The document type must be "${VerifiableCredentialUri}".`);
    } else if(!document[claimUri]) {
      error = new Error('The document must contain a ');
    }
    return {verified: !error, error};
  }

  async createProof({proof, proofPurposeOptions}) {
    proof.proofPurpose = this.uri;
    return proof;
  }
};
