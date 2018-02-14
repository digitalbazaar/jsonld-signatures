module.exports = {
  "@context": [{
    "@version": 1.1
  }, "https://w3id.org/security/v1", {
    "Ed25519Signature2018": "sec:Ed25519Signature2018",
    "EquihashProof2018": "sec:EquihashProof2018",
    "RsaSignature2018": "sec:RsaSignature2018",

    "jws": "sec:jws",
    "proof": {"@id": "sec:proof", "@type": "@id", "@container": "@graph"},
    "proofPurpose": {"@id": "sec:proofPurpose", "@type": "@vocab"},
    "proofValue": "sec:proofValue"
  }]
};
