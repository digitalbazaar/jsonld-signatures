module.exports = {
  "@context": [{
    "@version": 1.1
  }, "https://w3id.org/security/v1", {
    "RsaSignature2018": "sec:RsaSignature2018",

    "jws": "sec:jws",
    "proof": {"@id": "sec:proof", "@type": "@id", "@container": "@graph"},
    "proofPurpose": {"@id": "sec:proofPurpose", "@type": "@vocab"}
  }]
};
