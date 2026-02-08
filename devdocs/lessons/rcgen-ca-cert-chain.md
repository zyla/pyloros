# rcgen: CA cert chain verification requires `from_ca_cert_der`

When using rcgen to sign host certificates with a CA, `CertificateParams::from_ca_cert_der` (requires `x509-parser` feature) must be used to reconstruct the CA cert from its DER before calling `self_signed()`. Creating a new `CertificateParams` manually (even with the same DN/key usage) produces a different certificate (different serial, dates) that won't chain-verify against the original CA cert stored in client trust stores.

**Symptom**: `InvalidCertificate(UnknownIssuer)` when verifying a cert chain where the CA was reconstructed from params rather than parsed from DER.

**Fix**: `CertificateParams::from_ca_cert_der(&cert_der)` + `.self_signed(&key_pair)` preserves serial, validity, and subject key identifier so the signed child cert chains correctly.
