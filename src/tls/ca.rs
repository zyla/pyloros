//! Certificate Authority management

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls_pemfile;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use crate::error::{Error, Result};

/// A generated CA certificate and key pair
pub struct GeneratedCa {
    /// PEM-encoded certificate
    pub cert_pem: String,
    /// PEM-encoded private key
    pub key_pem: String,
}

impl GeneratedCa {
    /// Generate a new CA certificate
    pub fn generate() -> Result<Self> {
        let mut params = CertificateParams::default();

        // Set distinguished name
        params
            .distinguished_name
            .push(DnType::CommonName, "Redlimitador Proxy CA");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "Redlimitador");

        // This is a CA certificate
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

        // Key usage for CA
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];

        // Valid for 10 years
        params.not_before = time::OffsetDateTime::now_utc();
        params.not_after = params.not_before + time::Duration::days(3650);

        // Generate key pair
        let key_pair = KeyPair::generate().map_err(|e| Error::certificate(e.to_string()))?;

        // Generate certificate
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| Error::certificate(e.to_string()))?;

        Ok(Self {
            cert_pem: cert.pem(),
            key_pem: key_pair.serialize_pem(),
        })
    }

    /// Save the certificate and key to files
    pub fn save(&self, cert_path: impl AsRef<Path>, key_path: impl AsRef<Path>) -> Result<()> {
        std::fs::write(cert_path.as_ref(), &self.cert_pem).map_err(|e| {
            Error::certificate(format!(
                "Failed to write certificate to '{}': {}",
                cert_path.as_ref().display(),
                e
            ))
        })?;

        std::fs::write(key_path.as_ref(), &self.key_pem).map_err(|e| {
            Error::certificate(format!(
                "Failed to write key to '{}': {}",
                key_path.as_ref().display(),
                e
            ))
        })?;

        // Set restrictive permissions on key file (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(key_path.as_ref())?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(key_path.as_ref(), perms)?;
        }

        Ok(())
    }
}

/// A loaded Certificate Authority for signing MITM certificates
pub struct CertificateAuthority {
    /// The CA key pair (used for signing)
    key_pair: Arc<KeyPair>,
    /// DER-encoded CA certificate
    cert_der: CertificateDer<'static>,
}

impl CertificateAuthority {
    /// Load a CA from PEM-encoded certificate and key
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self> {
        // Parse the private key
        let key_pair = KeyPair::from_pem(key_pem)
            .map_err(|e| Error::certificate(format!("Failed to parse CA private key: {}", e)))?;

        // Parse the certificate PEM to DER
        let mut cert_reader = BufReader::new(cert_pem.as_bytes());
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
            .filter_map(|r| r.ok())
            .collect();

        let cert_der = certs
            .into_iter()
            .next()
            .ok_or_else(|| Error::certificate("No certificate found in PEM"))?;

        Ok(Self {
            key_pair: Arc::new(key_pair),
            cert_der,
        })
    }

    /// Load a CA from files
    pub fn from_files(cert_path: impl AsRef<Path>, key_path: impl AsRef<Path>) -> Result<Self> {
        let cert_pem = std::fs::read_to_string(cert_path.as_ref()).map_err(|e| {
            Error::certificate(format!(
                "Failed to read CA certificate '{}': {}",
                cert_path.as_ref().display(),
                e
            ))
        })?;

        let key_pem = std::fs::read_to_string(key_path.as_ref()).map_err(|e| {
            Error::certificate(format!(
                "Failed to read CA key '{}': {}",
                key_path.as_ref().display(),
                e
            ))
        })?;

        Self::from_pem(&cert_pem, &key_pem)
    }

    /// Generate a certificate for a specific hostname
    pub fn generate_cert_for_host(
        &self,
        hostname: &str,
    ) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
        let mut params = CertificateParams::default();

        // Set common name
        params.distinguished_name.push(DnType::CommonName, hostname);

        // Add Subject Alternative Name
        params.subject_alt_names =
            vec![rcgen::SanType::DnsName(hostname.try_into().map_err(
                |e| Error::certificate(format!("Invalid hostname '{}': {}", hostname, e)),
            )?)];

        // This is not a CA
        params.is_ca = IsCa::NoCa;

        // Extended key usage for server auth
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        // Key usage
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];

        // Valid for 1 day (short-lived MITM certs)
        params.not_before = time::OffsetDateTime::now_utc();
        params.not_after = params.not_before + time::Duration::days(1);

        // Generate new key pair for this cert
        let cert_key_pair = KeyPair::generate().map_err(|e| Error::certificate(e.to_string()))?;

        // Create a signing CA certificate params to sign the new cert
        // We need to create params that represent the CA for signing
        let mut ca_params = CertificateParams::default();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Redlimitador Proxy CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];

        // Create a self-signed CA cert just for signing (uses stored key)
        let ca_cert = ca_params
            .self_signed(&self.key_pair)
            .map_err(|e| Error::certificate(format!("Failed to create CA for signing: {}", e)))?;

        // Sign the new certificate with the CA
        let cert = params
            .signed_by(&cert_key_pair, &ca_cert, &self.key_pair)
            .map_err(|e| Error::certificate(format!("Failed to sign certificate: {}", e)))?;

        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert_key_pair.serialize_der()));

        Ok((cert_der, key_der))
    }

    /// Get the CA certificate in DER format
    pub fn cert_der(&self) -> &CertificateDer<'static> {
        &self.cert_der
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ca() {
        let ca = GeneratedCa::generate().unwrap();
        assert!(ca.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(ca.key_pem.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn test_load_generated_ca() {
        let generated = GeneratedCa::generate().unwrap();
        let ca = CertificateAuthority::from_pem(&generated.cert_pem, &generated.key_pem).unwrap();
        assert!(!ca.cert_der().is_empty());
    }

    #[test]
    fn test_generate_host_cert() {
        let generated = GeneratedCa::generate().unwrap();
        let ca = CertificateAuthority::from_pem(&generated.cert_pem, &generated.key_pem).unwrap();

        let (cert_der, key_der) = ca.generate_cert_for_host("example.com").unwrap();
        assert!(!cert_der.is_empty());
        assert!(!key_der.secret_der().is_empty());
    }

    #[test]
    fn test_generate_host_cert_with_subdomain() {
        let generated = GeneratedCa::generate().unwrap();
        let ca = CertificateAuthority::from_pem(&generated.cert_pem, &generated.key_pem).unwrap();

        let (cert_der, _) = ca.generate_cert_for_host("api.example.com").unwrap();
        assert!(!cert_der.is_empty());
    }

    #[test]
    fn test_save_and_load_ca() {
        let generated = GeneratedCa::generate().unwrap();

        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("ca.crt");
        let key_path = dir.path().join("ca.key");

        generated.save(&cert_path, &key_path).unwrap();

        let ca = CertificateAuthority::from_files(&cert_path, &key_path).unwrap();
        let (cert_der, _) = ca.generate_cert_for_host("test.com").unwrap();
        assert!(!cert_der.is_empty());
    }
}
