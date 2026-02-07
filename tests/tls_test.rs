//! Integration tests for TLS certificate generation

use redlimitador::tls::{CertificateAuthority, GeneratedCa, MitmCertificateGenerator};
use std::time::Duration;

#[test]
fn test_ca_generation() {
    let ca = GeneratedCa::generate().unwrap();

    assert!(ca.cert_pem.contains("BEGIN CERTIFICATE"));
    assert!(ca.cert_pem.contains("END CERTIFICATE"));
    assert!(ca.key_pem.contains("BEGIN PRIVATE KEY"));
    assert!(ca.key_pem.contains("END PRIVATE KEY"));
}

#[test]
fn test_ca_save_and_load() {
    let generated = GeneratedCa::generate().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("test_ca.crt");
    let key_path = dir.path().join("test_ca.key");

    generated.save(&cert_path, &key_path).unwrap();

    // Verify files exist
    assert!(cert_path.exists());
    assert!(key_path.exists());

    // Load and use
    let ca = CertificateAuthority::from_files(&cert_path, &key_path).unwrap();

    // Should be able to generate a cert
    let (cert_der, key_der) = ca.generate_cert_for_host("test.example.com").unwrap();
    assert!(!cert_der.is_empty());
    assert!(!key_der.secret_der().is_empty());
}

#[test]
fn test_host_certificate_generation() {
    let generated = GeneratedCa::generate().unwrap();
    let ca = CertificateAuthority::from_pem(&generated.cert_pem, &generated.key_pem).unwrap();

    let hosts = [
        "example.com",
        "api.example.com",
        "sub.domain.example.com",
        "localhost",
        "my-service.internal",
    ];

    for host in hosts {
        let (cert_der, key_der) = ca.generate_cert_for_host(host).unwrap();
        assert!(
            !cert_der.is_empty(),
            "Cert for {} should not be empty",
            host
        );
        assert!(
            !key_der.secret_der().is_empty(),
            "Key for {} should not be empty",
            host
        );
    }
}

#[test]
fn test_mitm_generator_caching() {
    let generated = GeneratedCa::generate().unwrap();
    let ca = CertificateAuthority::from_pem(&generated.cert_pem, &generated.key_pem).unwrap();
    let gen = MitmCertificateGenerator::new(ca);

    assert_eq!(gen.cache_size(), 0);

    // Generate cert for host
    let _ = gen.get_cert_for_host("example.com").unwrap();
    assert_eq!(gen.cache_size(), 1);

    // Second call should use cache
    let _ = gen.get_cert_for_host("example.com").unwrap();
    assert_eq!(gen.cache_size(), 1);

    // Different host
    let _ = gen.get_cert_for_host("other.com").unwrap();
    assert_eq!(gen.cache_size(), 2);
}

#[test]
fn test_mitm_generator_cache_capacity() {
    let generated = GeneratedCa::generate().unwrap();
    let ca = CertificateAuthority::from_pem(&generated.cert_pem, &generated.key_pem).unwrap();
    let gen = MitmCertificateGenerator::with_cache(ca, 2, Duration::from_secs(3600));

    // Fill cache
    let _ = gen.get_cert_for_host("one.com").unwrap();
    let _ = gen.get_cert_for_host("two.com").unwrap();
    assert_eq!(gen.cache_size(), 2);

    // Add third - should evict first
    let _ = gen.get_cert_for_host("three.com").unwrap();
    assert_eq!(gen.cache_size(), 2);
}

#[test]
fn test_server_config_generation() {
    // Install crypto provider for test
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let generated = GeneratedCa::generate().unwrap();
    let ca = CertificateAuthority::from_pem(&generated.cert_pem, &generated.key_pem).unwrap();
    let gen = MitmCertificateGenerator::new(ca);

    // Should be able to create a server config
    let config = gen.server_config_for_host("example.com").unwrap();

    // Basic validation - config should exist
    assert!(config.alpn_protocols.is_empty()); // Default has no ALPN
}

#[test]
fn test_ca_cert_der() {
    let generated = GeneratedCa::generate().unwrap();
    let ca = CertificateAuthority::from_pem(&generated.cert_pem, &generated.key_pem).unwrap();
    let gen = MitmCertificateGenerator::new(ca);

    let ca_der = gen.ca_cert_der();
    assert!(!ca_der.is_empty());
}

#[test]
fn test_invalid_ca_pem() {
    let result = CertificateAuthority::from_pem("not a cert", "not a key");
    assert!(result.is_err());
}

#[test]
fn test_file_not_found() {
    let result = CertificateAuthority::from_files("/nonexistent/ca.crt", "/nonexistent/ca.key");
    assert!(result.is_err());
}
