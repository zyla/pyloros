//! Integration tests for TLS certificate generation

#[path = "common/mod.rs"]
mod common;

use redlimitador::tls::{CertificateAuthority, GeneratedCa, MitmCertificateGenerator};
use std::time::Duration;

#[test]
fn test_ca_generation() {
    let t = test_report!("CA certificate generation");

    t.action("Generate CA");
    let ca = GeneratedCa::generate().unwrap();

    t.assert_contains(
        "Cert PEM has BEGIN CERTIFICATE",
        &ca.cert_pem,
        "BEGIN CERTIFICATE",
    );
    t.assert_contains(
        "Cert PEM has END CERTIFICATE",
        &ca.cert_pem,
        "END CERTIFICATE",
    );
    t.assert_contains(
        "Key PEM has BEGIN PRIVATE KEY",
        &ca.key_pem,
        "BEGIN PRIVATE KEY",
    );
    t.assert_contains(
        "Key PEM has END PRIVATE KEY",
        &ca.key_pem,
        "END PRIVATE KEY",
    );
}

#[test]
fn test_ca_save_and_load() {
    let t = test_report!("CA save to disk and reload");

    t.action("Generate CA");
    let generated = GeneratedCa::generate().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("test_ca.crt");
    let key_path = dir.path().join("test_ca.key");

    t.action(format!("Save CA to {}", dir.path().display()));
    generated.save(&cert_path, &key_path).unwrap();

    t.assert_true("cert file exists", cert_path.exists());
    t.assert_true("key file exists", key_path.exists());

    t.action("Load CA from saved files");
    let ca = CertificateAuthority::from_files(&cert_path, &key_path).unwrap();

    t.action("Generate cert for test.example.com");
    let (cert_der, key_der) = ca.generate_cert_for_host("test.example.com").unwrap();
    t.assert_true("cert DER not empty", !cert_der.is_empty());
    t.assert_true("key DER not empty", !key_der.secret_der().is_empty());
}

#[test]
fn test_host_certificate_generation() {
    let t = test_report!("Per-host certificate generation");

    t.action("Generate CA");
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
        t.action(format!("Generate cert for {}", host));
        let (cert_der, key_der) = ca.generate_cert_for_host(host).unwrap();
        t.assert_true(
            &format!("cert for {} not empty", host),
            !cert_der.is_empty(),
        );
        t.assert_true(
            &format!("key for {} not empty", host),
            !key_der.secret_der().is_empty(),
        );
    }
}

#[test]
fn test_mitm_generator_caching() {
    let t = test_report!("MITM generator caches certificates");

    t.action("Generate CA + create MITM generator");
    let generated = GeneratedCa::generate().unwrap();
    let ca = CertificateAuthority::from_pem(&generated.cert_pem, &generated.key_pem).unwrap();
    let gen = MitmCertificateGenerator::new(ca);

    t.assert_eq("Initial cache size", &gen.cache_size(), &0usize);

    t.action("Generate cert for example.com");
    let _ = gen.get_cert_for_host("example.com").unwrap();
    t.assert_eq("Cache size after first host", &gen.cache_size(), &1usize);

    t.action("Request example.com again (should hit cache)");
    let _ = gen.get_cert_for_host("example.com").unwrap();
    t.assert_eq("Cache size unchanged", &gen.cache_size(), &1usize);

    t.action("Generate cert for other.com");
    let _ = gen.get_cert_for_host("other.com").unwrap();
    t.assert_eq("Cache size after second host", &gen.cache_size(), &2usize);
}

#[test]
fn test_mitm_generator_cache_capacity() {
    let t = test_report!("MITM generator evicts oldest when cache full");

    t.action("Create MITM generator with capacity=2");
    let generated = GeneratedCa::generate().unwrap();
    let ca = CertificateAuthority::from_pem(&generated.cert_pem, &generated.key_pem).unwrap();
    let gen = MitmCertificateGenerator::with_cache(ca, 2, Duration::from_secs(3600));

    t.action("Fill cache: one.com, two.com");
    let _ = gen.get_cert_for_host("one.com").unwrap();
    let _ = gen.get_cert_for_host("two.com").unwrap();
    t.assert_eq("Cache full at 2", &gen.cache_size(), &2usize);

    t.action("Add three.com (should evict oldest)");
    let _ = gen.get_cert_for_host("three.com").unwrap();
    t.assert_eq("Cache still at capacity 2", &gen.cache_size(), &2usize);
}

#[test]
fn test_server_config_generation() {
    let t = test_report!("Server TLS config with ALPN protocols");

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    t.action("Generate CA + create MITM generator");
    let generated = GeneratedCa::generate().unwrap();
    let ca = CertificateAuthority::from_pem(&generated.cert_pem, &generated.key_pem).unwrap();
    let gen = MitmCertificateGenerator::new(ca);

    t.action("Create server config for example.com");
    let config = gen.server_config_for_host("example.com").unwrap();

    t.assert_eq(
        "ALPN protocols",
        &config.alpn_protocols,
        &vec![b"h2".to_vec(), b"http/1.1".to_vec()],
    );
}

#[test]
fn test_ca_cert_der() {
    let t = test_report!("CA DER export not empty");

    t.action("Generate CA + create MITM generator");
    let generated = GeneratedCa::generate().unwrap();
    let ca = CertificateAuthority::from_pem(&generated.cert_pem, &generated.key_pem).unwrap();
    let gen = MitmCertificateGenerator::new(ca);

    let ca_der = gen.ca_cert_der();
    t.assert_true("CA DER not empty", !ca_der.is_empty());
}

#[test]
fn test_invalid_ca_pem() {
    let t = test_report!("Invalid CA PEM rejected");

    t.action("Load invalid PEM data");
    let result = CertificateAuthority::from_pem("not a cert", "not a key");
    t.assert_true("from_pem returns error", result.is_err());
}

#[test]
fn test_file_not_found() {
    let t = test_report!("Non-existent CA files rejected");

    t.action("Load from /nonexistent/ca.crt");
    let result = CertificateAuthority::from_files("/nonexistent/ca.crt", "/nonexistent/ca.key");
    t.assert_true("from_files returns error", result.is_err());
}
