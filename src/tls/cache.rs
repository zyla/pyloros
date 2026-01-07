//! Certificate caching for MITM

use lru::LruCache;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A cached certificate entry
struct CacheEntry {
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    created_at: Instant,
}

/// LRU cache for generated certificates
pub struct CertificateCache {
    cache: Mutex<LruCache<String, CacheEntry>>,
    ttl: Duration,
}

impl CertificateCache {
    /// Create a new certificate cache
    ///
    /// # Arguments
    /// * `capacity` - Maximum number of certificates to cache
    /// * `ttl` - Time-to-live for cached certificates
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        let capacity = NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::new(1000).unwrap());
        Self {
            cache: Mutex::new(LruCache::new(capacity)),
            ttl,
        }
    }

    /// Get a certificate from the cache if it exists and hasn't expired
    pub fn get(&self, hostname: &str) -> Option<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
        let mut cache = self.cache.lock().unwrap();

        if let Some(entry) = cache.get(hostname) {
            if entry.created_at.elapsed() < self.ttl {
                return Some((entry.cert.clone(), entry.key.clone_key()));
            } else {
                // Expired, remove it
                cache.pop(hostname);
            }
        }

        None
    }

    /// Store a certificate in the cache
    pub fn put(
        &self,
        hostname: String,
        cert: CertificateDer<'static>,
        key: PrivateKeyDer<'static>,
    ) {
        let mut cache = self.cache.lock().unwrap();
        cache.put(
            hostname,
            CacheEntry {
                cert,
                key,
                created_at: Instant::now(),
            },
        );
    }

    /// Get the number of cached certificates
    pub fn len(&self) -> usize {
        self.cache.lock().unwrap().len()
    }

    /// Check if the cache is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clear all cached certificates
    pub fn clear(&self) {
        self.cache.lock().unwrap().clear();
    }
}

impl Default for CertificateCache {
    fn default() -> Self {
        // Default: 1000 certs, 12 hour TTL
        Self::new(1000, Duration::from_secs(12 * 60 * 60))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::ca::{CertificateAuthority, GeneratedCa};

    fn generate_test_cert(hostname: &str) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let generated = GeneratedCa::generate().unwrap();
        let ca = CertificateAuthority::from_pem(&generated.cert_pem, &generated.key_pem).unwrap();
        ca.generate_cert_for_host(hostname).unwrap()
    }

    #[test]
    fn test_cache_put_get() {
        let cache = CertificateCache::default();

        let (cert, key) = generate_test_cert("example.com");
        cache.put("example.com".to_string(), cert.clone(), key);

        let result = cache.get("example.com");
        assert!(result.is_some());

        let (cached_cert, _) = result.unwrap();
        assert_eq!(cached_cert.as_ref(), cert.as_ref());
    }

    #[test]
    fn test_cache_miss() {
        let cache = CertificateCache::default();
        assert!(cache.get("nonexistent.com").is_none());
    }

    #[test]
    fn test_cache_expiration() {
        // Very short TTL
        let cache = CertificateCache::new(100, Duration::from_millis(1));

        let (cert, key) = generate_test_cert("example.com");
        cache.put("example.com".to_string(), cert, key);

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(10));

        assert!(cache.get("example.com").is_none());
    }

    #[test]
    fn test_cache_capacity() {
        let cache = CertificateCache::new(2, Duration::from_secs(3600));

        let (cert1, key1) = generate_test_cert("one.com");
        let (cert2, key2) = generate_test_cert("two.com");
        let (cert3, key3) = generate_test_cert("three.com");

        cache.put("one.com".to_string(), cert1, key1);
        cache.put("two.com".to_string(), cert2, key2);
        cache.put("three.com".to_string(), cert3, key3);

        // LRU eviction should have removed "one.com"
        assert!(cache.get("one.com").is_none());
        assert!(cache.get("two.com").is_some());
        assert!(cache.get("three.com").is_some());
    }

    #[test]
    fn test_cache_len() {
        let cache = CertificateCache::default();
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());

        let (cert, key) = generate_test_cert("example.com");
        cache.put("example.com".to_string(), cert, key);

        assert_eq!(cache.len(), 1);
        assert!(!cache.is_empty());
    }

    #[test]
    fn test_cache_clear() {
        let cache = CertificateCache::default();

        let (cert, key) = generate_test_cert("example.com");
        cache.put("example.com".to_string(), cert, key);

        cache.clear();
        assert!(cache.is_empty());
    }
}
