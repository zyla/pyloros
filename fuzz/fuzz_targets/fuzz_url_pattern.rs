#![no_main]

use libfuzzer_sys::fuzz_target;
use pyloros::filter::matcher::UrlPattern;

fuzz_target!(|data: &[u8]| {
    let input = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Exercise URL pattern parsing; errors are fine
    if let Ok(pattern) = UrlPattern::new(input) {
        // Exercise matching with some fixed inputs
        let _ = pattern.matches("https", "example.com", None, "/", None);
        let _ = pattern.matches("http", "localhost", Some(8080), "/api/v1", Some("q=test"));
        let _ = pattern.matches("https", "sub.example.com", Some(443), "/path", None);
    }
});
