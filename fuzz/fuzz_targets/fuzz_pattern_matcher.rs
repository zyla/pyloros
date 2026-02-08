#![no_main]

use libfuzzer_sys::fuzz_target;
use pyloros::filter::matcher::PatternMatcher;

fuzz_target!(|data: &[u8]| {
    // Split input into pattern and text at the first null byte
    let split = data.iter().position(|&b| b == 0);
    let (pattern_bytes, text_bytes) = match split {
        Some(pos) => (&data[..pos], &data[pos + 1..]),
        None => (data, &[] as &[u8]),
    };

    let pattern = match std::str::from_utf8(pattern_bytes) {
        Ok(s) => s,
        Err(_) => return,
    };
    let text = match std::str::from_utf8(text_bytes) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Exercise pattern compilation; errors are fine
    if let Ok(matcher) = PatternMatcher::new(pattern) {
        // Exercise matching
        let _ = matcher.matches(text);
        let _ = matcher.is_literal();
        let _ = matcher.pattern();
    }
});
