#![no_main]

use libfuzzer_sys::fuzz_target;
use pyloros::filter::matcher::PatternMatcher;
use pyloros::filter::pktline;

fuzz_target!(|data: &[u8]| {
    // Exercise capabilities extraction
    let _ = pktline::extract_capabilities(data);

    // Exercise ref extraction
    let _ = pktline::extract_push_refs(data);

    // Exercise branch checking with a fixed set of patterns
    let patterns = [
        PatternMatcher::new("main").unwrap(),
        PatternMatcher::new("feature/*").unwrap(),
        PatternMatcher::new("refs/tags/*").unwrap(),
    ];
    let _ = pktline::check_push_branches(data, &patterns);
    let _ = pktline::blocked_refs(data, &patterns);
});
