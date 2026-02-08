#![no_main]

use libfuzzer_sys::fuzz_target;
use pyloros::Config;

fuzz_target!(|data: &[u8]| {
    let input = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Exercise TOML config parsing; errors are fine
    let _ = Config::parse(input);
});
