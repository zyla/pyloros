# rustls CryptoProvider must be installed early

When both `aws-lc-rs` and `ring` features are enabled on rustls (common when reqwest pulls in one and direct deps pull in the other), you must call `rustls::crypto::aws_lc_rs::default_provider().install_default()` before any rustls operations. In test harnesses, do this at the earliest entry point (e.g., test CA generation) rather than just before the proxy starts.
