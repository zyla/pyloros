#!/usr/bin/env bash
set -e
cd "$(dirname "$0")/.."
cargo build --manifest-path tools/test-report/Cargo.toml --release -q
./tools/test-report/target/release/test-report "$@"
echo "Report: test-report.md / test-report.html"
