//! Request filtering and pattern matching

mod matcher;
mod rules;

pub use matcher::PatternMatcher;
pub use rules::{CompiledRule, FilterEngine, RequestInfo};
