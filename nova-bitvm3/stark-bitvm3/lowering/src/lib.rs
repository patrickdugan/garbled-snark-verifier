//! Boolean checker for a trusted, finalized upstream circuit and its public policy.
//! This is a circuit-language adapter, not a complete Stwo or Cairo verifier.
mod program;
pub use program::*;
#[cfg(feature = "test-utils")]
pub mod testing;
#[cfg(feature = "test-utils")]
pub mod fixture;
