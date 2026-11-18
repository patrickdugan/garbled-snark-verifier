use std::{fmt, ops::Deref};

use rand::Rng;

use crate::S;

const MAX_NONZERO_DELTA_ATTEMPTS: usize = 64;

/// A wrapper type for the global Free-XOR delta `Δ`.
///
/// This wrapper provides semantic clarity and ensures proper handling
/// of the delta value in garbled circuits. The delta is used in the
/// Free-XOR technique where `label1 = label0 ⊕ Δ`.
///
/// Use [`Delta::generate(rng)`] to obtain a valid instance.
///
/// # Security Note
/// The delta value must be kept secret during garbling and must not leak
/// to the evaluator. Proper wrapper usage helps prevent accidental exposure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Delta(S);

impl Delta {
    /// Generates a new non-zero delta using the provided RNG.
    ///
    /// This ensures the delta generation is part of the single source of truth
    /// for randomness in the garbling process while rejecting degenerate zero
    /// deltas that would collapse opposite wire labels (`label0 == label1`).
    pub fn generate(rng: &mut impl Rng) -> Self {
        for _ in 0..MAX_NONZERO_DELTA_ATTEMPTS {
            let candidate = S::random(rng);
            if candidate != S::ZERO {
                return Self(candidate);
            }
        }
        panic!("RNG failed to produce a non-zero Free-XOR delta");
    }
}

impl fmt::Debug for Delta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Delta([REDACTED])")
    }
}

impl Deref for Delta {
    type Target = S;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
