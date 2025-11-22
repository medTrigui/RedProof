//! Placeholder crate for zero-knowledge circuits.

/// Returns the version of the ZK module. This is a stub for Phase 0.
pub fn version() -> &'static str {
    "0.0.0-phase0"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_stable() {
        assert_eq!(version(), "0.0.0-phase0");
    }
}
