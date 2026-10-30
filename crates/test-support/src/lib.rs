// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

mod tracing;
pub use tracing::with_tracing;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

pub fn create_shared_rng_from_u64(value: u64) -> Arc<Mutex<ChaCha20Rng>> {
    Arc::new(Mutex::new(ChaCha20Rng::seed_from_u64(value)))
}

/// Each simulated node gets a distinct mutex, even for the same seed.
pub fn derive_shared_rng(base_seed: u64, salt: u64) -> Arc<Mutex<ChaCha20Rng>> {
    create_shared_rng_from_u64(base_seed.wrapping_add(salt))
}

pub fn create_seed_from_u64(value: u64) -> [u8; 32] {
    ChaCha20Rng::seed_from_u64(value).get_seed()
}

/// Find an existing bb binary; discovery never installs tools or prepares artifacts.
pub async fn find_bb() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("E3_CUSTOM_BB") {
        let path = PathBuf::from(p.trim());
        if path.is_file() {
            return Some(path);
        }
    }
    if let Ok(output) = tokio::process::Command::new("which")
        .arg("bb")
        .output()
        .await
    {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Some(PathBuf::from(path));
            }
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        for path in [
            format!("{}/.bb/bb", home),
            format!("{}/.nargo/bin/bb", home),
            format!("{}/.interfold/noir/bin/bb", home),
        ] {
            if std::path::Path::new(&path).exists() {
                return Some(PathBuf::from(path));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn node_rngs_are_repeatable_but_do_not_share_a_lock() {
        let first = derive_shared_rng(42, 1);
        let repeated = derive_shared_rng(42, 1);
        let other_node = derive_shared_rng(42, 2);
        let mut first = first.lock().unwrap();
        let mut repeated = repeated.try_lock().expect("a distinct node mutex");
        let first_value = first.next_u64();
        assert_eq!(first_value, repeated.next_u64());
        assert_ne!(first_value, other_node.lock().unwrap().next_u64());
    }

    #[test]
    fn node_seed_derivation_preserves_wrapping_addition() {
        assert_eq!(
            derive_shared_rng(u64::MAX, 1).lock().unwrap().get_seed(),
            create_seed_from_u64(0),
        );
    }
}
