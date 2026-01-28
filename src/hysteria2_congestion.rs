//! Hysteria2 congestion control configuration.
//!
//! This module provides bandwidth configuration for Hysteria2 clients.
//! Due to Quinn's API limitations (private types in quinn-proto), we use BBR
//! congestion control for all modes. The BandwidthConfig tracks the negotiated
//! rate for application-level use.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Shared bandwidth configuration for tracking negotiated rate.
///
/// - `target_rate_bps == 0` → BBR mode (dynamic bandwidth detection)
/// - `target_rate_bps > 0` → Fixed rate (in bytes per second)
///
/// Note: Due to Quinn's API limitations, BBR is always used as the congestion
/// controller. The rate value can be used for application-level rate limiting
/// if needed in the future.
#[derive(Clone, Debug)]
pub struct BandwidthConfig {
    /// Target rate in bytes per second (0 = BBR mode/unlimited)
    pub target_rate_bps: Arc<AtomicU64>,
}

impl BandwidthConfig {
    /// Create a new BandwidthConfig with BBR mode (rate = 0)
    pub fn new_bbr() -> Self {
        Self {
            target_rate_bps: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Create a new BandwidthConfig with a fixed rate
    pub fn new_brutal(rate_bps: u64) -> Self {
        Self {
            target_rate_bps: Arc::new(AtomicU64::new(rate_bps)),
        }
    }

    /// Set the target rate (0 = BBR/unlimited, >0 = fixed rate)
    pub fn set_rate(&self, rate_bps: u64) {
        self.target_rate_bps.store(rate_bps, Ordering::Relaxed);
    }

    /// Get the current target rate
    pub fn get_rate(&self) -> u64 {
        self.target_rate_bps.load(Ordering::Relaxed)
    }

    /// Check if currently in BBR/unlimited mode
    pub fn is_bbr(&self) -> bool {
        self.target_rate_bps.load(Ordering::Relaxed) == 0
    }

    /// Check if currently in fixed rate mode
    pub fn is_brutal(&self) -> bool {
        self.target_rate_bps.load(Ordering::Relaxed) > 0
    }
}

impl Default for BandwidthConfig {
    fn default() -> Self {
        Self::new_bbr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bandwidth_config_bbr_mode() {
        let config = BandwidthConfig::new_bbr();
        assert_eq!(config.get_rate(), 0);
        assert!(config.is_bbr());
        assert!(!config.is_brutal());

        config.set_rate(0);
        assert!(config.is_bbr());
    }

    #[test]
    fn test_bandwidth_config_brutal_mode() {
        let config = BandwidthConfig::new_brutal(1_000_000); // 1 Mbps
        assert_eq!(config.get_rate(), 1_000_000);
        assert!(!config.is_bbr());
        assert!(config.is_brutal());

        config.set_rate(5_000_000); // 5 Mbps
        assert_eq!(config.get_rate(), 5_000_000);
        assert!(config.is_brutal());
    }

    #[test]
    fn test_bandwidth_config_switch_modes() {
        let config = BandwidthConfig::new_bbr();

        // Initially in BBR mode
        assert!(config.is_bbr());

        // Switch to Brutal mode
        config.set_rate(10_000_000);
        assert!(config.is_brutal());
        assert_eq!(config.get_rate(), 10_000_000);

        // Switch back to BBR mode
        config.set_rate(0);
        assert!(config.is_bbr());
    }
}
