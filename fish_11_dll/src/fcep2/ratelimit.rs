//! FCEP-2 Fragment Rate Limiter (RFC Section 8.4)
//!
//! Per-destination sliding-window rate limiter enforcing a maximum of
//! 4 fragments per second per destination by default.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use super::types::FragmentRateBucket;

/// Default max fragments per second per destination
const DEFAULT_MAX_PER_SECOND: u32 = 4;

/// Sliding window size in seconds
const WINDOW_SECS: i64 = 1;

/// Per-destination fragment rate limiter
pub struct FragmentRateLimiter {
    buckets: HashMap<String, FragmentRateBucket>,
}

impl Default for FragmentRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl FragmentRateLimiter {
    pub fn new() -> Self {
        Self { buckets: HashMap::new() }
    }

    /// Check if a fragment send is allowed for the given destination.
    /// If allowed, records the timestamp and returns true.
    /// If rate-limited, returns false.
    pub fn allow_send(&mut self, destination: &str) -> bool {
        let now = Self::now_secs();
        let window_start = now.saturating_sub(WINDOW_SECS);

        let bucket = self.buckets.entry(destination.to_string()).or_insert_with(|| {
            FragmentRateBucket { timestamps: Vec::new(), max_per_second: DEFAULT_MAX_PER_SECOND }
        });

        // Prune timestamps outside the window
        bucket.timestamps.retain(|&t| t > window_start);

        if bucket.timestamps.len() as u32 >= bucket.max_per_second {
            return false;
        }

        bucket.timestamps.push(now);
        true
    }

    /// Remove stale buckets with no recent timestamps
    pub fn cleanup_stale(&mut self) {
        let now = Self::now_secs();
        let window_start = now.saturating_sub(WINDOW_SECS * 2);
        self.buckets.retain(|_, bucket| {
            bucket.timestamps.retain(|&t| t > window_start);
            !bucket.timestamps.is_empty()
        });
    }

    fn now_secs() -> i64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allows_under_limit() {
        let mut limiter = FragmentRateLimiter::new();
        assert!(limiter.allow_send("#test"));
        assert!(limiter.allow_send("#test"));
        assert!(limiter.allow_send("#test"));
        assert!(limiter.allow_send("#test"));
    }

    #[test]
    fn test_blocks_at_limit() {
        let mut limiter = FragmentRateLimiter::new();
        for _ in 0..4 {
            assert!(limiter.allow_send("#test"));
        }
        assert!(!limiter.allow_send("#test"));
    }

    #[test]
    fn test_independent_destinations() {
        let mut limiter = FragmentRateLimiter::new();
        for _ in 0..4 {
            assert!(limiter.allow_send("#ch1"));
        }
        assert!(!limiter.allow_send("#ch1"));
        assert!(limiter.allow_send("#ch2"));
    }
}
