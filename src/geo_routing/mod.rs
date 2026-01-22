//! Geo routing module for Clash-style traffic分流
//!
//! This module provides GeoIP and GeoSite based routing decisions.
//! It implements a simplified routing strategy:
//! - CN (China) IPs and domains → Direct
//! - Everything else → Proxy
//!
//! # Usage
//!
//! ```rust,ignore
//! use shoes::geo_routing;
//! use url::Host;
//!
//! // Create matcher from .dat files
//! let geo_matcher = match geo_routing::GeoMatcher::from_dat_files(
//!     Some("/path/to/geoip.dat"),
//!     Some("/path/to/geosite.dat"),
//! ) {
//!     Ok(Some(matcher)) => Some(matcher),
//!     Ok(None) => None, // No geo data available
//!     Err(e) => {
//!         log::warn!("Failed to load geo data: {}", e);
//!         None
//!     }
//! };
//!
//! // Use matcher to judge traffic
//! if let Some(matcher) = &geo_matcher {
//!     let host = Host::Domain("example.com".to_string());
//!     match geo_routing::judge(matcher, &host) {
//!         Some(geo_routing::RouteAction::Direct) => {
//!             // Route directly
//!         }
//!         Some(geo_routing::RouteAction::Proxy) => {
//!             // Route through proxy
//!         }
//!         None => {
//!             // No geo match, fall back to other rules
//!         }
//!     }
//! }
//! ```

mod dat_loader;
mod matcher;
mod proto;

// Re-export public types
pub use matcher::{GeoMatcher, RouteAction};

/// Judge traffic based on geo routing rules
///
/// This is the main entry point for geo-based routing decisions.
/// Returns:
/// - `Some(RouteAction::Direct)` if the host matches CN geo rules
/// - `Some(RouteAction::Proxy)` if the host does NOT match CN (default to proxy)
/// - `None` if geo matching is not applicable
///
/// # Arguments
///
/// * `matcher` - The GeoMatcher instance
/// * `host` - The destination host to match against
///
/// # Example
///
/// ```rust,ignore
/// use shoes::geo_routing;
/// use url::Host;
///
/// let host = Host::Domain("baidu.com".to_string());
/// if let Some(action) = geo_routing::judge(&matcher, &host) {
///     match action {
///         geo_routing::RouteAction::Direct => {
///             // Route directly without proxy
///         }
///         geo_routing::RouteAction::Proxy => {
///             // Route through proxy
///         }
///     }
/// }
/// ```
pub fn judge(matcher: &GeoMatcher, host: &url::Host) -> Option<RouteAction> {
    matcher.judge(host)
}
