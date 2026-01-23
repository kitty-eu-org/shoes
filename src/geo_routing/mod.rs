//! Geo routing module for Clash-style traffic diversion based on GeoIP and GeoSite.
//!
//! This module re-exports the `v2ray_router` library for geo-based routing decisions.
//!
//! # Usage
//!
//! ```rust,ignore
//! use shoes::geo_routing;
//! use url::Host;
//!
//! // Create router from .dat files
//! let router = geo_routing::Router::from_paths(
//!     "data/geosite.dat",
//!     "data/geoip.dat",
//! )?;
//!
//! // Query domain
//! let action = router.query_domain("www.google.com");
//! match action {
//!     geo_routing::RouteAction::Proxy => println!("Route through proxy"),
//!     geo_routing::RouteAction::Direct => println!("Route directly"),
//!     geo_routing::RouteAction::Reject => println!("Reject connection"),
//! }
//! ```

// Re-export v2ray_router types
pub use v2ray_router::{Router, RouteAction};

/// Judge traffic based on geo routing rules.
///
/// This is a compatibility function that wraps the router's query_domain method.
/// For domain hosts, it queries the domain; for IP hosts, it queries the IP.
///
/// # Arguments
///
/// * `router` - The Router instance
/// * `host` - The destination host to match against
///
/// # Example
///
/// ```rust,ignore
/// use shoes::geo_routing;
/// use url::Host;
///
/// let host = Host::Domain("baidu.com".to_string());
/// match geo_routing::judge(&router, &host) {
///     geo_routing::RouteAction::Direct => {
///         // Route directly without proxy
///     }
///     geo_routing::RouteAction::Proxy => {
///         // Route through proxy
///     }
///     geo_routing::RouteAction::Reject => {
///         // Reject the connection
///     }
/// }
/// ```
pub fn judge(router: &Router, host: &url::Host) -> RouteAction {
    match host {
        url::Host::Domain(domain) => router.query_domain(domain),
        url::Host::Ipv4(ip) => router.query_ip((*ip).into()),
        url::Host::Ipv6(ip) => router.query_ip((*ip).into()),
    }
}
