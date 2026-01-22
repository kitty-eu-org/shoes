//! GeoMatcher - Core routing logic for GeoIP and GeoSite matching

use super::dat_loader::{try_load_geoip, try_load_geosite};
use super::proto::{DomainType, GeoIpList, GeoSiteList};
use addr::parse_domain_name;
use cidr::{Ipv4Cidr, Ipv6Cidr};
use cidr_utils::combiner::{Ipv4CidrCombiner, Ipv6CidrCombiner};
use regex::Regex;
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use url::Host;

/// Route action for a connection
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteAction {
    /// Route directly without proxy (bypass)
    Direct,
    /// Route through proxy
    Proxy,
}

/// GeoMatcher - matches traffic against GeoIP and GeoSite rules
///
/// This matcher implements a simplified Clash-style routing:
/// - CN (China) IPs and domains → Direct
/// - Everything else → Proxy
#[derive(Debug)]
pub struct GeoMatcher {
    // CN IP ranges for direct routing
    cn_ipv4_combiner: Ipv4CidrCombiner,
    cn_ipv6_combiner: Ipv6CidrCombiner,

    // CN domain rules for geosite matching
    plain_site_map: HashMap<String, RouteAction>, // exact domain match
    root_domain_map: HashMap<String, RouteAction>, // root domain match
    regex_sites: Vec<Regex>,                      // regex patterns
}

impl Default for GeoMatcher {
    fn default() -> Self {
        Self {
            cn_ipv4_combiner: Ipv4CidrCombiner::new(),
            cn_ipv6_combiner: Ipv6CidrCombiner::new(),
            plain_site_map: HashMap::new(),
            root_domain_map: HashMap::new(),
            regex_sites: Vec::new(),
        }
    }
}

impl GeoMatcher {
    /// Create a new empty GeoMatcher
    pub fn new() -> Self {
        Self::default()
    }

    /// Create GeoMatcher from .dat files
    ///
    /// Tries to load geoip.dat and geosite.dat from the provided paths.
    /// If a path is None, tries to load from default locations.
    /// If loading fails, returns Ok(None) to allow graceful degradation.
    pub fn from_dat_files(
        geoip_path: Option<&str>,
        geosite_path: Option<&str>,
    ) -> Result<Option<Self>, Box<dyn std::error::Error>> {
        // Build list of paths to try for geoip
        let mut geoip_paths = Vec::new();
        if let Some(p) = geoip_path {
            geoip_paths.push(PathBuf::from(p));
        }
        // Add default paths
        geoip_paths.push(PathBuf::from("geoip.dat"));
        geoip_paths.push(PathBuf::from("/usr/local/share/shoes/geoip.dat"));

        // Build list of paths to try for geosite
        let mut geosite_paths = Vec::new();
        if let Some(p) = geosite_path {
            geosite_paths.push(PathBuf::from(p));
        }
        // Add default paths
        geosite_paths.push(PathBuf::from("geosite.dat"));
        geosite_paths.push(PathBuf::from("/usr/local/share/shoes/geosite.dat"));

        let geoip_data = match try_load_geoip(&geoip_paths)? {
            Some(data) => data,
            None => {
                log::warn!("No GeoIP data loaded, geo routing will be limited");
                GeoIpList::default()
            }
        };

        let geosite_data = match try_load_geosite(&geosite_paths)? {
            Some(data) => data,
            None => {
                log::warn!("No GeoSite data loaded, geo routing will be limited");
                GeoSiteList::default()
            }
        };

        Ok(Some(Self::from_geo_data(geoip_data, geosite_data)))
    }

    /// Create GeoMatcher from parsed GeoIP and GeoSite data
    pub fn from_geo_data(geoip_data: GeoIpList, geosite_data: GeoSiteList) -> Self {
        let mut ipv4_combiner = Ipv4CidrCombiner::new();
        let mut ipv6_combiner = Ipv6CidrCombiner::new();
        let mut plain_site_map: HashMap<String, RouteAction> = HashMap::new();
        let mut regex_sites: Vec<Regex> = Vec::new();
        let mut root_domain_map: HashMap<String, RouteAction> = HashMap::new();

        // Process GeoIP - only CN country code
        for geo_ip in geoip_data.entry.iter() {
            if geo_ip.country_code.to_lowercase() == "cn" {
                for cidr in &geo_ip.cidr {
                    if cidr.ip.len() == 4 {
                        if let Ok(ipv4_cidr) = Ipv4Cidr::from_str(&cidr.to_string()) {
                            ipv4_combiner.push(ipv4_cidr);
                        }
                    }
                    if cidr.ip.len() == 8 {
                        if let Ok(ipv6_cidr) = Ipv6Cidr::from_str(&cidr.to_string()) {
                            ipv6_combiner.push(ipv6_cidr);
                        }
                    }
                }
            }
        }

        // Process GeoSite - only CN country code
        for geo_site in geosite_data.entry.iter() {
            if geo_site.country_code.to_lowercase() == "cn" {
                for domain in &geo_site.domain {
                    match domain.get_type() {
                        DomainType::Plain => {
                            plain_site_map.insert(domain.value.clone(), RouteAction::Direct);
                        }
                        DomainType::Regex => {
                            if let Ok(re) = Regex::new(&domain.value) {
                                regex_sites.push(re);
                            }
                        }
                        DomainType::Domain => {
                            let domain = parse_domain_name(&domain.value);
                            let domain_root = match domain {
                                Ok(root_domain) => match root_domain.root() {
                                    Some(domain) => domain.to_string(),
                                    None => String::new(),
                                },
                                Err(_) => String::new(),
                            };
                            if !domain_root.is_empty() {
                                root_domain_map.insert(domain_root, RouteAction::Direct);
                            }
                        }
                        DomainType::Full => {
                            root_domain_map.insert(domain.value.clone(), RouteAction::Direct);
                        }
                    }
                }
                break; // Only need CN
            }
        }

        Self {
            cn_ipv4_combiner: ipv4_combiner,
            cn_ipv6_combiner: ipv6_combiner,
            plain_site_map,
            root_domain_map,
            regex_sites,
        }
    }

    /// Check if a regex pattern matches the input site
    fn regex_match_cn(&self, input_site: &str) -> bool {
        for regex in &self.regex_sites {
            if regex.is_match(input_site) {
                return true;
            }
        }
        false
    }

    /// Check if a domain matches CN geosite rules
    fn domain_match_cn(&self, input_site: &str) -> Option<&RouteAction> {
        let domain = parse_domain_name(input_site);
        match domain {
            Ok(name) => {
                if let Some(domain_root) = name.root() {
                    // Convert to String for HashMap lookup
                    let root_str = domain_root.to_string();
                    self.root_domain_map.get(&root_str)
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    /// Match a domain string against geosite rules
    pub fn match_domain(&self, domain: &str) -> Option<RouteAction> {
        // Check exact domain match first
        if let Some(action) = self.plain_site_map.get(domain) {
            return Some(*action);
        }

        // Check root domain match
        if let Some(action) = self.domain_match_cn(domain) {
            return Some(*action);
        }

        // Check regex match
        if self.regex_match_cn(domain) {
            return Some(RouteAction::Direct);
        }

        None
    }

    /// Match an IP address against geoip rules
    pub fn match_ip(&self, ip: &std::net::IpAddr) -> Option<RouteAction> {
        match ip {
            std::net::IpAddr::V4(addr) => {
                if self.cn_ipv4_combiner.contains(addr) {
                    Some(RouteAction::Direct)
                } else {
                    None
                }
            }
            std::net::IpAddr::V6(addr) => {
                if self.cn_ipv6_combiner.contains(addr) {
                    Some(RouteAction::Direct)
                } else {
                    None
                }
            }
        }
    }

    /// Match a Host against geo rules
    /// Returns Some(action) if matched, None if not matched
    pub fn match_host(&self, host: &Host) -> Option<RouteAction> {
        match host {
            Host::Ipv4(ip) => self.match_ip(&std::net::IpAddr::V4(*ip)),
            Host::Ipv6(ip) => self.match_ip(&std::net::IpAddr::V6(*ip)),
            Host::Domain(domain) => self.match_domain(domain),
        }
    }

    /// Judge whether traffic should go Direct or Proxy based on geo rules
    /// Returns Some(action) - always returns a decision (Direct or Proxy)
    pub fn judge(&self, host: &Host) -> Option<RouteAction> {
        match self.match_host(host) {
            Some(RouteAction::Direct) => Some(RouteAction::Direct),
            Some(RouteAction::Proxy) => Some(RouteAction::Proxy),
            None => {
                // No match - default to Proxy for non-CN traffic
                Some(RouteAction::Proxy)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_match_ip_cn() {
        let matcher = GeoMatcher::new();
        // CN IP range (example)
        let cn_ip = Ipv4Addr::new(110, 242, 68, 66); // baidu.com IP
        // Test with empty matcher - should return None
        assert!(matcher.match_ip(&std::net::IpAddr::V4(cn_ip)).is_none());
    }

    #[test]
    fn test_match_domain() {
        let matcher = GeoMatcher::new();
        // Test with empty matcher
        assert!(matcher.match_domain("baidu.com").is_none());
    }

    #[test]
    fn test_host_match() {
        let matcher = GeoMatcher::new();
        let host = Host::Domain("example.com".to_string());
        // Empty matcher should return None for non-CN
        assert!(matcher.match_host(&host).is_none());
    }
}
