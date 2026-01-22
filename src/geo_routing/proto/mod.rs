// Protobuf definitions for GeoIP and GeoSite
// Based on V2Ray geodata format

// Domain matching type
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum DomainType {
    /// The value is used as is.
    Plain = 0,
    /// The value is used as a regular expression.
    Regex = 1,
    /// The value is a root domain.
    Domain = 2,
    /// The value is a domain.
    Full = 3,
}

/// Domain for geosite matching
#[derive(Clone, PartialEq, prost::Message)]
pub struct Domain {
    /// Domain matching type.
    #[prost(enumeration = "DomainType", tag = "1")]
    pub r#type: i32,
    /// Domain value.
    #[prost(string, tag = "2")]
    pub value: String,
}

impl Domain {
    pub fn get_type(&self) -> DomainType {
        match self.r#type {
            0 => DomainType::Plain,
            1 => DomainType::Regex,
            2 => DomainType::Domain,
            3 => DomainType::Full,
            _ => DomainType::Plain,
        }
    }
}

/// IP for routing decision, in CIDR form.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Cidr {
    /// IP address, should be either 4 or 16 bytes.
    #[prost(bytes = "vec", tag = "1")]
    pub ip: Vec<u8>,
    /// Number of leading ones in the network mask.
    #[prost(uint32, tag = "2")]
    pub prefix: u32,
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}/{}",
            self.ip
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<String>>()
                .join("."),
            self.prefix
        )
    }
}

/// GeoIP entry for a country
#[derive(Clone, PartialEq, prost::Message)]
pub struct GeoIp {
    #[prost(string, tag = "1")]
    pub country_code: String,
    #[prost(message, repeated, tag = "2")]
    pub cidr: Vec<Cidr>,
    #[prost(bool, tag = "3")]
    pub reverse_match: bool,
}

/// List of GeoIP entries
#[derive(Clone, PartialEq, prost::Message)]
pub struct GeoIpList {
    #[prost(message, repeated, tag = "1")]
    pub entry: Vec<GeoIp>,
}

/// GeoSite entry for a country code
#[derive(Clone, PartialEq, prost::Message)]
pub struct GeoSite {
    #[prost(string, tag = "1")]
    pub country_code: String,
    #[prost(message, repeated, tag = "2")]
    pub domain: Vec<Domain>,
}

/// List of GeoSite entries
#[derive(Clone, PartialEq, prost::Message)]
pub struct GeoSiteList {
    #[prost(message, repeated, tag = "1")]
    pub entry: Vec<GeoSite>,
}
