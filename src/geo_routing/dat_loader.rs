//! Loading and parsing GeoIP and GeoSite .dat files

use super::proto::{GeoIpList, GeoSite, GeoSiteList};
use prost::Message;
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

/// Errors that can occur when loading geo data files
#[derive(Debug)]
pub enum GeoDataError {
    Io(std::io::Error),
    Protobuf(String),
}

impl std::fmt::Display for GeoDataError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO error: {}", e),
            Self::Protobuf(s) => write!(f, "Protobuf error: {}", s),
        }
    }
}

impl std::error::Error for GeoDataError {}

impl From<std::io::Error> for GeoDataError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Load GeoIP data from a .dat file
///
/// GeoIP.dat files contain a serialized GeoIpList protobuf message
pub fn load_geoip<P: AsRef<Path>>(path: P) -> Result<GeoIpList, GeoDataError> {
    let path = path.as_ref();

    // Try to open and read the file
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            log::warn!("Failed to open GeoIP file {:?}: {}", path, e);
            return Err(GeoDataError::Io(e));
        }
    };

    let mut content = Vec::new();
    if let Err(e) = file.read_to_end(&mut content) {
        log::warn!("Failed to read GeoIP file {:?}: {}", path, e);
        return Err(GeoDataError::Io(e));
    }

    // Decode the protobuf message
    match GeoIpList::decode(&content[..]) {
        Ok(geo_ips) => Ok(geo_ips),
        Err(e) => {
            log::warn!("Failed to decode GeoIP file {:?}: {}", path, e);
            Err(GeoDataError::Protobuf(e.to_string()))
        }
    }
}

/// Load GeoSite data from a .dat file
///
/// GeoSite.dat files contain a stream of GeoSite protobuf messages
/// (not a GeoSiteList), so we need to decode them sequentially
pub fn load_geosite<P: AsRef<Path>>(path: P) -> Result<GeoSiteList, GeoDataError> {
    let path = path.as_ref();

    // Try to open and read the file
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            log::warn!("Failed to open GeoSite file {:?}: {}", path, e);
            return Err(GeoDataError::Io(e));
        }
    };

    let mut content = Vec::new();
    if let Err(e) = file.read_to_end(&mut content) {
        log::warn!("Failed to read GeoSite file {:?}: {}", path, e);
        return Err(GeoDataError::Io(e));
    }

    // GeoSite.dat contains a stream of GeoSite messages, not a GeoSiteList
    // We need to decode them sequentially
    let mut cursor = Cursor::new(&content);
    let mut entries = Vec::new();

    while cursor.position() < content.len() as u64 {
        match GeoSite::decode(&mut cursor) {
            Ok(geo_site) => entries.push(geo_site),
            Err(e) => {
                log::warn!(
                    "Failed to decode GeoSite at position {}: {}",
                    cursor.position(),
                    e
                );
                break;
            }
        }
    }

    Ok(GeoSiteList { entry: entries })
}

/// Try to load geo data from multiple possible paths
/// Returns Ok(Some(data)) if found, Ok(None) if no valid file found
pub fn try_load_geoip(paths: &[PathBuf]) -> Result<Option<GeoIpList>, GeoDataError> {
    for path in paths {
        match load_geoip(path) {
            Ok(data) => {
                log::info!("Loaded GeoIP data from {:?}", path);
                return Ok(Some(data));
            }
            Err(GeoDataError::Io(_)) => {
                // Try next path
                continue;
            }
            Err(e) => {
                // Non-IO error (like decode error) - propagate
                return Err(e);
            }
        }
    }
    log::warn!("No valid GeoIP file found in {:?}", paths);
    Ok(None)
}

/// Try to load geosite data from multiple possible paths
/// Returns Ok(Some(data)) if found, Ok(None) if no valid file found
pub fn try_load_geosite(paths: &[PathBuf]) -> Result<Option<GeoSiteList>, GeoDataError> {
    for path in paths {
        match load_geosite(path) {
            Ok(data) => {
                log::info!("Loaded GeoSite data from {:?}", path);
                return Ok(Some(data));
            }
            Err(GeoDataError::Io(_)) => {
                // Try next path
                continue;
            }
            Err(e) => {
                // Non-IO error (like decode error) - propagate
                return Err(e);
            }
        }
    }
    log::warn!("No valid GeoSite file found in {:?}", paths);
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_try_load_geoip_missing_file() {
        let result = try_load_geoip(&[PathBuf::from("/nonexistent/geoip.dat")]);
        assert!(matches!(result, Ok(None)));
    }
}
