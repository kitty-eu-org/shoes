//! Shoes - A multi-protocol proxy server.
//!
//! This library provides both server and client proxy functionality.
//!
//! # Quick Start
//!
//! ```rust,no_run
//! use shoes;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Start servers from config file paths
//!     let handles = shoes::start_from_paths(&["config.yaml"]).await?;
//!
//!     // The handles are JoinHandles for the spawned server tasks
//!     // You can await them or abort them as needed
//!     for handle in handles {
//!         handle.await?;
//!     }
//!     Ok(())
//! }
//! ```
//!
//! # Advanced Usage
//!
//! ```rust,no_run
//! use shoes::config;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Load configs from files
//!     let configs = config::load_configs(&vec!["config.yaml".to_string()]).await?;
//!
//!     // Convert cert paths to inline data
//!     let (configs, _) = config::convert_cert_paths(configs).await?;
//!
//!     // Create server configs
//!     let server_configs = config::create_server_configs(configs).await?;
//!
//!     // Start all servers
//!     let mut handles = vec![];
//!     for server_config in server_configs {
//!         handles.extend(shoes::start_server(server_config).await?);
//!     }
//!
//!     // Servers are now running
//!     // ...
//!
//!     // Cleanup: abort all handles
//!     for handle in handles {
//!         handle.abort();
//!     }
//!
//!     Ok(())
//! }
//! ```

// Re-export all modules
pub mod address;
pub mod async_stream;
pub mod buf_reader;
pub mod client_proxy_chain;
pub mod client_proxy_selector;
pub mod config;
pub mod copy_bidirectional;
pub mod copy_bidirectional_message;
pub mod copy_multidirectional_message;
pub mod copy_session_messages;
pub mod crypto;
pub mod http_handler;
pub mod hysteria2_client;
pub mod hysteria2_protocol;
pub mod hysteria2_server;
pub mod option_util;
pub mod port_forward_handler;
pub mod quic_server;
pub mod quic_stream;
pub mod reality;
pub mod reality_client_handler;
pub mod resolver;
pub mod rustls_config_util;
pub mod rustls_connection_util;
pub mod shadow_tls;
pub mod shadowsocks;
pub mod slide_buffer;
pub mod snell;
pub mod socket_util;
pub mod socks5_udp_relay;
pub mod socks_handler;
pub mod stream_reader;
pub mod sync_adapter;
pub mod tcp;
pub mod thread_util;
pub mod tls_client_handler;
pub mod tls_server_handler;
pub mod trojan_handler;
pub mod tuic_server;
pub mod udp_message_stream;
pub mod udp_multi_message_stream;
pub mod udp_session_message_stream;
pub mod uot;
pub mod util;
pub mod vless;
pub mod vmess;
pub mod websocket;
pub mod xudp;

// Re-export commonly used submodules for backward compatibility
pub use tcp::tcp_handler;
pub use tcp::tcp_server;

use std::path::Path;
use tokio::task::JoinHandle;

pub use config::ServerConfig;

/// Start servers from one or more configuration file paths.
///
/// This is the simplest way to start servers programmatically.
///
/// # Arguments
///
/// * `paths` - Slice of configuration file paths to load
///
/// # Returns
///
/// A vector of `JoinHandle` for the spawned server tasks.
///
/// # Errors
///
/// Returns an error if:
/// - Config files cannot be read or parsed
/// - Server configs cannot be created
/// - Servers fail to start
///
/// # Example
///
/// ```rust,no_run
/// use shoes;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let handles = shoes::start_from_paths(&["config.yaml"]).await?;
///     // Servers are now running
///     // ...
///     Ok(())
/// }
/// ```
pub async fn start_from_paths<P: AsRef<Path>>(
    paths: &[P],
) -> std::io::Result<Vec<JoinHandle<()>>> {
    let path_strings: Vec<String> = paths
        .iter()
        .map(|p| p.as_ref().to_string_lossy().to_string())
        .collect();

    start_from_path_strings(&path_strings).await
}

/// Start servers from one or more configuration file paths (as strings).
///
/// Same as [`start_from_paths`] but accepts `&[&str]` or `&[String]`.
///
/// # Example
///
/// ```rust,no_run
/// use shoes;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let paths = vec!["config.yaml".to_string()];
///     let handles = shoes::start_from_path_strings(&paths).await?;
///     // Servers are now running
///     // ...
///     Ok(())
/// }
/// ```
pub async fn start_from_path_strings(
    paths: &[String],
) -> std::io::Result<Vec<JoinHandle<()>>> {
    // Load configs from files
    let configs = config::load_configs(&paths.to_vec()).await?;

    // Convert cert paths to inline data
    let (configs, load_file_count) = config::convert_cert_paths(configs).await?;

    if load_file_count > 0 {
        log::debug!("Loaded {} certs/keys from files", load_file_count);
    }

    // Create server configs
    let server_configs = config::create_server_configs(configs).await?;

    // Start all servers
    let mut handles = vec![];
    for server_config in server_configs {
        handles.extend(start_server(server_config).await?);
    }

    Ok(handles)
}

/// Start a single server from a [`ServerConfig`].
///
/// Use this function when you have already loaded and validated configurations.
///
/// # Arguments
///
/// * `config` - A validated server configuration
///
/// # Returns
///
/// A vector of `JoinHandle` for the spawned server tasks (one per listener endpoint).
///
/// # Errors
///
/// Returns an error if the server fails to start.
///
/// # Example
///
/// ```rust,no_run
/// use shoes::{config, start_server};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let configs = config::load_configs(&vec!["config.yaml".to_string()]).await?;
///     let (configs, _) = config::convert_cert_paths(configs).await?;
///     let server_configs = config::create_server_configs(configs).await?;
///
///     for server_config in server_configs {
///         let handles = start_server(server_config).await?;
///         // Server is now running
///         // ...
///     }
///     Ok(())
/// }
/// ```
pub async fn start_server(config: ServerConfig) -> std::io::Result<Vec<JoinHandle<()>>> {
    match config.transport {
        config::Transport::Tcp => tcp::tcp_server::start_tcp_servers(config).await,
        config::Transport::Quic => quic_server::start_quic_servers(config).await,
        config::Transport::Udp => {
            Err(std::io::Error::other("UDP transport is not yet implemented"))
        }
    }
}

/// Start multiple servers from a slice of [`ServerConfig`].
///
/// # Arguments
///
/// * `configs` - Slice of validated server configurations
///
/// # Returns
///
/// A vector of all `JoinHandle` from all servers.
///
/// # Errors
///
/// Returns an error if any server fails to start.
///
/// # Example
///
/// ```rust,no_run
/// use shoes::{config, start_servers};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let configs = config::load_configs(&vec!["config.yaml".to_string()]).await?;
///     let (configs, _) = config::convert_cert_paths(configs).await?;
///     let server_configs = config::create_server_configs(configs).await?;
///
///     let handles = start_servers(&server_configs).await?;
///     // All servers are now running
///     // ...
///     Ok(())
/// }
/// ```
pub async fn start_servers(
    configs: &[ServerConfig],
) -> std::io::Result<Vec<JoinHandle<()>>> {
    let mut handles = vec![];
    for config in configs {
        handles.extend(start_server(config.clone()).await?);
    }
    Ok(handles)
}
