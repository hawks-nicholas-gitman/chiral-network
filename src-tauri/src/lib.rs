// Library interface for chiral-network
// This exposes internal modules for integration testing

pub mod crypto;
pub mod dht;
pub mod encryption;
pub mod ethereum;
pub mod file_transfer;
pub mod geth_downloader;
pub mod manager;
pub mod peer_selection;
pub mod keystore;
pub mod net;

// Re-export commonly used types for easier testing
pub use dht::{DhtService, FileMetadata, DhtEvent};
pub use file_transfer::{FileTransferService, FileTransferEvent};
pub use peer_selection::{PeerMetrics, SelectionStrategy};