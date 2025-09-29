use chiral_network::{dht::{DhtService, FileMetadata}, file_transfer::FileTransferService};
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::sleep;
use tracing_test::traced_test;

/// Integration test helper for managing test network nodes
pub struct TestNetwork {
    pub nodes: Vec<TestNode>,
    pub _temp_dirs: Vec<TempDir>, // Keep temp dirs alive
}

/// Represents a single test node in the network
pub struct TestNode {
    pub dht: DhtService,
    pub file_transfer: FileTransferService,
    pub peer_id: String,
    pub port: u16,
    pub temp_dir: TempDir,
}

impl TestNetwork {
    /// Create a new test network with the specified number of nodes
    pub async fn new(node_count: usize) -> Result<Self, Box<dyn std::error::Error>> {
        let mut nodes = Vec::new();
        let mut temp_dirs = Vec::new();
        let base_port = 40000 + (rand::random::<u16>() % 10000); // Random port range to avoid conflicts

        // Create bootstrap node first
        if node_count > 0 {
            let temp_dir = tempfile::tempdir()?;
            let port = base_port;

            let dht = DhtService::new(
                port,
                vec![], // Bootstrap node has no bootstrap peers
                None,   // Random secret
                true,   // This is a bootstrap node
                true,   // Enable autonat
                Some(Duration::from_secs(30)),
                vec![],
                None, // No proxy
            ).await?;

            // Start the DHT service
            dht.run().await;
            let peer_id = dht.get_peer_id().await;

            let file_transfer = FileTransferService::new().await
                .map_err(|e| format!("Failed to create file transfer service: {}", e))?;

            nodes.push(TestNode {
                dht,
                file_transfer,
                peer_id,
                port,
                temp_dir,
            });
        }

        // Create additional nodes that bootstrap from the first node
        for i in 1..node_count {
            let temp_dir = tempfile::tempdir()?;
            let port = base_port + i as u16;

            // Get bootstrap address from first node
            let bootstrap_addr = format!("/ip4/127.0.0.1/tcp/{}/p2p/{}",
                                      base_port, nodes[0].peer_id);

            let dht = DhtService::new(
                port,
                vec![bootstrap_addr],
                None,   // Random secret
                false,  // Not a bootstrap node
                true,   // Enable autonat
                Some(Duration::from_secs(30)),
                vec![],
                None, // No proxy
            ).await?;

            // Start the DHT service
            dht.run().await;
            let peer_id = dht.get_peer_id().await;

            let file_transfer = FileTransferService::new().await
                .map_err(|e| format!("Failed to create file transfer service: {}", e))?;

            nodes.push(TestNode {
                dht,
                file_transfer,
                peer_id,
                port,
                temp_dir,
            });
        }

        // Move temp_dirs after node creation to keep them alive
        for _node in &nodes {
            temp_dirs.push(tempfile::tempdir()?); // Create placeholder temp dirs
        }

        Ok(TestNetwork {
            nodes,
            _temp_dirs: temp_dirs,
        })
    }

    /// Wait for all nodes to discover each other
    pub async fn wait_for_discovery(&self, timeout: Duration) -> Result<(), String> {
        let start = std::time::Instant::now();
        let expected_peers = if self.nodes.len() > 1 { 1 } else { 0 }; // At least 1 peer for multi-node

        while start.elapsed() < timeout {
            let mut all_connected = true;

            for (i, node) in self.nodes.iter().enumerate() {
                let peer_count = node.dht.get_peer_count().await;
                tracing::debug!("Node {} has {} peers", i, peer_count);
                if peer_count < expected_peers {
                    all_connected = false;
                    break;
                }
            }

            if all_connected {
                tracing::info!("All nodes discovered each other");
                return Ok(());
            }

            sleep(Duration::from_millis(500)).await;
        }

        Err(format!("Network discovery timed out after {:?}", timeout))
    }

    /// Create a test file in the given node's temp directory
    pub async fn create_test_file(&self, node_idx: usize, filename: &str, content: &[u8]) -> Result<String, String> {
        if node_idx >= self.nodes.len() {
            return Err("Invalid node index".to_string());
        }

        let file_path = self.nodes[node_idx].temp_dir.path().join(filename);
        tokio::fs::write(&file_path, content).await
            .map_err(|e| format!("Failed to write test file: {}", e))?;

        Ok(file_path.to_string_lossy().to_string())
    }

    /// Shutdown all nodes gracefully
    pub async fn shutdown(&self) {
        for (i, node) in self.nodes.iter().enumerate() {
            if let Err(e) = node.dht.shutdown().await {
                tracing::error!("Failed to shutdown DHT node {}: {}", i, e);
            }
        }
    }
}

impl Drop for TestNetwork {
    fn drop(&mut self) {
        // Cleanup will be handled by TempDir drops and shutdown
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::info;

    #[traced_test]
    #[tokio::test]
    async fn test_single_node_startup() {
        let network = TestNetwork::new(1).await.expect("Failed to create test network");

        assert_eq!(network.nodes.len(), 1);
        assert!(!network.nodes[0].peer_id.is_empty());

        // Verify node is running
        let peer_count = network.nodes[0].dht.get_peer_count().await;
        assert_eq!(peer_count, 0); // Single node should have no peers

        network.shutdown().await;
    }

    #[traced_test]
    #[tokio::test]
    async fn test_two_node_discovery() {
        let network = TestNetwork::new(2).await.expect("Failed to create test network");

        // Wait for nodes to discover each other
        network.wait_for_discovery(Duration::from_secs(15)).await
            .expect("Nodes failed to discover each other");

        // Verify both nodes found each other
        for (i, node) in network.nodes.iter().enumerate() {
            let peer_count = node.dht.get_peer_count().await;
            info!("Node {} has {} peers", i, peer_count);
            assert!(peer_count >= 1, "Node {} should have at least 1 peer", i);
        }

        network.shutdown().await;
    }

    #[traced_test]
    #[tokio::test]
    async fn test_file_upload_and_local_storage() {
        let network = TestNetwork::new(1).await.expect("Failed to create test network");

        // Create a test file
        let test_content = b"Hello, Chiral Network Integration Test!";
        let file_path = network.create_test_file(0, "test.txt", test_content).await
            .expect("Failed to create test file");

        // Upload file through file transfer service
        network.nodes[0].file_transfer.upload_file(file_path.clone(), "test.txt".to_string()).await
            .expect("Failed to upload file");

        // Wait for upload to complete by checking events
        sleep(Duration::from_millis(1000)).await;

        let events = network.nodes[0].file_transfer.drain_events(10).await;
        let upload_event = events.iter().find(|event| {
            matches!(event, chiral_network::file_transfer::FileTransferEvent::FileUploaded { .. })
        });
        assert!(upload_event.is_some(), "Should have upload event");

        // Verify file was stored (check internal storage)
        let stored_files = network.nodes[0].file_transfer.get_stored_files().await
            .expect("Failed to get stored files");

        assert!(!stored_files.is_empty(), "Should have stored at least one file");

        let found_file = stored_files.iter().find(|(_, name)| name == "test.txt");
        assert!(found_file.is_some(), "Should find the uploaded test file");

        network.shutdown().await;
    }

    #[traced_test]
    #[tokio::test]
    async fn test_file_metadata_publishing() {
        let network = TestNetwork::new(2).await.expect("Failed to create test network");

        // Wait for network formation
        network.wait_for_discovery(Duration::from_secs(15)).await
            .expect("Network discovery failed");

        // Create and upload a test file
        let test_content = b"Test file for metadata publishing";
        let file_path = network.create_test_file(0, "metadata_test.txt", test_content).await
            .expect("Failed to create test file");

        network.nodes[0].file_transfer.upload_file(file_path.clone(), "metadata_test.txt".to_string()).await
            .expect("Failed to upload file");

        // Calculate file hash
        let file_hash = chiral_network::file_transfer::FileTransferService::calculate_file_hash(test_content);

        // Publish metadata to DHT
        let metadata = FileMetadata {
            file_hash: file_hash.clone(),
            file_name: "metadata_test.txt".to_string(),
            file_size: test_content.len() as u64,
            seeders: vec![network.nodes[0].peer_id.clone()],
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            mime_type: Some("text/plain".to_string()),
            is_encrypted: false,
            encryption_method: None,
            key_fingerprint: None,
        };

        network.nodes[0].dht.publish_file(metadata.clone()).await
            .expect("Failed to publish file metadata");

        // Wait for DHT propagation
        sleep(Duration::from_secs(3)).await;

        // Search for file from node 1
        let found_metadata = network.nodes[1].dht.search_metadata(file_hash.clone(), 10000).await
            .expect("Failed to search for file metadata");

        assert!(found_metadata.is_some(), "File metadata should be found by peer");
        let found = found_metadata.unwrap();
        assert_eq!(found.file_name, "metadata_test.txt");
        assert_eq!(found.file_size, test_content.len() as u64);
        assert_eq!(found.file_hash, file_hash);

        network.shutdown().await;
    }

    #[traced_test]
    #[tokio::test]
    async fn test_multi_node_network_formation() {
        let network = TestNetwork::new(3).await.expect("Failed to create test network");

        // Wait for full network discovery with longer timeout for 3 nodes
        network.wait_for_discovery(Duration::from_secs(20)).await
            .expect("Multi-node network discovery failed");

        // Verify all nodes are connected to the network
        for (i, node) in network.nodes.iter().enumerate() {
            let peer_count = node.dht.get_peer_count().await;
            info!("Node {} has {} peers", i, peer_count);
            assert!(peer_count >= 1, "Node {} should have at least 1 peer", i);
        }

        // Test DHT health across all nodes
        for (i, node) in network.nodes.iter().enumerate() {
            let health = node.dht.metrics_snapshot().await;
            info!("Node {} DHT health: peer_count={}, last_peer_event={:?}",
                  i, health.peer_count, health.last_peer_event);
            assert!(health.peer_count > 0, "Node {} should have connected peers", i);
        }

        network.shutdown().await;
    }

    #[traced_test]
    #[tokio::test]
    async fn test_file_discovery_across_network() {
        let network = TestNetwork::new(3).await.expect("Failed to create test network");

        // Wait for network formation
        network.wait_for_discovery(Duration::from_secs(20)).await
            .expect("Network discovery failed");

        // Create files on different nodes
        let files = vec![
            ("file1.txt", b"Content of file 1"),
            ("file2.txt", b"Content of file 2"),
        ];

        let mut file_hashes = Vec::new();

        // Upload files from first two nodes
        for (i, (filename, content)) in files.iter().enumerate() {
            let file_path = network.create_test_file(i, filename, *content).await
                .expect("Failed to create test file");

            network.nodes[i].file_transfer.upload_file(file_path, filename.to_string()).await
                .expect("Failed to upload file");

            let file_hash = chiral_network::file_transfer::FileTransferService::calculate_file_hash(*content);

            // Publish metadata
            let metadata = FileMetadata {
                file_hash: file_hash.clone(),
                file_name: filename.to_string(),
                file_size: content.len() as u64,
                seeders: vec![network.nodes[i].peer_id.clone()],
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                mime_type: Some("text/plain".to_string()),
                is_encrypted: false,
                encryption_method: None,
                key_fingerprint: None,
            };

            network.nodes[i].dht.publish_file(metadata).await
                .expect("Failed to publish file metadata");

            file_hashes.push(file_hash);
        }

        // Wait for DHT propagation
        sleep(Duration::from_secs(5)).await;

        // Third node should be able to find both files
        for (file_idx, (expected_filename, expected_content)) in files.iter().enumerate() {
            let metadata = network.nodes[2].dht.search_metadata(file_hashes[file_idx].clone(), 10000).await
                .expect("Failed to search for file");

            assert!(metadata.is_some(),
                "Node 2 should find file {} ({})", file_idx, expected_filename);

            let found_metadata = metadata.unwrap();
            assert_eq!(found_metadata.file_name, *expected_filename);
            assert_eq!(found_metadata.file_size, expected_content.len() as u64);
        }

        network.shutdown().await;
    }

    #[traced_test]
    #[tokio::test]
    async fn test_dht_metrics_and_health() {
        let network = TestNetwork::new(2).await.expect("Failed to create test network");

        network.wait_for_discovery(Duration::from_secs(15)).await
            .expect("Network discovery failed");

        // Test metrics for each node
        for (i, node) in network.nodes.iter().enumerate() {
            let metrics = node.dht.metrics_snapshot().await;

            info!("Node {} metrics: peer_count={}, last_peer_event={:?}, bootstrap_failures={}",
                  i, metrics.peer_count, metrics.last_peer_event, metrics.bootstrap_failures);

            // Basic health checks
            assert!(metrics.peer_count > 0, "Node {} should have connected peers", i);
            assert!(metrics.bootstrap_failures >= 0, "Node {} should have non-negative bootstrap failure count", i);
        }

        network.shutdown().await;
    }

    #[traced_test]
    #[tokio::test]
    async fn test_file_transfer_events() {
        let network = TestNetwork::new(1).await.expect("Failed to create test network");

        // Create a test file
        let test_content = b"Event test file content";
        let file_path = network.create_test_file(0, "event_test.txt", test_content).await
            .expect("Failed to create test file");

        // Upload file
        network.nodes[0].file_transfer.upload_file(file_path.clone(), "event_test.txt".to_string()).await
            .expect("Failed to upload file");

        // Wait a bit for events to be processed
        sleep(Duration::from_millis(500)).await;

        // Check for file transfer events
        let events = network.nodes[0].file_transfer.drain_events(10).await;

        // Should have at least one event (file uploaded)
        assert!(!events.is_empty(), "Should have file transfer events");

        let has_upload_event = events.iter().any(|event| {
            matches!(event, chiral_network::file_transfer::FileTransferEvent::FileUploaded { .. })
        });

        assert!(has_upload_event, "Should have file upload event");

        network.shutdown().await;
    }
}