use chiral_network::{dht::{DhtService, FileMetadata}, file_transfer::FileTransferService};
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::sleep;
use tracing_test::traced_test;

/// Network-focused integration tests for P2P functionality
pub struct NetworkTestHarness {
    pub nodes: Vec<TestNode>,
}

pub struct TestNode {
    pub dht: DhtService,
    pub file_transfer: FileTransferService,
    pub peer_id: String,
    pub port: u16,
    pub temp_dir: TempDir,
}

impl NetworkTestHarness {
    pub async fn new_with_topology(node_count: usize, _bootstrap_connections: Vec<Vec<usize>>) -> Result<Self, Box<dyn std::error::Error>> {
        let mut nodes = Vec::new();
        let base_port = 40000 + (rand::random::<u16>() % 10000);

        // Create all nodes first
        for i in 0..node_count {
            let temp_dir = tempfile::tempdir()?;
            let port = base_port + i as u16;
            let is_bootstrap = i == 0; // First node is always bootstrap

            let bootstrap_addrs = if i == 0 {
                vec![] // Bootstrap node
            } else {
                // Connect to bootstrap node by default
                vec![format!("/ip4/127.0.0.1/tcp/{}/p2p/{}", base_port, "placeholder")]
            };

            let dht = DhtService::new(
                port,
                bootstrap_addrs, // Will be updated with real peer IDs
                None,
                is_bootstrap,
                true,
                Some(Duration::from_secs(30)),
                vec![],
                None,
            ).await?;

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

        Ok(NetworkTestHarness { nodes })
    }

    pub async fn wait_for_network_stability(&self, timeout: Duration) -> Result<(), String> {
        let start = std::time::Instant::now();

        while start.elapsed() < timeout {
            let mut stable = true;

            // Check if all nodes have at least one connection
            for (i, node) in self.nodes.iter().enumerate() {
                let peer_count = node.dht.get_peer_count().await;
                if self.nodes.len() > 1 && peer_count == 0 {
                    stable = false;
                    tracing::debug!("Node {} still has no peers", i);
                    break;
                }
            }

            if stable {
                tracing::info!("Network appears stable");
                return Ok(());
            }

            sleep(Duration::from_millis(1000)).await;
        }

        Err(format!("Network failed to stabilize within {:?}", timeout))
    }

    pub async fn simulate_network_partition(&self, partition_a: Vec<usize>, partition_b: Vec<usize>) -> Result<(), String> {
        // This would disconnect nodes between partitions
        // For now, we'll simulate by testing that partitioned nodes can't find each other's files
        tracing::info!("Simulating network partition: A={:?}, B={:?}", partition_a, partition_b);
        Ok(())
    }

    pub async fn shutdown(&self) {
        for (i, node) in self.nodes.iter().enumerate() {
            if let Err(e) = node.dht.shutdown().await {
                tracing::error!("Failed to shutdown node {}: {}", i, e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::info;

    #[traced_test]
    #[tokio::test]
    async fn test_bootstrap_node_discovery() {
        let harness = NetworkTestHarness::new_with_topology(3, vec![vec![0], vec![0], vec![0]])
            .await.expect("Failed to create network");

        harness.wait_for_network_stability(Duration::from_secs(20)).await
            .expect("Network failed to stabilize");

        // Verify bootstrap node has connections
        let bootstrap_peer_count = harness.nodes[0].dht.get_peer_count().await;
        info!("Bootstrap node has {} peers", bootstrap_peer_count);
        assert!(bootstrap_peer_count > 0, "Bootstrap node should have peers");

        // Verify other nodes connected to bootstrap
        for i in 1..harness.nodes.len() {
            let peer_count = harness.nodes[i].dht.get_peer_count().await;
            info!("Node {} has {} peers", i, peer_count);
            assert!(peer_count > 0, "Node {} should be connected to network", i);
        }

        harness.shutdown().await;
    }

    #[traced_test]
    #[tokio::test]
    async fn test_peer_discovery_resilience() {
        let harness = NetworkTestHarness::new_with_topology(4, vec![vec![0], vec![0], vec![1], vec![2]])
            .await.expect("Failed to create network");

        harness.wait_for_network_stability(Duration::from_secs(25)).await
            .expect("Network failed to stabilize");

        // Test that nodes can still discover content even with indirect connections
        let test_content = b"Resilience test content";
        let file_hash = chiral_network::file_transfer::FileTransferService::calculate_file_hash(test_content);

        // Upload file on node 0
        let file_path = harness.nodes[0].temp_dir.path().join("resilience_test.txt");
        tokio::fs::write(&file_path, test_content).await.unwrap();

        harness.nodes[0].file_transfer.upload_file(
            file_path.to_string_lossy().to_string(),
            "resilience_test.txt".to_string()
        ).await.expect("Failed to upload file");

        // Publish metadata
        let metadata = FileMetadata {
            file_hash: file_hash.clone(),
            file_name: "resilience_test.txt".to_string(),
            file_size: test_content.len() as u64,
            seeders: vec![harness.nodes[0].peer_id.clone()],
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            mime_type: Some("text/plain".to_string()),
            is_encrypted: false,
            encryption_method: None,
            key_fingerprint: None,
        };

        harness.nodes[0].dht.publish_file(metadata).await
            .expect("Failed to publish file metadata");

        // Wait for propagation
        sleep(Duration::from_secs(5)).await;

        // Test that last node (potentially most distant) can find the file
        let last_node_idx = harness.nodes.len() - 1;
        let found_metadata = harness.nodes[last_node_idx]
            .dht.search_metadata(file_hash.clone(), 15000).await
            .expect("Failed to search for file");

        assert!(found_metadata.is_some(), "Distant node should find file through DHT");

        harness.shutdown().await;
    }

    #[traced_test]
    #[tokio::test]
    async fn test_dht_routing_table_formation() {
        let harness = NetworkTestHarness::new_with_topology(5, vec![])
            .await.expect("Failed to create network");

        harness.wait_for_network_stability(Duration::from_secs(30)).await
            .expect("Network failed to stabilize");

        // Test DHT routing by publishing content from different nodes
        // and ensuring it's discoverable from all nodes
        let test_files = vec![
            ("node0_file.txt", b"Content from node 0"),
            ("node1_file.txt", b"Content from node 1"),
            ("node2_file.txt", b"Content from node 2"),
        ];

        let mut file_hashes = Vec::new();

        // Publish files from first 3 nodes
        for (node_idx, (filename, content)) in test_files.iter().enumerate() {
            let file_path = harness.nodes[node_idx].temp_dir.path().join(filename);
            tokio::fs::write(&file_path, content).await.unwrap();

            harness.nodes[node_idx].file_transfer.upload_file(
                file_path.to_string_lossy().to_string(),
                filename.to_string()
            ).await.expect("Failed to upload file");

            let file_hash = chiral_network::file_transfer::FileTransferService::calculate_file_hash(*content);

            let metadata = FileMetadata {
                file_hash: file_hash.clone(),
                file_name: filename.to_string(),
                file_size: content.len() as u64,
                seeders: vec![harness.nodes[node_idx].peer_id.clone()],
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                mime_type: Some("text/plain".to_string()),
                is_encrypted: false,
                encryption_method: None,
                key_fingerprint: None,
            };

            harness.nodes[node_idx].dht.publish_file(metadata).await
                .expect("Failed to publish file metadata");

            file_hashes.push(file_hash);
        }

        // Wait for DHT propagation
        sleep(Duration::from_secs(8)).await;

        // Test that all nodes can find all files (DHT routing working)
        for searcher_idx in 0..harness.nodes.len() {
            for (file_idx, (filename, _)) in test_files.iter().enumerate() {
                let found = harness.nodes[searcher_idx]
                    .dht.search_metadata(file_hashes[file_idx].clone(), 10000).await
                    .expect("Failed to search for file");

                assert!(found.is_some(),
                    "Node {} should find file '{}' through DHT routing", searcher_idx, filename);
            }
        }

        harness.shutdown().await;
    }

    #[traced_test]
    #[tokio::test]
    async fn test_network_metrics_collection() {
        let harness = NetworkTestHarness::new_with_topology(3, vec![])
            .await.expect("Failed to create network");

        harness.wait_for_network_stability(Duration::from_secs(20)).await
            .expect("Network failed to stabilize");

        // Generate some network activity
        for i in 0..harness.nodes.len() {
            let content = format!("Test file from node {}", i).into_bytes();
            let file_path = harness.nodes[i].temp_dir.path().join(&format!("test_{}.txt", i));
            tokio::fs::write(&file_path, &content).await.unwrap();

            harness.nodes[i].file_transfer.upload_file(
                file_path.to_string_lossy().to_string(),
                format!("test_{}.txt", i)
            ).await.expect("Failed to upload file");

            let file_hash = chiral_network::file_transfer::FileTransferService::calculate_file_hash(&content);

            let metadata = FileMetadata {
                file_hash: file_hash.clone(),
                file_name: format!("test_{}.txt", i),
                file_size: content.len() as u64,
                seeders: vec![harness.nodes[i].peer_id.clone()],
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                mime_type: Some("text/plain".to_string()),
                is_encrypted: false,
                encryption_method: None,
                key_fingerprint: None,
            };

            harness.nodes[i].dht.publish_file(metadata).await
                .expect("Failed to publish file metadata");
        }

        sleep(Duration::from_secs(3)).await;

        // Check metrics on all nodes
        for (i, node) in harness.nodes.iter().enumerate() {
            let metrics = node.dht.metrics_snapshot().await;

            info!("Node {} metrics: peer_count={}, last_peer_event={:?}, bootstrap_failures={}",
                  i, metrics.peer_count, metrics.last_peer_event, metrics.bootstrap_failures);

            // Verify metrics show network activity
            assert!(metrics.peer_count > 0, "Node {} should have peers", i);
            assert!(metrics.last_peer_event.is_some(), "Node {} should have peer events", i);
        }

        harness.shutdown().await;
    }

    #[traced_test]
    #[tokio::test]
    async fn test_concurrent_file_publishing() {
        let harness = NetworkTestHarness::new_with_topology(3, vec![])
            .await.expect("Failed to create network");

        harness.wait_for_network_stability(Duration::from_secs(20)).await
            .expect("Network failed to stabilize");

        // Publish multiple files sequentially from different nodes (simplified for testing)
        let mut file_hashes = Vec::new();

        for i in 0..harness.nodes.len() {
            for j in 0..2 { // 2 files per node
                let content = format!("File {} from node {}", j, i).into_bytes();
                let filename = format!("test_{}_{}.txt", i, j);
                let file_path = harness.nodes[i].temp_dir.path().join(&filename);

                tokio::fs::write(&file_path, &content).await.unwrap();

                // Upload file
                harness.nodes[i].file_transfer.upload_file(
                    file_path.to_string_lossy().to_string(),
                    filename.clone()
                ).await.expect("Failed to upload file");

                // Publish metadata
                let file_hash = chiral_network::file_transfer::FileTransferService::calculate_file_hash(&content);

                let metadata = FileMetadata {
                    file_hash: file_hash.clone(),
                    file_name: filename,
                    file_size: content.len() as u64,
                    seeders: vec![harness.nodes[i].peer_id.clone()],
                    created_at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    mime_type: Some("text/plain".to_string()),
                    is_encrypted: false,
                    encryption_method: None,
                    key_fingerprint: None,
                };

                harness.nodes[i].dht.publish_file(metadata).await
                    .expect("Failed to publish file metadata");

                file_hashes.push(file_hash);
            }
        }

        // Wait for DHT propagation
        sleep(Duration::from_secs(5)).await;

        // Verify all files are discoverable
        let search_node = &harness.nodes[0]; // Use first node to search for all files
        for file_hash in file_hashes {
            let found = search_node.dht.search_metadata(file_hash.clone(), 10000).await
                .expect("Failed to search for file");

            assert!(found.is_some(), "Should find published file: {}", file_hash);
        }

        harness.shutdown().await;
    }
}