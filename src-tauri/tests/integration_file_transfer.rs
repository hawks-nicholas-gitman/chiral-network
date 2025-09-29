use chiral_network::{dht::{DhtService, FileMetadata}, file_transfer::{FileTransferService, FileTransferEvent}};
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::sleep;
use tracing_test::traced_test;

/// File transfer focused integration tests
pub struct FileTransferTestHarness {
    pub nodes: Vec<TestNode>,
}

pub struct TestNode {
    pub dht: DhtService,
    pub file_transfer: FileTransferService,
    pub peer_id: String,
    pub port: u16,
    pub temp_dir: TempDir,
}

impl FileTransferTestHarness {
    pub async fn new(node_count: usize) -> Result<Self, Box<dyn std::error::Error>> {
        let mut nodes = Vec::new();
        let base_port = 41000 + (rand::random::<u16>() % 10000);

        // Create bootstrap node
        if node_count > 0 {
            let temp_dir = tempfile::tempdir()?;
            let dht = DhtService::new(
                base_port,
                vec![],
                None,
                true,
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
                port: base_port,
                temp_dir,
            });
        }

        // Create additional nodes
        for i in 1..node_count {
            let temp_dir = tempfile::tempdir()?;
            let port = base_port + i as u16;
            let bootstrap_addr = format!("/ip4/127.0.0.1/tcp/{}/p2p/{}", base_port, nodes[0].peer_id);

            let dht = DhtService::new(
                port,
                vec![bootstrap_addr],
                None,
                false,
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

        Ok(FileTransferTestHarness { nodes })
    }

    pub async fn wait_for_network(&self, timeout: Duration) -> Result<(), String> {
        let start = std::time::Instant::now();

        while start.elapsed() < timeout {
            let mut all_connected = true;

            for (i, node) in self.nodes.iter().enumerate() {
                let peer_count = node.dht.get_peer_count().await;
                if self.nodes.len() > 1 && peer_count == 0 {
                    all_connected = false;
                    tracing::debug!("Node {} waiting for peers", i);
                    break;
                }
            }

            if all_connected {
                return Ok(());
            }

            sleep(Duration::from_millis(500)).await;
        }

        Err("Network formation timeout".to_string())
    }

    pub async fn create_test_file(&self, node_idx: usize, filename: &str, size_bytes: usize) -> Result<(String, Vec<u8>), String> {
        if node_idx >= self.nodes.len() {
            return Err("Invalid node index".to_string());
        }

        // Create test content
        let content = (0..size_bytes).map(|i| (i % 256) as u8).collect::<Vec<u8>>();
        let file_path = self.nodes[node_idx].temp_dir.path().join(filename);

        tokio::fs::write(&file_path, &content).await
            .map_err(|e| format!("Failed to write test file: {}", e))?;

        Ok((file_path.to_string_lossy().to_string(), content))
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
    async fn test_basic_file_upload_and_storage() {
        let harness = FileTransferTestHarness::new(1).await
            .expect("Failed to create test harness");

        // Create test file
        let (file_path, content) = harness.create_test_file(0, "basic_test.txt", 1024).await
            .expect("Failed to create test file");

        // Upload file
        harness.nodes[0].file_transfer
            .upload_file(file_path.clone(), "basic_test.txt".to_string()).await
            .expect("Failed to upload file");

        // Wait for upload to complete
        sleep(Duration::from_millis(1000)).await;

        // Check for upload event to confirm completion
        let events = harness.nodes[0].file_transfer.drain_events(10).await;
        let upload_event = events.iter().find(|event| {
            matches!(event, chiral_network::file_transfer::FileTransferEvent::FileUploaded { .. })
        });
        assert!(upload_event.is_some(), "Should have upload event");

        // Verify file is stored locally
        let stored_files = harness.nodes[0].file_transfer.get_stored_files().await
            .expect("Failed to get stored files");

        let found = stored_files.iter().find(|(_, name)| name == "basic_test.txt");
        assert!(found.is_some(), "Uploaded file should be in storage");

        // Verify file hash calculation
        let expected_hash = chiral_network::file_transfer::FileTransferService::calculate_file_hash(&content);
        let (actual_hash, _) = found.unwrap();
        assert_eq!(*actual_hash, expected_hash, "File hash should match expected value");

        harness.shutdown().await;
    }

    #[traced_test]
    #[tokio::test]
    async fn test_file_transfer_events() {
        let harness = FileTransferTestHarness::new(1).await
            .expect("Failed to create test harness");

        // Create test file
        let (file_path, _) = harness.create_test_file(0, "events_test.txt", 512).await
            .expect("Failed to create test file");

        // Upload file
        harness.nodes[0].file_transfer
            .upload_file(file_path.clone(), "events_test.txt".to_string()).await
            .expect("Failed to upload file");

        // Wait for events to be processed
        sleep(Duration::from_millis(500)).await;

        // Check events
        let events = harness.nodes[0].file_transfer.drain_events(10).await;
        assert!(!events.is_empty(), "Should have file transfer events");

        let upload_event = events.iter().find(|event| {
            matches!(event, FileTransferEvent::FileUploaded { .. })
        });

        assert!(upload_event.is_some(), "Should have upload event");

        if let Some(FileTransferEvent::FileUploaded { file_name, .. }) = upload_event {
            assert_eq!(file_name, "events_test.txt", "Event should have correct filename");
        }

        harness.shutdown().await;
    }

    #[traced_test]
    #[tokio::test]
    async fn test_large_file_handling() {
        let harness = FileTransferTestHarness::new(1).await
            .expect("Failed to create test harness");

        // Create larger test file (10MB)
        let large_size = 10 * 1024 * 1024; // 10MB
        let (file_path, content) = harness.create_test_file(0, "large_file.bin", large_size).await
            .expect("Failed to create large test file");

        info!("Created large test file of {} bytes", content.len());

        // Upload large file
        let start_time = std::time::Instant::now();
        harness.nodes[0].file_transfer
            .upload_file(file_path.clone(), "large_file.bin".to_string()).await
            .expect("Failed to upload large file");

        let upload_duration = start_time.elapsed();
        info!("Large file upload took {:?}", upload_duration);

        // Verify storage
        let stored_files = harness.nodes[0].file_transfer.get_stored_files().await
            .expect("Failed to get stored files");

        let found = stored_files.iter().find(|(_, name)| name == "large_file.bin");
        assert!(found.is_some(), "Large file should be stored");

        // Verify hash integrity
        let expected_hash = chiral_network::file_transfer::FileTransferService::calculate_file_hash(&content);
        let (actual_hash, _) = found.unwrap();
        assert_eq!(*actual_hash, expected_hash, "Large file hash should be correct");

        harness.shutdown().await;
    }

    #[traced_test]
    #[tokio::test]
    async fn test_concurrent_file_uploads() {
        let harness = FileTransferTestHarness::new(1).await
            .expect("Failed to create test harness");

        // Create multiple test files and upload them sequentially for simplicity
        let file_count = 5;
        let mut created_files = Vec::new();

        for i in 0..file_count {
            let filename = format!("concurrent_{}.txt", i);
            let (file_path, _) = harness.create_test_file(0, &filename, 1024 + i * 100).await
                .expect("Failed to create test file");
            created_files.push((file_path, filename));
        }

        // Upload files sequentially (to avoid lifetime issues in this test)
        for (file_path, filename) in created_files {
            harness.nodes[0].file_transfer
                .upload_file(file_path, filename.clone()).await
                .expect(&format!("Failed to upload {}", filename));
        }

        // Verify all files are stored
        let stored_files = harness.nodes[0].file_transfer.get_stored_files().await
            .expect("Failed to get stored files");

        assert_eq!(stored_files.len(), file_count, "Should have all uploads stored");

        harness.shutdown().await;
    }

    #[traced_test]
    #[tokio::test]
    async fn test_file_metadata_consistency() {
        let harness = FileTransferTestHarness::new(2).await
            .expect("Failed to create test harness");

        harness.wait_for_network(Duration::from_secs(15)).await
            .expect("Network formation failed");

        // Create and upload test file
        let (file_path, content) = harness.create_test_file(0, "metadata_consistency.txt", 2048).await
            .expect("Failed to create test file");

        harness.nodes[0].file_transfer
            .upload_file(file_path.clone(), "metadata_consistency.txt".to_string()).await
            .expect("Failed to upload file");

        let file_hash = chiral_network::file_transfer::FileTransferService::calculate_file_hash(&content);

        // Create metadata with specific attributes
        let metadata = FileMetadata {
            file_hash: file_hash.clone(),
            file_name: "metadata_consistency.txt".to_string(),
            file_size: content.len() as u64,
            seeders: vec![harness.nodes[0].peer_id.clone()],
            created_at: 1234567890, // Fixed timestamp for testing
            mime_type: Some("text/plain".to_string()),
            is_encrypted: false,
            encryption_method: None,
            key_fingerprint: None,
        };

        // Publish metadata
        harness.nodes[0].dht.publish_file(metadata.clone()).await
            .expect("Failed to publish file metadata");

        // Wait for DHT propagation
        sleep(Duration::from_secs(3)).await;

        // Search for metadata from other node
        let found_metadata = harness.nodes[1].dht.search_metadata(file_hash.clone(), 10000).await
            .expect("Failed to search for file metadata");

        assert!(found_metadata.is_some(), "Metadata should be found");

        let found = found_metadata.unwrap();
        assert_eq!(found.file_name, metadata.file_name, "Filename should match");
        assert_eq!(found.file_size, metadata.file_size, "File size should match");
        assert_eq!(found.file_hash, metadata.file_hash, "File hash should match");
        assert_eq!(found.created_at, metadata.created_at, "Creation time should match");
        assert_eq!(found.mime_type, metadata.mime_type, "MIME type should match");
        assert_eq!(found.is_encrypted, metadata.is_encrypted, "Encryption flag should match");

        harness.shutdown().await;
    }

    #[traced_test]
    #[tokio::test]
    async fn test_file_discovery_performance() {
        let harness = FileTransferTestHarness::new(3).await
            .expect("Failed to create test harness");

        harness.wait_for_network(Duration::from_secs(20)).await
            .expect("Network formation failed");

        // Upload multiple files from different nodes
        let files_per_node = 3;
        let mut all_hashes = Vec::new();

        for node_idx in 0..harness.nodes.len() {
            for file_idx in 0..files_per_node {
                let filename = format!("perf_test_{}_{}.txt", node_idx, file_idx);
                let (file_path, content) = harness.create_test_file(node_idx, &filename, 1024).await
                    .expect("Failed to create test file");

                harness.nodes[node_idx].file_transfer
                    .upload_file(file_path, filename.clone()).await
                    .expect("Failed to upload file");

                let file_hash = chiral_network::file_transfer::FileTransferService::calculate_file_hash(&content);

                let metadata = FileMetadata {
                    file_hash: file_hash.clone(),
                    file_name: filename,
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

                all_hashes.push(file_hash);
            }
        }

        // Wait for DHT propagation
        sleep(Duration::from_secs(5)).await;

        // Measure search performance
        let search_node = &harness.nodes[0];
        let search_start = std::time::Instant::now();

        let mut found_count = 0;
        for hash in &all_hashes {
            let found = search_node.dht.search_metadata(hash.clone(), 5000).await
                .expect("Failed to search for file");

            if found.is_some() {
                found_count += 1;
            }
        }

        let search_duration = search_start.elapsed();
        let avg_search_time = search_duration / all_hashes.len() as u32;

        info!("Found {}/{} files in {:?} (avg: {:?} per search)",
              found_count, all_hashes.len(), search_duration, avg_search_time);

        // Performance assertions
        assert!(found_count >= all_hashes.len() / 2, "Should find at least half the files");
        assert!(avg_search_time < Duration::from_millis(2000), "Average search should be under 2 seconds");

        harness.shutdown().await;
    }

    #[traced_test]
    #[tokio::test]
    async fn test_download_metrics_tracking() {
        let harness = FileTransferTestHarness::new(1).await
            .expect("Failed to create test harness");

        // Create and upload a test file
        let (file_path, content) = harness.create_test_file(0, "metrics_test.txt", 1024).await
            .expect("Failed to create test file");

        harness.nodes[0].file_transfer
            .upload_file(file_path.clone(), "metrics_test.txt".to_string()).await
            .expect("Failed to upload file");

        let file_hash = chiral_network::file_transfer::FileTransferService::calculate_file_hash(&content);

        // Attempt to download the file (should succeed from local storage)
        let download_path = harness.nodes[0].temp_dir.path().join("downloaded_metrics_test.txt");

        harness.nodes[0].file_transfer
            .download_file(file_hash, download_path.to_string_lossy().to_string()).await
            .expect("Failed to download file");

        // Wait for metrics to be updated
        sleep(Duration::from_millis(500)).await;

        // Check download metrics
        let metrics = harness.nodes[0].file_transfer.download_metrics_snapshot().await;

        info!("Download metrics: success={}, failures={}, retries={}",
              metrics.total_success, metrics.total_failures, metrics.total_retries);

        assert!(metrics.total_success > 0, "Should have successful downloads");
        assert!(!metrics.recent_attempts.is_empty(), "Should have recent attempt records");

        harness.shutdown().await;
    }
}