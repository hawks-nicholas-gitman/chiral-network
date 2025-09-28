#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

pub mod commands;
mod dht;
mod ethereum;
pub mod net;
mod file_transfer;
mod geth_downloader;
mod headless;
mod keystore;

use commands::proxy::{proxy_connect, proxy_disconnect, list_proxies, ProxyNode};
use dht::{DhtEvent, DhtMetricsSnapshot, DhtService, FileMetadata};
use ethereum::{
    create_new_account, get_account_from_private_key, get_balance, get_block_number, get_hashrate,
    get_mined_blocks_count, get_mining_logs, get_mining_performance, get_mining_status,
    get_network_difficulty, get_network_hashrate, get_peer_count, get_recent_mined_blocks,
    start_mining, stop_mining, EthAccount, GethProcess, MinedBlock,
};
use file_transfer::{FileTransferEvent, FileTransferService};
use fs2::available_space;
use geth_downloader::GethDownloader;
use keystore::Keystore;
use std::path::Path;
use std::{
    sync::{Arc},
    time::Instant,
};
use sysinfo::{Components, System, MINIMUM_CPU_UPDATE_INTERVAL};
use systemstat::{Platform, System as SystemStat};
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Emitter, Manager, State,
};
use tokio::sync::Mutex;
use tracing::{info, warn};

// Security validation functions
fn validate_file_path(path: &str) -> Result<(), String> {
    // Check for path traversal attempts
    if path.contains("..") || path.contains("\\..") || path.contains("../") {
        return Err("Path traversal attempt detected".to_string());
    }

    // Check for absolute paths that might access system files
    if path.starts_with("/etc") || path.starts_with("/sys") || path.starts_with("/proc") {
        return Err("Access to system directories is not allowed".to_string());
    }

    #[cfg(target_os = "windows")]
    {
        if path.starts_with("C:\\Windows") || path.starts_with("C:\\System32") {
            return Err("Access to system directories is not allowed".to_string());
        }
    }

    Ok(())
}

fn validate_filename(filename: &str) -> Result<(), String> {
    // Check for dangerous characters
    let dangerous_chars = ['<', '>', ':', '"', '|', '?', '*', '\0'];
    if filename.chars().any(|c| dangerous_chars.contains(&c)) {
        return Err("Invalid characters in filename".to_string());
    }

    // Check for reserved names on Windows
    #[cfg(target_os = "windows")]
    {
        let reserved_names = ["CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4",
                             "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2",
                             "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"];
        if reserved_names.contains(&filename.to_uppercase().as_str()) {
            return Err("Reserved filename".to_string());
        }
    }

    Ok(())
}

struct AppState {
    geth: Mutex<GethProcess>,
    downloader: Arc<GethDownloader>,
    miner_address: Mutex<Option<String>>,
    dht: Mutex<Option<Arc<DhtService>>>,
    file_transfer: Mutex<Option<Arc<FileTransferService>>>,
    proxies: Arc<Mutex<Vec<ProxyNode>>>,
}

#[tauri::command]
async fn create_chiral_account() -> Result<EthAccount, String> {
    create_new_account()
}

#[tauri::command]
async fn import_chiral_account(private_key: String) -> Result<EthAccount, String> {
    get_account_from_private_key(&private_key)
}

#[tauri::command]
async fn start_geth_node(state: State<'_, AppState>, data_dir: String) -> Result<(), String> {
    let mut geth = state.geth.lock().await;
    let miner_address = state.miner_address.lock().await;
    geth.start(&data_dir, miner_address.as_deref())
}

#[tauri::command]
async fn stop_geth_node(state: State<'_, AppState>) -> Result<(), String> {
    let mut geth = state.geth.lock().await;
    geth.stop()
}

#[tauri::command]
async fn save_account_to_keystore(
    address: String,
    private_key: String,
    password: String,
) -> Result<(), String> {
    let mut keystore = Keystore::load()?;
    keystore.add_account(address, &private_key, &password)?;
    Ok(())
}

#[tauri::command]
async fn load_account_from_keystore(
    address: String,
    password: String,
) -> Result<EthAccount, String> {
    let keystore = Keystore::load()?;

    // Get decrypted private key from keystore
    let private_key = keystore.get_account(&address, &password)?;

    // Derive account details from private key
    get_account_from_private_key(&private_key)
}

#[tauri::command]
async fn list_keystore_accounts() -> Result<Vec<String>, String> {
    let keystore = Keystore::load()?;
    Ok(keystore.list_accounts())
}

#[tauri::command]
async fn remove_account_from_keystore(address: String) -> Result<(), String> {
    let mut keystore = Keystore::load()?;
    keystore.remove_account(&address)?;
    Ok(())
}

#[tauri::command]
async fn get_account_balance(address: String) -> Result<String, String> {
    get_balance(&address).await
}

#[tauri::command]
async fn get_network_peer_count() -> Result<u32, String> {
    get_peer_count().await
}

#[tauri::command]
async fn is_geth_running(state: State<'_, AppState>) -> Result<bool, String> {
    let geth = state.geth.lock().await;
    Ok(geth.is_running())
}

#[tauri::command]
async fn check_geth_binary(state: State<'_, AppState>) -> Result<bool, String> {
    Ok(state.downloader.is_geth_installed())
}

#[tauri::command]
async fn download_geth_binary(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let downloader = state.downloader.clone();
    let app_handle = app.clone();

    downloader
        .download_geth(move |progress| {
            let _ = app_handle.emit("geth-download-progress", progress);
        })
        .await
}

#[tauri::command]
async fn set_miner_address(state: State<'_, AppState>, address: String) -> Result<(), String> {
    let mut miner_address = state.miner_address.lock().await;
    *miner_address = Some(address);
    Ok(())
}

#[tauri::command]
async fn start_miner(
    state: State<'_, AppState>,
    address: String,
    threads: u32,
    data_dir: String,
) -> Result<(), String> {
    // Store the miner address for future geth restarts
    {
        let mut miner_address = state.miner_address.lock().await;
        *miner_address = Some(address.clone());
    } // MutexGuard is dropped here

    // Try to start mining
    match start_mining(&address, threads).await {
        Ok(_) => Ok(()),
        Err(e) if e.contains("-32601") || e.to_lowercase().contains("does not exist") => {
            // miner_setEtherbase method doesn't exist, need to restart with etherbase
            println!("miner_setEtherbase not supported, restarting geth with miner address...");

            // Need to restart geth with the miner address
            // First stop geth
            {
                let mut geth = state.geth.lock().await;
                geth.stop()?;
            }

            // Wait a moment for it to shut down
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

            // Restart with miner address
            {
                let mut geth = state.geth.lock().await;
                let miner_address = state.miner_address.lock().await;
                println!("Restarting geth with miner address: {:?}", miner_address);
                geth.start(&data_dir, miner_address.as_deref())?;
            }

            // Wait for geth to start up and be ready to accept RPC connections
            let mut attempts = 0;
            let max_attempts = 30; // 30 seconds max wait
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                attempts += 1;

                // Check if geth is responding to RPC calls
                if let Ok(response) = reqwest::Client::new()
                    .post("http://127.0.0.1:8545")
                    .json(&serde_json::json!({
                        "jsonrpc": "2.0",
                        "method": "net_version",
                        "params": [],
                        "id": 1
                    }))
                    .send()
                    .await
                {
                    if response.status().is_success() {
                        if let Ok(json) = response.json::<serde_json::Value>().await {
                            if json.get("result").is_some() {
                                println!("Geth is ready for RPC calls");
                                break;
                            }
                        }
                    }
                }

                if attempts >= max_attempts {
                    return Err("Geth failed to start up within 30 seconds".to_string());
                }

                println!(
                    "Waiting for geth to start up... (attempt {}/{})",
                    attempts, max_attempts
                );
            }

            // Try mining again without setting etherbase (it's set via command line now)
            let client = reqwest::Client::new();
            let start_mining_direct = serde_json::json!({
                "jsonrpc": "2.0",
                "method": "miner_start",
                "params": [threads],
                "id": 1
            });

            let response = client
                .post("http://127.0.0.1:8545")
                .json(&start_mining_direct)
                .send()
                .await
                .map_err(|e| format!("Failed to start mining after restart: {}", e))?;

            let json_response: serde_json::Value = response
                .json()
                .await
                .map_err(|e| format!("Failed to parse response: {}", e))?;

            if let Some(error) = json_response.get("error") {
                Err(format!("Failed to start mining after restart: {}", error))
            } else {
                Ok(())
            }
        }
        Err(e) => Err(format!("Failed to start mining: {}", e)),
    }
}

#[tauri::command]
async fn stop_miner() -> Result<(), String> {
    stop_mining().await
}

#[tauri::command]
async fn get_miner_status() -> Result<bool, String> {
    get_mining_status().await
}

#[tauri::command]
async fn get_miner_hashrate() -> Result<String, String> {
    get_hashrate().await
}

#[tauri::command]
async fn get_current_block() -> Result<u64, String> {
    get_block_number().await
}

#[tauri::command]
async fn get_network_stats() -> Result<(String, String), String> {
    let difficulty = get_network_difficulty().await?;
    let hashrate = get_network_hashrate().await?;
    Ok((difficulty, hashrate))
}

#[tauri::command]
async fn get_miner_logs(data_dir: String, lines: usize) -> Result<Vec<String>, String> {
    get_mining_logs(&data_dir, lines)
}

#[tauri::command]
async fn get_miner_performance(data_dir: String) -> Result<(u64, f64), String> {
    get_mining_performance(&data_dir)
}

#[tauri::command]
async fn get_blocks_mined(address: String) -> Result<u64, String> {
    get_mined_blocks_count(&address).await
}
#[tauri::command]
async fn get_recent_mined_blocks_pub(
    address: String,
    lookback: u64,
    limit: usize,
) -> Result<Vec<MinedBlock>, String> {
    get_recent_mined_blocks(&address, lookback, limit).await
}
#[tauri::command]
async fn start_dht_node(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    port: u16,
    bootstrap_nodes: Vec<String>,
) -> Result<String, String> {
    {
        let dht_guard = state.dht.lock().await;
        if dht_guard.is_some() {
            return Err("DHT node is already running".to_string());
        }
    }

    let dht_service = DhtService::new(port, bootstrap_nodes, None)
        .await
        .map_err(|e| format!("Failed to start DHT: {}", e))?;

    let peer_id = dht_service.get_peer_id().await;

    // Start the DHT node running in background
    dht_service.run().await;
    let dht_arc = Arc::new(dht_service);

    // Spawn the event pump
    let app_handle = app.clone();
    let proxies_arc = state.proxies.clone();
    let dht_clone_for_pump = dht_arc.clone();

    tokio::spawn(async move {
        use std::time::Duration;
        loop {
            // If the DHT service has been shut down, the weak reference will be None
            let events = dht_clone_for_pump.drain_events(64).await;
            if events.is_empty() {
                // Avoid busy-waiting
                tokio::time::sleep(Duration::from_millis(200)).await;
                // Check if the DHT is still alive before continuing
                if Arc::strong_count(&dht_clone_for_pump) <= 1 { // 1 is the pump itself
                    info!("DHT service appears to be shut down. Exiting event pump.");
                    break;
                }
                continue;
            }

            for ev in events {
                match ev {
                    DhtEvent::ProxyStatus { id, address, status, latency_ms, error } => {
                        let mut proxies = proxies_arc.lock().await;
                        // upsert: find by id (peer id) or by address (initial connection url)
                        if let Some(p) = proxies.iter_mut().find(|p| p.id == id || p.address == id || (!address.is_empty() && p.address == address)) {
                            p.id = id.clone(); // always update to the real peer id
                            if !address.is_empty() { p.address = address.clone(); }
                            p.status = status.clone();
                            if let Some(ms) = latency_ms { p.latency = ms as u32; }
                            p.error = error.clone();
                            let _ = app_handle.emit("proxy_status_update", p.clone());
                        } else {
                            // let new_node = ProxyNode {
                            //     id: id.clone(),
                            //     address: if address.is_empty() { id.clone() } else { address.clone() },
                            //     status,
                            //     latency: latency_ms.unwrap_or(999) as u32,
                            //     error,
                            // };
                            // proxies.push(new_node.clone());
                            // let _ = app_handle.emit("proxy_status_update", new_node);
                        }
                    }
                    DhtEvent::PeerRtt { peer, rtt_ms } => {
                        let mut proxies = proxies_arc.lock().await;
                        if let Some(p) = proxies.iter_mut().find(|p| p.id == peer) {
                            p.latency = rtt_ms as u32;
                            let _ = app_handle.emit("proxy_status_update", p.clone());
                        }
                    }
                    _ => {}
                }
            }
        }
    });

    {
        let mut dht_guard = state.dht.lock().await;
        *dht_guard = Some(dht_arc);
    }

    Ok(peer_id)
}

#[tauri::command]
async fn stop_dht_node(state: State<'_, AppState>) -> Result<(), String> {
    let dht = {
        let mut dht_guard = state.dht.lock().await;
        dht_guard.take()
    };

    if let Some(dht) = dht {
        dht.shutdown()
            .await
            .map_err(|e| format!("Failed to stop DHT: {}", e))?;
    }
    Ok(())
}

#[tauri::command]
async fn publish_file_metadata(
    state: State<'_, AppState>,
    file_hash: String,
    file_name: String,
    file_size: u64,
    mime_type: Option<String>,
) -> Result<(), String> {
    let dht = {
        let dht_guard = state.dht.lock().await;
        dht_guard.as_ref().cloned()
    };

    if let Some(dht) = dht {
        let metadata = FileMetadata {
            file_hash,
            file_name,
            file_size,
            seeders: vec![],
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            mime_type,
        };

        dht.publish_file(metadata).await
    } else {
        Err("DHT node is not running".to_string())
    }
}

#[tauri::command]
async fn search_file_metadata(state: State<'_, AppState>, file_hash: String) -> Result<(), String> {
    let dht = {
        let dht_guard = state.dht.lock().await;
        dht_guard.as_ref().cloned()
    };

    if let Some(dht) = dht {
        dht.get_file(file_hash).await
    } else {
        Err("DHT node is not running".to_string())
    }
}

#[tauri::command]
async fn connect_to_peer(state: State<'_, AppState>, peer_address: String) -> Result<(), String> {
    let dht = {
        let dht_guard = state.dht.lock().await;
        dht_guard.as_ref().cloned()
    };

    if let Some(dht) = dht {
        dht.connect_peer(peer_address).await
    } else {
        Err("DHT node is not running".to_string())
    }
}

#[tauri::command]
async fn get_dht_peer_count(state: State<'_, AppState>) -> Result<usize, String> {
    let dht = {
        let dht_guard = state.dht.lock().await;
        dht_guard.as_ref().cloned()
    };

    if let Some(dht) = dht {
        Ok(dht.get_peer_count().await)
    } else {
        Ok(0) // Return 0 if DHT is not running
    }
}

#[tauri::command]
async fn get_dht_peer_id(state: State<'_, AppState>) -> Result<Option<String>, String> {
    let dht = {
        let dht_guard = state.dht.lock().await;
        dht_guard.as_ref().cloned()
    };

    if let Some(dht) = dht {
        Ok(Some(dht.get_peer_id().await))
    } else {
        Ok(None) // Return None if DHT is not running
    }
}

#[tauri::command]
async fn get_dht_health(state: State<'_, AppState>) -> Result<Option<DhtMetricsSnapshot>, String> {
    let dht = {
        let dht_guard = state.dht.lock().await;
        dht_guard.as_ref().cloned()
    };

    if let Some(dht) = dht {
        Ok(Some(dht.metrics_snapshot().await))
    } else {
        Ok(None)
    }
}

#[tauri::command]
async fn get_nat_status(state: State<'_, AppState>) -> Result<Option<String>, String> {
    let dht = {
        let dht_guard = state.dht.lock().map_err(|e| e.to_string())?;
        dht_guard.as_ref().cloned()
    };

    if let Some(dht) = dht {
        let snap = dht.metrics_snapshot().await;
        Ok(snap.nat_status)
    } else {
        Ok(None)
    }
}

#[tauri::command]
async fn get_dht_events(state: State<'_, AppState>) -> Result<Vec<String>, String> {
    let dht = {
        let dht_guard = state.dht.lock().await;
        dht_guard.as_ref().cloned()
    };

    if let Some(dht) = dht {
        let events = dht.drain_events(100).await;
        // Convert events to concise human-readable strings for the UI
        let mapped: Vec<String> = events
            .into_iter()
            .map(|e| match e {
                DhtEvent::PeerDiscovered(p) => format!("peer_discovered:{}", p),
                DhtEvent::PeerConnected(p) => format!("peer_connected:{}", p),
                DhtEvent::PeerDisconnected(p) => format!("peer_disconnected:{}", p),
                DhtEvent::FileDiscovered(meta) => format!(
                    "file_discovered:{}:{}:{}",
                    meta.file_hash, meta.file_name, meta.file_size
                ),
                DhtEvent::FileNotFound(hash) => format!("file_not_found:{}", hash),
                DhtEvent::Error(err) => format!("error:{}", err),
                DhtEvent::ProxyStatus { id, address, status, latency_ms, error } => {
                    let lat = latency_ms.map(|ms| format!("{ms}")).unwrap_or_else(|| "-".into());
                    let err = error.unwrap_or_default();
                    format!("proxy_status:{id}:{address}:{status}:{lat}{}", 
                            if err.is_empty() { "".into() } else { format!(":{err}") })
                }
                DhtEvent::PeerRtt { peer, rtt_ms } => format!("peer_rtt:{peer}:{rtt_ms}"),
            })
            .collect();
        Ok(mapped)
    } else {
        Ok(vec![])
    }
}

#[tauri::command]
fn get_cpu_temperature() -> Option<f32> {
    static mut LAST_UPDATE: Option<Instant> = None;
    unsafe {
        if let Some(last) = LAST_UPDATE {
            if last.elapsed() < MINIMUM_CPU_UPDATE_INTERVAL {
                return None;
            }
        }
        LAST_UPDATE = Some(Instant::now());
    }
    
    // Try sysinfo first (works on some platforms including M1 macs and some Windows)
    let mut sys = System::new_all();
    sys.refresh_cpu_all();
    let components = Components::new_with_refreshed_list();

    let mut core_count = 0;

    let sum: f32 = components
        .iter()
        .filter(|c| {
            let label = c.label().to_lowercase();
            label.contains("cpu") || label.contains("package") || label.contains("tdie") || label.contains("core") || label.contains("thermal")
        })
        .map(|c| {
            core_count += 1;
            c.temperature()
        })
        .sum();
    if core_count > 0 {
        return Some(sum / core_count as f32);
    }
    
    // Windows-specific temperature detection methods
    #[cfg(target_os = "windows")]
    {
        if let Some(temp) = get_windows_temperature() {
            return Some(temp);
        }
    }
    
    // Linux-specific temperature detection methods
    #[cfg(target_os = "linux")]
    {
        if let Some(temp) = get_linux_temperature() {
            return Some(temp);
        }
    }
    
    // Fallback for other platforms
    let stat_sys = SystemStat::new();
    if let Ok(temp) = stat_sys.cpu_temp() {
        return Some(temp);
    }

    None
}

#[cfg(target_os = "windows")]
fn get_windows_temperature() -> Option<f32> {
    use std::process::Command;
    
    // Method 1: Try the fastest method first - HighPrecisionTemperature from WMI
    if let Ok(output) = Command::new("powershell")
        .args([
            "-Command",
            "Get-WmiObject -Query \"SELECT HighPrecisionTemperature FROM Win32_PerfRawData_Counters_ThermalZoneInformation\" | Select-Object -First 1 -ExpandProperty HighPrecisionTemperature"
        ])
        .output()
    {
        if let Ok(output_str) = String::from_utf8(output.stdout) {
            if let Ok(temp_tenths_kelvin) = output_str.trim().parse::<f32>() {
                let temp_celsius = (temp_tenths_kelvin / 10.0) - 273.15;
                if temp_celsius > 0.0 && temp_celsius < 150.0 {
                    return Some(temp_celsius);
                }
            }
        }
    }
    
    // Method 2: Fallback to regular Temperature field
    if let Ok(output) = Command::new("powershell")
        .args([
            "-Command",
            "Get-WmiObject -Query \"SELECT Temperature FROM Win32_PerfRawData_Counters_ThermalZoneInformation\" | Select-Object -First 1 -ExpandProperty Temperature"
        ])
        .output()
    {
        if let Ok(output_str) = String::from_utf8(output.stdout) {
            if let Ok(temp_tenths_kelvin) = output_str.trim().parse::<f32>() {
                let temp_celsius = (temp_tenths_kelvin / 10.0) - 273.15;
                if temp_celsius > 0.0 && temp_celsius < 150.0 {
                    return Some(temp_celsius);
                }
            }
        }
    }
    
    None
}

#[cfg(target_os = "linux")]
fn get_linux_temperature() -> Option<f32> {
    use std::fs;
    
    // Method 1: Try sensors command first (most reliable and matches user expectations)
    if let Ok(output) = std::process::Command::new("sensors")
        .arg("-u")  // Raw output
        .output()
    {
        if let Ok(output_str) = String::from_utf8(output.stdout) {
            let lines: Vec<&str> = output_str.lines().collect();
            let mut i = 0;
            
            while i < lines.len() {
                let line = lines[i].trim();
                
                // Look for CPU package temperature section
                if line.contains("Package id 0:") {
                    // Look for temp1_input in the following lines
                    for j in (i + 1)..(i + 10).min(lines.len()) {
                        let temp_line = lines[j].trim();
                        if temp_line.starts_with("temp1_input:") {
                            if let Some(temp_str) = temp_line.split(':').nth(1) {
                                if let Ok(temp) = temp_str.trim().parse::<f32>() {
                                    if temp > 0.0 && temp < 150.0 {
                                        return Some(temp);
                                    }
                                }
                            }
                            break;
                        }
                    }
                }
                // Look for first core temperature as fallback
                else if line.contains("Core 0:") {
                    // Look for temp2_input (Core 0 uses temp2_input)
                    for j in (i + 1)..(i + 10).min(lines.len()) {
                        let temp_line = lines[j].trim();
                        if temp_line.starts_with("temp2_input:") {
                            if let Some(temp_str) = temp_line.split(':').nth(1) {
                                if let Ok(temp) = temp_str.trim().parse::<f32>() {
                                    if temp > 0.0 && temp < 150.0 {
                                        return Some(temp);
                                    }
                                }
                            }
                            break;
                        }
                    }
                }
                i += 1;
            }
        }
    }
    
    // Method 2: Try thermal zones (fallback)
    // Look for CPU thermal zones in /sys/class/thermal/
    // Prioritize x86_pkg_temp as it's usually the most accurate for CPU package temperature
    for i in 0..20 {
        let type_path = format!("/sys/class/thermal/thermal_zone{}/type", i);
        if let Ok(zone_type) = fs::read_to_string(&type_path) {
            let zone_type = zone_type.trim().to_lowercase();
            if zone_type == "x86_pkg_temp" {
                let thermal_path = format!("/sys/class/thermal/thermal_zone{}/temp", i);
                if let Ok(temp_str) = fs::read_to_string(&thermal_path) {
                    if let Ok(temp_millidegrees) = temp_str.trim().parse::<i32>() {
                        let temp_celsius = temp_millidegrees as f32 / 1000.0;
                        if temp_celsius > 0.0 && temp_celsius < 150.0 {
                            return Some(temp_celsius);
                        }
                    }
                }
            }
        }
    }
    
    // Fallback to other CPU thermal zones
    for i in 0..20 {
        let type_path = format!("/sys/class/thermal/thermal_zone{}/type", i);
        if let Ok(zone_type) = fs::read_to_string(&type_path) {
            let zone_type = zone_type.trim().to_lowercase();
            if zone_type.contains("cpu") || zone_type.contains("coretemp") || zone_type.contains("k10temp") {
                let thermal_path = format!("/sys/class/thermal/thermal_zone{}/temp", i);
                if let Ok(temp_str) = fs::read_to_string(&thermal_path) {
                    if let Ok(temp_millidegrees) = temp_str.trim().parse::<i32>() {
                        let temp_celsius = temp_millidegrees as f32 / 1000.0;
                        if temp_celsius > 0.0 && temp_celsius < 150.0 {
                            return Some(temp_celsius);
                        }
                    }
                }
            }
        }
    }
    
    // Method 3: Try hwmon (hardware monitoring) interfaces
    // Look for CPU temperature sensors in /sys/class/hwmon/
    for i in 0..10 {
        let hwmon_dir = format!("/sys/class/hwmon/hwmon{}", i);
        
        // Check if this hwmon device is for CPU temperature
        let name_path = format!("{}/name", hwmon_dir);
        if let Ok(name) = fs::read_to_string(&name_path) {
            let name = name.trim().to_lowercase();
            if name.contains("coretemp") || name.contains("k10temp") || 
               name.contains("cpu") || name.contains("acpi") {
                
                // Try different temperature input files
                for temp_input in 1..=8 {
                    let temp_path = format!("{}/temp{}_input", hwmon_dir, temp_input);
                    if let Ok(temp_str) = fs::read_to_string(&temp_path) {
                        if let Ok(temp_millidegrees) = temp_str.trim().parse::<i32>() {
                            let temp_celsius = temp_millidegrees as f32 / 1000.0;
                            if temp_celsius > 0.0 && temp_celsius < 150.0 {
                                return Some(temp_celsius);
                            }
                        }
                    }
                }
            }
        }
    }
    
    // Method 4: Try reading from specific CPU temperature files
    let cpu_temp_paths = [
        "/sys/devices/platform/coretemp.0/hwmon/hwmon*/temp1_input",
        "/sys/devices/platform/coretemp.0/temp1_input", 
        "/sys/bus/platform/devices/coretemp.0/hwmon/hwmon*/temp*_input",
        "/sys/devices/pci0000:00/0000:00:18.3/hwmon/hwmon*/temp1_input", // AMD
    ];
    
    for pattern in &cpu_temp_paths {
        if let Ok(paths) = glob::glob(pattern) {
            for path_result in paths {
                if let Ok(path) = path_result {
                    if let Ok(temp_str) = fs::read_to_string(&path) {
                        if let Ok(temp_millidegrees) = temp_str.trim().parse::<i32>() {
                            let temp_celsius = temp_millidegrees as f32 / 1000.0;
                            if temp_celsius > 0.0 && temp_celsius < 150.0 {
                                return Some(temp_celsius);
                            }
                        }
                    }
                }
            }
        }
    }
    
    None
}

#[tauri::command]
fn detect_locale() -> String {
    sys_locale::get_locale().unwrap_or_else(|| "en-US".into())
}

#[tauri::command]
async fn start_file_transfer_service(state: State<'_, AppState>) -> Result<(), String> {
    {
        let ft_guard = state.file_transfer.lock().await;
        if ft_guard.is_some() {
            return Err("File transfer service is already running".to_string());
        }
    }

    let file_transfer_service = FileTransferService::new()
        .await
        .map_err(|e| format!("Failed to start file transfer service: {}", e))?;

    {
        let mut ft_guard = state.file_transfer.lock().await;
        *ft_guard = Some(Arc::new(file_transfer_service));
    }

    Ok(())
}

#[tauri::command]
async fn upload_file_to_network(
    state: State<'_, AppState>,
    file_path: String,
    file_name: String,
) -> Result<String, String> {
    // Validate inputs for security
    validate_file_path(&file_path)?;
    validate_filename(&file_name)?;

    let ft = {
        let ft_guard = state.file_transfer.lock().await;
        ft_guard.as_ref().cloned()
    };

    if let Some(ft) = ft {
        // Upload the file
        ft.upload_file(file_path.clone(), file_name.clone()).await?;

        // Get the file hash by reading the file and calculating it
        let file_data = tokio::fs::read(&file_path)
            .await
            .map_err(|e| format!("Failed to read file: {}", e))?;
        let file_hash = file_transfer::FileTransferService::calculate_file_hash(&file_data);

        // Also publish to DHT if it's running
        let dht = {
            let dht_guard = state.dht.lock().await;
            dht_guard.as_ref().cloned()
        };

        if let Some(dht) = dht {
            let metadata = FileMetadata {
                file_hash: file_hash.clone(),
                file_name: file_name.clone(),
                file_size: file_data.len() as u64,
                seeders: vec![],
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                mime_type: None,
            };

            if let Err(e) = dht.publish_file(metadata).await {
                warn!("Failed to publish file metadata to DHT: {}", e);
            }
        }

        Ok(file_hash)
    } else {
        Err("File transfer service is not running".to_string())
    }
}

#[tauri::command]
async fn download_file_from_network(
    state: State<'_, AppState>,
    file_hash: String,
    output_path: String,
) -> Result<(), String> {
    // Validate inputs for security
    validate_file_path(&output_path)?;

    let ft = {
        let ft_guard = state.file_transfer.lock().await;
        ft_guard.as_ref().cloned()
    };

    if let Some(ft) = ft {
        // First try to download from local storage
        match ft
            .download_file(file_hash.clone(), output_path.clone())
            .await
        {
            Ok(()) => {
                info!("File downloaded successfully from local storage");
                return Ok(());
            }
            Err(_) => {
                // File not found locally, would need to implement P2P download here
                // For now, return an error
                return Err(
                    "File not found in local storage. P2P download not yet implemented."
                        .to_string(),
                );
            }
        }
    } else {
        Err("File transfer service is not running".to_string())
    }
}

#[tauri::command]
async fn upload_file_data_to_network(
    state: State<'_, AppState>,
    file_name: String,
    file_data: Vec<u8>,
) -> Result<String, String> {
    let ft = {
        let ft_guard = state.file_transfer.lock().await;
        ft_guard.as_ref().cloned()
    };

    if let Some(ft) = ft {
        // Calculate file hash from the data
        let file_hash = file_transfer::FileTransferService::calculate_file_hash(&file_data);

        // Store the file data directly in memory
        let file_size = file_data.len() as u64;
        ft.store_file_data(file_hash.clone(), file_name.clone(), file_data)
            .await;

        // Also publish to DHT if it's running
        let dht = {
            let dht_guard = state.dht.lock().await;
            dht_guard.as_ref().cloned()
        };

        if let Some(dht) = dht {
            let metadata = FileMetadata {
                file_hash: file_hash.clone(),
                file_name: file_name.clone(),
                file_size: file_size,
                seeders: vec![],
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                mime_type: None,
            };

            if let Err(e) = dht.publish_file(metadata).await {
                warn!("Failed to publish file metadata to DHT: {}", e);
            }
        }

        Ok(file_hash)
    } else {
        Err("File transfer service is not running".to_string())
    }
}

#[tauri::command]
async fn show_in_folder(path: String) -> Result<(), String> {
    // Validate path for security
    validate_file_path(&path)?;

    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("explorer")
            .args(["/select,", &path])
            .spawn()
            .map_err(|e| format!("Failed to open folder: {}", e))?;
    }

    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .args(["-R", &path])
            .spawn()
            .map_err(|e| format!("Failed to open folder: {}", e))?;
    }

    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .args([&std::path::Path::new(&path)
                .parent()
                .unwrap_or(std::path::Path::new("/"))])
            .spawn()
            .map_err(|e| format!("Failed to open folder: {}", e))?;
    }

    Ok(())
}

#[tauri::command]
async fn get_file_transfer_events(state: State<'_, AppState>) -> Result<Vec<String>, String> {
    let ft = {
        let ft_guard = state.file_transfer.lock().await;
        ft_guard.as_ref().cloned()
    };

    if let Some(ft) = ft {
        let events = ft.drain_events(100).await;
        let mapped: Vec<String> = events
            .into_iter()
            .map(|e| match e {
                FileTransferEvent::FileUploaded {
                    file_hash,
                    file_name,
                } => {
                    format!("file_uploaded:{}:{}", file_hash, file_name)
                }
                FileTransferEvent::FileDownloaded { file_path } => {
                    format!("file_downloaded:{}", file_path)
                }
                FileTransferEvent::FileNotFound { file_hash } => {
                    format!("file_not_found:{}", file_hash)
                }
                FileTransferEvent::Error { message } => {
                    format!("error:{}", message)
                }
            })
            .collect();
        Ok(mapped)
    } else {
        Ok(vec![])
    }
}

#[tauri::command]
fn get_available_storage() -> f64 {
    let storage = available_space(Path::new("/")).unwrap_or(0);
    (storage as f64 / 1024.0 / 1024.0 / 1024.0).floor()
}

fn main() {
    // Initialize logging for debug builds
    #[cfg(debug_assertions)]
    {
        use tracing_subscriber::{fmt, prelude::*, EnvFilter};
        tracing_subscriber::registry()
            .with(fmt::layer())
            .with(
                EnvFilter::from_default_env()
                    .add_directive("chiral_network=info".parse().unwrap())
                    .add_directive("libp2p=trace".parse().unwrap())
                    .add_directive("libp2p_kad=debug".parse().unwrap())
                    .add_directive("libp2p_swarm=debug".parse().unwrap()),
            )
            .init();
    }

    // Parse command line arguments
    use clap::Parser;
    let args = headless::CliArgs::parse();

    // If running in headless mode, don't start the GUI
    if args.headless {
        println!("Running in headless mode...");

        // Create a tokio runtime for async operations
        let runtime = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");

        // Run the headless mode
        if let Err(e) = runtime.block_on(headless::run_headless(args)) {
            eprintln!("Error in headless mode: {}", e);
            std::process::exit(1);
        }
        return;
    }

    println!("Starting Chiral Network...");

    tauri::Builder::default()
        .manage(AppState {
            geth: Mutex::new(GethProcess::new()),
            downloader: Arc::new(GethDownloader::new()),
            miner_address: Mutex::new(None),
            dht: Mutex::new(None),
            file_transfer: Mutex::new(None),
            proxies: Arc::new(Mutex::new(Vec::new())),
        })
        .invoke_handler(tauri::generate_handler![
            create_chiral_account,
            import_chiral_account,
            start_geth_node,
            stop_geth_node,
            save_account_to_keystore,
            load_account_from_keystore,
            list_keystore_accounts,
            remove_account_from_keystore,
            get_account_balance,
            get_network_peer_count,
            is_geth_running,
            check_geth_binary,
            download_geth_binary,
            set_miner_address,
            start_miner,
            stop_miner,
            get_miner_status,
            get_miner_hashrate,
            get_current_block,
            get_network_stats,
            get_miner_logs,
            get_miner_performance,
            get_blocks_mined,
            get_recent_mined_blocks_pub,
            get_cpu_temperature,
            start_dht_node,
            stop_dht_node,
            publish_file_metadata,
            search_file_metadata,
            connect_to_peer,
            get_dht_events,
            detect_locale,
            get_dht_health,
            get_dht_peer_count,
            get_dht_peer_id,
            get_nat_status,
            start_file_transfer_service,
            upload_file_to_network,
            upload_file_data_to_network,
            download_file_from_network,
            get_file_transfer_events,
            show_in_folder,
            get_available_storage,
            proxy_connect,
            proxy_disconnect,
            list_proxies
        ])
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_store::Builder::default().build())
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::Destroyed = event {
                // When window is destroyed, stop geth
                if let Some(state) = window.app_handle().try_state::<AppState>() {
                    if let Ok(mut geth) = state.geth.try_lock() {
                        let _ = geth.stop();
                        println!("Geth node stopped on window destroy");
                    }
                }
            }
        })
        .setup(|app| {
            // Clean up any orphaned geth processes on startup
            println!("Cleaning up any orphaned geth processes from previous sessions...");
            #[cfg(unix)]
            {
                use std::process::Command;
                // Kill any geth processes that might be running from previous sessions
                let _ = Command::new("pkill")
                    .arg("-9")
                    .arg("-f")
                    .arg("geth.*--datadir.*geth-data")
                    .output();
            }

            println!("App setup complete");
            println!("Window should be visible now!");

            let show_i = MenuItem::with_id(app, "show", "Show", true, None::<&str>)?;
            let hide_i = MenuItem::with_id(app, "hide", "Hide", true, None::<&str>)?;
            let quit_i = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show_i, &hide_i, &quit_i])?;

            let _tray = TrayIconBuilder::new()
                .icon(app.default_window_icon().unwrap().clone())
                .menu(&menu)
                .tooltip("Chiral Network")
                .show_menu_on_left_click(false)
                .on_tray_icon_event(|tray, event| match event {
                    TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } => {
                        println!("Tray icon left-clicked");
                        let app = tray.app_handle();
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.unminimize();
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                    _ => {}
                })
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        println!("Show menu item clicked");
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                    "hide" => {
                        println!("Hide menu item clicked");
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.hide();
                        }
                    }
                    "quit" => {
                        println!("Quit menu item clicked");
                        // Stop geth before exiting
                        if let Some(state) = app.try_state::<AppState>() {
                            if let Ok(mut geth) = state.geth.try_lock() {
                                let _ = geth.stop();
                                println!("Geth node stopped");
                            }
                        }
                        app.exit(0);
                    }
                    _ => {}
                })
                .build(app)?;

            // Get the main window and ensure it's visible
            if let Some(window) = app.get_webview_window("main") {
                window.show().unwrap();
                window.set_focus().unwrap();
                println!("Window shown and focused");

                let app_handle = app.handle().clone();
                window.on_window_event(move |event| {
                    if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                        // Prevent the window from closing and hide it instead
                        api.prevent_close();
                        if let Some(window) = app_handle.get_webview_window("main") {
                            let _ = window.hide();
                        }
                    }
                });
            } else {
                println!("Could not find main window!");
            }

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app_handle, event| match event {
            tauri::RunEvent::ExitRequested { .. } => {
                println!("Exit requested event received");
                // Don't prevent exit, let it proceed naturally
            }
            tauri::RunEvent::Exit => {
                println!("App exiting, cleaning up geth...");
                // Stop geth before exiting
                if let Some(state) = app_handle.try_state::<AppState>() {
                    if let Ok(mut geth) = state.geth.try_lock() {
                        let _ = geth.stop();
                        println!("Geth node stopped on exit");
                    }
                }
            }
            _ => {}
        });
}
