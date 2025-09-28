import { invoke } from '@tauri-apps/api/core';
import { downloadDir, join } from '@tauri-apps/api/path';
import { validateFilename, validateFilePath, validateFileHash, defaultRateLimiter } from '../security';

/**
 * A service class to interact with the file transfer and DHT commands
 * on the Rust backend. This is adapted from the implementation guide to match
 * the current backend commands in `main.rs`.
 */
export class FileService {
  /**
   * Initializes the file transfer and DHT services on the backend.
   * This should be called once when the application starts.
   */
  async initializeServices(): Promise<void> {
    await invoke('start_file_transfer_service');
    // Also start the DHT node, as it's closely related to file sharing.
    // The port and bootstrap nodes could be made configurable in the future.
    // Using a default bootstrap node from your headless.rs for now.
    const defaultBootstrap =
      '/ip4/54.198.145.146/tcp/4001/p2p/12D3KooWNHdYWRTe98KMF1cDXXqGXvNjd1SAchDaeP5o4MsoJLu2';
    await invoke('start_dht_node', { port: 4001, bootstrapNodes: [defaultBootstrap] });
  }

  /**
   * Uploads a file to the network by sending its data to the backend.
   * This is suitable for files selected via a file input in the browser.
   * @param file The file object to upload.
   * @returns The hash of the uploaded file.
   */
  async uploadFile(file: File): Promise<string> {
    // Security validations
    const filenameValidation = validateFilename(file.name);
    if (!filenameValidation.valid) {
      throw new Error(`Invalid filename: ${filenameValidation.error}`);
    }

    // Rate limiting
    if (!defaultRateLimiter.isAllowed('upload')) {
      throw new Error('Upload rate limit exceeded. Please try again later.');
    }

    // File size validation (100MB limit)
    if (file.size > 100 * 1024 * 1024) {
      throw new Error('File size too large (max 100MB)');
    }

    const buffer = await file.arrayBuffer();
    const bytes = new Uint8Array(buffer);

    // Calls 'upload_file_data_to_network' on the backend.
    // Tauri automatically converts camelCase JS arguments to snake_case Rust arguments.
    const hash = await invoke<string>('upload_file_data_to_network', {
      fileName: file.name,
      fileData: Array.from(bytes), // Convert Uint8Array to number[] for serialization
    });

    return hash;
  }

  /**
   * Uploads a file to the network from a given file path.
   * This is suitable for files already on the user's disk, referenced by path.
   * @param filePath The absolute path to the file.
   * @param fileName The name of the file.
   * @returns The hash of the uploaded file.
   */
  async uploadFileFromPath(filePath: string, fileName: string): Promise<string> {
    // Security validations
    const pathValidation = validateFilePath(filePath);
    if (!pathValidation.valid) {
      throw new Error(`Invalid file path: ${pathValidation.error}`);
    }

    const filenameValidation = validateFilename(fileName);
    if (!filenameValidation.valid) {
      throw new Error(`Invalid filename: ${filenameValidation.error}`);
    }

    // Rate limiting
    if (!defaultRateLimiter.isAllowed('upload')) {
      throw new Error('Upload rate limit exceeded. Please try again later.');
    }

    // Calls 'upload_file_to_network' on the backend.
    const hash = await invoke<string>('upload_file_to_network', {
      filePath,
      fileName,
    });
    return hash;
  }

  /**
   * Downloads a file from the network given its hash.
   * The backend saves it to the user's default download directory.
   * @param hash The hash of the file to download.
   * @param fileName The name to save the file as.
   * @returns The full path to the downloaded file.
   */
  async downloadFile(hash: string, fileName: string): Promise<string> {
    // Security validations
    if (!validateFileHash(hash)) {
      throw new Error('Invalid file hash format');
    }

    const filenameValidation = validateFilename(fileName);
    if (!filenameValidation.valid) {
      throw new Error(`Invalid filename: ${filenameValidation.error}`);
    }

    // Rate limiting
    if (!defaultRateLimiter.isAllowed('download')) {
      throw new Error('Download rate limit exceeded. Please try again later.');
    }

    const downloadPath = await downloadDir();
    const outputPath = await join(downloadPath, fileName);

    // Calls 'download_file_from_network' on the backend.
    // Note: The current backend implementation only retrieves from its local
    // storage, not from other peers yet. This is a starting point.
    await invoke('download_file_from_network', {
      fileHash: hash,
      outputPath: outputPath,
    });

    return outputPath;
  }

  /**
   * Opens the folder containing the specified file in the native file explorer.
   * @param path The full path to the file.
   */
  async showInFolder(path: string): Promise<void> {
    // Security validation
    const pathValidation = validateFilePath(path);
    if (!pathValidation.valid) {
      throw new Error(`Invalid file path: ${pathValidation.error}`);
    }

    await invoke('show_in_folder', { path });
  }

  /**
   * Queries the backend for the amount of free disk space (in GB) the node can use.
   * Returns null when the call fails so the UI can surface a retry affordance.
   */
  async getAvailableStorage(): Promise<number | null> {
    try {
      const storage = await invoke<number>('get_available_storage');
      return Number.isFinite(storage) ? storage : null;
    } catch (error) {
      console.error('Failed to load available storage:', error);
      return null;
    }
  }
}

// It's often useful to export a singleton instance of the service.
export const fileService = new FileService();
