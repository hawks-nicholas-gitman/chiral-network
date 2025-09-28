/**
 * Security validation functions for Chiral Network
 * Provides comprehensive input validation and security checks
 */

// File hash validation (IPFS-style CID format)
export function validateFileHash(hash: string): boolean {
  if (!hash || typeof hash !== 'string') {
    return false;
  }

  // Basic IPFS CID validation - should start with Qm and be base58
  const ipfsRegex = /^Qm[1-9A-HJ-NP-Za-km-z]{44}$/;
  return ipfsRegex.test(hash);
}

// Filename validation
export function validateFilename(filename: string): { valid: boolean; error?: string } {
  if (!filename || typeof filename !== 'string') {
    return { valid: false, error: 'Filename is required' };
  }

  if (filename.length > 255) {
    return { valid: false, error: 'Filename too long (max 255 characters)' };
  }

  // Check for dangerous characters
  const dangerousChars = /[<>:"|?*\x00-\x1f]/;
  if (dangerousChars.test(filename)) {
    return { valid: false, error: 'Filename contains invalid characters' };
  }

  // Check for path traversal attempts
  if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
    return { valid: false, error: 'Filename cannot contain path separators' };
  }

  // Windows reserved names
  const windowsReserved = /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|$)/i;
  if (windowsReserved.test(filename)) {
    return { valid: false, error: 'Filename is reserved by the system' };
  }

  return { valid: true };
}

// File path validation
export function validateFilePath(path: string): { valid: boolean; error?: string } {
  if (!path || typeof path !== 'string') {
    return { valid: false, error: 'File path is required' };
  }

  // Check for path traversal attempts
  if (path.includes('..') || path.includes('\\..') || path.includes('../')) {
    return { valid: false, error: 'Path traversal attempt detected' };
  }

  // Restrict access to system directories
  const systemPaths = ['/etc', '/sys', '/proc', 'C:\\Windows', 'C:\\System32'];
  if (systemPaths.some(sysPath => path.startsWith(sysPath))) {
    return { valid: false, error: 'Access to system directories is not allowed' };
  }

  return { valid: true };
}

// URL validation for peer addresses
export function validatePeerAddress(address: string): { valid: boolean; error?: string } {
  if (!address || typeof address !== 'string') {
    return { valid: false, error: 'Peer address is required' };
  }

  // Allow multiaddr format: /ip4/x.x.x.x/tcp/port/p2p/hash
  const multiaddrRegex = /^\/ip[46]\/[^\/]+\/tcp\/\d+\/p2p\/[a-zA-Z0-9]+$/;
  if (multiaddrRegex.test(address)) {
    return { valid: true };
  }

  // Allow simple host:port format
  const hostPortRegex = /^[a-zA-Z0-9.-]+:\d+$/;
  if (hostPortRegex.test(address)) {
    return { valid: true };
  }

  return { valid: false, error: 'Invalid peer address format' };
}

// Rate limiting implementation
export class RateLimiter {
  private requests: Map<string, number[]> = new Map();
  private readonly maxRequests: number;
  private readonly windowMs: number;

  constructor(maxRequests: number = 100, windowMs: number = 60000) {
    this.maxRequests = maxRequests;
    this.windowMs = windowMs;
  }

  isAllowed(identifier: string): boolean {
    const now = Date.now();
    const windowStart = now - this.windowMs;

    // Get existing requests for this identifier
    let requests = this.requests.get(identifier) || [];

    // Remove old requests outside the window
    requests = requests.filter(timestamp => timestamp > windowStart);

    // Check if limit exceeded
    if (requests.length >= this.maxRequests) {
      return false;
    }

    // Add current request
    requests.push(now);
    this.requests.set(identifier, requests);

    return true;
  }

  reset(identifier?: string): void {
    if (identifier) {
      this.requests.delete(identifier);
    } else {
      this.requests.clear();
    }
  }
}

// Sanitize user input
export function sanitizeInput(input: string, maxLength: number = 1000): string {
  if (!input || typeof input !== 'string') {
    return '';
  }

  // Trim and limit length
  const sanitized = input.trim().substring(0, maxLength);

  // Remove control characters except newlines and tabs
  return sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
}

// Validate content type
export function validateContentType(contentType: string): boolean {
  if (!contentType || typeof contentType !== 'string') {
    return false;
  }

  // Allow common safe content types
  const allowedTypes = [
    'application/pdf',
    'application/zip',
    'application/x-zip-compressed',
    'text/plain',
    'text/csv',
    'image/jpeg',
    'image/png',
    'image/gif',
    'image/webp',
    'audio/mpeg',
    'audio/wav',
    'audio/ogg',
    'video/mp4',
    'video/webm',
    'video/ogg'
  ];

  return allowedTypes.includes(contentType.toLowerCase());
}

// Security headers for API responses
export function getSecurityHeaders(): Record<string, string> {
  return {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'"
  };
}

// Default rate limiter instance
export const defaultRateLimiter = new RateLimiter();