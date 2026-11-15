'use strict';
/**
 * ReconScan Node.js Client SDK
 * Zero-dependency Node.js client (uses native fetch in Node 18+).
 */

class ReconScanClient {
  /**
   * @param {Object} [options]
   * @param {string} [options.baseUrl] - Base URL of ReconScan (default: http://localhost:3001)
   * @param {string} [options.apiKey] - Optional API key for x-api-key authentication
   * @param {number} [options.timeout] - Request timeout in ms (default: 30000)
   */
  constructor(options = {}) {
    this.baseUrl = (options.baseUrl || process.env.RECONSCAN_URL || 'http://localhost:3001').replace(/\/+$/, '');
    this.apiKey = options.apiKey || process.env.RECONSCAN_API_KEY || null;
    this.timeout = options.timeout || 30000;
  }

  async _request(method, endpoint, body = null, isJson = true) {
    const url = `${this.baseUrl}${endpoint}`;
    const headers = {
      'User-Agent': 'ReconScan-Node-Client/2.0',
      'Accept': isJson ? 'application/json' : '*/*',
    };
    if (this.apiKey) {
      headers['x-api-key'] = this.apiKey;
    }
    if (body && method !== 'GET') {
      headers['Content-Type'] = 'application/json';
    }

    const res = await fetch(url, {
      method,
      headers,
      body: body ? JSON.stringify(body) : null,
      signal: AbortSignal.timeout(this.timeout),
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => '');
      let errMsg = errText;
      try {
        const errJson = JSON.parse(errText);
        errMsg = errJson.error || errText;
      } catch (_) {}
      throw new Error(`API Error [${res.status}]: ${errMsg || res.statusText}`);
    }

    if (isJson) {
      return res.json();
    }
    return res.arrayBuffer();
  }

  /**
   * Check server health
   */
  async health() {
    return this._request('GET', '/health');
  }

  /**
   * Start a new vulnerability scan
   * @param {string} domain - Target domain (e.g. example.com)
   * @param {Object} [options]
   * @param {'full'|'single'} [options.scanMode]
   * @param {string[]} [options.selectedModules]
   * @returns {Promise<{scanId: string, status: string, scanMode: string, selectedModules: any}>}
   */
  async startScan(domain, options = {}) {
    return this._request('POST', '/api/scan/start', {
      domain,
      scanMode: options.scanMode || 'full',
      selectedModules: options.selectedModules || [],
    });
  }

  /**
   * Get scan details by ID
   * @param {string} scanId
   */
  async getScan(scanId) {
    return this._request('GET', `/api/scan/${scanId}`);
  }

  /**
   * List all scans
   */
  async listScans() {
    return this._request('GET', '/api/scan');
  }

  /**
   * Cancel a running scan
   * @param {string} scanId
   */
  async cancelScan(scanId) {
    return this._request('DELETE', `/api/scan/${scanId}`);
  }

  /**
   * Compare two scans
   * @param {string} scanIdA
   * @param {string} scanIdB
   */
  async compareScans(scanIdA, scanIdB) {
    return this._request('GET', `/api/scan/compare?a=${encodeURIComponent(scanIdA)}&b=${encodeURIComponent(scanIdB)}`);
  }

  /**
   * Poll until a scan finishes
   * @param {string} scanId
   * @param {Object} [opts]
   * @param {number} [opts.intervalMs] - Polling interval in ms (default: 2000)
   * @param {number} [opts.timeoutMs] - Maximum wait time in ms (default: 600000)
   * @param {Function} [opts.onProgress] - Callback invoked on each poll
   */
  async waitForScan(scanId, opts = {}) {
    const intervalMs = opts.intervalMs || 2000;
    const timeoutMs = opts.timeoutMs || 600000;
    const startTime = Date.now();

    while (Date.now() - startTime < timeoutMs) {
      const scan = await this.getScan(scanId);
      if (typeof opts.onProgress === 'function') {
        opts.onProgress(scan);
      }

      if (['complete', 'error', 'cancelled'].includes(scan.status)) {
        return scan;
      }

      await new Promise(r => setTimeout(r, intervalMs));
    }

    throw new Error(`Timeout waiting for scan ${scanId} to finish after ${timeoutMs / 1000}s`);
  }

  /**
   * Get JSON report
   * @param {string} scanId
   */
  async getReportJson(scanId) {
    return this._request('GET', `/api/report/json/${scanId}`);
  }

  /**
   * Get HTML report as string
   * @param {string} scanId
   * @returns {Promise<string>}
   */
  async getReportHtml(scanId) {
    const buf = await this._request('GET', `/api/report/html/${scanId}`, null, false);
    return Buffer.from(buf).toString('utf-8');
  }

  /**
   * Get PDF report as Buffer
   * @param {string} scanId
   * @returns {Promise<Buffer>}
   */
  async getReportPdf(scanId) {
    const buf = await this._request('GET', `/api/report/pdf/${scanId}`, null, false);
    return Buffer.from(buf);
  }
}

module.exports = { ReconScanClient };

