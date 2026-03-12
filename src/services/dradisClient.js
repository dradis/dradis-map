/**
 * dradisClient.js
 *
 * Isolated service layer for all Dradis Pro API communication.
 * No Express imports — this module has no knowledge of HTTP request/response.
 *
 * Responsibilities:
 *   - Build authenticated requests with correct headers
 *   - Handle TLS trust configuration (CA cert or self-signed flag)
 *   - Enforce a response body size limit to prevent memory exhaustion
 *   - Surface clear, actionable error messages for common failure modes
 */

import https from 'https';
import http from 'http';

// Maximum response body we'll buffer from Dradis (10 MB).
// Prevents memory exhaustion if the upstream server misbehaves.
const MAX_RESPONSE_BYTES = 10 * 1024 * 1024;

// Request timeout in milliseconds.
const REQUEST_TIMEOUT_MS = 15_000;

export class DradisClient {
  /**
   * @param {object} config
   * @param {string}  config.host              - Base URL, e.g. "https://192.168.1.1"
   * @param {string}  config.token             - API token
   * @param {Buffer}  [config.caCert]          - PEM buffer for a custom CA certificate
   * @param {boolean} [config.trustSelfSigned] - Accept self-signed certs (dev only)
   */
  constructor({ host, token, caCert = null, trustSelfSigned = false }) {
    this.host            = host.replace(/\/$/, '');
    this.token           = token;
    this.caCert          = caCert;
    this.trustSelfSigned = trustSelfSigned;
  }

  // ── Public API methods ──────────────────────────────────────────────────────

  /** Fetch all projects. */
  getProjects() {
    return this._request('projects');
  }

  /**
   * Fetch document properties for a project.
   * @param {number} projectId
   */
  getDocumentProperties(projectId) {
    return this._request('document_properties', projectId);
  }

  /**
   * Fetch all issues for a project.
   * @param {number} projectId
   */
  getIssues(projectId) {
    return this._request('issues', projectId);
  }

  // ── Private helpers ─────────────────────────────────────────────────────────

  /**
   * Make an authenticated GET request to the Dradis Pro API.
   *
   * @param {string}      endpoint  - API path segment, e.g. "issues"
   * @param {number|null} projectId - Sent as Dradis-Project-Id header when provided
   * @returns {Promise<unknown>}    - Parsed JSON response body
   */
  _request(endpoint, projectId = null) {
    const url = new URL(`/pro/api/${endpoint}`, this.host);

    const headers = {
      Authorization:      `Token token="${this.token}"`,
      'Content-Type':     'application/json',
      Accept:             'application/json',
      'User-Agent':       'dradis-map/2.0',
    };

    if (projectId !== null) {
      headers['Dradis-Project-Id'] = String(projectId);
    }

    const tlsOptions = {};
    if (this.caCert)          tlsOptions.ca                 = this.caCert;
    if (this.trustSelfSigned) tlsOptions.rejectUnauthorized = false;

    const options = {
      hostname: url.hostname,
      port:     url.port || (url.protocol === 'https:' ? 443 : 80),
      path:     url.pathname + url.search,
      method:   'GET',
      headers,
      ...tlsOptions,
    };

    const transport = url.protocol === 'https:' ? https : http;

    return new Promise((resolve, reject) => {
      const req = transport.request(options, (res) => {
        let bytes = 0;
        const chunks = [];

        res.on('data', (chunk) => {
          bytes += chunk.length;
          if (bytes > MAX_RESPONSE_BYTES) {
            req.destroy();
            reject(new Error(
              `Dradis response exceeded ${MAX_RESPONSE_BYTES / 1024 / 1024} MB limit`
            ));
            return;
          }
          chunks.push(chunk);
        });

        res.on('end', () => {
          const body = Buffer.concat(chunks).toString('utf8');

          if (res.statusCode >= 400) {
            reject(new DradisApiError(
              `Dradis returned HTTP ${res.statusCode}`,
              res.statusCode,
              body
            ));
            return;
          }

          try {
            resolve(JSON.parse(body));
          } catch {
            reject(new Error(`Dradis returned non-JSON response for /${endpoint}`));
          }
        });
      });

      req.on('error', (err) => {
        reject(this._wrapTlsError(err));
      });

      req.setTimeout(REQUEST_TIMEOUT_MS, () => {
        req.destroy(new Error(
          `Dradis request timed out after ${REQUEST_TIMEOUT_MS / 1000}s`
        ));
      });

      req.end();
    });
  }

  /**
   * Translate low-level TLS error codes into actionable messages.
   * @param {Error} err
   * @returns {Error}
   */
  _wrapTlsError(err) {
    const TLS_CODES = new Set([
      'DEPTH_ZERO_SELF_SIGNED_CERT',
      'SELF_SIGNED_CERT_IN_CHAIN',
      'ERR_TLS_CERT_ALTNAME_INVALID',
      'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
    ]);

    if (TLS_CODES.has(err.code)) {
      return new Error(
        `TLS error (${err.code}): add TRUST_SELF_SIGNED=true to your .env, ` +
        `or point CA_CERT_PATH at your Dradis certificate file.`
      );
    }

    return err;
  }
}

/**
 * Structured error for non-2xx Dradis API responses.
 * Carries the upstream status code so the proxy route can forward it correctly.
 */
export class DradisApiError extends Error {
  /**
   * @param {string} message
   * @param {number} statusCode - Upstream HTTP status
   * @param {string} body       - Raw upstream response body
   */
  constructor(message, statusCode, body) {
    super(message);
    this.name       = 'DradisApiError';
    this.statusCode = statusCode;
    this.body       = body;
  }
}
