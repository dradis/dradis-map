/**
 * server.js — application entry point
 *
 * Responsibilities here are intentionally narrow:
 *   1. Load and validate environment config
 *   2. Construct the DradisClient service
 *   3. Mount middleware and routes onto Express
 *   4. Start the HTTP server
 *   5. Handle graceful shutdown on SIGTERM / SIGINT
 *
 * Business logic lives in src/services/. Route logic lives in src/routes/.
 */

import express           from 'express';
import helmet            from 'helmet';
import morgan            from 'morgan';
import rateLimit         from 'express-rate-limit';
import fs, { readFileSync } from 'fs';
import path              from 'path';
import { fileURLToPath } from 'url';
import dotenv            from 'dotenv';
import crypto            from 'crypto';

import { DradisClient }    from './src/services/dradisClient.js';
import { createApiRouter } from './src/routes/api.js';

dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ── Config validation ─────────────────────────────────────────────────────────
// Fail fast at startup with a clear message rather than crashing on first request.

const {
  PORT              = '3000',
  DRADIS_HOST       = '',
  DRADIS_TOKEN      = '',
  CA_CERT_PATH      = '',
  TRUST_SELF_SIGNED = 'false',
  NODE_ENV          = 'development',
} = process.env;

const configErrors = [];
if (!DRADIS_HOST)  configErrors.push('DRADIS_HOST is required');
if (!DRADIS_TOKEN) configErrors.push('DRADIS_TOKEN is required');

if (configErrors.length) {
  console.error('\n❌  Missing required environment variables:');
  configErrors.forEach(e => console.error(`    • ${e}`));
  console.error('\n    Copy .env.example → .env and fill in your values.\n');
  process.exit(1);
}

const port = parseInt(PORT, 10);
if (isNaN(port) || port < 1 || port > 65535) {
  console.error(`\n❌  Invalid PORT value: "${PORT}". Must be a number 1–65535.\n`);
  process.exit(1);
}

let caCert = null;
if (CA_CERT_PATH) {
  try {
    caCert = fs.readFileSync(CA_CERT_PATH);
  } catch (err) {
    console.error(`\n❌  Could not read CA_CERT_PATH "${CA_CERT_PATH}": ${err.message}\n`);
    process.exit(1);
  }
}

const trustSelfSigned = TRUST_SELF_SIGNED === 'true';
if (trustSelfSigned) {
  console.warn(
    '⚠️   TRUST_SELF_SIGNED=true — accepting self-signed TLS certificates.\n' +
    '    Safe on a trusted local network; do not use in production.\n'
  );
}

// ── Services ──────────────────────────────────────────────────────────────────

const dradisClient = new DradisClient({
  host: DRADIS_HOST,
  token: DRADIS_TOKEN,
  caCert,
  trustSelfSigned,
});

// ── Express app ───────────────────────────────────────────────────────────────

const app = express();

// ── Logging ───────────────────────────────────────────────────────────────────
// Morgan goes first so every request is logged regardless of what happens later.
// "dev" format in development (coloured, concise).
// "combined" Apache format in production (suitable for log aggregators).
app.use(morgan(NODE_ENV === 'production' ? 'combined' : 'dev'));

// Attach a minimal per-request logger to res so route handlers can emit
// structured context without importing a logging lib everywhere.
// Replace with pino-http or winston if the app grows.
app.use((_req, res, next) => {
  res.log = {
    error: (meta, msg) => console.error(
      `[${new Date().toISOString()}] ERROR`,
      msg ?? '',
      meta?.err?.message ?? ''
    ),
  };
  next();
});

// ── Nonce-based CSP ───────────────────────────────────────────────────────────
// A fresh cryptographic nonce is generated for every request.
// It is injected into both the Content-Security-Policy header and the served
// index.html, replacing 'unsafe-inline' on script-src entirely.
// This means injected <script> tags cannot execute even if XSS occurs.

const indexHtmlPath = path.join(__dirname, 'public', 'index.html');
// Read once at startup — if the file changes, restart the server.
// In development, node --watch handles restarts automatically.
let indexHtmlTemplate = readFileSync(indexHtmlPath, 'utf8');

// Strip the meta CSP tag from the HTML — the authoritative CSP comes from
// the HTTP header set by helmet below. Duplicate declarations cause confusion.
indexHtmlTemplate = indexHtmlTemplate.replace(
  /<meta http-equiv="Content-Security-Policy"[^>]*>/i, ''
);

app.use((req, res, next) => {
  // 128 bits of entropy, base64url encoded — safe for use in HTML attributes
  res.locals.cspNonce = crypto.randomBytes(16).toString('base64url');
  next();
});

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      // Nonce replaces 'unsafe-inline' — only scripts bearing this nonce execute
      scriptSrc:  ["'self'", (req, res) => `'nonce-${res.locals.cspNonce}'`,
                   'https://cdnjs.cloudflare.com'],
      styleSrc:   ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc:    ['https://fonts.gstatic.com'],
      connectSrc: ["'self'", 'https://cdn.jsdelivr.net'],
      imgSrc:     ["'self'", 'data:'],
    },
  },
}));

// Serve index.html with the nonce injected into the <script> tag.
// This route must come before express.static so it intercepts index.html requests.
app.get('/', (req, res) => {
  const html = indexHtmlTemplate.replace(
    '<script data-replace-with-nonce>',
    `<script nonce="${res.locals.cspNonce}">`
  );
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(html);
});

// ── Rate limiting & Routes ────────────────────────────────────────────────────
// 60 req/min per IP is generous for a map dashboard,
// but prevents runaway clients from hammering the Dradis upstream.
// trustProxy: false ensures we never trust X-Forwarded-For headers,
// since this server is never intended to sit behind a proxy.
const apiLimiter = rateLimit({
  windowMs:        60 * 1_000,
  max:             60,
  standardHeaders: true,
  legacyHeaders:   false,
  trustProxy:      false,
  message:         { error: 'Too many requests — please wait a moment and try again.' },
});

app.use('/api', apiLimiter, createApiRouter(dradisClient, DRADIS_HOST));

// Static files — mounted after /api so API paths are never shadowed by disk files.
app.use(express.static(path.join(__dirname, 'public')));

// 404 — unmatched routes
app.use((_req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Global error handler — catches anything thrown without a try/catch in routes.
// The four-argument signature is required by Express to identify error middleware.
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  console.error('[unhandled error]', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ── Start server ──────────────────────────────────────────────────────────────

const server = app.listen(port, '127.0.0.1', () => {
  console.log('\n✅  Dradis Map server running');
  console.log(`    Open:      http://localhost:${port}`);
  console.log(`    Proxying:  ${DRADIS_HOST}`);
  console.log(`    Env:       ${NODE_ENV}\n`);
});

// ── Graceful shutdown ─────────────────────────────────────────────────────────
// Allows in-flight requests to complete before the process exits.
// Necessary for clean restarts under PM2, Docker, or systemd.

function shutdown(signal) {
  console.log(`\n${signal} received — shutting down gracefully…`);

  server.close((err) => {
    if (err) {
      console.error('Error during shutdown:', err.message);
      process.exit(1);
    }
    console.log('Server closed. Goodbye.\n');
    process.exit(0);
  });

  // Force-exit if graceful shutdown stalls beyond 10 seconds.
  // .unref() prevents this timer from keeping the event loop alive on its own.
  setTimeout(() => {
    console.error('Shutdown timed out — forcing exit.');
    process.exit(1);
  }, 10_000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));
