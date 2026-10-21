#!/usr/bin/env node
/**
 * Entry point. Vibe Hosting (and most PaaS) run `npm start`, which runs this file
 * and injects the port to listen on through the PORT environment variable.
 */
import { loadConfig } from './src/config.js';
import { createApp } from './src/app.js';
import { log } from './src/logger.js';

const config = loadConfig();
const server = createApp(config);

server.listen(config.port, config.host, () => {
  log.info('server started', {
    url: `http://${config.host === '0.0.0.0' ? 'localhost' : config.host}:${config.port}`,
    env: config.env,
    version: config.version,
    trustProxy: config.trustProxy,
    admin: Boolean(config.adminToken),
    telegram: Boolean(config.telegram.botToken && config.telegram.chatId),
  });
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') log.error(`port ${config.port} is already in use — set PORT to another value`);
  else log.error('server error', { err: err.message });
  process.exit(1);
});

// Graceful shutdown: finish in-flight requests when the platform redeploys/stops us
let stopping = false;
function shutdown(signal) {
  if (stopping) return;
  stopping = true;
  log.info('shutting down', { signal });
  server.close(() => process.exit(0));
  server.closeIdleConnections?.();
  setTimeout(() => process.exit(0), 10_000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('unhandledRejection', (err) => log.error('unhandledRejection', { err: String(err?.stack || err) }));
