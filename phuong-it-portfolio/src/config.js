/**
 * Runtime configuration, read once from environment variables.
 * Every value has a safe default so `npm start` works with no .env at all.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function bool(v, fallback) {
  if (v === undefined || v === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(v).toLowerCase());
}

function int(v, fallback) {
  const n = Number.parseInt(v, 10);
  return Number.isFinite(n) ? n : fallback;
}

// Minimal .env loader (no dotenv dependency). Real env vars always win.
function loadDotEnv(file) {
  try {
    const text = readFileSync(file, 'utf8');
    for (const line of text.split(/\r?\n/)) {
      const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/i);
      if (!m || line.trim().startsWith('#')) continue;
      const value = m[2].replace(/^(['"])(.*)\1$/, '$2');
      if (process.env[m[1]] === undefined) process.env[m[1]] = value;
    }
  } catch {
    /* no .env file: fine */
  }
}

export function loadConfig(overrides = {}) {
  if (!overrides.skipDotEnv) loadDotEnv(path.join(ROOT, '.env'));
  const env = process.env;
  const pkg = JSON.parse(readFileSync(path.join(ROOT, 'package.json'), 'utf8'));

  return {
    root: ROOT,
    version: pkg.version,
    // `npm run dev` passes --dev (works on Windows cmd too, unlike NODE_ENV=... prefixes)
    env: env.NODE_ENV || (process.argv.includes('--dev') ? 'development' : 'production'),
    host: env.HOST || '0.0.0.0',
    port: int(env.PORT, 3000),
    // Behind Vibe Hosting's reverse proxy this must be on to see real visitor IPs.
    trustProxy: bool(env.TRUST_PROXY, true),
    publicDir: path.join(ROOT, 'public'),
    contentFile: path.join(ROOT, 'content', 'site.json'),
    dataDir: env.DATA_DIR ? path.resolve(env.DATA_DIR) : path.join(ROOT, 'data'),
    adminToken: env.ADMIN_TOKEN || '',
    telegram: {
      botToken: env.TELEGRAM_BOT_TOKEN || '',
      chatId: env.TELEGRAM_CHAT_ID || '',
    },
    siteUrl: (env.SITE_URL || '').replace(/\/$/, ''),
    logRequests: bool(env.LOG_REQUESTS, true),
    ...overrides,
  };
}
