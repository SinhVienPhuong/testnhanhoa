/**
 * Contact form: validation, spam filtering, storage and optional Telegram alert.
 */
import { promises as fs } from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { HttpError } from '../http.js';
import { log } from '../logger.js';

const EMAIL_RE = /^[^\s@<>()[\]\\,;:"]{1,64}@[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,24}$/i;
const MIN_FILL_MS = 3000; // humans take longer than 3 s to fill a form

export const TOPICS = {
  job: 'Cơ hội việc làm',
  support: 'Hỗ trợ IT / hạ tầng',
  lab: 'Trao đổi kỹ thuật',
  other: 'Khác',
};

/** Pure validation, unit tested. Returns { value } or { errors }. */
export function validateContact(body, now = Date.now()) {
  const errors = {};
  const clean = (v, max) => String(v ?? '').replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '').trim().slice(0, max + 1);

  const name = clean(body.name, 80);
  const email = clean(body.email, 254).toLowerCase();
  const message = clean(body.message, 2000);
  const topic = TOPICS[body.topic] ? body.topic : 'other';

  if (name.length < 2) errors.name = 'Hãy nhập tên (ít nhất 2 ký tự).';
  else if (name.length > 80) errors.name = 'Tên tối đa 80 ký tự.';
  if (!EMAIL_RE.test(email)) errors.email = 'Email chưa đúng định dạng, ví dụ ten@congty.vn.';
  if (message.length < 10) errors.message = 'Nội dung cần ít nhất 10 ký tự.';
  else if (message.length > 2000) errors.message = 'Nội dung tối đa 2000 ký tự.';

  // Spam signals: honeypot field filled, or the form was submitted inhumanly fast
  const spam = Boolean(body.website) || (Number(body.startedAt) > 0 && now - Number(body.startedAt) < MIN_FILL_MS);
  const linkCount = (message.match(/https?:\/\//gi) || []).length;
  const linkSpam = linkCount > 3;
  if (linkSpam) errors.message = 'Nội dung chứa quá nhiều đường link.';

  if (Object.keys(errors).length) return { errors };
  return { value: { name, email, message, topic }, spam };
}

export class ContactStore {
  constructor(dataDir) {
    this.file = path.join(dataDir, 'messages.jsonl');
    this.dir = dataDir;
    this.queue = Promise.resolve(); // serialize appends
  }

  async add(entry) {
    this.queue = this.queue.then(async () => {
      await fs.mkdir(this.dir, { recursive: true });
      await fs.appendFile(this.file, JSON.stringify(entry) + '\n', { mode: 0o600 });
    });
    return this.queue;
  }

  async list(limit = 100) {
    try {
      const text = await fs.readFile(this.file, 'utf8');
      return text
        .split('\n')
        .filter(Boolean)
        .map((l) => {
          try {
            return JSON.parse(l);
          } catch {
            return null;
          }
        })
        .filter(Boolean)
        .reverse()
        .slice(0, limit);
    } catch (e) {
      if (e.code === 'ENOENT') return [];
      throw e;
    }
  }
}

async function notifyTelegram({ botToken, chatId }, entry) {
  if (!botToken || !chatId) return;
  const text = [`📩 Liên hệ mới: ${TOPICS[entry.topic]}`, `Tên: ${entry.name}`, `Email: ${entry.email}`, '', entry.message].join('\n');
  try {
    const r = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text, disable_web_page_preview: true }),
      signal: AbortSignal.timeout(5000),
    });
    if (!r.ok) log.warn('telegram notify failed', { status: r.status });
  } catch (e) {
    log.warn('telegram notify error', { err: e.message });
  }
}

export async function handleContact(body, { store, ip, userAgent, telegram }) {
  const result = validateContact(body);
  if (result.errors) throw new HttpError(422, 'Thông tin chưa hợp lệ.', { fields: result.errors });

  const entry = {
    id: crypto.randomUUID(),
    at: new Date().toISOString(),
    ...result.value,
    ip,
    ua: String(userAgent || '').slice(0, 200),
    spam: result.spam,
  };
  await store.add(entry);
  if (!result.spam) notifyTelegram(telegram, entry); // fire and forget
  else log.info('contact spam filtered', { ip });

  // Same answer for spam and real messages so bots learn nothing
  return { ok: true, id: entry.id };
}
