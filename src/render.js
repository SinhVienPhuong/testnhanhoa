/**
 * Server-side render of the home page from content/site.json.
 * Done once at startup (and on file change), so the HTML is complete for
 * search engines and for visitors with JavaScript disabled.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { escapeHtml as e } from './http.js';

const COLORS = new Set(['blue', 'green', 'amber', 'slate']);
const color = (c) => (COLORS.has(c) ? c : 'slate');

function safeUrl(u) {
  const s = String(u || '').trim();
  if (/^mailto:[^\s]+@[^\s]+$/i.test(s)) return s;
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s)) return 'mailto:' + s;
  try {
    const url = new URL(s);
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.href : '';
  } catch {
    return '';
  }
}

export function renderParts(site) {
  const links = (site.links || [])
    .map((l) => ({ label: l.label, href: safeUrl(l.url) }))
    .filter((l) => l.href)
    .map((l) => `<li><a href="${e(l.href)}" rel="me noopener" ${l.href.startsWith('http') ? 'target="_blank"' : ''}>${e(l.label)}</a></li>`)
    .join('');

  const timeline = (site.timeline || [])
    .map(
      (t) => `
        <li class="tl-item">
          <p class="tl-period">${e(t.period)}</p>
          <h3 class="tl-title">${e(t.title)}</h3>
          <p class="tl-place">${e(t.place)}</p>
          ${t.text ? `<p class="tl-text">${e(t.text)}</p>` : ''}
        </li>`,
    )
    .join('');

  const skills = (site.skills || [])
    .map(
      (g) => `
        <div class="skill-group" data-color="${color(g.color)}">
          <h3 class="skill-title"><span class="cable" aria-hidden="true"></span>${e(g.group)}</h3>
          <ul>${(g.items || []).map((i) => `<li>${e(i)}</li>`).join('')}</ul>
        </div>`,
    )
    .join('');

  const categories = [...new Set((site.labs || []).map((l) => l.category))];
  const labFilters = ['Tất cả', ...categories]
    .map((c, i) => `<button type="button" class="chip" data-filter="${i === 0 ? '*' : e(c)}" aria-pressed="${i === 0}">${e(c)}</button>`)
    .join('');

  const labs = (site.labs || [])
    .map(
      (l) => `
        <li class="lab" data-color="${color(l.color)}" data-category="${e(l.category)}">
          <div class="lab-head">
            <h3 class="lab-title">${e(l.title)}</h3>
            <span class="lab-cat">${e(l.category)}</span>
          </div>
          <p class="lab-text">${e(l.text)}</p>
          <ul class="tags">${(l.tags || []).map((t) => `<li>${e(t)}</li>`).join('')}</ul>
        </li>`,
    )
    .join('');

  return { links, timeline, skills, labs, labFilters, labCount: String((site.labs || []).length) };
}

export function renderIndex(templateFile, contentFile, { version, siteUrl }) {
  const site = JSON.parse(readFileSync(contentFile, 'utf8'));
  const tpl = readFileSync(templateFile, 'utf8');
  const parts = renderParts(site);
  const vars = {
    name: site.name,
    shortName: site.shortName || site.name.split(/\s+/).map((w) => w[0]).join('').toUpperCase(),
    role: site.role,
    location: site.location,
    summary: site.summary,
    availability: site.availability,
    metaTitle: site.meta?.title || site.name,
    metaDescription: site.meta?.description || site.summary,
    version,
    year: String(new Date().getFullYear()),
    canonical: siteUrl ? `<link rel="canonical" href="${e(siteUrl)}/">` : '',
    ogUrl: siteUrl ? `<meta property="og:url" content="${e(siteUrl)}/">` : '',
  };

  // {{{raw}}} for pre-rendered HTML parts, {{escaped}} for plain values
  const html = tpl
    .replace(/\{\{\{(\w+)\}\}\}/g, (_, k) => (k in parts ? parts[k] : k in vars && k.match(/^(canonical|ogUrl)$/) ? vars[k] : ''))
    .replace(/\{\{(\w+)\}\}/g, (_, k) => e(vars[k] ?? parts[k] ?? ''));

  const raw = Buffer.from(html, 'utf8');
  return {
    raw,
    etag: '"' + crypto.createHash('sha1').update(raw).digest('base64url').slice(0, 20) + '"',
    site,
  };
}

export const TEMPLATE_PATH = (root) => path.join(root, 'src', 'views', 'index.html');
