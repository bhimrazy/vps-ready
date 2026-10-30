// Generates Starlight pages from the repo's docs/*.md, which stay the single
// source of truth. Each page gets frontmatter from its H1, relative links are
// rewritten to site routes (other docs) or GitHub URLs (anything else), and
// mermaid fences become <pre class="mermaid"> for client-side rendering.
// The repo logos are copied in as the favicon and Starlight logo.
// Output paths are gitignored; run via `npm run build` or `npm run dev`.

import { copyFileSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, posix } from 'node:path';
import { fileURLToPath } from 'node:url';

const site = join(dirname(fileURLToPath(import.meta.url)), '..');
const repo = join(site, '..');
const BASE = '';
const REPO_URL = 'https://github.com/bhimrazy/vps-ready';

// docs/<file> -> route under /docs/, plus an optional sidebar label.
// Every docs/*.md must be listed so a new doc can't be silently left out.
const PAGES = {
  'architecture.md': { slug: 'guides/architecture' },
  'security-baseline.md': { slug: 'guides/security-controls', label: 'Security controls' },
  'testing.md': { slug: 'guides/testing', label: 'Testing' },
  'release.md': { slug: 'guides/release', label: 'Supply chain and release' },
  'scope.md': { slug: 'project/scope', label: 'Vision and scope' },
  'decisions.md': { slug: 'project/decisions', label: 'Decisions' },
  'm2-plan.md': { slug: 'project/design-notes/m2-plan', label: 'M2: engine and safe modules' },
  'm3-plan.md': { slug: 'project/design-notes/m3-plan', label: 'M3: dead-man switch' },
};
const OUT_DIRS = ['guides', 'project'].map((d) => join(site, 'src/content/docs/docs', d));

const docsDir = join(repo, 'docs');
const files = readdirSync(docsDir).filter((f) => f.endsWith('.md'));
const unmapped = files.filter((f) => !PAGES[f]);
if (unmapped.length) {
  console.error(`sync-docs: add these to PAGES in scripts/sync-docs.mjs: ${unmapped.join(', ')}`);
  process.exit(1);
}

for (const d of OUT_DIRS) rmSync(d, { recursive: true, force: true });

// Resolves a link target written relative to docs/ (or the repo root for README).
function rewrite(target, fromDir, isImage) {
  if (/^([a-z][a-z0-9+.-]*:|#|\/)/i.test(target)) return target;
  const [path, hash = ''] = target.split(/(?=#)/);
  const repoPath = posix.normalize(posix.join(fromDir, path));
  const name = repoPath.startsWith('docs/') ? repoPath.slice(5) : null;
  if (name && PAGES[name]) return `${BASE}/docs/${PAGES[name].slug}/${hash}`;
  if (isImage) return `https://raw.githubusercontent.com/bhimrazy/vps-ready/main/${repoPath}`;
  return `${REPO_URL}/blob/main/${repoPath}${hash}`;
}

function escapeHtml(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function plain(md) {
  return md
    .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/[`*_>]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function transform(src, file) {
  const lines = src.split('\n');
  const h1 = lines.findIndex((l) => l.startsWith('# '));
  if (h1 === -1) throw new Error(`${file}: no H1`);
  const title = lines[h1].slice(2).trim();
  let body = lines.slice(h1 + 1).join('\n');

  // Mermaid fences; everything else keeps its fence.
  body = body.replace(/^```mermaid\n([\s\S]*?)^```$/gm, (_, code) => `<pre class="mermaid">${escapeHtml(code)}</pre>`);

  // Shiki calls GitHub's `sshconfig` fence language `ssh-config`.
  body = body.replace(/^```sshconfig$/gm, '```ssh-config');

  // Rewrite links outside fenced code only.
  const parts = body.split(/(^```[\s\S]*?^```$)/m);
  body = parts
    .map((part, i) =>
      i % 2
        ? part
        : part.replace(/(!?)\[([^\]]*)\]\(([^)\s]+)\)/g, (_, bang, text, target) =>
            `${bang}[${text}](${rewrite(target, 'docs', bang === '!')})`,
          ),
    )
    .join('');

  const firstPara = body.split(/\n\s*\n/).map((p) => p.trim()).find((p) => p && /^[A-Za-z*`]/.test(p));
  const description = firstPara ? plain(firstPara).slice(0, 200).replace(/\s\S*$/, '') : '';
  const page = PAGES[file];
  const fm = [
    '---',
    `title: ${JSON.stringify(title)}`,
    description && `description: ${JSON.stringify(description)}`,
    page.label && `sidebar:\n  label: ${JSON.stringify(page.label)}`,
    `editUrl: ${JSON.stringify(`${REPO_URL}/edit/main/docs/${file}`)}`,
    '---',
    '',
    `<!-- Generated from docs/${file} by scripts/sync-docs.mjs. Edit the source, not this file. -->`,
  ];
  return fm.filter(Boolean).join('\n') + '\n' + body.replace(/^\n+/, '\n');
}

for (const file of files) {
  const out = join(site, 'src/content/docs/docs', `${PAGES[file].slug}.md`);
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, transform(readFileSync(join(docsDir, file), 'utf8'), file));
}

mkdirSync(join(site, 'public'), { recursive: true });
mkdirSync(join(site, 'src/assets/brand'), { recursive: true });
copyFileSync(join(repo, 'assets/logo-light.svg'), join(site, 'public/favicon.svg'));
copyFileSync(join(repo, 'assets/logo-light.svg'), join(site, 'src/assets/brand/logo-light.svg'));
copyFileSync(join(repo, 'assets/logo.svg'), join(site, 'src/assets/brand/logo-dark.svg'));

console.log(`sync-docs: ${files.length} pages from docs/`);
