// Renders the audit controls catalog (src/audit/controls/*.toml) as the
// Security controls reference page, and copies the repo logos and the
// terminal screenshot. The repo's docs/ are for contributors and are not part
// of the site. Output paths are gitignored; run via `npm run build` or
// `npm run dev`.

import { copyFileSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const site = join(dirname(fileURLToPath(import.meta.url)), '..');
const repo = join(site, '..');
const REPO_URL = 'https://github.com/bhimrazy/vps-ready';
const DOCS_OUT = join(site, 'src/content/docs/docs');
const CONTROLS_SLUG = 'reference/security-controls';

// The controls catalog: one table per area file, in the order audit groups them.
const AREAS = [
  ['ssh.toml', 'SSH server'],
  ['firewall.toml', 'Firewall'],
  ['kernel.toml', 'Kernel'],
  ['network.toml', 'Network'],
  ['updates.toml', 'Updates'],
  ['mac.toml', 'Mandatory access control'],
];
const controlsDir = join(repo, 'crates/vps-ready/src/audit/controls');
const areaFiles = readdirSync(controlsDir).filter((f) => f.endsWith('.toml'));
const unlisted = areaFiles.filter((f) => !AREAS.some(([a]) => a === f));
if (unlisted.length) {
  console.error(`sync-docs: add these to AREAS in scripts/sync-docs.mjs: ${unlisted.join(', ')}`);
  process.exit(1);
}

// Only the flat `key = "string"` lines are read; `check` is left to the binary.
function parseControls(text) {
  return text
    .split(/^\[\[control\]\]$/m)
    .slice(1)
    .map((block) => {
      const c = {};
      for (const [, key, value] of block.matchAll(/^(id|severity|title|why|fix) = "(.*)"$/gm)) c[key] = value;
      return c;
    });
}

const cell = (s) => s.replace(/\|/g, '\\|');
let total = 0;
const sections = AREAS.map(([file, name]) => {
  const src = readFileSync(join(controlsDir, file), 'utf8');
  // The file's header comment says where its checks read from.
  const header = src.slice(0, src.search(/^[^#]/m)).replace(/^#\s?/gm, '').replace(/\s+/g, ' ');
  const intro = header.match(/Checks? [^.]*\./)?.[0] ?? '';
  const controls = parseControls(src);
  total += controls.length;
  const rows = controls.map(
    (c) =>
      `| \`${c.id}\`<br/>${c.severity} | **${cell(c.title)}**<br/>${cell(c.why)}<br/>Fixed by ${c.fix ? `\`${c.fix}\`` : 'no module yet'} |`,
  );
  return [`## ${name}`, '', intro, '', '| Control | What it checks and why |', '|---|---|', ...rows].join('\n');
});
const controlsPage = [
  '---',
  'title: "Security controls: every audit check"',
  'sidebar:\n  label: Security controls\n  order: 2',
  `description: ${JSON.stringify(`Every control vps-ready audit checks: its stable ID, severity, why it matters and the module that fixes it.`)}`,
  `editUrl: ${JSON.stringify(`${REPO_URL}/tree/main/crates/vps-ready/src/audit/controls`)}`,
  '---',
  '',
  '<!-- Generated from crates/vps-ready/src/audit/controls/*.toml by scripts/sync-docs.mjs. -->',
  '',
  `A control is one thing \`vps-ready audit\` checks. There are ${total}, each with a stable ID you can track in CI, a severity, and the reason it matters. When a module can fix a failed control, \`audit\` prints the command under it, for example \`fix: sudo vps-ready apply --module ssh.server\`.`,
  '',
  'Each control ends as one of four outcomes: **pass**, **fail** (with the value found), **unknown** (the fact could not be read, usually without root) or **skip** (not checked here, for example kernel settings inside a container). Unknown never counts as a pass: `audit` exits 0 only when no control fails or is unknown.',
  '',
  ...sections.flatMap((s) => [s, '']),
  `The catalog lives in [\`crates/vps-ready/src/audit/controls\`](${REPO_URL}/tree/main/crates/vps-ready/src/audit/controls), one TOML file per area, so you can review it without reading Rust.`,
  '',
].join('\n');
mkdirSync(join(DOCS_OUT, 'reference'), { recursive: true });
writeFileSync(join(DOCS_OUT, `${CONTROLS_SLUG}.md`), controlsPage);

mkdirSync(join(site, 'public'), { recursive: true });
mkdirSync(join(site, 'src/assets/brand'), { recursive: true });
copyFileSync(join(repo, 'assets/logo-light.svg'), join(site, 'public/favicon.svg'));
copyFileSync(join(repo, 'assets/logo-light.svg'), join(site, 'src/assets/brand/logo-light.svg'));
copyFileSync(join(repo, 'assets/logo.svg'), join(site, 'src/assets/brand/logo-dark.svg'));

// The real terminal screenshot from the repo (how-it-works*.png still shows confirm as planned).
mkdirSync(join(site, 'public/docs'), { recursive: true });
for (const f of ['demo.png']) {
  copyFileSync(join(repo, 'assets', f), join(site, 'public/docs', f));
}

console.log(`sync-docs: ${total} controls`);
