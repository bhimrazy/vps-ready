import { execFileSync } from 'node:child_process';

// The latest release tag reachable from this commit, not Cargo.toml: main can
// carry a version bump before that release is tagged and published, and the
// site must not advertise a version that cannot be downloaded yet.
export const VERSION = execFileSync('git', ['describe', '--tags', '--abbrev=0', '--match', 'v*'], { encoding: 'utf8' })
  .trim()
  .replace(/^v/, '');

export const REPO = 'https://github.com/bhimrazy/vps-ready';
export const INSTALL_URL = `${REPO}/releases/latest/download/install.sh`;
export const TAGLINE = 'Make a fresh VPS ready and secure, safely.';

export const LINKS = {
  issues: `${REPO}/issues`,
  bug: `${REPO}/issues/new?template=bug_report.yml`,
  lockout: `${REPO}/issues/new?template=lockout_report.yml`,
  idea: `${REPO}/issues/new?template=idea.yml`,
  contributing: `${REPO}/blob/main/CONTRIBUTING.md`,
  security: `${REPO}/security/advisories/new`,
  releases: `${REPO}/releases`,
  crates: 'https://crates.io/crates/vps-ready',
};
export const EMAIL = 'contact@bhimraj.com.np';
export const MAILTO = `mailto:${EMAIL}?subject=vps-ready%3A%20&body=Hi%20Bhimraj%2C%0A%0A%0A%0A---%0Avps-ready%20version%20(vps-ready%20--version)%3A%20%0AServer%20OS%3A%20`;

// Ways to reach the project, shared by the footers and the feedback panel.
// `icon` is the body of a 24px stroke SVG.
export const CONTACTS = [
  { href: LINKS.bug, title: 'Report a bug', note: 'Open a GitHub issue', icon: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="1.5"/>' },
  { href: LINKS.lockout, title: 'Got locked out?', note: 'File a lockout report', icon: '<circle cx="8" cy="15" r="4.5"/><path d="M11.5 12L20 3.5M16.5 7l3 3"/>' },
  { href: LINKS.idea, title: 'Idea or question', note: 'Start a GitHub issue', icon: '<path d="M9 18h6M10 21h4M12 3a6 6 0 00-3.5 10.9V16h7v-2.1A6 6 0 0012 3z"/>' },
  { href: LINKS.contributing, title: 'Contribute', note: 'Send a pull request', icon: '<circle cx="6" cy="6" r="2.5"/><circle cx="6" cy="18" r="2.5"/><circle cx="18" cy="18" r="2.5"/><path d="M6 8.5v7M18 15.5V11a3 3 0 00-3-3h-4"/>' },
  { href: LINKS.security, title: 'Security issue', note: 'Report privately', icon: '<path d="M12 3l8 3v6c0 5-3.4 8-8 9-4.6-1-8-4-8-9V6z"/>' },
];
export const MAIL_ICON = '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3.5 6.5L12 13l8.5-6.5"/>';

export const AUTHOR = {
  name: 'Bhimraj Yadav',
  site: 'https://bhimraj.com.np',
  github: 'https://github.com/bhimrazy',
  linkedin: 'https://www.linkedin.com/in/bhimrazy',
  x: 'https://x.com/bhimrazy',
};
