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
  security: `${REPO}/security/advisories/new`,
  releases: `${REPO}/releases`,
  crates: 'https://crates.io/crates/vps-ready',
};
export const EMAIL = 'contact@bhimraj.com.np';
export const MAILTO = `mailto:${EMAIL}?subject=vps-ready%3A%20&body=Hi%20Bhimraj%2C%0A%0A%0A%0A---%0Avps-ready%20version%20(vps-ready%20--version)%3A%20%0AServer%20OS%3A%20`;

export const AUTHOR = {
  name: 'Bhimraj Yadav',
  site: 'https://bhimraj.com.np',
  github: 'https://github.com/bhimrazy',
  linkedin: 'https://www.linkedin.com/in/bhimrazy',
  x: 'https://x.com/bhimrazy',
};
