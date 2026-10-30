// @ts-check
import starlight from '@astrojs/starlight';
import tailwindcss from '@tailwindcss/vite';
import { defineConfig } from 'astro/config';
import starlightLinksValidator from 'starlight-links-validator';

export default defineConfig({
  site: 'https://vps-ready.bhimraj.com.np',
  trailingSlash: 'always',
  integrations: [
    starlight({
      title: 'vps-ready',
      description: 'Make a fresh VPS ready and secure, safely.',
      logo: {
        light: './src/assets/brand/logo-light.svg',
        dark: './src/assets/brand/logo-dark.svg',
        alt: '',
      },
      favicon: '/favicon.svg',
      // Replaced by src/pages/404.astro, which also covers the landing page.
      disable404Route: true,
      social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/bhimrazy/vps-ready' }],
      editLink: { baseUrl: 'https://github.com/bhimrazy/vps-ready/edit/main/site/' },
      customCss: ['./src/styles/docs.css'],
      components: {
        Footer: './src/components/docs/Footer.astro',
        Head: './src/components/docs/Head.astro',
        SiteTitle: './src/components/docs/SiteTitle.astro',
        ThemeProvider: './src/components/docs/ThemeProvider.astro',
      },
      expressiveCode: {
        themes: ['github-dark', 'github-light'],
        defaultProps: { wrap: true },
        styleOverrides: {
          borderRadius: '10px',
          frames: { frameBoxShadowCssValue: 'none' },
          codeFontFamily: "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
          codeFontSize: '0.8125rem',
          uiFontFamily: "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
        },
      },
      sidebar: [
        {
          label: 'Getting started',
          items: [
            { label: 'Introduction', slug: 'docs' },
            { slug: 'docs/install' },
            { slug: 'docs/quick-start' },
          ],
        },
        {
          label: 'Guides',
          items: [
            { slug: 'docs/guides/security-controls' },
            { slug: 'docs/guides/architecture' },
            { slug: 'docs/guides/testing' },
            { slug: 'docs/guides/release' },
          ],
        },
        {
          label: 'Project',
          items: [
            { slug: 'docs/project/scope' },
            { slug: 'docs/project/decisions' },
            {
              label: 'Design notes',
              items: [
                { slug: 'docs/project/design-notes/m2-plan' },
                { slug: 'docs/project/design-notes/m3-plan' },
              ],
            },
          ],
        },
      ],
      plugins: [starlightLinksValidator({ errorOnLocalLinks: true })],
    }),
  ],
  vite: {
    plugins: [tailwindcss()],
    // Mermaid's diagram chunks are large but load lazily, only on pages with a diagram.
    build: { chunkSizeWarningLimit: 1600 },
  },
});
