// @ts-check
import {themes as prismThemes} from 'prism-react-renderer';

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'EUDI Wallet SDK',
  tagline: 'A headless, native two-fold EUDI wallet SDK — issuance, storage, and presentation for eIDAS 2.0',
  favicon: 'img/favicon.ico',

  future: {v4: true},

  url: 'https://lukasjhan.github.io',
  baseUrl: '/Axle/',
  organizationName: 'lukasjhan',
  projectName: 'Axle',
  onBrokenLinks: 'warn',
  onBrokenMarkdownLinks: 'warn',

  i18n: {
    defaultLocale: 'en',
    locales: ['en', 'ko'],
    localeConfigs: {
      en: {label: 'English'},
      ko: {label: '한국어'},
    },
  },

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          routeBasePath: '/', // docs at the site root
          sidebarPath: './sidebars.js',
        },
        blog: false,
        theme: {customCss: './src/css/custom.css'},
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      navbar: {
        title: 'EUDI Wallet SDK',
        items: [
          {type: 'docSidebar', sidebarId: 'docs', position: 'left', label: 'Docs'},
          {type: 'localeDropdown', position: 'right'},
        ],
      },
      footer: {
        style: 'dark',
        copyright: 'EUDI Wallet SDK — built from scratch for eIDAS 2.0 (ARF/HAIP).',
      },
      prism: {
        theme: prismThemes.github,
        darkTheme: prismThemes.dracula,
        additionalLanguages: ['kotlin', 'swift', 'java', 'json', 'bash'],
      },
    }),
};

export default config;
