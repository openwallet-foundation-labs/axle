// @ts-check

/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
const sidebars = {
  docs: [
    'intro',
    'concepts',
    'architecture',
    'getting-started',
    {
      type: 'category',
      label: 'Guides',
      collapsed: false,
      items: [
        'guides/issuance',
        'guides/presentation',
        'guides/dc-api',
        'guides/dc-api-ios',
        'guides/android-adapters',
        'guides/ios-adapters',
        'guides/proximity',
        'guides/trust-and-audit',
      ],
    },
    {
      type: 'category',
      label: 'Reference',
      items: ['reference/facade', 'reference/ports', 'reference/specs'],
    },
    'android-demo',
    'ios-demo',
  ],
};

export default sidebars;
