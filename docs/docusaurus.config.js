module.exports = {
  title: 'OAuth2 Proxy',
  tagline: 'A lightweight authentication proxy written in Go',
  url: 'https://oauth2-proxy.github.io',
  baseUrl: '/oauth2-proxy/',
  onBrokenLinks: 'throw',
  favicon: 'img/logos/OAuth2_Proxy_icon.svg',
  organizationName: 'oauth2-proxy', // Usually your GitHub org/user name.
  projectName: 'oauth2-proxy', // Usually your repo name.
  themeConfig: {
    navbar: {
      title: 'OAuth2 Proxy',
      logo: {
        alt: 'OAuth2 Proxy',
        src: 'img/logos/OAuth2_Proxy_icon.svg',
      },
      items: [
        {
          to: 'docs/',
          activeBasePath: 'docs',
          label: 'Docs',
          position: 'left',
        },
        {
          type: 'docsVersionDropdown',
          position: 'right',
          dropdownActiveClassDisabled: true,
        },
        {
          href: 'https://github.com/oauth2-proxy/oauth2-proxy',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      copyright: `Copyright © ${new Date().getFullYear()} OAuth2 Proxy.`,
    },
  },
  presets: [
    [
      '@docusaurus/preset-classic',
      {
        docs: {
          sidebarPath: require.resolve('./sidebars.js'),
          // Please change this to your repo.
          editUrl:
            'https://github.com/oauth2-proxy/oauth2-proxy/edit/master/docs/',
        },
        theme: {
          customCss: require.resolve('./src/css/custom.css'),
        },
      },
    ],
  ],
  themes: [
    [
      require.resolve("@easyops-cn/docusaurus-search-local"),
      /** @type {import("@easyops-cn/docusaurus-search-local").PluginOptions} */
      ({
        hashed: true,
      }),
    ],
  ],
};
