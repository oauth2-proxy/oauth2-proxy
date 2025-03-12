const sidebars = {
  docs: [
    {
      type: 'doc',
      id: 'welcome',
    },
    {
      type: 'doc',
      id: 'installation',
    },
    {
      type: 'doc',
      id: 'behaviour',
    },
    {
      type: 'category',
      label: 'Configuration',
      link: {
        type: 'doc',
        id: 'configuration/overview',
      },
      collapsed: false,
      items: [
        'configuration/overview',
        'configuration/integration',
        {
          type: 'category',
          label: 'OAuth Provider Configuration',
          link: {
            type: 'doc',
            id: 'configuration/providers/index',
          },
          items: [
            "configuration/providers/adfs",
            "configuration/providers/azure",
            "configuration/providers/bitbucket",
            "configuration/providers/digitalocean",
            "configuration/providers/facebook",
            "configuration/providers/gitea",
            "configuration/providers/github",
            "configuration/providers/gitlab",
            "configuration/providers/google",
            "configuration/providers/keycloak",
            "configuration/providers/keycloak_oidc",
            "configuration/providers/linkedin",
            "configuration/providers/login_gov",
            "configuration/providers/ms_entra_id",
            "configuration/providers/nextcloud",
            "configuration/providers/openid_connect",
          ],
        },
        'configuration/session_storage',
        'configuration/tls',
        'configuration/alpha-config',
      ],
    },
    {
      type: 'category',
      label: 'Features',
      link: {
        type: 'doc',
        id: 'features/endpoints',
      },
      collapsed: false,
      items: ['features/endpoints'],
    },
    {
      type: 'category',
      label: 'Community',
      link: {
        type: 'doc',
        id: 'community/security',
      },
      collapsed: false,
      items: ['community/contribution', 'community/security'],
    },
  ],
};

export default sidebars;
