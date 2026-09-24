---
id: kubestellar-console
title: KubeStellar Console
---

[KubeStellar Console](https://console.kubestellar.io?utm_source=github&utm_medium=pr&utm_campaign=cncf_outreach&utm_term=oauth2-proxy) is an open-source Kubernetes dashboard that includes structured install and troubleshooting missions for CNCF projects. It ships with an oauth2-proxy install mission and solution missions for common configuration issues.

## oauth2-proxy install mission

The [oauth2-proxy install mission](https://console.kubestellar.io/missions/install-oauth2-proxy?utm_source=github&utm_medium=pr&utm_campaign=cncf_outreach&utm_term=oauth2-proxy) runs `helm install` against your cluster via kubeconfig. Each step validates the result by querying pod status, service endpoints, and events. On failure it reads logs and suggests fixes.

No cluster connection is required to browse the mission read-only.

## oauth2-proxy solution missions

These address specific configuration and troubleshooting scenarios sourced from oauth2-proxy GitHub issues:

| Mission | Topic |
|---------|-------|
| [Microsoft Identity Platform with Azure provider (#1231)](https://console.kubestellar.io/missions/oauth2-proxy-1231-support-for-microsoft-identity-platform-with-azure-provider?utm_source=github&utm_medium=pr&utm_campaign=cncf_outreach&utm_term=oauth2-proxy) | Azure Entra ID provider setup |
| [OIDC with PKCE — client secret not required (#1714)](https://console.kubestellar.io/missions/oauth2-proxy-1714-client-secret-is-not-required-for-oidc-with-pkce-enabled?utm_source=github&utm_medium=pr&utm_campaign=cncf_outreach&utm_term=oauth2-proxy) | PKCE without client secret |
| [PKCE Code Challenge in Proxy (#1361)](https://console.kubestellar.io/missions/oauth2-proxy-1361-include-pkce-code-challenge-in-proxy-2nd-try?utm_source=github&utm_medium=pr&utm_campaign=cncf_outreach&utm_term=oauth2-proxy) | PKCE code challenge flow |
| [Azure provider v7.2.1 ADAL token validation failure (#1505)](https://console.kubestellar.io/missions/oauth2-proxy-1505-azure-provider-with-v7-2-1-and-adal-stop-working-access-token-?utm_source=github&utm_medium=pr&utm_campaign=cncf_outreach&utm_term=oauth2-proxy) | Azure ADAL token debugging |
| [Configurable user ID claim (#431)](https://console.kubestellar.io/missions/oauth2-proxy-431-make-it-configurable-which-claim-is-user-id-currently-email?utm_source=github&utm_medium=pr&utm_campaign=cncf_outreach&utm_term=oauth2-proxy) | Custom claim for user identity |
| [Group/role restriction on /oauth2/auth (#831)](https://console.kubestellar.io/missions/oauth2-proxy-831-group-role-access-restriction-support-in-oauth2-auth-endpoint?utm_source=github&utm_medium=pr&utm_campaign=cncf_outreach&utm_term=oauth2-proxy) | Group-based access control |
| [id_token_hint in OIDC logout URL (#884)](https://console.kubestellar.io/missions/oauth2-proxy-884-add-an-id-token-hint-parameter-to-the-logout-provider-url-for-o?utm_source=github&utm_medium=pr&utm_campaign=cncf_outreach&utm_term=oauth2-proxy) | OIDC logout with token hint |
| [Traefik integration (#46)](https://console.kubestellar.io/missions/oauth2-proxy-46-support-for-traefik?utm_source=github&utm_medium=pr&utm_campaign=cncf_outreach&utm_term=oauth2-proxy) | ForwardAuth with Traefik |
| [Token introspection per RFC 7662 (#612)](https://console.kubestellar.io/missions/oauth2-proxy-612-new-feature-support-oauth2-token-introspection-as-per-rfc7662-s?utm_source=github&utm_medium=pr&utm_campaign=cncf_outreach&utm_term=oauth2-proxy) | RFC 7662 token introspection |
| [skip-provider-button returns blank page (#334)](https://console.kubestellar.io/missions/oauth2-proxy-334-option-skip-provider-button-provides-white-page-with-found-link?utm_source=github&utm_medium=pr&utm_campaign=cncf_outreach&utm_term=oauth2-proxy) | Debugging redirect loop |

## Using OAuth2 Proxy with KubeStellar Console

The console has built-in GitHub OAuth but can sit behind OAuth2 Proxy for other OIDC providers.

Deploy the console:

```bash
curl -sSL https://raw.githubusercontent.com/kubestellar/console/main/deploy.sh | bash
```

Point OAuth2 Proxy's upstream at the console service (port 8080):

```yaml
extraArgs:
  upstream: "http://kubestellar-console.kubestellar.svc.cluster.local:8080"
  reverse-proxy: true
  pass-authorization-header: true
```

Or use the built-in GitHub OAuth without OAuth2 Proxy:

```bash
export GITHUB_CLIENT_ID=<your-client-id>
export GITHUB_CLIENT_SECRET=<your-client-secret>
curl -sSL https://raw.githubusercontent.com/kubestellar/console/main/deploy.sh | bash
```

---

Mission definitions are in [kubestellar/console-kb](https://github.com/kubestellar/console-kb?utm_source=github&utm_medium=pr&utm_campaign=cncf_outreach&utm_term=oauth2-proxy) ([oauth2-proxy install source](https://github.com/kubestellar/console-kb/blob/master/solutions/cncf-install/install-oauth2-proxy.json?utm_source=github&utm_medium=pr&utm_campaign=cncf_outreach&utm_term=oauth2-proxy)). PRs welcome.
