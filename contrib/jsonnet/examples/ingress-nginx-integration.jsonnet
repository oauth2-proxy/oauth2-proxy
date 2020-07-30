local k = import 'github.com/ksonnet/ksonnet-lib/ksonnet.beta.4/k.libsonnet';
local op = import 'github.com/oauth2-proxy/oauth2-proxy/contrib/jsonnet/oauth2-proxy.libsonnet';
local deployment = k.apps.v1.deployment;
local container = deployment.mixin.spec.template.spec.containersType;
local envVar = container.envType;
local resourceRequirements = container.mixin.resourcesType;
local secret = k.core.v1.secret;
local ingress = k.networking.v1beta1.ingress;
local ingressRule = ingress.mixin.spec.rulesType;
local httpIngressPath = ingressRule.mixin.http.pathsType;

local oauth2Proxy = op {
  _config+:: {
    namespace: 'oauth2-proxy',

    oauth2Proxy+:: {
      name: 'oauth2-proxy',
      namespace: $._config.namespace,
      version: 'v6.0.0',

      configToml: |||
        client_id         = "123456.apps.googleusercontent.com"
        cookie_domains    = [".yourcompany.com"]
        email_domains     = [".yourcompany.com"]
        reverse_proxy     = true
        upstreams         = ["file:///dev/null"]
        whitelist_domains = [".yourcompany.com"]
      |||,

      env: [
        envVar.fromSecretRef(
          'OAUTH2_PROXY_CLIENT_SECRET',
          secretRefName=$._config.oauth2Proxy.name,
          secretRefKey='clientSecret'
        ),
        envVar.fromSecretRef(
          'OAUTH2_PROXY_COOKIE_SECRET',
          secretRefName=$._config.oauth2Proxy.name,
          secretRefKey='cookieSecret'
        ),
      ],
    },
  },

  oauth2Proxy+: {
    secret:
      secret.new($._config.oauth2Proxy.name, {
        clientSecret: std.base64('xxxxxxxxxx'),
        cookieSecret: std.base64('xxxxxxxxxx'),
      }) +
      secret.mixin.metadata.withNamespace($._config.oauth2Proxy.namespace) +
      secret.mixin.metadata.withLabels($._config.oauth2Proxy.commonLabels),

    container+::
      container.mixin.resources.withLimits({ cpu: '100m', memory: '100Mi' }) +
      container.mixin.resources.withRequests({ cpu: '100m', memory: '100Mi' }),

    deployment+:
      deployment.mixin.spec.withReplicas(3) +
      deployment.mixin.spec.template.metadata.withAnnotationsMixin({
        'checksum/oauth2-proxy-secret': std.md5(std.toString($.oauth2Proxy.secret)),
      }),

    ingress:
      ingress.new() +
      ingress.mixin.metadata.withName($._config.oauth2Proxy.name) +
      ingress.mixin.metadata.withNamespace($._config.namespace) +
      ingress.mixin.metadata.withLabels($._config.oauth2Proxy.commonLabels) +
      ingress.mixin.spec.withRules([
        ingressRule.new() +
        ingressRule.withHost('oauth2-proxy.yourcompany.com') +
        ingressRule.mixin.http.withPaths(
          httpIngressPath.new() +
          httpIngressPath.mixin.backend.withServiceName($._config.oauth2Proxy.name) +
          httpIngressPath.mixin.backend.withServicePort('http')
        ),
      ]),
  },

}.oauth2Proxy;

local yourApp = {
  yourApp: {
    ingress:
      ingress.new() +
      ingress.mixin.metadata.withName('yourapp') +
      ingress.mixin.metadata.withNamespace('yourapp') +
      ingress.mixin.metadata.withLabels({ app: 'yourapp' }) +
      ingress.mixin.metadata.withAnnotations({
        'nginx.ingress.kubernetes.io/auth-url': 'http://oauth2-proxy.oauth2-proxy.svc.cluster.local:4180/oauth2/auth',
        'nginx.ingress.kubernetes.io/auth-signin': 'https://oauth2-proxy.yourcompany.com/oauth2/start?rd=$scheme%3A%2F%2F$http_host$escaped_request_uri',
      }) +
      ingress.mixin.spec.withRules([
        ingressRule.new() +
        ingressRule.withHost('yourapp.yourcompany.com') +
        ingressRule.mixin.http.withPaths(
          httpIngressPath.new() +
          httpIngressPath.mixin.backend.withServiceName('yourapp') +
          httpIngressPath.mixin.backend.withServicePort(80)
        ),
      ]),
  },
}.yourApp;

k.core.v1.list.new([
  oauth2Proxy.configMap,
  oauth2Proxy.deployment,
  oauth2Proxy.ingress,
  oauth2Proxy.podDisruptionBudget,
  oauth2Proxy.secret,
  oauth2Proxy.service,
  oauth2Proxy.serviceAccount,
  yourApp.ingress,
])
