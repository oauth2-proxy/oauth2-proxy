local k = import 'github.com/ksonnet/ksonnet-lib/ksonnet.beta.4/k.libsonnet';
local op = import 'github.com/oauth2-proxy/oauth2-proxy/contrib/jsonnet/oauth2-proxy.libsonnet';
local deployment = k.apps.v1.deployment;
local container = deployment.mixin.spec.template.spec.containersType;
local envVar = container.envType;
local resourceRequirements = container.mixin.resourcesType;
local secret = k.core.v1.secret;

local oauth2Proxy = op {
  _config+:: {
    namespace: 'oauth2-proxy',

    oauth2Proxy+:: {
      name: 'oauth2-proxy',
      version: 'v6.0.0',

      configToml: |||
        client_id         = "123456.apps.googleusercontent.com"
        upstreams         = ["yourapp:80"]
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
  },
}.oauth2Proxy;

k.core.v1.list.new([
  oauth2Proxy.configMap,
  oauth2Proxy.deployment,
  oauth2Proxy.podDisruptionBudget,
  oauth2Proxy.secret,
  oauth2Proxy.service,
  oauth2Proxy.serviceAccount,
])
