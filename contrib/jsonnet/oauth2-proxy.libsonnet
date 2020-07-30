local k = import 'github.com/ksonnet/ksonnet-lib/ksonnet.beta.4/k.libsonnet';
local deployment = k.apps.v1.deployment;

{
  local cfg = $._config.oauth2Proxy,
  local op = $.oauth2Proxy,

  _config+:: {
    namespace: error 'must provide namespace',

    oauth2Proxy+:: {
      name: 'oauth2-proxy',
      namespace: $._config.namespace,
      version: 'v6.0.0',
      image: 'quay.io/oauth2-proxy/oauth2-proxy:' + self.version,

      commonLabels:: {
        'app.kubernetes.io/name': 'oauth2-proxy',
        'app.kubernetes.io/instance': cfg.name,
        'app.kubernetes.io/version': cfg.version,
      },

      podLabelSelector:: {
        [labelName]: cfg.commonLabels[labelName]
        for labelName in std.objectFields(cfg.commonLabels)
        if !std.setMember(labelName, ['app.kubernetes.io/version'])
      },

      configToml: '',
      env: [],
    },
  },

  oauth2Proxy+: {

    configMap:
      local configMap = k.core.v1.configMap;
      configMap.new(cfg.name, { 'oauth2-proxy.toml': cfg.configToml }),

    container+::
      local container = deployment.mixin.spec.template.spec.containersType;
      local containerPort = container.portsType;
      local containerVolumeMount = container.volumeMountsType;
      local resourceRequirements = container.mixin.resourcesType;

      container.new('oauth2-proxy', cfg.image) +
      container.withPorts(containerPort.newNamed(4180, 'http')) +
      container.withArgs([
        '--http-address=0.0.0.0:4180',
        '--config=/etc/oauth2-proxy/oauth2-proxy.toml',
      ]) +
      container.withEnv(cfg.env) +
      container.mixin.livenessProbe +
      container.mixin.livenessProbe.httpGet.withPort('http') +
      container.mixin.livenessProbe.httpGet.withPath('/ping') +
      container.mixin.readinessProbe +
      container.mixin.readinessProbe.httpGet.withPort('http') +
      container.mixin.readinessProbe.httpGet.withPath('/ping') +
      container.withVolumeMounts([containerVolumeMount.new('config', '/etc/oauth2-proxy')]),

    deployment+:
      local affinity = deployment.mixin.spec.template.spec.affinity.podAntiAffinity.preferredDuringSchedulingIgnoredDuringExecutionType;
      local volume = k.apps.v1.deployment.mixin.spec.template.spec.volumesType;

      deployment.new(cfg.name, 1, op.container, cfg.commonLabels) +
      deployment.mixin.metadata.withLabels(cfg.commonLabels) +
      deployment.mixin.spec.selector.withMatchLabels(cfg.podLabelSelector) +
      deployment.mixin.spec.template.metadata.withAnnotations({
        'checksum/oauth2-proxy-config': std.md5(std.toString(op.configMap)),
      }) +
      deployment.mixin.spec.template.spec.securityContext.withRunAsNonRoot(true) +
      deployment.mixin.spec.template.spec.securityContext.withRunAsUser(2000) +
      deployment.mixin.spec.template.spec.securityContext.withFsGroup(2000) +
      deployment.mixin.spec.template.spec.withServiceAccountName(cfg.name) +
      deployment.mixin.spec.template.spec.affinity.podAntiAffinity.withPreferredDuringSchedulingIgnoredDuringExecution(
        affinity.new() +
        affinity.withWeight(100) +
        affinity.mixin.podAffinityTerm.withNamespaces(cfg.namespace) +
        affinity.mixin.podAffinityTerm.withTopologyKey('kubernetes.io/hostname') +
        affinity.mixin.podAffinityTerm.labelSelector.withMatchLabels(cfg.podLabelSelector)
      ) +
      deployment.mixin.spec.template.spec.withVolumes([
        volume.withName('config') + volume.mixin.configMap.withName(cfg.name),
      ]),

    podDisruptionBudget:
      local podDisruptionBudget = k.policy.v1beta1.podDisruptionBudget;

      podDisruptionBudget.new() +
      podDisruptionBudget.mixin.metadata.withName(cfg.name) +
      podDisruptionBudget.mixin.metadata.withNamespace(cfg.namespace) +
      podDisruptionBudget.mixin.metadata.withLabels(cfg.commonLabels) +
      podDisruptionBudget.mixin.spec.withMaxUnavailable(1) +
      podDisruptionBudget.mixin.spec.selector.withMatchLabels(cfg.podLabelSelector),

    service:
      local service = k.core.v1.service;
      local servicePort = k.core.v1.service.mixin.spec.portsType;

      service.new(cfg.name, cfg.podLabelSelector, servicePort.newNamed('http', 80, 'http')) +
      service.mixin.metadata.withLabels(cfg.commonLabels) +
      service.mixin.metadata.withNamespace(cfg.namespace),

    serviceAccount:
      local serviceAccount = k.core.v1.serviceAccount;

      serviceAccount.new(cfg.name) +
      serviceAccount.mixin.metadata.withNamespace(cfg.namespace) +
      serviceAccount.mixin.metadata.withLabels(cfg.commonLabels),
  },
}
