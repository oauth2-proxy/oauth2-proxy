local op = import 'oauth2-proxy.libsonnet';

local oauth2Proxy = op {
  _config+:: {
    namespace: 'oauth2-proxy',
  },
}.oauth2Proxy;

local manifests = {
  [std.asciiLower(resource)]: oauth2Proxy[resource]
  for resource in std.objectFields(oauth2Proxy)
  if !std.member(['ConfigMap'], oauth2Proxy[resource].kind)
};

local kustomization = {
  apiVersion: 'kustomize.config.k8s.io/v1beta1',
  kind: 'Kustomization',
  resources: [name + '.yaml' for name in std.objectFields(manifests)],
};

manifests {
  kustomization: kustomization,
}
