# Kubernetes example
Based on [kind](https://kind.sigs.k8s.io) as a local Kubernetes cluster.

## Quick start

Before you start: 

_Required_
* install [kind](https://kind.sigs.k8s.io/docs/user/quick-start/#installation)
* install [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/)

_Optional_
* install [helm 3](https://helm.sh/docs/intro/quickstart/#install-helm).

Then: 

* `make create-cluster`
* `make deploy` OR `make helm-deploy` for helm

Visit http://httpbin.localtest.me or http://hello-world.localtest.me/

## Uninstall

* `make delete-cluster`
