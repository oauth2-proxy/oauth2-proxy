# create kind cluster with nginx-ingress as the most popular ingress controller for K8S
.PHONY: deploy
create-cluster:
	kind create cluster --name oauth2-proxy --config kind-cluster.yaml
	make setup-dns
	make setup-ingress

.PHONY: setup-ingress
setup-ingress:
	kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/master/deploy/static/provider/kind/deploy.yaml
	sleep 5 # because of https://github.com/kubernetes/kubernetes/issues/83242
	kubectl --namespace ingress-nginx wait --for=condition=available --timeout=30s deployment/ingress-nginx-controller
	kubectl --namespace ingress-nginx rollout status --timeout 90s deployment/ingress-nginx-controller

# default Pod CIDR is 10.244.0.0/16 https://github.com/kubernetes-sigs/kind/blob/master/pkg/apis/config/v1alpha4/default.go
# what makes cluster host IP equal to 10.244.0.1
# thus we add dex.localtest.me and oauth2-proxy.localtest.me stub hosts pointing to this IP
# NOT NEEDED IN REAL LIFE!
.PHONY: setup-dns
setup-dns:
	kubectl apply -f custom-dns.yaml
	kubectl -n kube-system rollout restart deployment/coredns
	kubectl -n kube-system rollout status --timeout 60s deployment/coredns

.PHONY: undeploy
delete-cluster:
	kind delete cluster --name oauth2-proxy

.PHONY: helm-init
helm-init:
	helm dep update

.PHONY: undeploy
deploy: helm-init
	helm upgrade --wait --debug --install --render-subchart-notes oauth2-proxy-example .

.PHONY: undeploy
undeploy:
	helm del oauth2-proxy-example

# unpacking is useful to be able to explore underlying helm charts
.PHONY: helm-unpack
helm-unpack:
	cd charts; for f in *.tgz; do tar -zxf "$$f"; done
