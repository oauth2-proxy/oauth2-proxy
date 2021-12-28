.PHONY: up
up:
	docker-compose up

.PHONY: build-up
build-up:
	docker-compose -f docker-compose.yaml -f docker-compose-build-oauth.yaml up --build

.PHONY: %
%:
	docker-compose $*

.PHONY: alpha-config-up
alpha-config-up:
	docker-compose -f docker-compose.yaml -f docker-compose-alpha-config.yaml up

.PHONY: alpha-config-build-up
alpha-config-build-up:
	docker-compose -f docker-compose.yaml -f docker-compose-alpha-config.yaml -f docker-compose-build-oauth.yaml up --build

.PHONY: alpha-config-multiple-providers-build-up
alpha-config-multiple-providers-build-up:
	docker-compose -f docker-compose.yaml -f docker-compose-multiple-providers.yaml -f docker-compose-alpha-config.yaml -f docker-compose-build-oauth.yaml up --build

.PHONY: alpha-config-multiple-providers-up
alpha-config-multiple-providers-up:
	docker-compose -f docker-compose.yaml -f docker-compose-multiple-providers.yaml -f docker-compose-alpha-config.yaml up

.PHONY: alpha-config-%
alpha-config-%:
	docker-compose -f docker-compose.yaml -f docker-compose-nginx.yaml $*

.PHONY: nginx-up
nginx-up:
	docker-compose -f docker-compose.yaml -f docker-compose-nginx.yaml up

.PHONY: nginx-%
nginx-%:
	docker-compose -f docker-compose.yaml -f docker-compose-nginx.yaml $*

.PHONY: keycloak-up
keycloak-up:
	docker-compose -f docker-compose-keycloak.yaml up

.PHONY: keycloak-%
keycloak-%:
	docker-compose -f docker-compose-keycloak.yaml $*

.PHONY: kubernetes-up
kubernetes-up:
	make -C kubernetes create-cluster
	make -C kubernetes deploy

.PHONY: kubernetes-down
kubernetes-down:
	make -C kubernetes delete-cluster

.PHONY: traefik-up
traefik-up:
	docker-compose -f docker-compose.yaml -f docker-compose-traefik.yaml up

.PHONY: traefik-%
traefik-%:
	docker-compose -f docker-compose.yaml -f docker-compose-traefik.yaml $*
