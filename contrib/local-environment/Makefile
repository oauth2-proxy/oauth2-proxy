.PHONY: up
up:
	docker-compose up -d

.PHONY: down
down:
	docker-compose down --remove-orphans

.PHONY: alpha-config-up
alpha-config-up:
	docker-compose -f docker-compose.yaml -f docker-compose-alpha-config.yaml up -d

.PHONY: alpha-config-down
alpha-config-down:
	docker-compose -f docker-compose.yaml -f docker-compose-alpha-config.yaml down --remove-orphans

.PHONY: alpha-config-multiple-providers-up
alpha-config-multiple-providers-up:
	docker-compose -f docker-compose.yaml -f docker-compose-multiple-providers.yaml up -d

.PHONY: alpha-config-multiple-providers-down
alpha-config-multiple-providers-down:
	docker-compose -f docker-compose.yaml -f docker-compose-multiple-providers.yaml down --remove-orphans

.PHONY: build-up
build-up:
	BUILDPLATFORM=$(shell dpkg --print-architecture) VERSION=$(shell git rev-parse --abbrev-ref HEAD) DOCKER_BUILDKIT=1 COMPOSE_DOCKER_CLI_BUILD=1 docker-compose -f docker-compose.yaml -f docker-compose-build-oauth.yaml up --build

.PHONY: alpha-config-build-up
alpha-config-build-up:
	BUILDPLATFORM=$(shell dpkg --print-architecture) VERSION=$(shell git rev-parse --abbrev-ref HEAD) DOCKER_BUILDKIT=1 COMPOSE_DOCKER_CLI_BUILD=1 docker-compose -f docker-compose.yaml -f docker-compose-alpha-config.yaml -f docker-compose-build-oauth.yaml up --build

.PHONY: alpha-config-multiple-providers-build-up
alpha-config-multiple-providers-build-up:
	BUILDPLATFORM=$(shell dpkg --print-architecture) VERSION=$(shell git rev-parse --abbrev-ref HEAD) DOCKER_BUILDKIT=1 COMPOSE_DOCKER_CLI_BUILD=1 docker-compose -f docker-compose.yaml -f docker-compose-multiple-providers.yaml -f docker-compose-build-oauth.yaml up --build

.PHONY: nginx-up
nginx-up:
	docker-compose -f docker-compose.yaml -f docker-compose-nginx.yaml up -d

.PHONY: nginx-%
nginx-%:
	docker-compose -f docker-compose.yaml -f docker-compose-nginx.yaml $*

.PHONY: keycloak-up
keycloak-up:
	docker-compose -f docker-compose-keycloak.yaml up -d

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
	docker-compose -f docker-compose.yaml -f docker-compose-traefik.yaml up -d

.PHONY: traefik-%
traefik-%:
	docker-compose -f docker-compose.yaml -f docker-compose-traefik.yaml $*
