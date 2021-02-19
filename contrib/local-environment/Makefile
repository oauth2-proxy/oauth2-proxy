.PHONY: up
up:
	docker-compose up -d

.PHONY: %
%:
	docker-compose $*

.PHONY: alpha-config-up
alpha-config-up:
	docker-compose -f docker-compose.yaml -f docker-compose-alpha-config.yaml up -d

.PHONY: alpha-config-%
alpha-config-%:
	docker-compose -f docker-compose.yaml -f docker-compose-nginx.yaml $*

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
