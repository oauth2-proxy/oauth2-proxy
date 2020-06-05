.PHONY: up
up:
	docker-compose up -d

.PHONY: %
%:
	docker-compose $*

.PHONY: nginx-up
nginx-up:
	docker-compose -f docker-compose.yaml -f docker-compose-nginx.yaml up -d

.PHONY: nginx-%
nginx-%:
	docker-compose -f docker-compose.yaml -f docker-compose-nginx.yaml $*

.PHONY: keycloak-up
keycloak-up:
	docker-compose -f docker-compose-keycloak.yaml up -d keycloak
	keycloak/wait-for-keycloak.sh echo Keycloak is up
	keycloak/init-keycloak.sh
	docker-compose -f docker-compose-keycloak.yaml up -d

.PHONY: keycloak-%
keycloak-%:
	docker-compose -f docker-compose-keycloak.yaml $*
