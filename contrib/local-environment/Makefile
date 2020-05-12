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
