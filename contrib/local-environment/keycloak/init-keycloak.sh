#!/bin/sh

# init-keycloak.sh
kcadm_opts="--no-config --server http://localhost:8080/auth --realm master --user admin@example.com --password password -r master"
res="$(docker-compose -f docker-compose-keycloak.yaml exec keycloak /opt/jboss/keycloak/bin/kcadm.sh get clients/0493c7c6-6e20-49ea-9acb-627c0b52d400 --fields clientId $kcadm_opts)"

if [[ "$res" == *"Resource not found for url"* ]]; then
    echo "Adding oauth2-proxy client to keycloak"
    docker-compose -f docker-compose-keycloak.yaml exec keycloak /opt/jboss/keycloak/bin/kcadm.sh create clients $kcadm_opts -f /opt/jboss/keycloak/realm-config/oauth2-proxy.json
fi

admin_id=$(docker-compose -f docker-compose-keycloak.yaml exec keycloak /opt/jboss/keycloak/bin/kcadm.sh get users -q username=admin@example.com --fields id $kcadm_opts | grep '"id"' | cut -d'"' -f 4)
echo "Updating email for user id=$admin_id"
docker-compose -f docker-compose-keycloak.yaml exec keycloak /opt/jboss/keycloak/bin/kcadm.sh update users/${admin_id} -s email=admin@example.com -s emailVerified=true $kcadm_opts
