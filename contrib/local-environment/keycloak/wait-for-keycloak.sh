#!/bin/sh
# wait-for-keycloak.sh

set -e

cmd="$@"

host="http://keycloak.localtest.me:8080/auth/realms/master/.well-known/openid-configuration"
wait_for=0


until [ "200" = "$(curl -m 1 --write-out %{http_code} --silent --output /dev/null $host)" ] || [ $wait_for -gt 30 ] ; do
  >&2 echo "Keycloak is unavailable - waiting for $wait_for/30 seconds "
  wait_for=$((wait_for+3))
  sleep 3
done

if [ "200" != "$(curl -m 1 --write-out %{http_code} --silent --output /dev/null $host)" ] || [ $wait_for -gt 30 ]; then
    >&2 echo "Keycloak didn't get up - exiting"
    exit 1
fi

exec $cmd
