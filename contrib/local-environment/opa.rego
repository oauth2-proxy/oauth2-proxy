# This configuration is intended to be used with the docker-compose testing
# environment.
# This should configure OPA to run on port 8181 and provides static
# authorization
package oauth2proxy.authz

default allow = false

allow {
	[_, token, _] := io.jwt.decode(input.token)
	path := split(trim(input.query.path, "/"), "/")

	token.name == "admin"
	input.query.method == "GET"

	path[0] == "test"
	path[1] == "a"
}
