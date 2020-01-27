#
# Autocompletion for oauth2_proxy
# 
# To install this, copy/move this file to /etc/bash.completion.d/
# or add a line to your ~/.bashrc | ~/.bash_profile that says ". /path/to/oauth2_proxy/contrib/oauth2_proxy_autocomplete.sh"
#

_oauth2_proxy() {
	_oauth2_proxy_commands=$(oauth2_proxy -h 2>&1 | sed -n '/^\s*-/s/ \+/ /gp' | awk '{print $1}' | tr '\n' ' ')
	local cur prev
	COMPREPLY=()
	cur="${COMP_WORDS[COMP_CWORD]}"
	prev="${COMP_WORDS[COMP_CWORD-1]}"
	case "$prev" in
		-@(config|tls-cert-file|tls-key-file|authenticated-emails-file|htpasswd-file|custom-templates-dir|logging-filename|jwt-key-file))
			_filedir
			return 0
			;;
		-provider)
			COMPREPLY=( $(compgen -W "google azure facebook github keycloak gitlab linkedin login.gov digitalocean" -- ${cur}) )
			return 0
			;;
		-@(http-address|https-address|redirect-url|upstream|basic-auth-password|skip-auth-regex|flush-interval|extra-jwt-issuers|email-domain|whitelist-domain|keycloak-group|azure-tenant|bitbucket-team|bitbucket-repository|github-org|github-team|gitlab-group|google-group|google-admin-email|google-service-account-json|client-id|client_secret|banner|footer|proxy-prefix|ping-path|cookie-name|cookie-secret|cookie-domain|cookie-path|cookie-expire|cookie-refresh|cookie-samesite|redist-sentinel-master-name|redist-sentinel-connection-urls|logging-max-size|logging-max-age|logging-max-backups|standard-logging-format|request-logging-format|exclude-logging-paths|auth-logging-format|oidc-issuer-url|oidc-jwks-url|login-url|redeem-url|profile-url|resource|validate-url|scope|approval-prompt|signature-key|acr-values|jwt-key|pubjwk-url))
			return 0
			;;
	esac
	COMPREPLY=( $(compgen -W "${_oauth2_proxy_commands}" -- ${cur}) )
	return 0;
}
complete -F _oauth2_proxy oauth2_proxy
