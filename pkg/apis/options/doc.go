//go:generate -command reference-gen go run github.com/oauth2-proxy/tools/reference-gen/cmd/reference-gen@v0.0.0-20220223111546-d3b50d1a591a
//go:generate reference-gen --package github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options --types AlphaOptions --header-file ../../../docs/docs/configuration/alpha_config.md.tmpl --out-file ../../../docs/docs/configuration/alpha_config.md
package options
