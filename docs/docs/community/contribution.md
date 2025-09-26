---
id: contribution
title: Contribution Guide
---

We track bugs and issues using Github.

If you find a bug, please open an Issue. When opening an Issue or Pull Request please follow the preconfigured template and take special note of the checkboxes.

If you want to fix a bug, add a new feature or extend existing functionality, please create a fork, create a feature branch and open a PR back to this repo.
Please mention open bug issue number(s) within your PR if applicable.

We suggest using [Visual Studio Code](https://code.visualstudio.com/docs/languages/go) with the official [Go for Visual Studio Code](https://marketplace.visualstudio.com/items?itemName=golang.go) extension.


# Go version

See the `go.mod` file in the root of this repository for the version of Go used by this project.
You can follow [the installation guide for Go](https://go.dev/doc/install),
and you can find this specific Go version on [the Go downloads page](https://go.dev/dl/).

# Preparing your fork
Clone your fork, create a feature branch and update the depedencies to get started.
```bash
git clone git@github.com:<YOUR_FORK>/oauth2-proxy
cd oauth2-proxy
git branch feature/<BRANCH_NAME>
git push --set-upstream origin feature/<BRANCH_NAME>
go mod download
```


# Testing / Debugging
For starting oauth2-proxy locally open the debugging tab and create the `launch.json` and select `Go: Launch Package`.

![Debugging Tab](/img/debug-tab.png)
```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Launch OAuth2-Proxy with Dex",
            "type": "go",
            "request": "launch",
            "mode": "auto",
            "program": "${workspaceFolder}",
            "args": [
                "--config",
                // The following configuration contains settings for a locally deployed
                // upstream and dex as an idetity provider
                "contrib/local-environment/oauth2-proxy.cfg"
            ]
        },
        {
            "name": "Launch OAuth2-Proxy with Keycloak",
            "type": "go",
            "request": "launch",
            "mode": "auto",
            "program": "${workspaceFolder}",
            "args": [
                "--config",
                // The following configuration contains settings for a locally deployed
                // upstream and keycloak as an idetity provider
                "contrib/local-environment/oauth2-proxy-keycloak.cfg"
            ]
        }
    ]
}
```

Before you can start your local version of oauth2-proxy, you will have to use the provided docker compose files to start a local upstream service and identity provider. We suggest using [httpbin](https://hub.docker.com/r/kennethreitz/httpbin) as your upstream for testing as it allows for request and response introspection of all things HTTP.

Inside the `contrib/local-environment` directory you can use the `Makefile` for
starting different example setups:

- Dex as your IdP: `make up` or `make down`
- Dex as your IdP using the alpha-config: `make alpha-config-up`
- Keycloak as your IdP: `make keycloak-up`
- Dex as your IdP & nginx reverse proxy: `make nginx-up`
- and many more...

Check out the `Makefile` to see what is available.

The username and password for all setups is usually `admin@example.com` and `password`.

The docker compose setups expose the services with a dynamic reverse DNS resolver: localtest.me

- OAuth2-Proxy: http://oauth2-proxy.localtest.me:4180
- Upstream: http://httpbin.localtest.me:8080
- Dex: http://dex.localtest.me:5556

