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

This project is currently still using go 1.22. You can follow the installation guide for go [here.](https://go.dev/doc/install) And you can find go version 1.22 in the archived section [here.](https://go.dev/dl/)

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

Open a terminal and switch to the `contrib/local-environment` directory.

- Dex as your IdP: `docker compose -f docker-compose.yaml up dex etcd httpbin`
- Keycloak as your IdP: `docker compose -f docker-compose-keycloak.yaml up keycloak httpbin`

The username for both is `admin@example.com` and password is `password`.

Start oauth2-proxy from the debug tab and open http://oauth2-proxy.localtest.me:4180/ for testing.
