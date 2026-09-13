# Contributing

Thank you for contributing to OAuth2 Proxy. We track bugs, feature requests,
and other work in GitHub issues. Please follow the issue and pull request
templates, including their checkboxes.

## Development setup

Fork the repository, clone your fork, create a feature branch, and download Go
dependencies:

```bash
git clone git@github.com:<YOUR_FORK>/oauth2-proxy.git
cd oauth2-proxy
git switch -c feature/<BRANCH_NAME>
go mod download
```

Install the Go version declared in the repository's `go.mod`. The
[Go installation guide](https://go.dev/doc/install) and
[Go downloads page](https://go.dev/dl/) explain how to install a specific
release.

We suggest [Visual Studio Code](https://code.visualstudio.com/docs/languages/go)
with the official
[Go extension](https://marketplace.visualstudio.com/items?itemName=golang.go).

### Local testing and debugging

To run OAuth2 Proxy locally with an example upstream and identity provider,
use the Makefile in `contrib/local-environment`:

```bash
cd contrib/local-environment
make up
```

Other available environments include:

- Dex with alpha config: `make alpha-config-up`
- Keycloak: `make keycloak-up`
- Dex with nginx: `make nginx-up`

See that Makefile for the complete set of environments and their corresponding
tear-down commands. The default local credentials are usually
`admin@example.com` and `password`.

The environments use `localtest.me`:

- OAuth2 Proxy: <http://oauth2-proxy.localtest.me:4180>
- Upstream: <http://httpbin.localtest.me:8080>
- Dex: <http://dex.localtest.me:5556>

For VS Code debugging, create `.vscode/launch.json` from the "Run and Debug"
view and use `Go: Launch Package`. The following configurations start OAuth2
Proxy with the local Dex or Keycloak environments:

```jsonc
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Launch OAuth2 Proxy with Dex",
      "type": "go",
      "request": "launch",
      "mode": "auto",
      "program": "${workspaceFolder}",
      "args": [
        "--config",
        "contrib/local-environment/oauth2-proxy.cfg"
      ]
    },
    {
      "name": "Launch OAuth2 Proxy with Keycloak",
      "type": "go",
      "request": "launch",
      "mode": "auto",
      "program": "${workspaceFolder}",
      "args": [
        "--config",
        "contrib/local-environment/oauth2-proxy-keycloak.cfg"
      ]
    }
  ]
}
```

## Pull requests and issues

If you find a bug, open an issue. To fix a bug, create a feature branch, make
the change, and open a pull request against this repository. Mention the
related issue number in the pull request when applicable.

GitHub's required reviews and CODEOWNERS rules are the authoritative merge
approval process. Reviewers should use GitHub's native review interface to
approve changes.

### GitHub commands

Prow-style commands may be posted as their own line in issue and pull request
comments:

- `/assign` and `/unassign` assign or unassign users.
- `/area`, `/kind`, and `/provider` apply a configured classification label.
- `/help` adds the `help wanted` label.

On pull requests only, project reviewers may also use `/lgtm` and
`/lgtm cancel` to manage the review-readiness label. A new commit removes the
`lgtm` label. The label does not merge a pull request or replace GitHub
approval requirements.

## AI use

OAuth2 Proxy is built by humans for humans. Authentication and authorization
depend on trust between people and systems. That trust also matters in how we
work together.

You may use AI tools when contributing, but YOU must not replace human
communication or judgment using those tools. You must understand, test, and 
review every AI-assisted change yourself. Write a clear, concise pull request 
description and respond to review comments yourself.

Listing AI tooling as a co-author, co-signing commits using an AI tool, or 
using the `assisted-by`, `co-developed` or similar commit trailer is not allowed.

The project maintainers will review contributions regardless of their origin. 
But we may close issues or pull requests without comment when they appear to be 
unreviewed automated output, low-quality slop, or contain essay-length descriptions 
or comments that waste reviewer time.

If a contribution does not show the care needed for a high-quality change,
maintainers will not spend time reviewing it.
