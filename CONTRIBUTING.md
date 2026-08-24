# Contributing

To develop on this project, please fork the repo and clone into your `$GOPATH`.

Dependencies are **not** checked in so please download those separately.
Download the dependencies using `go mod download`.

```bash
cd $GOPATH/src/github.com # Create this directory if it doesn't exist
git clone git@github.com:<YOUR_FORK>/oauth2-proxy oauth2-proxy/oauth2-proxy
cd oauth2-proxy/oauth2-proxy
go mod download
```

## Pull Requests and Issues

We track bugs and issues using Github.

If you find a bug, please open an Issue.

If you want to fix a bug, please fork, create a feature branch, fix the bug and
open a PR back to this repo.
Please mention the open bug issue number within your PR if applicable.

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
