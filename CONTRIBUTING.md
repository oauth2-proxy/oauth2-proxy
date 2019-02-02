# Contributing

To develop on this project, please fork the repo and clone into your `$GOPATH`.

Dependencies are **not** checked in so please download those separately.
Download the dependencies using [`dep`](https://github.com/golang/dep).

```bash
cd $GOPATH/src/github.com # Create this directory if it doesn't exist
git clone git@github.com:<YOUR_FORK>/oauth2_proxy pusher/oauth2_proxy
cd pusher/oauth2_proxy
./configure # Setup your environment variables
make dep
```

## Pull Requests and Issues

We track bugs and issues using Github.

If you find a bug, please open an Issue.

If you want to fix a bug, please fork, create a feature branch, fix the bug and
open a PR back to this repo.
Please mention the open bug issue number within your PR if applicable.
