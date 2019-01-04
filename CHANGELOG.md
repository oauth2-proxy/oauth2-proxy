# Vx.x.x (Pre-release)

## Changes since v2.2:

- Move automated build to debian base image
- Add Makefile
  - Update CI to run `make test`
  - Update Dockerfile to use `make clean oauth2_proxy`
  - Update `VERSION` parameter to be set by `ldflags` from Git Status
  - Remove lint and test scripts
- Remove Go v1.8.x from Travis CI testing
- Add CODEOWNERS file
- Add CONTRIBUTING guide
- Add Issue and Pull Request templates
- Add Dockerfile
- Fix fsnotify import
- Update README to reflect new repository ownership
- Update CI scripts to separate linting and testing
  - Now using `gometalinter` for linting
- Move Go import path from `github.com/bitly/oauth2_proxy` to `github.com/pusher/oauth2_proxy`
- Repository forked on 27/11/18
  - README updated to include note that this repository is forked
  - CHANGLOG created to track changes to repository from original fork
