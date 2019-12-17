# Release

Here's how OAuth2_Proxy releases are created.

## Schedule

Our aim is to release once a quarter, but bug fixes will be prioritised and might be released earlier.

## The Process

Note this uses `v4.1.0` as an example release number.

1. Create a draft Github release
  * Use format `v4.1.0` for both the tag and title
2. Update [CHANGELOG.md](CHANGELOG.md)
  * Write the release highlights
  * Copy in headings ready for the next release
3. Create release commit
  ```
  git checkout -b release-v4.1.0
  ```
4. Create pull request getting other maintainers to review
5. Copy the release notes in to the draft Github release, adding a link to [CHANGELOG.md](CHANGELOG.md)
6. Update you local master branch
  ```
  git checkout master
  git pull
  ```
7. Create & push the tag
  ```
  git tag v4.1.0
  git push --tags
  ```
8. Make the release artefacts
  ```
  make release
  ```
9. Upload all the files (not the folders) from the `/release` folder to Github release as binary artefacts. There should be both the tarballs (`tar.gz`) and the checksum files (`sha256sum.txt`).
10. Publish release in Github
11. Make and push docker images to Quay
  ```
  make docker-all
  make docker-push-all
  ```
  Note: Ensure the docker tags don't include `-dirty`. This means you have uncommitted changes.

12. Verify everything looks good at [quay](https://quay.io/repository/pusher/oauth2_proxy?tag=latest&tab=tags) and [github](https://github.com/pusher/oauth2_proxy/releases)
