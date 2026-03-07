## What changed
Fixed the documentation for the GitLab project flag: changed `--gitlab-projects` (plural) to `--gitlab-project` (singular) across all versioned docs to match the actual CLI flag name.

## Why
The docs incorrectly reference `--gitlab-projects` but the actual flag registered in the code is `--gitlab-project` (singular), causing users to get errors when following the documentation.

Fixes #3362

## Testing
- Verified the actual flag name is `--gitlab-project` in `pkg/apis/options/legacy_options.go`
- Confirmed all 16 affected doc files were updated
- Confirmed no remaining occurrences of `--gitlab-projects` in the docs
- Ran `go test ./pkg/apis/options/ ./providers/` — all tests pass
