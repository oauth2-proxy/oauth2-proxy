#!/bin/bash
# manually exiting from script, because after-build needs to run always
set +e
./cc-test-reporter before-build
make test
STATUS=$?
./cc-test-reporter after-build --exit-code $STATUS -t gocov
exit $STATUS
