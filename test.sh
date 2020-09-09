#!/bin/bash
# manually exiting from script, because after-build needs to run always
set +e
./cc-test-reporter before-build
make test
TEST_STATUS=$?
./cc-test-reporter after-build --exit-code $TEST_STATUS -t gocov
REPORT_STATUS=$?
if [ "$TEST_STATUS" -ne 0 ]; then
  echo "test failed, status code: $TEST_STATUS"
  exit $TEST_STATUS
elif [ "$REPORT_STATUS" -ne 0 ]; then
  echo "after-build failed, status code: $REPORT_STATUS"
  exit $REPORT_STATUS
fi
