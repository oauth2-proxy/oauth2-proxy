#!/bin/bash
# manually exiting from script, because after-build needs to run always
set +e
echo "1. Running before-build"
./cc-test-reporter before-build

echo "2. Running test"
make test
TEST_STATUS=$?
echo "TEST_STATUS: ${TEST_STATUS}"

echo "CC_TEST_REPORTER_ID: ${CC_TEST_REPORTER_ID}"

echo "3. Running after-build"
./cc-test-reporter after-build --exit-code $TEST_STATUS -t gocov
REPORT_STATUS=$?
echo "REPORT_STATUS: ${REPORT_STATUS}"

if [ "$TEST_STATUS" -ne 0 ]; then
  echo "test failed, status code: $TEST_STATUS"
  exit $TEST_STATUS
elif [ "$REPORT_STATUS" -ne 0 ]; then
  echo "after-build failed, status code: $REPORT_STATUS"
  exit $REPORT_STATUS
fi
