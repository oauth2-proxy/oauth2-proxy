package testutil

import (
	"errors"
	"fmt"
	"unicode"
	"unicode/utf8"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/onsi/gomega/format"
	"github.com/onsi/gomega/types"
)

type optionsMatcher struct {
	Expected       interface{}
	CompareOptions []cmp.Option
}

func EqualOpts(expected interface{}) types.GomegaMatcher {
	ignoreUnexported := cmp.FilterPath(func(p cmp.Path) bool {
		sf, ok := p.Index(-1).(cmp.StructField)
		if !ok {
			return false
		}
		r, _ := utf8.DecodeRuneInString(sf.Name())
		return !unicode.IsUpper(r)
	}, cmp.Ignore())

	return &optionsMatcher{
		Expected:       expected,
		CompareOptions: []cmp.Option{ignoreUnexported, cmpopts.EquateEmpty()},
	}
}

func (matcher *optionsMatcher) Match(actual interface{}) (success bool, err error) {
	if actual == nil && matcher.Expected == nil {
		return false, errors.New("trying to compare <nil> to <nil>")
	}
	return cmp.Equal(actual, matcher.Expected, matcher.CompareOptions...), nil
}

func (matcher *optionsMatcher) FailureMessage(actual interface{}) (message string) {
	actualString, actualOK := actual.(string)
	expectedString, expectedOK := fmt.Sprintf("%v", matcher.Expected), true
	if actualOK && expectedOK {
		return format.MessageWithDiff(actualString, "to equal", expectedString)
	}

	return format.Message(actual, "to equal", matcher.Expected) +
		"\n\nDiff:\n" + format.IndentString(matcher.getDiff(actual), 1)
}

func (matcher *optionsMatcher) NegatedFailureMessage(actual interface{}) (message string) {

	return format.Message(actual, "not to equal", matcher.Expected) +
		"\n\nDiff:\n" + format.IndentString(matcher.getDiff(actual), 1)
}

func (matcher *optionsMatcher) getDiff(actual interface{}) string {
	return cmp.Diff(actual, matcher.Expected, matcher.CompareOptions...)
}
