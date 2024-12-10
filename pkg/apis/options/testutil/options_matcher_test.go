package testutil

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Options Gomega Matcher", func() {
	type TestOptions struct {
		Foo  string
		Bar  int
		List []string

		// unexported fields should be ignored
		unexported string
		another    string
	}

	Context("two empty option structs are equal", func() {
		Expect(EqualOpts(TestOptions{}).Match(TestOptions{})).To(BeTrue())
	})

	Context("two options with the same content should be equal", func() {
		opt1 := TestOptions{Foo: "foo", Bar: 1}
		opt2 := TestOptions{Foo: "foo", Bar: 1}
		Expect(EqualOpts(opt1).Match(opt2)).To(BeTrue())
	})

	Context("when two options have different content", func() {
		opt1 := TestOptions{Foo: "foo", Bar: 1}
		opt2 := TestOptions{Foo: "foo", Bar: 2}
		Expect(EqualOpts(opt1).Match(opt2)).To(BeFalse())
	})

	Context("when two options have different types they are not equal", func() {
		opt1 := TestOptions{Foo: "foo", Bar: 1}
		opt2 := struct {
			Foo string
			Bar int
		}{
			Foo: "foo",
			Bar: 1,
		}
		Expect(EqualOpts(opt1).Match(opt2)).To(BeFalse())
	})

	Context("when two options have different unexported fields they are equal", func() {
		opts1 := TestOptions{Foo: "foo", Bar: 1, unexported: "unexported", another: "another"}
		opts2 := TestOptions{Foo: "foo", Bar: 1, unexported: "unexported2"}
		Expect(EqualOpts(opts1).Match(opts2)).To(BeTrue())
	})

	Context("when two options have different list content they are not equal", func() {
		opt1 := TestOptions{List: []string{"foo", "bar"}}
		opt2 := TestOptions{List: []string{"foo", "baz"}}
		Expect(EqualOpts(opt1).Match(opt2)).To(BeFalse())
	})

	Context("when two options have different list lengths they are not equal", func() {
		opt1 := TestOptions{List: []string{"foo", "bar"}}
		opt2 := TestOptions{List: []string{"foo", "bar", "baz"}}
		Expect(EqualOpts(opt1).Match(opt2)).To(BeFalse())
	})

	Context("when one options has a list of length 0 and the other is nil they are equal", func() {
		otp1 := TestOptions{List: []string{}}
		opt2 := TestOptions{}
		Expect(EqualOpts(otp1).Match(opt2)).To(BeTrue())
	})
})
