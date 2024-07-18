package requests

import (
	"errors"
	"net/http"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Result suite", func() {
	Context("with a result", func() {
		type resultTableInput struct {
			result             Result
			expectedError      error
			expectedStatusCode int
			expectedHeaders    http.Header
			expectedBody       []byte
		}

		DescribeTable("accessors should return expected results",
			func(in resultTableInput) {
				if in.expectedError != nil {
					Expect(in.result.Error()).To(MatchError(in.expectedError))
				} else {
					Expect(in.result.Error()).To(BeNil())
				}

				Expect(in.result.StatusCode()).To(Equal(in.expectedStatusCode))
				Expect(in.result.Headers()).To(Equal(in.expectedHeaders))
				Expect(in.result.Body()).To(Equal(in.expectedBody))
			},
			Entry("with an empty result", resultTableInput{
				result:             &result{},
				expectedError:      nil,
				expectedStatusCode: 0,
				expectedHeaders:    nil,
				expectedBody:       nil,
			}),
			Entry("with an error", resultTableInput{
				result: &result{
					err: errors.New("error"),
				},
				expectedError:      errors.New("error"),
				expectedStatusCode: 0,
				expectedHeaders:    nil,
				expectedBody:       nil,
			}),
			Entry("with a response with no headers", resultTableInput{
				result: &result{
					response: &http.Response{
						StatusCode: http.StatusTeapot,
					},
				},
				expectedError:      nil,
				expectedStatusCode: http.StatusTeapot,
				expectedHeaders:    nil,
				expectedBody:       nil,
			}),
			Entry("with a response with no status code", resultTableInput{
				result: &result{
					response: &http.Response{
						Header: http.Header{
							"foo": []string{"bar"},
						},
					},
				},
				expectedError:      nil,
				expectedStatusCode: 0,
				expectedHeaders: http.Header{
					"foo": []string{"bar"},
				},
				expectedBody: nil,
			}),
			Entry("with a response with a body", resultTableInput{
				result: &result{
					body: []byte("some body"),
				},
				expectedError:      nil,
				expectedStatusCode: 0,
				expectedHeaders:    nil,
				expectedBody:       []byte("some body"),
			}),
			Entry("with all fields", resultTableInput{
				result: &result{
					err: errors.New("some error"),
					response: &http.Response{
						StatusCode: http.StatusFound,
						Header: http.Header{
							"header": []string{"value"},
						},
					},
					body: []byte("a body"),
				},
				expectedError:      errors.New("some error"),
				expectedStatusCode: http.StatusFound,
				expectedHeaders: http.Header{
					"header": []string{"value"},
				},
				expectedBody: []byte("a body"),
			}),
		)
	})

	Context("UnmarshalInto", func() {
		type testStruct struct {
			A string `json:"a"`
			B int    `json:"b"`
		}

		type unmarshalIntoTableInput struct {
			result         Result
			expectedErr    error
			expectedOutput *testStruct
		}

		DescribeTable("with a result",
			func(in unmarshalIntoTableInput) {
				input := &testStruct{}
				err := in.result.UnmarshalInto(input)
				if in.expectedErr != nil {
					Expect(err).To(MatchError(in.expectedErr))
				} else {
					Expect(err).ToNot(HaveOccurred())
				}
				Expect(input).To(Equal(in.expectedOutput))
			},
			Entry("with an error", unmarshalIntoTableInput{
				result: &result{
					err: errors.New("got an error"),
					response: &http.Response{
						StatusCode: http.StatusOK,
					},
					body: []byte("{\"a\": \"foo\"}"),
				},
				expectedErr:    errors.New("got an error"),
				expectedOutput: &testStruct{},
			}),
			Entry("with a 409 status code", unmarshalIntoTableInput{
				result: &result{
					err: nil,
					response: &http.Response{
						StatusCode: http.StatusConflict,
					},
					body: []byte("{\"a\": \"foo\"}"),
				},
				expectedErr:    errors.New("unexpected status \"409\": {\"a\": \"foo\"}"),
				expectedOutput: &testStruct{},
			}),
			Entry("when the response has a valid json response", unmarshalIntoTableInput{
				result: &result{
					err: nil,
					response: &http.Response{
						StatusCode: http.StatusOK,
					},
					body: []byte("{\"a\": \"foo\", \"b\": 1}"),
				},
				expectedErr:    nil,
				expectedOutput: &testStruct{A: "foo", B: 1},
			}),
			Entry("when the response body is empty", unmarshalIntoTableInput{
				result: &result{
					err: nil,
					response: &http.Response{
						StatusCode: http.StatusOK,
					},
					body: []byte(""),
				},
				expectedErr:    errors.New("error unmarshalling body: unexpected end of JSON input"),
				expectedOutput: &testStruct{},
			}),
			Entry("when the response body is not json", unmarshalIntoTableInput{
				result: &result{
					err: nil,
					response: &http.Response{
						StatusCode: http.StatusOK,
					},
					body: []byte("not json"),
				},
				expectedErr:    errors.New("error unmarshalling body: invalid character 'o' in literal null (expecting 'u')"),
				expectedOutput: &testStruct{},
			}),
		)
	})

	Context("UnmarshalJSON", func() {
		type testStruct struct {
			A string `json:"a"`
			B int    `json:"b"`
		}

		type unmarshalJSONTableInput struct {
			result         Result
			expectedErr    error
			expectedOutput *testStruct
		}

		DescribeTable("with a result",
			func(in unmarshalJSONTableInput) {
				j, err := in.result.UnmarshalSimpleJSON()
				if in.expectedErr != nil {
					Expect(err).To(MatchError(in.expectedErr))
					Expect(j).To(BeNil())
					return
				}

				// No error so j should not be nil
				Expect(err).ToNot(HaveOccurred())

				input := &testStruct{
					A: j.Get("a").MustString(),
					B: j.Get("b").MustInt(),
				}
				Expect(input).To(Equal(in.expectedOutput))
			},
			Entry("with an error", unmarshalJSONTableInput{
				result: &result{
					err: errors.New("got an error"),
					response: &http.Response{
						StatusCode: http.StatusOK,
					},
					body: []byte("{\"a\": \"foo\"}"),
				},
				expectedErr:    errors.New("got an error"),
				expectedOutput: &testStruct{},
			}),
			Entry("with a 409 status code", unmarshalJSONTableInput{
				result: &result{
					err: nil,
					response: &http.Response{
						StatusCode: http.StatusConflict,
					},
					body: []byte("{\"a\": \"foo\"}"),
				},
				expectedErr:    errors.New("unexpected status \"409\": {\"a\": \"foo\"}"),
				expectedOutput: &testStruct{},
			}),
			Entry("when the response has a valid json response", unmarshalJSONTableInput{
				result: &result{
					err: nil,
					response: &http.Response{
						StatusCode: http.StatusOK,
					},
					body: []byte("{\"a\": \"foo\", \"b\": 1}"),
				},
				expectedErr:    nil,
				expectedOutput: &testStruct{A: "foo", B: 1},
			}),
			Entry("when the response body is empty", unmarshalJSONTableInput{
				result: &result{
					err: nil,
					response: &http.Response{
						StatusCode: http.StatusOK,
					},
					body: []byte(""),
				},
				expectedErr:    errors.New("error reading json: EOF"),
				expectedOutput: &testStruct{},
			}),
			Entry("when the response body is not json", unmarshalJSONTableInput{
				result: &result{
					err: nil,
					response: &http.Response{
						StatusCode: http.StatusOK,
					},
					body: []byte("not json"),
				},
				expectedErr:    errors.New("error reading json: invalid character 'o' in literal null (expecting 'u')"),
				expectedOutput: &testStruct{},
			}),
		)
	})

	Context("getBodyForUnmarshal", func() {
		type getBodyForUnmarshalTableInput struct {
			result       *result
			expectedErr  error
			expectedBody []byte
		}

		DescribeTable("when getting the body", func(in getBodyForUnmarshalTableInput) {
			body, err := in.result.getBodyForUnmarshal()
			if in.expectedErr != nil {
				Expect(err).To(MatchError(in.expectedErr))
			} else {
				Expect(err).ToNot(HaveOccurred())
			}
			Expect(body).To(Equal(in.expectedBody))
		},
			Entry("when the result has an error", getBodyForUnmarshalTableInput{
				result: &result{
					err: errors.New("got an error"),
					response: &http.Response{
						StatusCode: http.StatusOK,
					},
					body: []byte("body"),
				},
				expectedErr:  errors.New("got an error"),
				expectedBody: nil,
			}),
			Entry("when the response has a 409 status code", getBodyForUnmarshalTableInput{
				result: &result{
					err: nil,
					response: &http.Response{
						StatusCode: http.StatusConflict,
					},
					body: []byte("body"),
				},
				expectedErr:  errors.New("unexpected status \"409\": body"),
				expectedBody: nil,
			}),
			Entry("when the response has a 200 status code", getBodyForUnmarshalTableInput{
				result: &result{
					err: nil,
					response: &http.Response{
						StatusCode: http.StatusOK,
					},
					body: []byte("body"),
				},
				expectedErr:  nil,
				expectedBody: []byte("body"),
			}),
		)
	})
})
