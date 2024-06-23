package options

import (
	"encoding/json"
	"errors"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Common", func() {
	Context("Duration", func() {
		type marshalJSONTableInput struct {
			duration     Duration
			expectedJSON string
		}

		DescribeTable("MarshalJSON",
			func(in marshalJSONTableInput) {
				data, err := in.duration.MarshalJSON()
				Expect(err).ToNot(HaveOccurred())
				Expect(string(data)).To(Equal(in.expectedJSON))

				var d Duration
				Expect(json.Unmarshal(data, &d)).To(Succeed())
				Expect(d).To(Equal(in.duration))
			},
			Entry("30 seconds", marshalJSONTableInput{
				duration:     Duration(30 * time.Second),
				expectedJSON: "\"30s\"",
			}),
			Entry("1 minute", marshalJSONTableInput{
				duration:     Duration(1 * time.Minute),
				expectedJSON: "\"1m0s\"",
			}),
			Entry("1 hour 15 minutes", marshalJSONTableInput{
				duration:     Duration(75 * time.Minute),
				expectedJSON: "\"1h15m0s\"",
			}),
			Entry("A zero Duration", marshalJSONTableInput{
				duration:     Duration(0),
				expectedJSON: "\"0s\"",
			}),
		)

		type unmarshalJSONTableInput struct {
			json             string
			expectedErr      error
			expectedDuration Duration
		}

		DescribeTable("UnmarshalJSON",
			func(in unmarshalJSONTableInput) {
				// A duration must be initialised pointer before UnmarshalJSON will work.
				zero := Duration(0)
				d := &zero

				err := d.UnmarshalJSON([]byte(in.json))
				if in.expectedErr != nil {
					Expect(err).To(MatchError(in.expectedErr.Error()))
				} else {
					Expect(err).ToNot(HaveOccurred())
				}
				Expect(d).ToNot(BeNil())
				Expect(*d).To(Equal(in.expectedDuration))
			},
			Entry("1m", unmarshalJSONTableInput{
				json:             "\"1m\"",
				expectedDuration: Duration(1 * time.Minute),
			}),
			Entry("30s", unmarshalJSONTableInput{
				json:             "\"30s\"",
				expectedDuration: Duration(30 * time.Second),
			}),
			Entry("1h15m", unmarshalJSONTableInput{
				json:             "\"1h15m\"",
				expectedDuration: Duration(75 * time.Minute),
			}),
			Entry("am", unmarshalJSONTableInput{
				json:             "\"am\"",
				expectedErr:      errors.New("time: invalid duration \"am\""),
				expectedDuration: Duration(0),
			}),
		)
	})
})
