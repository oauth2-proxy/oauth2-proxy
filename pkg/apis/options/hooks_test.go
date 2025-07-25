package options

import (
	"testing"
	"time"
)

func TestToDurationHook(t *testing.T) {
	type result struct {
		Duration time.Duration `yaml:"duration"`
	}

	tests := []struct {
		name        string
		input       map[string]interface{}
		out         result
		expected    time.Duration
		expectedErr bool
	}{
		{
			name:        "Valid String Duration with single unit",
			input:       map[string]interface{}{"duration": "3s"},
			out:         result{},
			expected:    3 * time.Second,
			expectedErr: false,
		},
		{
			name:        "Valid String Duration with multiple units",
			input:       map[string]interface{}{"duration": "1h20m30s"},
			out:         result{},
			expected:    1*time.Hour + 20*time.Minute + 30*time.Second,
			expectedErr: false,
		},
		{
			name:        "Valid Float Duration",
			input:       map[string]interface{}{"duration": 2.5},
			out:         result{},
			expected:    2500 * time.Millisecond,
			expectedErr: false,
		},
		{
			name:        "Valid Int64 Duration",
			input:       map[string]interface{}{"duration": int64(5000000000)},
			out:         result{},
			expected:    5 * time.Second,
			expectedErr: false,
		},
		{
			name:        "Invalid String",
			input:       map[string]interface{}{"duration": "invalid"},
			out:         result{},
			expected:    0,
			expectedErr: true,
		},
		{
			name:        "Unsupported Type",
			input:       map[string]interface{}{"duration": true},
			out:         result{},
			expected:    0,
			expectedErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result struct {
				Duration time.Duration `yaml:"duration"`
			}

			err := Decode(tt.input, &result)
			if (err != nil) != tt.expectedErr {
				t.Errorf("expected error: %v, got: %v", tt.expectedErr, err)
			}

			if !tt.expectedErr {
				if result.Duration != tt.expected {
					t.Errorf("expected: %v, got: %v", tt.expected, result.Duration)
				}
			}
		})
	}
}

func TestStringToBytesHook(t *testing.T) {
	var result struct {
		Value []byte `yaml:"value"`
	}

	if err := Decode(map[string]interface{}{"value": "hello-world"}, &result); err != nil {
		t.Fatal(err)
	}

	if string(result.Value) != "hello-world" {
		t.Errorf("expected %q, got %q", "hello-world", string(result.Value))
	}
}
