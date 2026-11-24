package arm

import (
	"bytes"
	"testing"
)

func TestDeploymentCLIInlineTemplateEnvelope(t *testing.T) {
	for _, test := range []struct {
		name, body, expected string
		valid                bool
	}{
		{
			name:     "pinned Azure CLI serialization",
			body:     `{"properties": {"mode":"Incremental", template:{"metadata":{"literal":", template:inside-string"}}}}`,
			expected: `{"properties": {"mode":"Incremental", "template":{"metadata":{"literal":", template:inside-string"}}}}`,
			valid:    true,
		},
		{
			name:     "quoted JSON",
			body:     `{"properties":{"template":{"metadata":{"literal":"\\\"template: still a string"}}}}`,
			expected: `{"properties":{"template":{"metadata":{"literal":"\\\"template: still a string"}}}}`,
			valid:    true,
		},
		{
			name:     "unquoted unfamiliar key",
			body:     `{"properties":{"mode":"Incremental", properties:{}}}`,
			expected: `{"properties":{"mode":"Incremental", properties:{}}}`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			converted := quoteTemplateKey([]byte(test.body))
			if string(converted) != test.expected {
				t.Fatalf("unexpected normalization: %s", converted)
			}
			var input deploymentInput
			if err := strictJSON(bytes.NewReader(converted), &input); (err == nil) != test.valid {
				t.Fatalf("unexpected JSON decoder result: %v", err)
			}
		})
	}
}
