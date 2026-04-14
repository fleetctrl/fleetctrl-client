package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalize(t *testing.T) {
	input := "  aa-bb:cc dd  "
	want := "AABBCCDD"

	assert.Equal(t, want, normalize(input))
}

func TestIsJunk(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "empty", input: "", want: true},
		{name: "unknown", input: " Unknown ", want: true},
		{name: "default string", input: "Default String", want: true},
		{name: "not specified", input: "Not Specified", want: true},
		{name: "real value", input: "ABC-123", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isJunk(tt.input))
		})
	}
}
