package auth

import "testing"

func TestNormalizeIdentity(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "lowercase", input: "alice@example.com", want: "alice@example.com"},
		{name: "case variant", input: "Alice@EXAMPLE.com", want: "alice@example.com"},
		{name: "unicode lowercase", input: "\u212A@example.com", want: "k@example.com"},
		{name: "leading whitespace", input: " alice@example.com", wantErr: true},
		{name: "trailing whitespace", input: "alice@example.com ", wantErr: true},
		{name: "empty", input: "", wantErr: true},
		{name: "invalid utf8", input: string([]byte{0xff}), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeIdentity(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NormalizeIdentity(%q) error = %v, wantErr %t", tt.input, err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("NormalizeIdentity(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
