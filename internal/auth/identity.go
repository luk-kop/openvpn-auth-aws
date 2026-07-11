package auth

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// NormalizeIdentity returns the case-insensitive ownership key while keeping
// the certificate CN itself unchanged for OpenVPN commands and diagnostics.
func NormalizeIdentity(value string) (string, error) {
	if value == "" {
		return "", fmt.Errorf("identity is empty")
	}
	if !utf8.ValidString(value) {
		return "", fmt.Errorf("identity is not valid UTF-8")
	}
	if strings.TrimSpace(value) != value {
		return "", fmt.Errorf("identity has surrounding whitespace")
	}
	return strings.ToLower(value), nil
}
