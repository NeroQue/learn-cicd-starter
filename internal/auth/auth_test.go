package auth_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/bootdotdev/learn-cicd-starter/internal/auth"
)

//func headerWithAuthorization(v string) http.Header {
//	h := http.Header{}
//	if v != "" {
//		h.Set("Authorization", v)
//	}
//	return h
//}

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name      string
		authValue string
		expectKey string
		expectErr string // "", "no-header", or exact error text
	}{
		{
			name:      "success_ApiKey_with_token",
			authValue: "ApiKey abc123",
			expectKey: "abc123",
			expectErr: "",
		},
		{
			name:      "missing_header",
			authValue: "",
			expectKey: "",
			expectErr: "no-header",
		},
		{
			name:      "empty_value_in_header_present",
			authValue: "", // leave header not set; if you want set-but-empty, set explicitly below
			expectKey: "",
			expectErr: "no-header",
		},
		{
			name:      "wrong_scheme_bearer",
			authValue: "Bearer abc123",
			expectKey: "",
			expectErr: "malformed authorization header",
		},
		{
			name:      "only_scheme_no_token",
			authValue: "ApiKey",
			expectKey: "",
			expectErr: "malformed authorization header",
		},
		{
			name:      "leading_space_before_scheme",
			authValue: " ApiKey abc123",
			expectKey: "",
			expectErr: "malformed authorization header",
		},
		{
			name:      "extra_spaces_between_scheme_and_token",
			authValue: "ApiKey   abc123",
			expectKey: "", // current implementation returns split[1] which is "", not "abc123"
			expectErr: "", // no error from current code; decide if you want to change implementation
		},
		{
			name:      "wrong_case_scheme",
			authValue: "apikey abc123",
			expectKey: "",
			expectErr: "malformed authorization header",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			if tc.name == "empty_value_in_header_present" {
				h.Set("Authorization", "")
			} else if tc.authValue != "" {
				h.Set("Authorization", tc.authValue)
			}

			key, err := auth.GetAPIKey(h)

			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if key != tc.expectKey {
					t.Fatalf("expected key %q, got %q", tc.expectKey, key)
				}
				return
			}

			// Error expected
			if tc.expectErr == "no-header" {
				if !errors.Is(err, auth.ErrNoAuthHeaderIncluded) {
					t.Fatalf("expected ErrNoAuthHeaderIncluded, got %v", err)
				}
				if key != "" {
					t.Fatalf("expected empty key, got %q", key)
				}
				return
			}

			// Expect specific error text (for inline-created malformed error)
			if err == nil {
				t.Fatalf("expected error %q, got nil", tc.expectErr)
			}
			if err.Error() != tc.expectErr {
				t.Fatalf("expected error %q, got %q", tc.expectErr, err.Error())
			}
			if key != "" {
				t.Fatalf("expected empty key, got %q", key)
			}
		})
	}
}
