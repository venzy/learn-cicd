// go
package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		authHeader string
		wantKey    string
		wantErr    error
	}{
		{
			name:       "no authorization header",
			authHeader: "",
			wantKey:    "",
			wantErr:    ErrNoAuthHeaderIncluded,
		},
		{
			name:       "wrong prefix",
			authHeader: "Bearer sometoken",
			wantKey:    "",
			wantErr:    errors.New("malformed authorization header"),
		},
		{
			name:       "only prefix",
			authHeader: "ApiKey",
			wantKey:    "",
			wantErr:    errors.New("malformed authorization header"),
		},
		{
			name:       "correct prefix and key",
			authHeader: "ApiKey my-secret-key",
			wantKey:    "my-secret-key",
			wantErr:    nil,
		},
		{
			name:       "extra spaces",
			authHeader: "ApiKey    spaced-key",
			wantKey:    "spaced-key",
			wantErr:    nil,
		},
		{
			name:       "multiple words after prefix",
			authHeader: "ApiKey key1 key2",
			wantKey:    "key1",
			wantErr:    nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			headers := http.Header{}
			if tc.authHeader != "" {
				headers.Set("Authorization", tc.authHeader)
			}
			gotKey, gotErr := GetAPIKey(headers)
			if gotKey != tc.wantKey {
				t.Errorf("expected key %q, got %q", tc.wantKey, gotKey)
			}
			if (gotErr != nil && tc.wantErr == nil) || (gotErr == nil && tc.wantErr != nil) {
				t.Errorf("expected error %v, got %v", tc.wantErr, gotErr)
			}
			if gotErr != nil && tc.wantErr != nil && gotErr.Error() != tc.wantErr.Error() {
				t.Errorf("expected error %v, got %v", tc.wantErr, gotErr)
			}
		})
	}
}
