package traefik_jwt_plugin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	// Valid RS512 JWT token for testing
	testValidToken = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.JlX3gXGyClTBFciHhknWrjo7SKqyJ5iBO0n-3S2_I7cIgfaZAeRDJ3SQEbaPxVC7X8aqGCOM-pQOjZPKUJN8DMFrlHTOdqMs0TwQ2PRBmVAxXTSOZOoEhD4ZNCHohYoyfoDhJDP4Qye_FCqu6POJzg0Jcun4d3KW04QTiGxv2PkYqmB7nHxYuJdnqE3704hIS56pc_8q6AW0WIT0W-nIvwzaSbtBU9RgaC7ZpBD2LiNE265UBIFraMDF8IAFw9itZSUCTKg1Q-q27NwwBZNGYStMdIBDor2Bsq5ge51EkWajzZ7ALisVp-bskzUsqUf77ejqX_CBAqkNdH1Zebn93A"
	// Invalid token string for testing
	testInvalidToken = "invalid.token.here"
	// Public key for verifying the test token
	testPublicKey = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv\nvkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc\naT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy\ntvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0\ne+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb\nV6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9\nMwIDAQAB\n-----END PUBLIC KEY-----"
)

// TestMultipleHeaderValues tests the scenario where multiple JWT values are provided
// in comma-separated format within a single Authorization header
func TestMultipleHeaderValues(t *testing.T) {
	tests := []struct {
		name         string
		headerValue  string
		expectPass   bool
		expectedName string
	}{
		{
			name:         "valid token first in comma-separated list",
			headerValue:  "Bearer " + testValidToken + ", Bearer invalid",
			expectPass:   true,
			expectedName: "John Doe",
		},
		{
			name:         "valid token second in comma-separated list",
			headerValue:  "Bearer invalid, Bearer " + testValidToken,
			expectPass:   true,
			expectedName: "John Doe",
		},
		{
			name:         "valid token in middle of comma-separated list",
			headerValue:  "Bearer invalid1, Bearer " + testValidToken + ", Bearer invalid2",
			expectPass:   true,
			expectedName: "John Doe",
		},
		{
			name:        "all invalid tokens in comma-separated list",
			headerValue: "Bearer " + testInvalidToken + ", Bearer another.invalid.token",
			expectPass:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Required:   true,
				JwtHeaders: map[string]string{"Name": "name"},
				Keys:       []string{testPublicKey},
			}
			ctx := context.Background()
			nextCalled := false
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

			jwt, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
			if err != nil {
				t.Fatal(err)
			}

			recorder := httptest.NewRecorder()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header["Authorization"] = []string{tt.headerValue}

			jwt.ServeHTTP(recorder, req)

			if tt.expectPass {
				if !nextCalled {
					t.Fatal("Expected next.ServeHTTP to be called, but it wasn't")
				}
				if v := req.Header.Get("Name"); v != tt.expectedName {
					t.Fatalf("Expected header Name:%s, got %s", tt.expectedName, v)
				}
			} else {
				if nextCalled {
					t.Fatal("Expected next.ServeHTTP not to be called, but it was")
				}
			}
		})
	}
}

// TestDuplicateHeaders tests the scenario where multiple JWT tokens are provided
// using duplicate Authorization headers
func TestDuplicateHeaders(t *testing.T) {
	tests := []struct {
		name         string
		headerValues []string
		expectPass   bool
		expectedName string
	}{
		{
			name:         "valid token in first header",
			headerValues: []string{"Bearer " + testValidToken, "Bearer invalid"},
			expectPass:   true,
			expectedName: "John Doe",
		},
		{
			name:         "valid token in second header",
			headerValues: []string{"Bearer invalid", "Bearer " + testValidToken},
			expectPass:   true,
			expectedName: "John Doe",
		},
		{
			name:         "valid token in middle header",
			headerValues: []string{"Bearer invalid1", "Bearer " + testValidToken, "Bearer invalid2"},
			expectPass:   true,
			expectedName: "John Doe",
		},
		{
			name:         "all invalid tokens in duplicate headers",
			headerValues: []string{"Bearer " + testInvalidToken, "Bearer another.invalid.token"},
			expectPass:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Required:   true,
				JwtHeaders: map[string]string{"Name": "name"},
				Keys:       []string{testPublicKey},
			}
			ctx := context.Background()
			nextCalled := false
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

			jwt, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
			if err != nil {
				t.Fatal(err)
			}

			recorder := httptest.NewRecorder()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
			if err != nil {
				t.Fatal(err)
			}
			// Set multiple headers with the same key
			req.Header["Authorization"] = tt.headerValues

			jwt.ServeHTTP(recorder, req)

			if tt.expectPass {
				if !nextCalled {
					t.Fatal("Expected next.ServeHTTP to be called, but it wasn't")
				}
				if v := req.Header.Get("Name"); v != tt.expectedName {
					t.Fatalf("Expected header Name:%s, got %s", tt.expectedName, v)
				}
			} else {
				if nextCalled {
					t.Fatal("Expected next.ServeHTTP not to be called, but it was")
				}
			}
		})
	}
}

// TestCombinedMultipleHeadersAndValues tests both duplicate headers AND comma-separated values
func TestCombinedMultipleHeadersAndValues(t *testing.T) {
	cfg := Config{
		Required:   true,
		JwtHeaders: map[string]string{"Name": "name"},
		Keys:       []string{testPublicKey},
	}
	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { nextCalled = true })

	jwt, err := New(ctx, next, &cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set multiple headers, where the second header has comma-separated values with the valid token in the middle
	req.Header["Authorization"] = []string{
		"Bearer invalid1, Bearer invalid2",
		"Bearer invalid3, Bearer " + testValidToken + ", Bearer invalid4",
	}

	jwt.ServeHTTP(recorder, req)

	if !nextCalled {
		t.Fatal("Expected next.ServeHTTP to be called, but it wasn't")
	}
	if v := req.Header.Get("Name"); v != "John Doe" {
		t.Fatalf("Expected header Name:John Doe, got %s", v)
	}
}
