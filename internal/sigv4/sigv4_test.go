package sigv4

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	"tule.dev/accounts/internal/orgapi"
)

const (
	testAccessKey = "AKIDEXAMPLE"
	testSecretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
)

// The operations the tests sign: a read, and the destructive call a relay
// would rather it were.
const (
	describeTarget = "AWSOrganizationsV20161128.DescribeAccount"
	removeTarget   = "AWSOrganizationsV20161128.RemoveAccountFromOrganization"
)

var signedAt = time.Date(2026, time.March, 4, 5, 6, 7, 0, time.UTC)

// signedRequest builds a request signed the way the AWS SDK signs an Organizations
// Manager call, which is the only client this verifier has to satisfy.
func signedRequest(t *testing.T, body string) *http.Request {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Host = "organizations.localhost"
	req.Header.Set("Content-Type", orgapi.ContentType)
	req.Header.Set(orgapi.TargetHeader, describeTarget)

	// The SDK signs the payload hash into the canonical request without
	// sending it as a header, so the signer gets it and the server does not.
	sum := sha256.Sum256([]byte(body))

	creds := aws.Credentials{AccessKeyID: testAccessKey, SecretAccessKey: testSecretKey}
	if err := v4.NewSigner().SignHTTP(
		context.Background(), creds, req, hex.EncodeToString(sum[:]),
		"organizations", "us-east-1", signedAt,
	); err != nil {
		t.Fatalf("sign request: %v", err)
	}
	return req
}

func testVerifier() *Verifier {
	v := NewVerifier(Credentials{AccessKeyID: testAccessKey, SecretAccessKey: testSecretKey})
	v.now = func() time.Time { return signedAt }
	return v
}

func TestVerifyAcceptsASignedRequest(t *testing.T) {
	const body = `{"AccountId":"111111111111"}`

	req := signedRequest(t, body)
	if err := testVerifier().Verify(req); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// The handler must still see the body the signature covered.
	read, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(read) != body {
		t.Fatalf("body = %q, want %q", read, body)
	}
}

// rejectCase is one way a request can fail verification: how to break a
// correctly signed request, and the error type that must come back.
type rejectCase struct {
	tamper   func(*http.Request)
	verifier func() *Verifier
	name     string
	wantType string
}

// rejectCases is split in two only to keep each table short: the first covers
// what the Authorization header itself must carry, the second what the
// signature over the request must cover.
func rejectCases() []rejectCase {
	return append(headerRejectCases(), signatureRejectCases()...)
}

func headerRejectCases() []rejectCase {
	return []rejectCase{
		{
			name:     "no Authorization header",
			tamper:   func(r *http.Request) { r.Header.Del("Authorization") },
			wantType: orgapi.TypeMissingAuthToken,
		},
		{
			name: "unsupported algorithm",
			tamper: func(r *http.Request) {
				r.Header.Set("Authorization", "AWS4-HMAC-SHA512 Credential=x")
			},
			wantType: orgapi.TypeIncompleteSig,
		},
		{
			name: "incomplete header",
			tamper: func(r *http.Request) {
				r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=x/y/z/w/aws4_request")
			},
			wantType: orgapi.TypeIncompleteSig,
		},
		{
			name:     "missing date",
			tamper:   func(r *http.Request) { r.Header.Del("X-Amz-Date") },
			wantType: orgapi.TypeIncompleteSig,
		},
	}
}

func signatureRejectCases() []rejectCase {
	return []rejectCase{
		{
			name:   "tampered body",
			tamper: func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader(`{}`)) },
			// The body is hashed into the signature, so changing it is a
			// signature failure rather than a hash mismatch.
			wantType: orgapi.TypeInvalidSignature,
		},
		{
			name:     "tampered target",
			tamper:   func(r *http.Request) { r.Header.Set(orgapi.TargetHeader, removeTarget) },
			wantType: orgapi.TypeInvalidSignature,
		},
		{
			name: "declared payload hash does not match the body",
			tamper: func(r *http.Request) {
				r.Header.Set("X-Amz-Content-Sha256", strings.Repeat("a", 64))
			},
			wantType: orgapi.TypeInvalidInput,
		},
		{
			name: "unknown access key",
			verifier: func() *Verifier {
				v := NewVerifier(Credentials{AccessKeyID: "OTHER", SecretAccessKey: testSecretKey})
				v.now = func() time.Time { return signedAt }
				return v
			},
			wantType: orgapi.TypeUnrecognizedClient,
		},
		{
			name: "wrong secret key",
			verifier: func() *Verifier {
				v := NewVerifier(Credentials{AccessKeyID: testAccessKey, SecretAccessKey: "wrong"})
				v.now = func() time.Time { return signedAt }
				return v
			},
			wantType: orgapi.TypeInvalidSignature,
		},
		{
			name: "expired signature",
			verifier: func() *Verifier {
				v := NewVerifier(Credentials{
					AccessKeyID:     testAccessKey,
					SecretAccessKey: testSecretKey,
				})
				v.now = func() time.Time { return signedAt.Add(time.Hour) }
				return v
			},
			wantType: orgapi.TypeInvalidSignature,
		},
	}
}

func TestVerifyRejects(t *testing.T) {
	const body = `{"AccountId":"111111111111"}`

	for _, tt := range rejectCases() {
		t.Run(tt.name, func(t *testing.T) {
			req := signedRequest(t, body)
			if tt.tamper != nil {
				tt.tamper(req)
			}

			verifier := testVerifier()
			if tt.verifier != nil {
				verifier = tt.verifier()
			}

			err := verifier.Verify(req)

			var apiErr *orgapi.Error
			if !errors.As(err, &apiErr) {
				t.Fatalf("Verify = %v, want an *orgapi.Error", err)
			}
			if apiErr.Type != tt.wantType {
				t.Fatalf("error type = %s, want %s", apiErr.Type, tt.wantType)
			}
		})
	}
}

func TestVerifyRejectsAnOversizedBody(t *testing.T) {
	req := signedRequest(t, "{}")
	req.Body = io.NopCloser(strings.NewReader(strings.Repeat("a", MaxBodySize+1)))

	err := testVerifier().Verify(req)

	var apiErr *orgapi.Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("Verify = %v, want an *orgapi.Error", err)
	}
	if apiErr.Status != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", apiErr.Status, http.StatusRequestEntityTooLarge)
	}
}

// signedWith signs a request the way a hand-rolled client could, with the
// payload hash and the header set the caller chooses, so a test can produce
// the requests the AWS SDK never would.
func signedWith(t *testing.T, body, payloadHash string, headers map[string]string) *http.Request {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Host = "organizations.localhost"
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	creds := aws.Credentials{AccessKeyID: testAccessKey, SecretAccessKey: testSecretKey}
	if err := v4.NewSigner().SignHTTP(
		context.Background(), creds, req, payloadHash,
		"organizations", "us-east-1", signedAt,
	); err != nil {
		t.Fatalf("sign request: %v", err)
	}
	return req
}

func TestVerifyRejectsAnUnsignedPayload(t *testing.T) {
	// A request signed with UNSIGNED-PAYLOAD has a signature that covers no
	// part of the body, so whoever relays it can swap the body for another
	// operation's. Only a real hash binds the body, so nothing else is
	// accepted.
	req := signedWith(t, `{"AccountId":"111111111111"}`, unsignedPayload, map[string]string{
		"Content-Type":         orgapi.ContentType,
		orgapi.TargetHeader:    describeTarget,
		"X-Amz-Content-Sha256": unsignedPayload,
	})
	req.Body = io.NopCloser(
		strings.NewReader(`{"AccountId":"222222222222"}`),
	)

	err := testVerifier().Verify(req)

	var apiErr *orgapi.Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("Verify = %v, want an *orgapi.Error", err)
	}
	if apiErr.Type != orgapi.TypeIncompleteSig {
		t.Fatalf("error type = %s, want %s", apiErr.Type, orgapi.TypeIncompleteSig)
	}
}

func TestVerifyRequiresTheHeadersThatNameTheRequest(t *testing.T) {
	const body = `{"AccountId":"111111111111"}`

	tests := []struct {
		headers map[string]string
		after   func(*http.Request)
		name    string
	}{
		{
			// Signed without the operation header, which is then added: the
			// signature covers a request that does not say what it does, so
			// the relay picks the operation. Here a read becomes a removal.
			name: "unsigned operation header",
			headers: map[string]string{
				"Content-Type": orgapi.ContentType,
			},
			after: func(r *http.Request) {
				r.Header.Set(orgapi.TargetHeader, removeTarget)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sum := sha256.Sum256([]byte(body))
			req := signedWith(t, body, hex.EncodeToString(sum[:]), tt.headers)
			tt.after(req)

			err := testVerifier().Verify(req)

			var apiErr *orgapi.Error
			if !errors.As(err, &apiErr) {
				t.Fatalf("Verify = %v, want an *orgapi.Error", err)
			}
			if apiErr.Type != orgapi.TypeIncompleteSig {
				t.Fatalf("error type = %s, want %s", apiErr.Type, orgapi.TypeIncompleteSig)
			}
		})
	}
}
