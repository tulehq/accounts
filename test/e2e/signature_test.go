//go:build e2e

package e2e

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"

	awsorg "github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// These tests cover how the signature binds a request beyond what the SDK
// ordinarily sends: headers added after signing, SignedHeaders lists no SDK
// writes, and credentials scoped or issued for something else.

const (
	targetPrefix   = "AWSOrganizationsV20161128."
	describeTarget = targetPrefix + "DescribeOrganization"
	amzJSON        = "application/x-amz-json-1.1"
)

func TestAnUnsignedAmzHeaderIsRefused(t *testing.T) {
	// AWS requires every x-amz-* header a request carries to be signed. One
	// added after signing is outside the signature, so a relay could add it
	// to any signed request.
	c := clientFor(startServer(t, nil), func(o *awsorg.Options) { o.RetryMaxAttempts = 1 })

	_, err := c.DescribeOrganization(t.Context(), &awsorg.DescribeOrganizationInput{},
		func(o *awsorg.Options) {
			o.APIOptions = append(o.APIOptions, addHeaderAfterSigning("X-Amz-Extra", "added"))
		})
	requireCode(t, err, "IncompleteSignatureException")
}

func TestSignedHeadersMustBeCanonical(t *testing.T) {
	// SigV4 lists the signed headers lowercase, sorted and unique. Each
	// request below is signed over the list exactly as it is sent, so only
	// the list's form can refuse it.
	srv := startServer(t, nil)

	tests := []struct {
		name          string
		signedHeaders string
		code          string
	}{
		// The control: the canonical list, signed by hand the same way, is
		// served, and DescribeOrganization reports there is no organization.
		{
			name:          "canonical",
			signedHeaders: "content-type;host;x-amz-date;x-amz-target",
			code:          "AWSOrganizationsNotInUseException",
		},
		{
			name:          "unsorted",
			signedHeaders: "host;content-type;x-amz-date;x-amz-target",
			code:          "IncompleteSignatureException",
		},
		{
			name:          "uppercase",
			signedHeaders: "Content-Type;host;x-amz-date;x-amz-target",
			code:          "IncompleteSignatureException",
		},
		{
			name:          "repeated",
			signedHeaders: "content-type;content-type;host;x-amz-date;x-amz-target",
			code:          "IncompleteSignatureException",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := handSigned(t, srv, tt.signedHeaders)
			status, code := send(t, srv, req)
			requireEqual(t, code, tt.code, "error type")
			if tt.code == "IncompleteSignatureException" {
				requireEqual(t, status, http.StatusForbidden, "status")
			}
		})
	}
}

func TestALargeRepeatedSignedHeadersListReturnsQuickly(t *testing.T) {
	// Each entry of the list puts its header's value into the canonical
	// request again, so a list naming one large header thousands of times
	// would have the server build and hash a canonical request of hundreds
	// of MiB. The list is refused before any of that.
	srv := startServer(t, nil)

	const (
		repeats   = 10000
		valueSize = 16 << 10
		// The headers sent are under 100 KiB; the canonical request the
		// list describes is 160 MiB.
		maxAllocated = 16 << 20
	)
	req := handSigned(t, srv, "host;x-amz-date;x-amz-target")
	req.Header.Set("X-Pad", strings.Repeat("a", valueSize))
	auth := req.Header.Get("Authorization")
	req.Header.Set("Authorization", strings.Replace(auth,
		"SignedHeaders=host;x-amz-date;x-amz-target",
		"SignedHeaders=host;x-amz-date;x-amz-target"+strings.Repeat(";x-pad", repeats), 1))

	// The server runs in this process, so what it allocates serving the
	// request shows in this process's allocation total.
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	status, code := send(t, srv, req)
	elapsed := time.Since(start)
	runtime.ReadMemStats(&after)

	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > maxAllocated {
		t.Errorf("the request allocated %d MiB, want at most %d MiB",
			allocated>>20, maxAllocated>>20)
	}
	if elapsed > 2*time.Second {
		t.Errorf("the request took %s, want it refused within 2s", elapsed)
	}
	requireEqual(t, status, http.StatusForbidden, "status")
	requireEqual(t, code, "IncompleteSignatureException", "error type")
}

func TestARequestSignedForAnyRegionIsServed(t *testing.T) {
	// Organizations is global behind us-east-1, and local clients are set up
	// for whatever region they work in, so the credential's region is signed
	// but not checked.
	c := clientFor(startServer(t, nil), func(o *awsorg.Options) { o.RetryMaxAttempts = 1 })

	_, err := c.DescribeOrganization(t.Context(), &awsorg.DescribeOrganizationInput{},
		awsorg.WithSigV4SigningRegion("eu-west-1"))
	requireAs[*types.AWSOrganizationsNotInUseException](t, err)
}

// addHeaderAfterSigning sets a header on the request once the SDK has signed
// it, so the signature does not cover it.
func addHeaderAfterSigning(name, value string) func(*middleware.Stack) error {
	return func(stack *middleware.Stack) error {
		return stack.Finalize.Add(middleware.FinalizeMiddlewareFunc(
			"e2eAddHeaderAfterSigning",
			func(
				ctx context.Context,
				in middleware.FinalizeInput,
				next middleware.FinalizeHandler,
			) (middleware.FinalizeOutput, middleware.Metadata, error) {
				if req, ok := in.Request.(*smithyhttp.Request); ok {
					req.Header.Set(name, value)
				}
				return next.HandleFinalize(ctx, in)
			},
		), middleware.After)
	}
}

// handSigned builds a DescribeOrganization POST with an empty JSON body, signed with the
// test/test key over signedHeaders exactly as given. The SDK signer always
// writes the list canonically, so the list is signed by hand: each entry,
// as written, names a line of the canonical headers, its value the header
// that name looks up (Host for "host"), or empty when it names none.
func handSigned(t *testing.T, srv *server, signedHeaders string) *http.Request {
	t.Helper()

	const body = `{}`
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		srv.URL+"/", strings.NewReader(body))
	requireNoErr(t, err, "build request")

	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	day := now.Format("20060102")
	req.Header.Set("Content-Type", amzJSON)
	req.Header.Set("X-Amz-Target", describeTarget)
	req.Header.Set("X-Amz-Date", amzDate)

	var headers strings.Builder
	for name := range strings.SplitSeq(signedHeaders, ";") {
		value := strings.Join(req.Header.Values(name), ",")
		if name == "host" {
			value = req.URL.Host
		}
		headers.WriteString(name + ":" + value + "\n")
	}

	canonical := strings.Join([]string{
		http.MethodPost, "/", "", headers.String(), signedHeaders, sha256Hex(body),
	}, "\n")
	scope := day + "/us-east-1/organizations/aws4_request"
	toSign := strings.Join([]string{
		"AWS4-HMAC-SHA256", amzDate, scope, sha256Hex(canonical),
	}, "\n")

	key := hmacSHA256([]byte("AWS4test"), day)
	for _, part := range []string{"us-east-1", "organizations", "aws4_request"} {
		key = hmacSHA256(key, part)
	}
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=test/"+scope+
		", SignedHeaders="+signedHeaders+
		", Signature="+hex.EncodeToString(hmacSHA256(key, toSign)))
	return req
}

// send sends req and returns the response's status and error type, empty
// on success.
func send(t *testing.T, srv *server, req *http.Request) (int, string) {
	t.Helper()

	res, err := srv.Client().Do(req)
	requireNoErr(t, err, "send request")
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode == http.StatusOK {
		_, _ = io.Copy(io.Discard, res.Body)
		return res.StatusCode, ""
	}
	return res.StatusCode, errorType(t, res.Body)
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}
