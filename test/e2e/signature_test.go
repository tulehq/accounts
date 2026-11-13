//go:build e2e

package e2e

import (
	"context"
	"testing"

	awsorg "github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// These tests cover how the signature binds a request beyond what the SDK
// ordinarily sends: headers added after signing, SignedHeaders lists no SDK
// writes, and credentials scoped or issued for something else.

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
