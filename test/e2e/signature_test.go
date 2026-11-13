//go:build e2e

package e2e

import (
	"testing"

	awsorg "github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
)

// These tests cover how the signature binds a request beyond what the SDK
// ordinarily sends: headers added after signing, SignedHeaders lists no SDK
// writes, and credentials scoped or issued for something else.

func TestARequestSignedForAnyRegionIsServed(t *testing.T) {
	// Organizations is global behind us-east-1, and local clients are set up
	// for whatever region they work in, so the credential's region is signed
	// but not checked.
	c := clientFor(startServer(t, nil), func(o *awsorg.Options) { o.RetryMaxAttempts = 1 })

	_, err := c.DescribeOrganization(t.Context(), &awsorg.DescribeOrganizationInput{},
		awsorg.WithSigV4SigningRegion("eu-west-1"))
	requireAs[*types.AWSOrganizationsNotInUseException](t, err)
}
