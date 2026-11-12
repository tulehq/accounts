//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awsorg "github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
)

func TestProbesNeedNoCredentials(t *testing.T) {
	srv := startServer(t, nil)

	for _, path := range []string{"/_health", "/_ready"} {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
			srv.URL+path, nil)
		requireNoErr(t, err, "build request")

		res, err := srv.Client().Do(req)
		requireNoErr(t, err, "probe "+path)
		_ = res.Body.Close()
		requireEqual(t, res.StatusCode, http.StatusOK, "unsigned "+path)
	}
}

func TestUnsignedRequestIsRejected(t *testing.T) {
	// MissingAuthenticationToken (HTTP 403) is the AWS common error for a
	// request with no signature (Organizations API reference, Common Error
	// Types).
	srv := startServer(t, nil)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		srv.URL+"/", strings.NewReader(`{}`))
	requireNoErr(t, err, "build request")
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "AWSOrganizationsV20161128.DescribeOrganization")

	res, err := srv.Client().Do(req)
	requireNoErr(t, err, "unsigned request")
	defer func() { _ = res.Body.Close() }()

	requireEqual(t, res.StatusCode, http.StatusForbidden, "unsigned request status")
	requireEqual(t, errorType(t, res.Body), "MissingAuthenticationTokenException",
		"unsigned request error type")
}

func TestWrongCredentialsAreRejected(t *testing.T) {
	srv := startServer(t, nil)

	tests := []struct {
		name   string
		key    string
		secret string
		code   string
	}{
		// An access key the service does not know: UnrecognizedClient, as in
		// secret-store and the AWS common errors.
		{
			name:   "unknown access key",
			key:    "other",
			secret: "test",
			code:   "UnrecognizedClientException",
		},
		// The right key signed with the wrong secret: the signature does not
		// match, InvalidSignatureException in the AWS common errors.
		{name: "wrong secret", key: "test", secret: "other", code: "InvalidSignatureException"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := clientFor(srv, func(o *awsorg.Options) {
				o.Credentials = credentials.NewStaticCredentialsProvider(tt.key, tt.secret, "")
				o.RetryMaxAttempts = 1
			})

			_, err := c.CreateOrganization(context.Background(), &awsorg.CreateOrganizationInput{})
			requireCode(t, err, tt.code)
		})
	}

	// Neither rejected request may have created anything.
	_, err := clientFor(srv).DescribeOrganization(context.Background(),
		&awsorg.DescribeOrganizationInput{})
	requireAs[*types.AWSOrganizationsNotInUseException](t, err)
}

func TestUnknownAndUnsupportedOperations(t *testing.T) {
	// The spec has an out-of-scope operation answer as an unknown target does.
	// UnknownOperationException is the AWS JSON 1.1 answer to a target the
	// service does not have, and what secret-store asserts too. Assumption:
	// the Organizations reference itself does not document the unknown-target
	// response.
	srv := startServer(t, nil)
	c := clientFor(srv, func(o *awsorg.Options) { o.RetryMaxAttempts = 1 })
	ctx := context.Background()
	createOrg(t, c)

	t.Run("unknown target", func(t *testing.T) {
		_, err := c.DescribeOrganization(t.Context(), &awsorg.DescribeOrganizationInput{},
			func(o *awsorg.Options) {
				o.APIOptions = append(o.APIOptions,
					setTargetHeader("AWSOrganizationsV20161128.Nonsense"))
			})
		requireCode(t, err, "UnknownOperationException")
	})

	t.Run("CreatePolicy", func(t *testing.T) {
		_, err := c.CreatePolicy(t.Context(), &awsorg.CreatePolicyInput{
			Name:        aws.String("example"),
			Description: aws.String("example"),
			Content:     aws.String(`{"Version":"2012-10-17","Statement":[]}`),
			Type:        types.PolicyTypeServiceControlPolicy,
		})
		requireCode(t, err, "UnknownOperationException")
	})

	t.Run("LeaveOrganization", func(t *testing.T) {
		_, err := c.LeaveOrganization(t.Context(), &awsorg.LeaveOrganizationInput{})
		requireCode(t, err, "UnknownOperationException")
	})

	// The service is still up and the organization untouched.
	_, err := c.DescribeOrganization(ctx, &awsorg.DescribeOrganizationInput{})
	requireNoErr(t, err, "describe organization after unsupported calls")
}

func TestConfiguredManagementAccount(t *testing.T) {
	c := clientFor(startServer(t, map[string]string{
		"TULE_Organization_ManagementAccountID":    "111122223333",
		"TULE_Organization_ManagementAccountEmail": "management@example.com",
		"TULE_Organization_ManagementAccountName":  "Example Management",
	}))
	o := createOrg(t, c)

	requireEqual(t, o.ManagementID, "111122223333", "MasterAccountId")

	described, err := c.DescribeOrganization(
		context.Background(),
		&awsorg.DescribeOrganizationInput{},
	)
	requireNoErr(t, err, "describe organization")
	requireEqual(t, aws.ToString(described.Organization.MasterAccountEmail),
		"management@example.com", "MasterAccountEmail")
	requireEqual(t, aws.ToString(described.Organization.Arn),
		"arn:aws:organizations::111122223333:organization/"+o.ID, "organization ARN")

	acct := describeAccount(t, c, "111122223333")
	requireEqual(t, aws.ToString(acct.Name), "Example Management", "management account name")
	requireEqual(t, aws.ToString(acct.Email), "management@example.com", "management account email")
}

func TestDataSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.db")
	env := map[string]string{"TULE_Store_Path": path}
	ctx := context.Background()

	first := startServer(t, env)
	c := clientFor(first)
	o := createOrg(t, c)
	created := createAccount(t, c, "Persisted", "persisted@example.com")
	accountID := aws.ToString(created.AccountId)
	ouID := createOU(t, c, o.RootID, "Workloads")
	_, err := c.MoveAccount(ctx, &awsorg.MoveAccountInput{
		AccountId:           aws.String(accountID),
		SourceParentId:      aws.String(o.RootID),
		DestinationParentId: aws.String(ouID),
	})
	requireNoErr(t, err, "move account")
	_, err = c.TagResource(ctx, &awsorg.TagResourceInput{
		ResourceId: aws.String(ouID),
		Tags:       []types.Tag{{Key: aws.String("env"), Value: aws.String("dev")}},
	})
	requireNoErr(t, err, "tag OU")

	// The next process on the same file is what a restart looks like.
	first.Stop(t)
	c = clientFor(startServer(t, env))

	described, err := c.DescribeOrganization(ctx, &awsorg.DescribeOrganizationInput{})
	requireNoErr(t, err, "describe organization after restart")
	requireEqual(t, aws.ToString(described.Organization.Id), o.ID, "organization ID after restart")

	acct := describeAccount(t, c, accountID)
	requireEqual(t, aws.ToString(acct.Name), "Persisted", "account name after restart")
	requireEqual(
		t,
		aws.ToString(parentOf(t, c, accountID).Id),
		ouID,
		"account parent after restart",
	)
	requireEqual(t, tagsOf(t, c, ouID)["env"], "dev", "OU tag after restart")

	status, err := c.DescribeCreateAccountStatus(ctx, &awsorg.DescribeCreateAccountStatusInput{
		CreateAccountRequestId: created.Id,
	})
	requireNoErr(t, err, "describe create account status after restart")
	requireEqual(t, status.CreateAccountStatus.State, types.CreateAccountStateSucceeded,
		"create account state after restart")
}

func errorType(t *testing.T, body io.Reader) string {
	t.Helper()

	var envelope struct {
		Type string `json:"__type"`
	}
	if err := json.NewDecoder(body).Decode(&envelope); err != nil {
		t.Fatalf("decode error envelope: %v", err)
	}
	// AWS JSON 1.1 allows a namespace prefix ("ns#Code"); the code is what
	// follows it.
	if i := strings.LastIndex(envelope.Type, "#"); i >= 0 {
		return envelope.Type[i+1:]
	}
	return envelope.Type
}
