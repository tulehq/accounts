package app

import (
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// startApp starts the app on a store in dir and returns an SDK client for
// its handler. The full server, over TCP, is what test/e2e drives; this only
// checks the wiring, the protocol and the store meet as the SDK expects.
func startApp(t *testing.T, dir string) *organizations.Client {
	t.Helper()
	t.Setenv("TULE_Store_Path", filepath.Join(dir, "nested", "accounts.db"))

	cfg, err := loadEnvConfig(t, "test", "test")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	if err = a.Start(context.Background()); err != nil {
		t.Fatalf("start app: %v", err)
	}
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(func() {
		srv.Close()
		if sErr := a.Shutdown(context.Background()); sErr != nil {
			t.Errorf("shutdown: %v", sErr)
		}
	})

	return organizations.New(organizations.Options{
		Region:           "us-east-1",
		BaseEndpoint:     aws.String(srv.URL),
		Credentials:      credentials.NewStaticCredentialsProvider("test", "test", ""),
		HTTPClient:       srv.Client(),
		RetryMaxAttempts: 1,
	})
}

func TestTheSDKCreatesAnOrganizationAndAnAccount(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	c := startApp(t, dir)

	org, err := c.CreateOrganization(ctx, &organizations.CreateOrganizationInput{})
	if err != nil {
		t.Fatalf("create organization: %v", err)
	}
	if got := org.Organization.FeatureSet; got != types.OrganizationFeatureSetAll {
		t.Fatalf("feature set = %s, want ALL", got)
	}

	created, err := c.CreateAccount(ctx, &organizations.CreateAccountInput{
		AccountName: aws.String("dev"),
		Email:       aws.String("dev@example.com"),
	})
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	st := created.CreateAccountStatus
	requireCompleted(t, st)

	got, err := c.DescribeAccount(ctx, &organizations.DescribeAccountInput{
		AccountId: st.AccountId,
	})
	if err != nil {
		t.Fatalf("describe account: %v", err)
	}
	if got.Account.State != types.AccountStateActive ||
		got.Account.JoinedMethod != types.AccountJoinedMethodCreated {
		t.Fatalf("account = %+v, want ACTIVE and CREATED", got.Account)
	}

	// The store is the SQLite file under the configured path, created with
	// the directory it sits in.
	if _, err = os.Stat(filepath.Join(dir, "nested", "accounts.db")); err != nil {
		t.Fatalf("store file: %v", err)
	}
}

// requireCompleted fails unless st is a request that succeeded, as the SDK
// decoded it: its state, the new account's ID and both timestamps.
func requireCompleted(t *testing.T, st *types.CreateAccountStatus) {
	t.Helper()
	if st.State != types.CreateAccountStateSucceeded || st.AccountId == nil {
		t.Fatalf("create account status = %+v, want SUCCEEDED with an account ID", st)
	}
	if st.RequestedTimestamp == nil || st.CompletedTimestamp == nil {
		t.Fatalf("create account status = %+v, want both timestamps", st)
	}
}

func TestTheSDKDecodesErrorsWithTheirReason(t *testing.T) {
	ctx := context.Background()
	c := startApp(t, t.TempDir())

	_, err := c.DescribeOrganization(ctx, &organizations.DescribeOrganizationInput{})
	var notInUse *types.AWSOrganizationsNotInUseException
	if !errors.As(err, &notInUse) {
		t.Fatalf("describe organization before create = %v, want "+
			"AWSOrganizationsNotInUseException", err)
	}

	if _, err = c.CreateOrganization(ctx, &organizations.CreateOrganizationInput{}); err != nil {
		t.Fatalf("create organization: %v", err)
	}
	_, err = c.ListAccounts(ctx, &organizations.ListAccountsInput{MaxResults: aws.Int32(21)})
	var invalid *types.InvalidInputException
	if !errors.As(err, &invalid) {
		t.Fatalf("list accounts with MaxResults 21 = %v, want InvalidInputException", err)
	}
	if invalid.Reason != types.InvalidInputExceptionReasonMaxValueExceeded {
		t.Fatalf("reason = %s, want MAX_VALUE_EXCEEDED", invalid.Reason)
	}
}

func TestAnUnservedOperationIsUnknown(t *testing.T) {
	ctx := context.Background()
	c := startApp(t, t.TempDir())

	// LeaveOrganization is an Organizations operation this service leaves
	// out, which AWS-shaped clients must see as unknown, not as a failure of
	// the operation itself.
	_, err := c.LeaveOrganization(ctx, &organizations.LeaveOrganizationInput{})
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "UnknownOperationException" {
		t.Fatalf("leave organization = %v, want UnknownOperationException", err)
	}
}

func TestATargetMustBeExactlyAnOperationUnderTheServicePrefix(t *testing.T) {
	ctx := context.Background()
	c := startApp(t, t.TempDir())
	if _, err := c.CreateOrganization(ctx, &organizations.CreateOrganizationInput{}); err != nil {
		t.Fatalf("create organization: %v", err)
	}

	for _, target := range []string{
		"ListRoots",
		"x.AWSOrganizationsV20161128.ListRoots",
		"awsorganizationsv20161128.ListRoots",
		"AWSOrganizationsV20161128.",
		"AWSOrganizationsV20161128.LeaveOrganization",
	} {
		t.Run(target, func(t *testing.T) {
			_, err := c.ListRoots(ctx, &organizations.ListRootsInput{},
				func(o *organizations.Options) {
					o.APIOptions = append(o.APIOptions, setTarget(target))
				})
			var apiErr smithy.APIError
			if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "UnknownOperationException" {
				t.Fatalf("target %q = %v, want UnknownOperationException", target, err)
			}
		})
	}
}

// setTarget replaces the X-Amz-Target header the SDK sends. It runs before
// signing, so the request stays properly signed.
func setTarget(target string) func(*middleware.Stack) error {
	return func(stack *middleware.Stack) error {
		return stack.Finalize.Add(middleware.FinalizeMiddlewareFunc(
			"testSetTarget",
			func(
				ctx context.Context,
				in middleware.FinalizeInput,
				next middleware.FinalizeHandler,
			) (middleware.FinalizeOutput, middleware.Metadata, error) {
				if req, ok := in.Request.(*smithyhttp.Request); ok {
					req.Header.Set("X-Amz-Target", target)
				}
				return next.HandleFinalize(ctx, in)
			},
		), middleware.Before)
	}
}

func TestTheStaticKeyIsRootUnderAConfiguredAccount(t *testing.T) {
	t.Setenv("TULE_Organization_ManagementAccountID", "123456789012")
	c := startApp(t, t.TempDir())

	out, err := c.CreateOrganization(context.Background(),
		&organizations.CreateOrganizationInput{})
	if err != nil {
		t.Fatalf("create organization: %v", err)
	}
	if got := aws.ToString(out.Organization.MasterAccountId); got != "123456789012" {
		t.Fatalf("management account = %s", got)
	}
	if _, err = c.ListAccounts(context.Background(),
		&organizations.ListAccountsInput{}); err != nil {
		t.Fatalf("list accounts with the static key: %v", err)
	}
}
