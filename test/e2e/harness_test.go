//go:build e2e

package e2e

import (
	"context"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awsorg "github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/gasmod/gas"
	"github.com/gasmod/gas/config"

	"tule.dev/accounts/internal/app"
)

// server is the app under test, served by the app's own *http.Server over a
// real TCP listener, as in secret-store's harness: the listener is created
// here because gas.App.Serve exposes neither the listener nor its port, and
// everything else is the server gas built from the bound configuration,
// reached over the network and shut down through gas.App.Stop.
type server struct {
	app      *gas.App
	listener net.Listener
	client   *http.Client
	served   chan error
	URL      string
	Addr     string
	stopped  bool
}

// clientTimeout bounds a test's own requests, so a hung server fails the test
// instead of the suite's timeout.
const clientTimeout = 30 * time.Second

// defaultManagementID is the management account ID the service uses when
// TULE_Organization_ManagementAccountID is unset.
const defaultManagementID = "000000000000"

// ID formats from the SDK model's field documentation (types.Organization.Id,
// types.Root.Id, types.OrganizationalUnit.Id, types.Account.Id,
// types.CreateAccountStatus.Id).
var (
	orgIDPattern     = regexp.MustCompile(`^o-[a-z0-9]{10,32}$`)
	rootIDPattern    = regexp.MustCompile(`^r-[0-9a-z]{4,32}$`)
	ouIDPattern      = regexp.MustCompile(`^ou-[0-9a-z]{4,32}-[a-z0-9]{8,32}$`)
	accountIDPattern = regexp.MustCompile(`^\d{12}$`)
	carIDPattern     = regexp.MustCompile(`^car-[a-z0-9]{8,32}$`)
)

// newClient starts the app on a fresh store and returns an SDK client pointed
// at it.
func newClient(t *testing.T) *awsorg.Client {
	t.Helper()
	return clientFor(startServer(t, nil))
}

// startServer starts the app on a fresh store, with env setting extra TULE_
// variables. It accepts the test/test credentials clientFor signs with unless
// env changes them.
func startServer(t *testing.T, env map[string]string) *server {
	t.Helper()

	setEnv(t, env)

	cfg, err := app.LoadConfigFrom(config.NewEnvProvider(
		config.WithEnvSeparator("_"),
		config.WithEnvPrefix("TULE_"),
	))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	a, err := app.New(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	// Start binds the configuration and initializes the services, so the
	// server built after it carries the configured timeouts.
	if err = a.Start(context.Background()); err != nil {
		t.Fatalf("start app: %v", err)
	}

	srv := serve(t, a)
	t.Cleanup(func() { srv.Stop(t) })
	return srv
}

func setEnv(t *testing.T, env map[string]string) {
	t.Helper()

	t.Setenv("TULE_GasEnv", "testing")
	t.Setenv("TULE_Store_Path", filepath.Join(t.TempDir(), "accounts.db"))
	t.Setenv("TULE_Auth_AccessKeyID", "test")
	t.Setenv("TULE_Auth_SecretAccessKey", "test")
	for k, v := range env {
		t.Setenv(k, v)
	}
}

// serve puts the app's own server on a loopback listener on a free port.
func serve(t *testing.T, a *gas.App) *server {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := &server{
		app:      a,
		listener: listener,
		client:   &http.Client{Timeout: clientTimeout},
		served:   make(chan error, 1),
		Addr:     listener.Addr().String(),
		URL:      "http://" + listener.Addr().String(),
	}

	go func() {
		srv.served <- a.Server().Serve(listener)
	}()

	return srv
}

// Client returns an HTTP client for the server.
func (s *server) Client() *http.Client {
	return s.client
}

// Stop shuts the app down the way a signal does, through gas.App.Stop, and
// fails the test if the shutdown or the server itself reported an error. It
// is idempotent, so a test can stop the server early and let the cleanup run
// anyway.
func (s *server) Stop(t *testing.T) {
	t.Helper()

	if s.stopped {
		return
	}
	s.stopped = true

	// Close the client's spare connections first; the server would otherwise
	// wait for them to age out during the shutdown.
	s.client.CloseIdleConnections()

	if err := s.app.Stop(context.Background()); err != nil {
		t.Errorf("stop app: %v", err)
	}

	select {
	case err := <-s.served:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("serve: %v", err)
		}
	case <-time.After(clientTimeout):
		t.Error("serve did not return after shutdown")
	}
}

// clientFor returns an SDK client for srv, with the test/test credentials
// unless opts change them.
func clientFor(srv *server, opts ...func(*awsorg.Options)) *awsorg.Client {
	return awsorg.New(awsorg.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String(srv.URL),
		Credentials:  credentials.NewStaticCredentialsProvider("test", "test", ""),
		HTTPClient:   srv.Client(),
	}, opts...)
}

// org is what a test needs to know about the organization it created.
type org struct {
	ID           string
	Arn          string
	RootID       string
	ManagementID string
}

// rootSuffix is the part of the root ID after "r-", which every OU ID in
// that root carries (types.OrganizationalUnit.Id).
func (o org) rootSuffix() string {
	return o.RootID[len("r-"):]
}

// newOrg starts the app on a fresh store, creates an organization with the
// default feature set, and returns a client and the organization.
func newOrg(t *testing.T) (*awsorg.Client, org) {
	t.Helper()
	c := newClient(t)
	return c, createOrg(t, c)
}

func createOrg(t *testing.T, c *awsorg.Client) org {
	t.Helper()
	ctx := t.Context()

	created, err := c.CreateOrganization(ctx, &awsorg.CreateOrganizationInput{})
	requireNoErr(t, err, "create organization")
	if created.Organization == nil {
		t.Fatal("create organization returned no organization")
	}

	roots, err := c.ListRoots(ctx, &awsorg.ListRootsInput{})
	requireNoErr(t, err, "list roots")
	requireEqual(t, len(roots.Roots), 1, "root count")

	return org{
		ID:           aws.ToString(created.Organization.Id),
		Arn:          aws.ToString(created.Organization.Arn),
		RootID:       aws.ToString(roots.Roots[0].Id),
		ManagementID: aws.ToString(created.Organization.MasterAccountId),
	}
}

// createAccount creates a member account and returns its final status,
// failing the test unless it succeeded.
func createAccount(t *testing.T, c *awsorg.Client, name, email string) types.CreateAccountStatus {
	t.Helper()

	out, err := c.CreateAccount(t.Context(), &awsorg.CreateAccountInput{
		AccountName: aws.String(name),
		Email:       aws.String(email),
	})
	requireNoErr(t, err, "create account "+name)
	if out.CreateAccountStatus == nil {
		t.Fatalf("create account %s returned no status", name)
	}
	st := *out.CreateAccountStatus
	if st.State != types.CreateAccountStateSucceeded {
		t.Fatalf("create account %s: state %s, failure reason %q", name, st.State, st.FailureReason)
	}
	return st
}

// createAccountID creates a member account and returns its ID.
func createAccountID(t *testing.T, c *awsorg.Client, name, email string) string {
	t.Helper()
	return aws.ToString(createAccount(t, c, name, email).AccountId)
}

// createOU creates an OU under parentID and returns its ID.
func createOU(t *testing.T, c *awsorg.Client, parentID, name string) string {
	t.Helper()

	out, err := c.CreateOrganizationalUnit(t.Context(),
		&awsorg.CreateOrganizationalUnitInput{
			ParentId: aws.String(parentID),
			Name:     aws.String(name),
		})
	requireNoErr(t, err, "create OU "+name)
	return aws.ToString(out.OrganizationalUnit.Id)
}

// describeAccount returns the account, failing the test on any error.
func describeAccount(t *testing.T, c *awsorg.Client, id string) types.Account {
	t.Helper()

	out, err := c.DescribeAccount(t.Context(), &awsorg.DescribeAccountInput{
		AccountId: aws.String(id),
	})
	requireNoErr(t, err, "describe account "+id)
	return *out.Account
}

// parentOf returns the single parent of an account or OU.
func parentOf(t *testing.T, c *awsorg.Client, childID string) types.Parent {
	t.Helper()

	out, err := c.ListParents(t.Context(), &awsorg.ListParentsInput{
		ChildId: aws.String(childID),
	})
	requireNoErr(t, err, "list parents of "+childID)
	requireEqual(t, len(out.Parents), 1, "parent count of "+childID)
	return out.Parents[0]
}

// tagsOf returns a resource's tags as a map, reading every page.
func tagsOf(t *testing.T, c *awsorg.Client, resourceID string) map[string]string {
	t.Helper()

	tags := map[string]string{}
	p := awsorg.NewListTagsForResourcePaginator(c, &awsorg.ListTagsForResourceInput{
		ResourceId: aws.String(resourceID),
	})
	for p.HasMorePages() {
		page, err := p.NextPage(t.Context())
		requireNoErr(t, err, "list tags for "+resourceID)
		for _, tag := range page.Tags {
			tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
		}
	}
	return tags
}

// accountIDs lists every account in the organization through the paginator.
func accountIDs(t *testing.T, c *awsorg.Client) []string {
	t.Helper()

	var ids []string
	p := awsorg.NewListAccountsPaginator(c, &awsorg.ListAccountsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(t.Context())
		requireNoErr(t, err, "list accounts")
		for _, a := range page.Accounts {
			ids = append(ids, aws.ToString(a.Id))
		}
	}
	return ids
}

// errOf returns the error of an SDK call and drops its output, for tests that
// call an operation only for the error it reports.
func errOf[T any](_ T, err error) error {
	return err
}

func requireNoErr(t *testing.T, err error, what string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

func requireEqual[T comparable](t *testing.T, got, want T, what string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s: got %v, want %v", what, got, want)
	}
}

func requireMatch(t *testing.T, re *regexp.Regexp, got, what string) {
	t.Helper()
	if !re.MatchString(got) {
		t.Fatalf("%s: %q does not match %s", what, got, re)
	}
}

// requireCode fails unless err is an API error with the given error code.
func requireCode(t *testing.T, err error, code string) {
	t.Helper()
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("want API error %s, got %v", code, err)
	}
	if apiErr.ErrorCode() != code {
		t.Fatalf("want error code %s, got %s (%v)", code, apiErr.ErrorCode(), err)
	}
}

// requireAs fails unless err matches the modeled SDK error type T.
func requireAs[T error](t *testing.T, err error) {
	t.Helper()
	var want T
	if !errors.As(err, &want) {
		t.Fatalf("want error of type %T, got %v", want, err)
	}
}

// requireInvalidInput fails unless err is an InvalidInputException with the
// given reason.
func requireInvalidInput(t *testing.T, err error, reason types.InvalidInputExceptionReason) {
	t.Helper()
	var e *types.InvalidInputException
	if !errors.As(err, &e) {
		t.Fatalf("want InvalidInputException %s, got %v", reason, err)
	}
	if e.Reason != reason {
		t.Fatalf("InvalidInputException reason = %q, want %q (%v)", e.Reason, reason, err)
	}
}

// requireConstraint fails unless err is a ConstraintViolationException with
// the given reason.
func requireConstraint(t *testing.T, err error, reason types.ConstraintViolationExceptionReason) {
	t.Helper()
	var e *types.ConstraintViolationException
	if !errors.As(err, &e) {
		t.Fatalf("want ConstraintViolationException %s, got %v", reason, err)
	}
	if e.Reason != reason {
		t.Fatalf("ConstraintViolationException reason = %q, want %q (%v)", e.Reason, reason, err)
	}
}

// setTargetHeader replaces the operation header the SDK sends, which is the
// only way to ask for an operation no Organizations client knows about. It
// runs before signing, so the request stays properly signed.
func setTargetHeader(target string) func(*middleware.Stack) error {
	return func(stack *middleware.Stack) error {
		return stack.Finalize.Add(middleware.FinalizeMiddlewareFunc(
			"e2eSetTargetHeader",
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
