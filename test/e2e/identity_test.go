//go:build e2e

package e2e

import (
	"bytes"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	awsorg "github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// These tests run accounts against a real identity service: identity is
// built from its checkout and run as a process, with the same root key, and
// pointed back at the accounts app under test for AssumeRole, so the one
// accounts serves both directions.

// identityDirEnv names the identity checkout to build, for a layout where it
// is not accounts' sibling.
const identityDirEnv = "TULE_E2E_IDENTITY_DIR"

// The root key both services are configured with. It is the AWS
// documentation's example key, since identity holds an access key ID given
// to an IAM operation to accessKeyIdType, at least 16 characters, which
// "test" would not meet.
const (
	identityRootKeyID  = "AKIAIOSFODNN7EXAMPLE"
	identityRootSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
)

// organizationRole is the role identity lets the root user assume in a
// member account.
const organizationRole = "OrganizationAccountAccessRole"

// identityStack is the accounts app under test with a running identity
// pointed at it, and clients for both.
type identityStack struct {
	srv         *server
	identity    *identityProcess
	root        *awsorg.Client
	iam         *iam.Client
	identityURL string
	rootCreds   aws.Credentials
}

func TestIdentityIssuedKeys(t *testing.T) {
	s := startIdentityStack(t)
	user := orgClientWith(s.srv, createUserKey(t, s.iam, "dev"))

	t.Run("a user key calls Organizations", func(t *testing.T) {
		_, err := user.CreateOrganization(t.Context(), &awsorg.CreateOrganizationInput{})
		requireNoErr(t, err, "create organization with the IAM user's key")
		_, err = user.DescribeOrganization(t.Context(), &awsorg.DescribeOrganizationInput{})
		requireNoErr(t, err, "describe organization with the IAM user's key")
		ids := accountIDs(t, user)
		requireEqual(t, len(ids), 1, "accounts listed with the IAM user's key")
		requireEqual(t, ids[0], defaultManagementID, "the management account")
	})
	t.Run("the root key keeps working", func(t *testing.T) {
		_, err := s.root.DescribeOrganization(t.Context(), &awsorg.DescribeOrganizationInput{})
		requireNoErr(t, err, "describe organization with the root key")
	})
	t.Run("an inactive key is refused", s.testInactiveKey)
	t.Run("a deleted key is refused", s.testDeletedKey)
	t.Run("a role session's credentials call Organizations", s.testRoleSession)

	// Last, since it stops identity.
	t.Run("identity down fails a user key as a fault, not a refusal", func(t *testing.T) {
		s.identity.Stop(t)

		err := errOf(user.DescribeOrganization(t.Context(), &awsorg.DescribeOrganizationInput{}))
		requireCode(t, err, "ServiceException")
		requireStatus(t, err, http.StatusInternalServerError)

		_, err = s.root.DescribeOrganization(t.Context(), &awsorg.DescribeOrganizationInput{})
		requireNoErr(t, err, "describe organization with the root key while identity is down")
	})
}

// startIdentityStack starts accounts pointed at identity on a free port,
// then identity on that port pointed back at accounts.
func startIdentityStack(t *testing.T) *identityStack {
	t.Helper()

	port := identityFreePort(t)
	s := &identityStack{
		identityURL: "http://127.0.0.1:" + strconv.Itoa(port),
		rootCreds: aws.Credentials{
			AccessKeyID:     identityRootKeyID,
			SecretAccessKey: identityRootSecret,
		},
	}
	s.srv = startServer(t, map[string]string{
		"TULE_Auth_AccessKeyID":      identityRootKeyID,
		"TULE_Auth_SecretAccessKey":  identityRootSecret,
		"TULE_Auth_IdentityEndpoint": s.identityURL,
	})
	s.identity = startIdentity(t, port, s.srv.URL)
	s.root = orgClientWith(s.srv, s.rootCreds)
	s.iam = iamClient(s.identityURL, s.rootCreds)
	return s
}

func (s *identityStack) testInactiveKey(t *testing.T) {
	key := createUserKey(t, s.iam, "inactive")
	_, err := s.iam.UpdateAccessKey(t.Context(), &iam.UpdateAccessKeyInput{
		UserName:    aws.String("inactive"),
		AccessKeyId: aws.String(key.AccessKeyID),
		Status:      iamtypes.StatusTypeInactive,
	})
	requireNoErr(t, err, "deactivate the key")

	requireUnrecognized(t, orgClientWith(s.srv, key))
}

func (s *identityStack) testDeletedKey(t *testing.T) {
	key := createUserKey(t, s.iam, "deleted")
	c := orgClientWith(s.srv, key)
	_, err := c.DescribeOrganization(t.Context(), &awsorg.DescribeOrganizationInput{})
	requireNoErr(t, err, "describe organization before the key is deleted")

	_, err = s.iam.DeleteAccessKey(t.Context(), &iam.DeleteAccessKeyInput{
		UserName:    aws.String("deleted"),
		AccessKeyId: aws.String(key.AccessKeyID),
	})
	requireNoErr(t, err, "delete the key")

	requireUnrecognized(t, c)
}

// testRoleSession assumes the organization role in a new member account
// through identity, as the root user, and calls accounts with the session.
func (s *identityStack) testRoleSession(t *testing.T) {
	member := createAccountID(t, s.root, "Member", "member@example.com")

	out, err := stsClient(s.identityURL, s.rootCreds).AssumeRole(t.Context(), &sts.AssumeRoleInput{
		RoleArn:         aws.String("arn:aws:iam::" + member + ":role/" + organizationRole),
		RoleSessionName: aws.String("e2e"),
	})
	requireNoErr(t, err, "assume role in "+member)
	session := aws.Credentials{
		AccessKeyID:     aws.ToString(out.Credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(out.Credentials.SecretAccessKey),
		SessionToken:    aws.ToString(out.Credentials.SessionToken),
	}

	got := describeAccount(t, orgClientWith(s.srv, session), member)
	requireEqual(t, aws.ToString(got.Id), member, "account described with the session")

	tampered := session
	tampered.SessionToken = tamper(session.SessionToken)
	requireUnrecognized(t, orgClientWith(s.srv, tampered))

	// A session key is only valid with its token.
	requireMatch(t, regexp.MustCompile(`^ASIA`), session.AccessKeyID, "session key ID")
	tokenless := session
	tokenless.SessionToken = ""
	requireUnrecognized(t, orgClientWith(s.srv, tokenless))
}

// requireUnrecognized fails unless a call with c is refused as AWS refuses
// an invalid key or token.
func requireUnrecognized(t *testing.T, c *awsorg.Client) {
	t.Helper()
	err := errOf(c.DescribeOrganization(t.Context(), &awsorg.DescribeOrganizationInput{}))
	requireCode(t, err, "UnrecognizedClientException")
	requireStatus(t, err, http.StatusForbidden)
}

// tamper changes one character of a session token, keeping it the same
// length and alphabet.
func tamper(token string) string {
	if token == "" {
		return "x"
	}
	b := []byte(token)
	i := len(b) / 2
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	return string(b)
}

// orgClientWith returns an SDK client for srv signing with creds.
func orgClientWith(srv *server, creds aws.Credentials) *awsorg.Client {
	return clientFor(srv, func(o *awsorg.Options) {
		o.Credentials = credentials.StaticCredentialsProvider{Value: creds}
		o.RetryMaxAttempts = 1
	})
}

func iamClient(url string, creds aws.Credentials) *iam.Client {
	return iam.New(iam.Options{
		Region:           "us-east-1",
		BaseEndpoint:     aws.String(url),
		Credentials:      credentials.StaticCredentialsProvider{Value: creds},
		HTTPClient:       &http.Client{Timeout: clientTimeout},
		RetryMaxAttempts: 1,
	})
}

func stsClient(url string, creds aws.Credentials) *sts.Client {
	return sts.New(sts.Options{
		Region:           "us-east-1",
		BaseEndpoint:     aws.String(url),
		Credentials:      credentials.StaticCredentialsProvider{Value: creds},
		HTTPClient:       &http.Client{Timeout: clientTimeout},
		RetryMaxAttempts: 1,
	})
}

// createUserKey creates an IAM user and an access key for it, and returns
// the key as credentials. A user holds at most two keys, so each test that
// needs a key of its own makes its own user.
func createUserKey(t *testing.T, ic *iam.Client, user string) aws.Credentials {
	t.Helper()
	_, err := ic.CreateUser(t.Context(), &iam.CreateUserInput{UserName: aws.String(user)})
	requireNoErr(t, err, "create user "+user)
	out, err := ic.CreateAccessKey(t.Context(), &iam.CreateAccessKeyInput{
		UserName: aws.String(user),
	})
	requireNoErr(t, err, "create access key for "+user)
	return aws.Credentials{
		AccessKeyID:     aws.ToString(out.AccessKey.AccessKeyId),
		SecretAccessKey: aws.ToString(out.AccessKey.SecretAccessKey),
	}
}

// identityProcess is a running identity service.
type identityProcess struct {
	cmd     *exec.Cmd
	exited  chan error
	out     *identityOutput
	stopped bool
}

// identityOutput collects the process's output, safe to write from the
// process's copying goroutines and read from the test.
type identityOutput struct {
	buf bytes.Buffer
	mu  sync.Mutex
}

func (b *identityOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p) //nolint:wrapcheck // bytes.Buffer.Write never fails
}

func (b *identityOutput) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// startIdentity builds the identity service from its checkout and runs it
// on port with a fresh store, the root key accounts has, and accountsURL as
// its accounts endpoint. The process is stopped when the test ends.
func startIdentity(t *testing.T, port int, accountsURL string) *identityProcess {
	t.Helper()

	bin := buildIdentity(t)
	dir := t.TempDir()

	cmd := exec.Command(bin) //nolint:gosec // G204: the binary this test just built
	cmd.Dir = dir
	cmd.Env = append(envWithoutTule(),
		"TULE_GasEnv=testing",
		"TULE_Server_Port="+strconv.Itoa(port),
		"TULE_Store_Path="+filepath.Join(dir, "identity.db"),
		"TULE_Auth_AccessKeyID="+identityRootKeyID,
		"TULE_Auth_SecretAccessKey="+identityRootSecret,
		"TULE_Identity_AccountsEndpoint="+accountsURL,
	)
	p := &identityProcess{cmd: cmd, exited: make(chan error, 1), out: &identityOutput{}}
	cmd.Stdout = p.out
	cmd.Stderr = p.out
	if err := cmd.Start(); err != nil {
		t.Fatalf("start identity: %v", err)
	}
	go func() { p.exited <- cmd.Wait() }()
	t.Cleanup(func() { p.Stop(t) })

	p.waitReady(t, "http://127.0.0.1:"+strconv.Itoa(port))
	return p
}

// buildIdentity builds the identity binary into a temporary directory.
func buildIdentity(t *testing.T) string {
	t.Helper()

	// The test runs in accounts/test/e2e; by default identity is accounts'
	// sibling. CI sets the directory. A missing checkout fails the test, so
	// the cross-service test is never silently left out.
	src, from := os.Getenv(identityDirEnv), identityDirEnv
	if src == "" {
		src, from = filepath.Join("..", "..", "..", "identity"), "the default sibling path"
	}
	src, err := filepath.Abs(src)
	requireNoErr(t, err, "identity directory")
	//nolint:gosec // G703: the checkout the test is told to build
	if _, err = os.Stat(filepath.Join(src, "go.mod")); err != nil {
		t.Fatalf("no identity checkout at %s (from %s); set %s to an identity checkout: %v",
			src, from, identityDirEnv, err)
	}

	bin := filepath.Join(t.TempDir(), "tule-identity")
	//nolint:gosec // G204: go build of the checkout into this test's directory
	build := exec.CommandContext(t.Context(), "go", "build", "-o", bin, "./cmd")
	build.Dir = src
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build identity: %v\n%s", err, out)
	}
	return bin
}

// envWithoutTule is this process's environment minus the TULE_ variables the
// tests set for accounts, so the identity process gets only its own.
func envWithoutTule() []string {
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "TULE_") {
			env = append(env, kv)
		}
	}
	return env
}

func identityFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	requireNoErr(t, err, "find a free port")
	port := l.Addr().(*net.TCPAddr).Port
	requireNoErr(t, l.Close(), "release the free port")
	return port
}

// waitReady polls identity's readiness probe until it answers 200.
func (p *identityProcess) waitReady(t *testing.T, url string) {
	t.Helper()

	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(clientTimeout)
	for time.Now().Before(deadline) {
		select {
		case err := <-p.exited:
			t.Fatalf("identity exited before it was ready: %v\n%s", err, p.out.String())
		default:
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url+"/_ready", nil)
		requireNoErr(t, err, "build readiness request")
		if res, err := client.Do(req); err == nil {
			_ = res.Body.Close()
			if res.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("identity was not ready within %v\n%s", clientTimeout, p.out.String())
}

// Stop interrupts the process, as a signal stops the service, and kills it
// if it does not exit in time. It is idempotent, so a test can stop identity
// early and let the cleanup run anyway.
func (p *identityProcess) Stop(t *testing.T) {
	t.Helper()

	if p.stopped {
		return
	}
	p.stopped = true

	_ = p.cmd.Process.Signal(os.Interrupt)
	select {
	case err := <-p.exited:
		if err != nil {
			t.Logf("identity exited: %v", err)
		}
	case <-time.After(clientTimeout):
		_ = p.cmd.Process.Kill()
		err := <-p.exited
		t.Errorf("identity did not stop on interrupt (%v)\n%s", err, p.out.String())
	}
}
