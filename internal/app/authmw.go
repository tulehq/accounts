package app

import (
	"fmt"
	"net/http"
	"time"

	"tule.dev/identity/keysource"
	"tule.dev/sigv4"

	"tule.dev/accounts/internal/modules/health"
	"tule.dev/accounts/internal/orgapi"
)

// maxBodySize bounds the request body the verifier buffers to hash it. The
// largest legitimate request is a CreateAccount or CreateOrganizationalUnit
// with 50 tags, a few tens of KiB at most, so this leaves ample room.
const maxBodySize = 1 << 20

// identityTimeout bounds a key lookup at identity, so an identity that hangs
// fails the request with ServiceException rather than holding it until the
// server's own timeout. A lookup is one small local request. It is a
// variable so a test can shorten it.
var identityTimeout = 10 * time.Second

// newVerifier returns the SigV4 verifier every request but the probes goes
// through. It knows the configured root key, belonging to the management
// account's root user, and, when an identity endpoint is configured, every
// key identity issued, asked of identity on each request after the root key.
// Any key it accepts may call every operation: there are no permissions.
// Requests are accepted signed for organizations in any region. Host,
// X-Amz-Date and X-Amz-Target must be signed: X-Amz-Target names the
// operation, and left unsigned it would let whoever relays a signed read
// turn it into a removal, since the two carry the same body.
func newVerifier(cfg *Config) (*sigv4.Verifier, error) {
	account := cfg.Organization.ManagementAccountID
	root, err := sigv4.NewStaticKey(sigv4.StaticKeyConfig{
		AccessKeyID:     cfg.Auth.AccessKeyID,
		SecretAccessKey: cfg.Auth.SecretAccessKey,
		AccountID:       account,
		ARN:             "arn:aws:iam::" + account + ":root",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to build the signature verifier: %w", err)
	}
	var keys sigv4.KeySource = root
	if cfg.Auth.IdentityEndpoint != "" {
		identity, kErr := keysource.New(keysource.Config{
			HTTPClient:      &http.Client{Timeout: identityTimeout},
			Endpoint:        cfg.Auth.IdentityEndpoint,
			AccessKeyID:     cfg.Auth.AccessKeyID,
			SecretAccessKey: cfg.Auth.SecretAccessKey,
		})
		if kErr != nil {
			return nil, fmt.Errorf("failed to build the signature verifier: %w", kErr)
		}
		keys = sigv4.Chain(root, identity)
	}
	v, err := sigv4.New(
		keys,
		sigv4.WithBufferedPayload(maxBodySize),
		sigv4.WithRequiredSignedHeaders("host", "x-amz-date", "x-amz-target"),
		sigv4.WithService("organizations"),
		sigv4.WithErrorMap(sigv4Error),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build the signature verifier: %w", err)
	}
	return v, nil
}

// verifySignature rejects requests whose SigV4 signature does not verify
// against v, and serves the rest as Verify returns them, with the signer's
// principal in their context and the body the signature covered.
//
// The health probes are exempt, so a container's health check needs no
// credentials; nothing else is, because any web page the developer has open
// can reach a server on localhost, and this one can create, close and remove
// accounts.
func verifySignature(v *sigv4.Verifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isProbe(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			verified, err := v.Verify(r)
			if err != nil {
				orgapi.WriteHTTPError(w, r, err)
				return
			}
			next.ServeHTTP(w, verified)
		})
	}
}

func isProbe(path string) bool {
	return path == health.HealthPath || path == health.ReadyPath
}
