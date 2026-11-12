package sqlimpl

import (
	"crypto/rand"
	"fmt"
	"strings"
)

// The ID formats Organizations uses, with the lengths AWS hands out within
// the ranges its patterns allow: o- and 10 characters, r- and 4, ou-, the
// root's 4, a dash and 8, car- and 32, and 12 digits for an account.
const (
	lowerAlnum = "abcdefghijklmnopqrstuvwxyz0123456789"
	digits     = "0123456789"

	organizationIDLength = 10
	rootIDLength         = 4
	ouIDLength           = 8
	requestIDLength      = 32
	accountIDLength      = 12
)

func newOrganizationID() (string, error) {
	return prefixed("o-", lowerAlnum, organizationIDLength)
}

func newRootID() (string, error) {
	return prefixed("r-", lowerAlnum, rootIDLength)
}

// newOUID returns an OU ID under the root rootID, which an OU ID carries: the
// root's suffix follows "ou-".
func newOUID(rootID string) (string, error) {
	return prefixed("ou-"+strings.TrimPrefix(rootID, "r-")+"-", lowerAlnum, ouIDLength)
}

func newRequestID() (string, error) {
	return prefixed("car-", lowerAlnum, requestIDLength)
}

func newAccountID() (string, error) {
	return prefixed("", digits, accountIDLength)
}

func prefixed(prefix, alphabet string, n int) (string, error) {
	s, err := randomString(alphabet, n)
	if err != nil {
		return "", err
	}
	return prefix + s, nil
}

// randomString returns n characters drawn uniformly from alphabet, which must
// be at most 256 characters long.
func randomString(alphabet string, n int) (string, error) {
	// Bytes at or above limit are discarded, so every character is equally
	// likely rather than the first 256 % len(alphabet) being favored.
	limit := 256 - 256%len(alphabet)
	out := make([]byte, 0, n)
	buf := make([]byte, n)
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("failed to generate an ID: %w", err)
		}
		for _, b := range buf {
			if int(b) < limit && len(out) < n {
				out = append(out, alphabet[int(b)%len(alphabet)])
			}
		}
	}
	return string(out), nil
}
