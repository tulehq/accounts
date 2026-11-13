package app

import (
	"net/http"

	"tule.dev/sigv4"

	"tule.dev/accounts/internal/orgapi"
)

// sigv4Error maps a verification failure to the Organizations error it is
// answered with. The messages are the verifier's own, the AWS JSON services'
// texts.
//
// Kinds this configuration cannot produce (presigned URLs, a streamed body,
// session tokens a KeySource reports expired) and KindKeyLookupFailed are
// returned as the *sigv4.Error itself: orgapi answers any error it does not
// know with ServiceException and logs it, so they surface as a 500 with
// their cause in the log.
func sigv4Error(e *sigv4.Error) error {
	switch e.Kind {
	case sigv4.KindMissingAuth:
		return orgapi.NewError(http.StatusForbidden, orgapi.TypeMissingAuthToken, e.Message)
	case sigv4.KindUnsupportedAlgorithm, sigv4.KindIncompleteAuth, sigv4.KindInvalidDate,
		sigv4.KindUnsignedHeader, sigv4.KindMalformedCredential,
		sigv4.KindCredentialDateMismatch, sigv4.KindPayloadHashNotAccepted:
		return orgapi.NewError(http.StatusForbidden, orgapi.TypeIncompleteSig, e.Message)
	case sigv4.KindRequestTimeTooSkewed, sigv4.KindSignatureMismatch, sigv4.KindWrongService:
		return orgapi.NewError(http.StatusForbidden, orgapi.TypeInvalidSignature, e.Message)
	case sigv4.KindUnknownAccessKey, sigv4.KindInvalidSessionToken:
		return orgapi.NewError(http.StatusForbidden, orgapi.TypeUnrecognizedClient, e.Message)
	case sigv4.KindPayloadHashMismatch, sigv4.KindBodyUnreadable:
		return orgapi.ErrInvalidInput(e.Message)
	case sigv4.KindBodyTooLarge:
		return orgapi.NewError(http.StatusRequestEntityTooLarge, orgapi.TypeInvalidInput, e.Message)
	default:
		return e
	}
}
