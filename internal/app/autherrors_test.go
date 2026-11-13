package app

import (
	"errors"
	"net/http"
	"testing"

	"tule.dev/sigv4"

	"tule.dev/accounts/internal/orgapi"
)

func TestSigv4ErrorMapsEveryKindTheVerifierReturns(t *testing.T) {
	tests := []struct {
		errType string
		kind    sigv4.Kind
		status  int
	}{
		{orgapi.TypeMissingAuthToken, sigv4.KindMissingAuth, http.StatusForbidden},
		{orgapi.TypeIncompleteSig, sigv4.KindUnsupportedAlgorithm, http.StatusForbidden},
		{orgapi.TypeIncompleteSig, sigv4.KindIncompleteAuth, http.StatusForbidden},
		{orgapi.TypeIncompleteSig, sigv4.KindInvalidDate, http.StatusForbidden},
		{orgapi.TypeIncompleteSig, sigv4.KindUnsignedHeader, http.StatusForbidden},
		{orgapi.TypeIncompleteSig, sigv4.KindMalformedCredential, http.StatusForbidden},
		{orgapi.TypeIncompleteSig, sigv4.KindCredentialDateMismatch, http.StatusForbidden},
		{orgapi.TypeIncompleteSig, sigv4.KindPayloadHashNotAccepted, http.StatusForbidden},
		{orgapi.TypeInvalidSignature, sigv4.KindRequestTimeTooSkewed, http.StatusForbidden},
		{orgapi.TypeInvalidSignature, sigv4.KindSignatureMismatch, http.StatusForbidden},
		{orgapi.TypeInvalidSignature, sigv4.KindWrongService, http.StatusForbidden},
		{orgapi.TypeUnrecognizedClient, sigv4.KindUnknownAccessKey, http.StatusForbidden},
		{orgapi.TypeUnrecognizedClient, sigv4.KindInvalidSessionToken, http.StatusForbidden},
		{orgapi.TypeInvalidInput, sigv4.KindPayloadHashMismatch, http.StatusBadRequest},
		{orgapi.TypeInvalidInput, sigv4.KindBodyUnreadable, http.StatusBadRequest},
		{orgapi.TypeInvalidInput, sigv4.KindBodyTooLarge, http.StatusRequestEntityTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.kind.String(), func(t *testing.T) {
			err := sigv4Error(&sigv4.Error{Kind: tt.kind, Message: "the verifier's text"})

			var apiErr *orgapi.Error
			if !errors.As(err, &apiErr) {
				t.Fatalf("error = %v, want an *orgapi.Error", err)
			}
			want := orgapi.Error{
				Status:  tt.status,
				Type:    tt.errType,
				Message: "the verifier's text",
			}
			if *apiErr != want {
				t.Fatalf("error = %+v, want %+v", *apiErr, want)
			}
		})
	}
}

func TestSigv4ErrorLeavesTheRestToServiceException(t *testing.T) {
	// The key lookup failing, and the Kinds this configuration cannot
	// produce, come back as the *sigv4.Error, which orgapi answers with
	// ServiceException and logs.
	for _, kind := range []sigv4.Kind{
		sigv4.KindKeyLookupFailed,
		sigv4.KindExpiredSessionToken,
		sigv4.KindInvalidExpires,
		sigv4.KindExpired,
		sigv4.KindRequestNotYetValid,
		sigv4.KindMissingPayloadHash,
		sigv4.KindUnverifiedPayload,
	} {
		t.Run(kind.String(), func(t *testing.T) {
			in := &sigv4.Error{Kind: kind, Message: "the verifier's text"}
			var out *sigv4.Error
			if err := sigv4Error(in); !errors.As(err, &out) || out != in {
				t.Fatalf("error = %v, want the *sigv4.Error itself", err)
			}
			got := orgapi.ToError(t.Context(), in)
			if got.Status != http.StatusInternalServerError || got.Type != orgapi.TypeService {
				t.Fatalf("answered as %d %s, want 500 %s", got.Status, got.Type, orgapi.TypeService)
			}
		})
	}
}
