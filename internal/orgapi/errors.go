package orgapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gasmod/gas"

	"tule.dev/accounts/internal/contracts"
	"tule.dev/accounts/internal/httpx"
)

// errorTypeHeader is the error code clients that do not read the body look
// for. The AWS JSON protocol carries the code in the body's __type, and the
// SDK reads either, so both are sent.
const errorTypeHeader = "X-Amzn-Errortype"

// Error is an Organizations error document. It implements error so handlers
// and the validation helpers can return one directly. Reason is the field
// InvalidInputException and ConstraintViolationException carry, naming the
// rule the request broke.
type Error struct {
	Type    string `json:"__type"`
	Message string `json:"Message"`
	Reason  string `json:"Reason,omitempty"`
	Status  int    `json:"-"`
}

func (e *Error) Error() string {
	if e.Reason != "" {
		return e.Type + " (" + e.Reason + "): " + e.Message
	}
	return e.Type + ": " + e.Message
}

// NewError builds an error document with the given status and type.
func NewError(status int, errType, message string) *Error {
	return &Error{Status: status, Type: errType, Message: message}
}

// The Organizations error types this service raises, and the AWS protocol
// errors beside them. The Organizations API reference gives every modeled
// client error the status 400 and ServiceException 500, which is what this
// service sends; the SDK model's httpError traits name 404 and 409 for some,
// but the SDKs read the error code, not the status.
const (
	TypeNotInUse                    = "AWSOrganizationsNotInUseException"
	TypeAlreadyInOrganization       = "AlreadyInOrganizationException"
	TypeOrganizationNotEmpty        = "OrganizationNotEmptyException"
	TypeAccountNotFound             = "AccountNotFoundException"
	TypeAccountAlreadyClosed        = "AccountAlreadyClosedException"
	TypeCreateAccountStatusNotFound = "CreateAccountStatusNotFoundException"
	TypeParentNotFound              = "ParentNotFoundException"
	TypeSourceParentNotFound        = "SourceParentNotFoundException"
	TypeDestinationParentNotFound   = "DestinationParentNotFoundException"
	TypeDuplicateAccount            = "DuplicateAccountException"
	TypeChildNotFound               = "ChildNotFoundException"
	TypeOrganizationalUnitNotFound  = "OrganizationalUnitNotFoundException"
	TypeOrganizationalUnitNotEmpty  = "OrganizationalUnitNotEmptyException"
	TypeDuplicateOrganizationalUnit = "DuplicateOrganizationalUnitException"
	TypeTargetNotFound              = "TargetNotFoundException"
	TypeMasterCannotLeave           = "MasterCannotLeaveOrganizationException"
	TypeConstraintViolation         = "ConstraintViolationException"
	TypeInvalidInput                = "InvalidInputException"
	TypeService                     = "ServiceException"
	TypeUnknownOperation            = "UnknownOperationException"
	TypeSerialization               = "SerializationException"
	TypeMissingAuthToken            = "MissingAuthenticationTokenException"
	TypeIncompleteSig               = "IncompleteSignatureException"
	TypeInvalidSignature            = "InvalidSignatureException"
	TypeUnrecognizedClient          = "UnrecognizedClientException"
	TypeExpiredToken                = "ExpiredTokenException"
	TypeAccessDenied                = "AccessDeniedException"
	constraintReasonOUDepth         = "OU_DEPTH_LIMIT_EXCEEDED"
	constraintReasonOUNumber        = "OU_NUMBER_LIMIT_EXCEEDED"
	constraintReasonMaxTags         = "MAX_TAG_LIMIT_EXCEEDED"
	constraintReasonCloseManagement = "CANNOT_CLOSE_MANAGEMENT_ACCOUNT"
	constraintReasonNotAllFeatures  = "ORGANIZATION_NOT_IN_ALL_FEATURES_MODE"
)

// The InvalidInputException reasons this service raises, as the SDK's
// InvalidInputExceptionReason enum spells them.
const (
	ReasonInputRequired     = "INPUT_REQUIRED"
	ReasonMinLengthExceeded = "MIN_LENGTH_EXCEEDED"
	ReasonMaxLengthExceeded = "MAX_LENGTH_EXCEEDED"
	ReasonMinValueExceeded  = "MIN_VALUE_EXCEEDED"
	ReasonMaxValueExceeded  = "MAX_VALUE_EXCEEDED"
	ReasonInvalidPattern    = "INVALID_PATTERN"
	ReasonInvalidEnum       = "INVALID_ENUM"
	ReasonInvalidNextToken  = "INVALID_NEXT_TOKEN"
	ReasonDuplicateTagKey   = "DUPLICATE_TAG_KEY"
	ReasonInvalidSystemTags = "INVALID_SYSTEM_TAGS_PARAMETER"
	ReasonInvalidRoleName   = "INVALID_ROLE_NAME"
)

// ErrInvalidInput is the error for a request that is not acceptable, with no
// reason: for the failures no modeled reason names.
func ErrInvalidInput(msg string) *Error {
	return NewError(http.StatusBadRequest, TypeInvalidInput, msg)
}

// ErrInvalidInputReason is ErrInvalidInput with the reason the SDK reports in
// InvalidInputException.Reason.
func ErrInvalidInputReason(reason, msg string) *Error {
	e := ErrInvalidInput(msg)
	e.Reason = reason
	return e
}

// errConstraint is a ConstraintViolationException with reason.
func errConstraint(reason, msg string) *Error {
	return &Error{
		Status:  http.StatusBadRequest,
		Type:    TypeConstraintViolation,
		Message: msg,
		Reason:  reason,
	}
}

// ErrSerialization is the error for a body that is not valid JSON, or whose
// fields have the wrong JSON types.
func ErrSerialization(msg string) *Error {
	return NewError(http.StatusBadRequest, TypeSerialization, msg)
}

// ErrUnknownOperation is the error for an X-Amz-Target this service does not
// serve, whether or not Organizations has such an operation.
func ErrUnknownOperation(msg string) *Error {
	return NewError(http.StatusBadRequest, TypeUnknownOperation, msg)
}

// ErrService is the error every unrecognized failure becomes.
func ErrService() *Error {
	return NewError(http.StatusInternalServerError, TypeService,
		"AWS Organizations can't complete your request because of an internal service error. "+
			"Try again later.")
}

// ErrNotAllowed is the AccessDeniedException of a request no identity-based
// policy allows, in the form of AWS's authorization messages ("Troubleshoot
// access denied error messages", IAM User Guide). The API reference gives
// AccessDeniedException the status 400.
func ErrNotAllowed(callerARN, action, resource string) *Error {
	return clientError(TypeAccessDenied, notAuthorized(callerARN, action, resource)+
		" because no identity-based policy allows the "+action+" action")
}

// ErrExplicitlyDenied is the AccessDeniedException of a request an
// identity-based policy denies, in the form of AWS's messages.
func ErrExplicitlyDenied(callerARN, action, resource string) *Error {
	return clientError(TypeAccessDenied, notAuthorized(callerARN, action, resource)+
		" with an explicit deny in an identity-based policy")
}

func notAuthorized(callerARN, action, resource string) string {
	return "User: " + callerARN + " is not authorized to perform: " + action +
		" on resource: " + resource
}

// ErrNotManagementAccount is the AccessDeniedException Organizations answers
// a principal of a member account with for an operation only the management
// account (or a delegated administrator) may call, whatever its policies
// allow. The message is AWS's as AWS's re:Post knowledge center reports it
// for a call from a member account
// (https://repost.aws/knowledge-center/config-organizations-admin); the API
// reference does not give it.
func ErrNotManagementAccount() *Error {
	return clientError(TypeAccessDenied, "You don't have permissions to access this resource.")
}

// ErrAccountNotActive is the AccessDeniedException a principal of a closed
// member account is answered with. AWS says only that "you cannot access
// AWS services" from a closed account, and "You can't make API calls to AWS
// services from a suspended account" ("Monitor the state of your AWS
// accounts", Organizations User Guide), without the error; this service
// answers as it answers a member account refused an operation.
func ErrAccountNotActive() *Error {
	return ErrNotManagementAccount()
}

func clientError(errType, msg string) *Error {
	return NewError(http.StatusBadRequest, errType, msg)
}

// sentinelErrors maps store-layer sentinels to the errors they become. The
// messages are modeled on the Organizations API reference's descriptions of
// each error; clients are expected to match on the type, not the text.
var sentinelErrors = []struct {
	err    error
	apiErr *Error
}{
	{contracts.ErrNotInUse, clientError(TypeNotInUse,
		"Your account isn't a member of an organization. To make this request, you must use "+
			"the credentials of an account that belongs to an organization.")},
	{contracts.ErrAlreadyInOrganization, clientError(TypeAlreadyInOrganization,
		"This account is already a member of an organization. An account can belong to only "+
			"one organization at a time.")},
	{contracts.ErrOrganizationNotEmpty, clientError(TypeOrganizationNotEmpty,
		"The organization isn't empty. To delete an organization, you must first remove all "+
			"accounts except the management account.")},
	{contracts.ErrAccountNotFound, clientError(TypeAccountNotFound,
		"We can't find an AWS account with the AccountId that you specified.")},
	{contracts.ErrAccountAlreadyClosed, clientError(TypeAccountAlreadyClosed,
		"You attempted to close an account that is already closed.")},
	{contracts.ErrCreateAccountStatusNotFound, clientError(TypeCreateAccountStatusNotFound,
		"We can't find an create account request with the CreateAccountRequestId that you "+
			"specified.")},
	{contracts.ErrParentNotFound, clientError(TypeParentNotFound,
		"We can't find a root or OU with the ParentId that you specified.")},
	{contracts.ErrSourceParentNotFound, clientError(TypeSourceParentNotFound,
		"We can't find a source root or OU with the ParentId that you specified.")},
	{contracts.ErrDestinationParentNotFound, clientError(TypeDestinationParentNotFound,
		"We can't find the destination container (a root or OU) with the ParentId that you "+
			"specified.")},
	{contracts.ErrDuplicateAccount, clientError(TypeDuplicateAccount,
		"That account is already present in the specified destination.")},
	{contracts.ErrChildNotFound, clientError(TypeChildNotFound,
		"We can't find an organizational unit (OU) or AWS account with the ChildId that you "+
			"specified.")},
	{contracts.ErrOrganizationalUnitNotFound, clientError(TypeOrganizationalUnitNotFound,
		"We can't find an OU with the OrganizationalUnitId that you specified.")},
	{contracts.ErrOrganizationalUnitNotEmpty, clientError(TypeOrganizationalUnitNotEmpty,
		"The specified OU is not empty. Move all accounts to another root or to other OUs, "+
			"remove all child OUs, and try the operation again.")},
	{contracts.ErrDuplicateOrganizationalUnit, clientError(TypeDuplicateOrganizationalUnit,
		"An OU with the same name already exists.")},
	{contracts.ErrTargetNotFound, clientError(TypeTargetNotFound,
		"We can't find a root, OU, account, or policy with the TargetId that you specified.")},
	{contracts.ErrManagementAccountCannotLeave, clientError(TypeMasterCannotLeave,
		"You can't remove a management account from an organization. If you want the "+
			"management account to become a member account in another organization, you must "+
			"first delete the current organization of the management account.")},
	{contracts.ErrCannotCloseManagementAccount, errConstraint(constraintReasonCloseManagement,
		"You attempted to close the management account.")},
	{contracts.ErrNotInAllFeaturesMode, errConstraint(constraintReasonNotAllFeatures,
		"You attempted to perform an operation that requires the organization to be "+
			"configured to support all features.")},
	{contracts.ErrOUDepthLimitExceeded, errConstraint(constraintReasonOUDepth,
		"You attempted to create an OU tree that is too many levels deep.")},
	{contracts.ErrOUNumberLimitExceeded, errConstraint(constraintReasonOUNumber,
		"You attempted to exceed the number of OUs that you can have in an organization.")},
	{contracts.ErrTagLimitExceeded, errConstraint(constraintReasonMaxTags,
		"You have exceeded the number of tags allowed on this resource.")},
	{contracts.ErrInvalidToken, ErrInvalidInputReason(ReasonInvalidNextToken,
		"The NextToken is not valid. Get the value for the NextToken parameter from the "+
			"response to a previous call of the operation.")},
}

// ToError maps err to an error document, logging it when it maps to an
// internal error. It returns a copy, safe for the caller to fill in.
func ToError(ctx context.Context, err error) *Error {
	apiErr := toAPIError(err)
	if apiErr.Status == http.StatusInternalServerError {
		httpx.Logger(ctx).Error("request failed").Err("error", err).Send()
	}
	return apiErr
}

func toAPIError(err error) *Error {
	var apiErr *Error
	if errors.As(err, &apiErr) {
		cp := *apiErr
		return &cp
	}

	for _, se := range sentinelErrors {
		if errors.Is(err, se.err) {
			cp := *se.apiErr
			return &cp
		}
	}

	return ErrService()
}

// WriteError renders err as an Organizations error response.
func WriteError(ctx gas.Context, err error) error {
	writeError(ctx.ResponseWriter(), ctx.Request(), err)
	return nil
}

// WriteHTTPError is WriteError for plain http.Handler middleware, which has no
// gas.Context.
func WriteHTTPError(w http.ResponseWriter, r *http.Request, err error) {
	writeError(w, r, err)
}

func writeError(w http.ResponseWriter, r *http.Request, err error) {
	apiErr := ToError(r.Context(), err)

	body, mErr := json.Marshal(apiErr)
	if mErr != nil {
		httpx.Logger(r.Context()).Error("failed to encode error response").
			Err("error", mErr).Send()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", ContentType)
	w.Header().Set(errorTypeHeader, apiErr.Type)
	setRequestID(w, r)
	w.WriteHeader(apiErr.Status)

	if _, wErr := w.Write(body); wErr != nil {
		httpx.Logger(r.Context()).Warn("failed to write error response").
			Err("error", wErr).Send()
	}
}
