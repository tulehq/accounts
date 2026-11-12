package orgapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"tule.dev/accounts/internal/contracts"
)

var errUnmapped = errors.New("something the store did not model")

func TestOperation(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   string
	}{
		{
			name:   "SDK target",
			header: "AWSOrganizationsV20161128.ListAccounts",
			want:   "ListAccounts",
		},
		{name: "bare operation", header: "ListAccounts", want: ""},
		{
			name: "prefix inside the header", header: "x.AWSOrganizationsV20161128.ListAccounts",
			want: "",
		},
		{name: "lowercase prefix", header: "awsorganizationsv20161128.ListAccounts", want: ""},
		{name: "empty", header: "", want: ""},
		{name: "prefix only", header: "AWSOrganizationsV20161128.", want: ""},
		{name: "another service", header: "secretsmanager.GetSecretValue", want: ""},
		{name: "shape ID", header: "com.amazonaws.organizations#ListAccounts", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Operation(tt.header); got != tt.want {
				t.Fatalf("Operation(%q) = %q, want %q", tt.header, got, tt.want)
			}
		})
	}
}

func TestTimestampMarshalsAsEpochSeconds(t *testing.T) {
	// The AWS JSON protocol puts a time on the wire as epoch seconds, so a
	// string here would be silently unparseable to every SDK.
	ts := Timestamp(time.Date(2026, time.January, 2, 3, 4, 5, 500*int(time.Millisecond),
		time.UTC))

	got, err := json.Marshal(ts)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if want := "1767323045.5"; string(got) != want {
		t.Fatalf("marshal = %s, want %s", got, want)
	}
}

func TestErrorEnvelopeShape(t *testing.T) {
	// The SDKs read the error code from __type, the text from Message and the
	// rule from Reason; renaming any of them loses it for every client.
	body, err := json.Marshal(ErrInvalidInputReason(ReasonInputRequired, "nope"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"__type":"InvalidInputException","Message":"nope","Reason":"INPUT_REQUIRED"}`
	if string(body) != want {
		t.Fatalf("envelope = %s, want %s", body, want)
	}

	// An error without a reason carries none.
	body, err = json.Marshal(ErrUnknownOperation("nope"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if want = `{"__type":"UnknownOperationException","Message":"nope"}`; string(body) != want {
		t.Fatalf("envelope = %s, want %s", body, want)
	}
}

// sentinelCases is what each store sentinel must become on the wire.
var sentinelCases = []struct {
	err        error
	wantType   string
	wantReason string
	wantStatus int
}{
	{contracts.ErrNotInUse, TypeNotInUse, "", http.StatusBadRequest},
	{contracts.ErrAlreadyInOrganization, TypeAlreadyInOrganization, "", http.StatusBadRequest},
	{contracts.ErrOrganizationNotEmpty, TypeOrganizationNotEmpty, "", http.StatusBadRequest},
	{contracts.ErrAccountNotFound, TypeAccountNotFound, "", http.StatusBadRequest},
	{contracts.ErrAccountAlreadyClosed, TypeAccountAlreadyClosed, "", http.StatusBadRequest},
	{
		contracts.ErrCreateAccountStatusNotFound, TypeCreateAccountStatusNotFound, "",
		http.StatusBadRequest,
	},
	{contracts.ErrParentNotFound, TypeParentNotFound, "", http.StatusBadRequest},
	{contracts.ErrSourceParentNotFound, TypeSourceParentNotFound, "", http.StatusBadRequest},
	{
		contracts.ErrDestinationParentNotFound, TypeDestinationParentNotFound, "",
		http.StatusBadRequest,
	},
	{contracts.ErrDuplicateAccount, TypeDuplicateAccount, "", http.StatusBadRequest},
	{contracts.ErrChildNotFound, TypeChildNotFound, "", http.StatusBadRequest},
	{
		contracts.ErrOrganizationalUnitNotFound, TypeOrganizationalUnitNotFound, "",
		http.StatusBadRequest,
	},
	{
		contracts.ErrOrganizationalUnitNotEmpty, TypeOrganizationalUnitNotEmpty, "",
		http.StatusBadRequest,
	},
	{
		contracts.ErrDuplicateOrganizationalUnit, TypeDuplicateOrganizationalUnit, "",
		http.StatusBadRequest,
	},
	{contracts.ErrTargetNotFound, TypeTargetNotFound, "", http.StatusBadRequest},
	{
		contracts.ErrManagementAccountCannotLeave, TypeMasterCannotLeave, "",
		http.StatusBadRequest,
	},
	{
		contracts.ErrCannotCloseManagementAccount, TypeConstraintViolation,
		"CANNOT_CLOSE_MANAGEMENT_ACCOUNT", http.StatusBadRequest,
	},
	{
		contracts.ErrNotInAllFeaturesMode, TypeConstraintViolation,
		"ORGANIZATION_NOT_IN_ALL_FEATURES_MODE", http.StatusBadRequest,
	},
	{
		contracts.ErrOUDepthLimitExceeded, TypeConstraintViolation,
		"OU_DEPTH_LIMIT_EXCEEDED", http.StatusBadRequest,
	},
	{
		contracts.ErrOUNumberLimitExceeded, TypeConstraintViolation,
		"OU_NUMBER_LIMIT_EXCEEDED", http.StatusBadRequest,
	},
	{
		contracts.ErrTagLimitExceeded, TypeConstraintViolation,
		"MAX_TAG_LIMIT_EXCEEDED", http.StatusBadRequest,
	},
	{contracts.ErrInvalidToken, TypeInvalidInput, ReasonInvalidNextToken, http.StatusBadRequest},
	{errUnmapped, TypeService, "", http.StatusInternalServerError},
}

func TestToErrorMapsStoreSentinels(t *testing.T) {
	for _, tt := range sentinelCases {
		t.Run(tt.wantType+"/"+tt.err.Error(), func(t *testing.T) {
			// Wrapped, as the store returns them.
			got := ToError(t.Context(), fmt.Errorf("context: %w", tt.err))
			if got.Type != tt.wantType || got.Reason != tt.wantReason {
				t.Fatalf("error = %s (%s), want %s (%s)", got.Type, got.Reason,
					tt.wantType, tt.wantReason)
			}
			if got.Status != tt.wantStatus {
				t.Fatalf("status = %d, want %d", got.Status, tt.wantStatus)
			}
		})
	}
}

func TestToErrorPassesAPIErrorsThrough(t *testing.T) {
	want := ErrInvalidInputReason(ReasonInvalidEnum, "ChildType must be one of ...")

	got := ToError(t.Context(), fmt.Errorf("handler: %w", want))

	if *got != *want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

// TestErrorsAreTheSDKs holds every error type and reason this service sends
// to the SDK model's, so a misspelling that would reach clients as an
// unknown error, or as a reason no SDK enumerates, fails here.
func TestErrorsAreTheSDKs(t *testing.T) {
	modeled := []string{
		(&types.AWSOrganizationsNotInUseException{}).ErrorCode(),
		(&types.AlreadyInOrganizationException{}).ErrorCode(),
		(&types.OrganizationNotEmptyException{}).ErrorCode(),
		(&types.AccountNotFoundException{}).ErrorCode(),
		(&types.AccountAlreadyClosedException{}).ErrorCode(),
		(&types.CreateAccountStatusNotFoundException{}).ErrorCode(),
		(&types.ParentNotFoundException{}).ErrorCode(),
		(&types.SourceParentNotFoundException{}).ErrorCode(),
		(&types.DestinationParentNotFoundException{}).ErrorCode(),
		(&types.DuplicateAccountException{}).ErrorCode(),
		(&types.ChildNotFoundException{}).ErrorCode(),
		(&types.OrganizationalUnitNotFoundException{}).ErrorCode(),
		(&types.OrganizationalUnitNotEmptyException{}).ErrorCode(),
		(&types.DuplicateOrganizationalUnitException{}).ErrorCode(),
		(&types.TargetNotFoundException{}).ErrorCode(),
		(&types.MasterCannotLeaveOrganizationException{}).ErrorCode(),
		(&types.ConstraintViolationException{}).ErrorCode(),
		(&types.InvalidInputException{}).ErrorCode(),
		(&types.ServiceException{}).ErrorCode(),
	}
	for _, se := range sentinelErrors {
		if !slices.Contains(modeled, se.apiErr.Type) {
			t.Errorf("%s is not an Organizations error the SDK models", se.apiErr.Type)
		}
		switch se.apiErr.Type {
		case TypeConstraintViolation:
			reason := types.ConstraintViolationExceptionReason(se.apiErr.Reason)
			if !slices.Contains(reason.Values(), reason) {
				t.Errorf("%s is not a ConstraintViolationException reason", reason)
			}
		case TypeInvalidInput:
			reason := types.InvalidInputExceptionReason(se.apiErr.Reason)
			if !slices.Contains(reason.Values(), reason) {
				t.Errorf("%s is not an InvalidInputException reason", reason)
			}
		}
	}

	reasons := types.InvalidInputExceptionReason("").Values()
	for _, r := range []string{
		ReasonInputRequired, ReasonMinLengthExceeded, ReasonMaxLengthExceeded,
		ReasonMinValueExceeded, ReasonMaxValueExceeded, ReasonInvalidPattern, ReasonInvalidEnum,
		ReasonInvalidNextToken, ReasonDuplicateTagKey, ReasonInvalidSystemTags,
		ReasonInvalidRoleName,
	} {
		if !slices.Contains(reasons, types.InvalidInputExceptionReason(r)) {
			t.Errorf("%s is not an InvalidInputException reason", r)
		}
	}
}

func requireReason(t *testing.T, err error, reason string) {
	t.Helper()
	var apiErr *Error
	if !errors.As(err, &apiErr) || apiErr.Type != TypeInvalidInput {
		t.Fatalf("got %v, want InvalidInputException", err)
	}
	if apiErr.Reason != reason {
		t.Fatalf("reason = %s, want %s (%v)", apiErr.Reason, reason, err)
	}
}

func TestRules(t *testing.T) {
	tests := []struct {
		name   string
		value  string
		reason string
		rule   Rule
	}{
		{"account ID", "123456789012", "", AccountID},
		{"short account ID", "12345678901", ReasonInvalidPattern, AccountID},
		{"long account ID", "1234567890123", ReasonMaxLengthExceeded, AccountID},
		{"root as parent", "r-ab12", "", ParentID},
		{"OU as parent", "ou-ab12-abcd1234", "", ParentID},
		{"account as parent", "123456789012", ReasonInvalidPattern, ParentID},
		{"uppercase parent", "r-AB12", ReasonInvalidPattern, ParentID},
		{"account as child", "123456789012", "", ChildID},
		{"root as child", "r-ab12", ReasonInvalidPattern, ChildID},
		{"request ID", "car-abcdefgh", "", CreateAccountRequestID},
		{"short request ID", "car-abc", ReasonInvalidPattern, CreateAccountRequestID},
		{"root as target", "r-ab12", "", TaggableResourceID},
		{"policy as target", "p-abcdefgh", "", TaggableResourceID},
		{"org as target", "o-abcdefghij", ReasonInvalidPattern, TaggableResourceID},
		{"account name", "Dev account", "", AccountName},
		{"account name of 51", strings.Repeat("a", 51), ReasonMaxLengthExceeded, AccountName},
		{"account name with a tab", "dev\tbox", ReasonInvalidPattern, AccountName},
		{"email", "dev@example.com", "", Email},
		{"short email", "a@b.c", ReasonMinLengthExceeded, Email},
		{"email without a dot", "dev@example", ReasonInvalidPattern, Email},
		{"email with two ats", "dev@ex@ample.com", ReasonInvalidPattern, Email},
		{"OU name", "Workloads / prod", "", OrganizationalUnitName},
		{
			"OU name of 129",
			strings.Repeat("ü", 129),
			ReasonMaxLengthExceeded,
			OrganizationalUnitName,
		},
		{"tag key", "cost-center:a/b=c+d@e", "", TagKey},
		{"tag key with a comma", "a,b", ReasonInvalidPattern, TagKey},
		{"empty tag value", "", "", TagValue},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Check("Field", tt.value)
			if tt.reason == "" {
				if err != nil {
					t.Fatalf("Check(%q) = %v, want it accepted", tt.value, err)
				}
				return
			}
			requireReason(t, err, tt.reason)
		})
	}

	requireReason(t, AccountID.Require("AccountId", ""), ReasonInputRequired)
}

func TestMaxResults(t *testing.T) {
	for _, n := range []int{1, 20} {
		got, err := MaxResults(&n)
		if err != nil || got != n {
			t.Fatalf("MaxResults(%d) = %d, %v", n, got, err)
		}
	}
	if got, err := MaxResults(nil); err != nil || got != 0 {
		t.Fatalf("MaxResults(nil) = %d, %v, want 0 for the default", got, err)
	}

	zero, over := 0, 21
	_, err := MaxResults(&zero)
	requireReason(t, err, ReasonMinValueExceeded)
	_, err = MaxResults(&over)
	requireReason(t, err, ReasonMaxValueExceeded)
}

func TestTags(t *testing.T) {
	v := func(s string) *string { return &s }

	if err := Tags([]Tag{{Key: "a", Value: v("")}, {Key: "b", Value: v("x")}}); err != nil {
		t.Fatalf("valid tags: %v", err)
	}
	requireReason(t, Tags([]Tag{{Key: "a", Value: v("1")}, {Key: "a", Value: v("2")}}),
		ReasonDuplicateTagKey)
	requireReason(t, Tags([]Tag{{Key: "a"}}), ReasonInputRequired)
	requireReason(t, Tags([]Tag{{Key: "", Value: v("x")}}), ReasonInputRequired)
	requireReason(t, Tags([]Tag{{Key: "AWS:created", Value: v("x")}}), ReasonInvalidSystemTags)
	requireReason(t, Tags([]Tag{{Key: "a", Value: v(strings.Repeat("x", 257))}}),
		ReasonMaxLengthExceeded)
}

func TestCheckRoleName(t *testing.T) {
	v := func(s string) *string { return &s }

	for _, ok := range []*string{nil, v("OrganizationAccountAccessRole"), v("a+=,.@-_1")} {
		if err := CheckRoleName(ok); err != nil {
			t.Fatalf("CheckRoleName(%v): %v", ok, err)
		}
	}
	requireReason(t, CheckRoleName(v("")), ReasonInvalidPattern)
	requireReason(t, CheckRoleName(v("has space")), ReasonInvalidPattern)
	requireReason(t, CheckRoleName(v("AWSServiceRoleForX")), ReasonInvalidRoleName)
}

func TestEnum(t *testing.T) {
	if err := Enum("FeatureSet", "", "ALL"); err != nil {
		t.Fatalf("absent optional enum: %v", err)
	}
	requireReason(t, Enum("FeatureSet", "all", "ALL"), ReasonInvalidEnum)
	requireReason(t, RequireEnum("ChildType", "", "ACCOUNT"), ReasonInputRequired)
}
