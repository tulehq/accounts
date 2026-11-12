//go:build e2e

package e2e

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsorg "github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
)

// IDs that are well formed but name nothing the tests create. Account IDs
// are random, so unknownAccountID could in principle collide; the tests that
// use it create at most a few accounts.
const (
	unknownAccountID = "999999999999"
	unknownCarID     = "car-0123456789abcdef"
	unknownRootID    = "r-zzzz9999"
)

// unknownOUID is a well-formed OU ID in o's root that no OU has.
func unknownOUID(o org) string {
	return "ou-" + o.rootSuffix() + "-zzzz9999"
}

func TestCreateAccount(t *testing.T) {
	c, o := newOrg(t)
	st := createDevAccount(t, c, o)

	t.Run("DescribeCreateAccountStatus agrees", func(t *testing.T) {
		got, err := c.DescribeCreateAccountStatus(
			t.Context(),
			&awsorg.DescribeCreateAccountStatusInput{
				CreateAccountRequestId: st.Id,
			},
		)
		requireNoErr(t, err, "describe create account status")
		requireSameStatus(t, *got.CreateAccountStatus, st)
	})

	t.Run("ListCreateAccountStatus agrees", func(t *testing.T) {
		got := listCreateAccountStatus(t, c, nil)
		requireEqual(t, len(got), 1, "create account records")
		requireSameStatus(t, got[0], st)
	})
}

func TestCreatedAccountDetails(t *testing.T) {
	c, o := newOrg(t)
	st := createDevAccount(t, c, o)
	id := aws.ToString(st.AccountId)

	t.Run("account", func(t *testing.T) {
		a := describeAccount(t, c, id)
		requireEqual(t, aws.ToString(a.Id), id, "ID")
		requireEqual(t, aws.ToString(a.Name), "Development", "name")
		requireEqual(t, aws.ToString(a.Email), "dev@example.com", "email")
		requireEqual(t, aws.ToString(a.Arn),
			"arn:aws:organizations::"+o.ManagementID+":account/"+o.ID+"/"+id, "ARN")
		// CreateAccount logs AccountJoinedOrganization with joinedMethod:Created.
		requireEqual(t, a.JoinedMethod, types.AccountJoinedMethodCreated, "joined method")
		requireEqual(t, a.State, types.AccountStateActive, "state")
		requireEqual(t, a.Status, types.AccountStatusActive, "status")
		if a.JoinedTimestamp == nil {
			t.Fatal("no JoinedTimestamp")
		}
	})

	t.Run("placed in the root", func(t *testing.T) {
		p := parentOf(t, c, id)
		requireEqual(t, aws.ToString(p.Id), o.RootID, "parent ID")
		requireEqual(t, p.Type, types.ParentTypeRoot, "parent type")
	})

	t.Run("takes the request's tags", func(t *testing.T) {
		requireTags(t, tagsOf(t, c, id), map[string]string{"env": "dev", "empty": ""})
	})

	t.Run("IDs are unique", func(t *testing.T) {
		second := createAccount(t, c, "Staging", "staging@example.com")
		if aws.ToString(second.AccountId) == id || aws.ToString(second.Id) == aws.ToString(st.Id) {
			t.Fatalf("second account reused an ID: %s / %s", aws.ToString(second.AccountId),
				aws.ToString(second.Id))
		}
		requireSameIDs(
			t,
			accountIDs(t, c),
			[]string{o.ManagementID, id, aws.ToString(second.AccountId)},
		)
	})
}

// createDevAccount creates the "Development" member with two tags and
// checks the final status CreateAccount returns.
func createDevAccount(t *testing.T, c *awsorg.Client, o org) types.CreateAccountStatus {
	t.Helper()
	ctx := t.Context()

	out, err := c.CreateAccount(ctx, &awsorg.CreateAccountInput{
		AccountName: aws.String("Development"),
		Email:       aws.String("dev@example.com"),
		Tags: []types.Tag{
			{Key: aws.String("env"), Value: aws.String("dev")},
			{Key: aws.String("empty"), Value: aws.String("")},
		},
	})
	requireNoErr(t, err, "create account")
	st := *out.CreateAccountStatus

	// Synchronous here: the returned status is already final.
	requireEqual(t, st.State, types.CreateAccountStateSucceeded, "state")
	requireMatch(t, carIDPattern, aws.ToString(st.Id), "create account request ID")
	requireEqual(t, aws.ToString(st.AccountName), "Development", "account name")
	requireEqual(t, st.FailureReason, types.CreateAccountFailureReason(""), "failure reason")
	if st.RequestedTimestamp == nil || st.CompletedTimestamp == nil {
		t.Fatalf(
			"timestamps: requested %v, completed %v",
			st.RequestedTimestamp,
			st.CompletedTimestamp,
		)
	}
	id := aws.ToString(st.AccountId)
	requireMatch(t, accountIDPattern, id, "account ID")
	if id == o.ManagementID {
		t.Fatal("new account reused the management account ID")
	}
	return st
}

func TestCreateAccountWithAnEmailInUseFails(t *testing.T) {
	// CreateAccountStatus.FailureReason: "EMAIL_ALREADY_EXISTS: The account
	// could not be created because another Amazon Web Services account with
	// that email address already exists." The failure is reported in the
	// status, not as an error (CreateAccount has no duplicate-email error).
	c, _ := newOrg(t)
	createAccountID(t, c, "Existing", "taken@example.com")

	tests := []struct {
		name  string
		email string
	}{
		{name: "a member's email", email: "taken@example.com"},
		// The management account is an AWS account too, so its email is
		// equally in use.
		{name: "the management account's email", email: managementEmail(t, c)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := accountIDs(t, c)

			out, err := c.CreateAccount(t.Context(), &awsorg.CreateAccountInput{
				AccountName: aws.String("Clash"),
				Email:       aws.String(tt.email),
			})
			requireNoErr(t, err, "create account")
			st := *out.CreateAccountStatus
			requireEqual(t, st.State, types.CreateAccountStateFailed, "state")
			requireEqual(t, st.FailureReason, types.CreateAccountFailureReasonEmailAlreadyExists,
				"failure reason")
			requireEqual(t, aws.ToString(st.AccountId), "", "account ID of a failed request")
			requireMatch(t, carIDPattern, aws.ToString(st.Id), "request ID")

			got, err := c.DescribeCreateAccountStatus(
				t.Context(),
				&awsorg.DescribeCreateAccountStatusInput{
					CreateAccountRequestId: st.Id,
				},
			)
			requireNoErr(t, err, "describe create account status")
			requireSameStatus(t, *got.CreateAccountStatus, st)

			failed := listCreateAccountStatus(
				t,
				c,
				[]types.CreateAccountState{types.CreateAccountStateFailed},
			)
			if !slices.ContainsFunc(failed, func(s types.CreateAccountStatus) bool {
				return aws.ToString(s.Id) == aws.ToString(st.Id)
			}) {
				t.Fatalf("FAILED records %v do not include %s", failed, aws.ToString(st.Id))
			}

			if after := accountIDs(t, c); len(after) != len(before) {
				t.Fatalf("accounts went from %v to %v", before, after)
			}
		})
	}
}

func TestListCreateAccountStatusFiltersByState(t *testing.T) {
	c, _ := newOrg(t)
	ctx := context.Background()

	ok := createAccount(t, c, "Good", "good@example.com")
	out, err := c.CreateAccount(ctx, &awsorg.CreateAccountInput{
		AccountName: aws.String("Clash"), Email: aws.String("good@example.com"),
	})
	requireNoErr(t, err, "create clashing account")
	bad := *out.CreateAccountStatus

	tests := []struct {
		name   string
		states []types.CreateAccountState
		want   []string
	}{
		{name: "no filter", states: nil, want: []string{aws.ToString(ok.Id), aws.ToString(bad.Id)}},
		{
			name:   "SUCCEEDED",
			states: []types.CreateAccountState{types.CreateAccountStateSucceeded},
			want:   []string{aws.ToString(ok.Id)},
		},
		{
			name: "FAILED", states: []types.CreateAccountState{types.CreateAccountStateFailed},
			want: []string{aws.ToString(bad.Id)},
		},
		{
			name:   "IN_PROGRESS",
			states: []types.CreateAccountState{types.CreateAccountStateInProgress},
			want:   nil,
		},
		{name: "both", states: []types.CreateAccountState{
			types.CreateAccountStateSucceeded, types.CreateAccountStateFailed,
		}, want: []string{aws.ToString(ok.Id), aws.ToString(bad.Id)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			for _, s := range listCreateAccountStatus(t, c, tt.states) {
				got = append(got, aws.ToString(s.Id))
			}
			slices.Sort(got)
			want := slices.Clone(tt.want)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Fatalf("records = %v, want %v", got, want)
			}
		})
	}
}

func TestCreateAccountRejectsInvalidInput(t *testing.T) {
	c, _ := newOrg(t)

	fiftyOneTags := manyTags(51)
	dev := devAccountInput

	tests := []struct {
		check func(*testing.T, error)
		name  string
		in    awsorg.CreateAccountInput
	}{
		// INVALID_ROLE_NAME: "A role name can't begin with the reserved
		// prefix AWSServiceRoleFor."
		{
			wantInvalid(
				types.InvalidInputExceptionReasonInvalidRoleName,
			),
			"reserved role name prefix",
			dev(awsorg.CreateAccountInput{RoleName: aws.String("AWSServiceRoleForExample")}),
		},
		// AccountName: length 1 to 50 (API reference).
		{
			wantInvalid(
				types.InvalidInputExceptionReasonMaxLengthExceeded,
			),
			"account name too long",
			dev(awsorg.CreateAccountInput{AccountName: aws.String(strings.Repeat("a", 51))}),
		},
		// Email: length 6 to 64 (API reference and the Email field doc).
		{
			wantInvalid(types.InvalidInputExceptionReasonMaxLengthExceeded),
			"email too long",
			dev(
				awsorg.CreateAccountInput{
					Email: aws.String(strings.Repeat("a", 53) + "@example.com"),
				},
			),
		},
		{
			wantInvalid(types.InvalidInputExceptionReasonMinLengthExceeded), "email too short",
			dev(awsorg.CreateAccountInput{Email: aws.String("a@b.c")}),
		},
		// Tags: "If any one of the tags is not valid or if you exceed the
		// maximum allowed number of tags for an account, then the entire
		// request fails and the account is not created." 50 tags per account
		// (Quotas for AWS Organizations).
		{
			wantConstraint(
				types.ConstraintViolationExceptionReasonMaxTagLimitExceeded,
			),
			"too many tags",
			dev(awsorg.CreateAccountInput{Tags: fiftyOneTags}),
		},
		{
			wantInvalid(types.InvalidInputExceptionReasonDuplicateTagKey), "duplicate tag key",
			dev(awsorg.CreateAccountInput{Tags: []types.Tag{tag("env", "a"), tag("env", "b")}}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := c.CreateAccount(t.Context(), &tt.in)
			tt.check(t, err)

			if ids := accountIDs(t, c); len(ids) != 1 {
				t.Fatalf("accounts after a rejected create = %v", ids)
			}
		})
	}
}

func TestDescribeCreateAccountStatusErrors(t *testing.T) {
	c, _ := newOrg(t)
	ctx := context.Background()

	_, err := c.DescribeCreateAccountStatus(ctx, &awsorg.DescribeCreateAccountStatusInput{
		CreateAccountRequestId: aws.String(unknownCarID),
	})
	requireAs[*types.CreateAccountStatusNotFoundException](t, err)

	// "car-" followed by 8 to 32 lowercase letters or digits.
	for _, id := range []string{"car-ABCDEFGHIJ", "car-abc", "xyz-0123456789"} {
		_, err = c.DescribeCreateAccountStatus(ctx, &awsorg.DescribeCreateAccountStatusInput{
			CreateAccountRequestId: aws.String(id),
		})
		requireInvalidInput(t, err, types.InvalidInputExceptionReasonInvalidPattern)
	}
}

func TestDescribeAccountErrors(t *testing.T) {
	c, _ := newOrg(t)
	ctx := context.Background()

	_, err := c.DescribeAccount(
		ctx,
		&awsorg.DescribeAccountInput{AccountId: aws.String(unknownAccountID)},
	)
	requireAs[*types.AccountNotFoundException](t, err)

	// Exactly 12 digits; these stay within the 12-character maximum so the
	// pattern is the only rule they break.
	for _, id := range []string{"12345", "12345678901a", "abcdefghijkl"} {
		_, err = c.DescribeAccount(ctx, &awsorg.DescribeAccountInput{AccountId: aws.String(id)})
		requireInvalidInput(t, err, types.InvalidInputExceptionReasonInvalidPattern)
	}
}

func TestCloseAccount(t *testing.T) {
	c, o := newOrg(t)
	ctx := context.Background()
	id := createAccountID(t, c, "Closing", "closing@example.com")

	_, err := c.CloseAccount(ctx, &awsorg.CloseAccountInput{AccountId: aws.String(id)})
	requireNoErr(t, err, "close account")

	// CloseAccount: Status is PENDING_CLOSURE while the closure runs and
	// SUSPENDED once it completes. State (account state guide, "Monitor the
	// state of your AWS accounts") is PENDING_CLOSURE, then CLOSED for the
	// 90-day post-closure period, during which the account is still listed;
	// its DescribeAccount example shows State CLOSED with Status SUSPENDED.
	a := describeAccount(t, c, id)
	closing := []types.AccountStatus{
		types.AccountStatusPendingClosure,
		types.AccountStatusSuspended,
	}
	if !slices.Contains(closing, a.Status) {
		t.Fatalf("status after close = %s, want one of %v", a.Status, closing)
	}
	closingStates := []types.AccountState{
		types.AccountStatePendingClosure,
		types.AccountStateClosed,
	}
	if !slices.Contains(closingStates, a.State) {
		t.Fatalf("state after close = %s, want one of %v", a.State, closingStates)
	}
	if !slices.Contains(accountIDs(t, c), id) {
		t.Fatal("closed account is missing from ListAccounts")
	}

	t.Run("closing twice", func(t *testing.T) {
		_, err := c.CloseAccount(t.Context(), &awsorg.CloseAccountInput{AccountId: aws.String(id)})
		requireAs[*types.AccountAlreadyClosedException](t, err)
	})

	t.Run("management account", func(t *testing.T) {
		_, err := c.CloseAccount(
			t.Context(),
			&awsorg.CloseAccountInput{AccountId: aws.String(o.ManagementID)},
		)
		requireConstraint(
			t,
			err,
			types.ConstraintViolationExceptionReasonCannotCloseManagementAccount,
		)
		requireEqual(t, describeAccount(t, c, o.ManagementID).State, types.AccountStateActive,
			"management state")
	})

	t.Run("unknown account", func(t *testing.T) {
		_, err := c.CloseAccount(
			t.Context(),
			&awsorg.CloseAccountInput{AccountId: aws.String(unknownAccountID)},
		)
		requireAs[*types.AccountNotFoundException](t, err)
	})

	t.Run("malformed ID", func(t *testing.T) {
		_, err := c.CloseAccount(
			t.Context(),
			&awsorg.CloseAccountInput{AccountId: aws.String("12345")},
		)
		requireInvalidInput(t, err, types.InvalidInputExceptionReasonInvalidPattern)
	})
}

func TestRemoveAccountFromOrganization(t *testing.T) {
	c, o := newOrg(t)
	ctx := context.Background()
	id := createAccountID(t, c, "Leaving", "leaving@example.com")
	staying := createAccountID(t, c, "Staying", "staying@example.com")

	_, err := c.RemoveAccountFromOrganization(ctx, &awsorg.RemoveAccountFromOrganizationInput{
		AccountId: aws.String(id),
	})
	requireNoErr(t, err, "remove account")

	_, err = c.DescribeAccount(ctx, &awsorg.DescribeAccountInput{AccountId: aws.String(id)})
	requireAs[*types.AccountNotFoundException](t, err)
	requireSameIDs(t, accountIDs(t, c), []string{o.ManagementID, staying})

	inRoot, err := c.ListAccountsForParent(
		ctx,
		&awsorg.ListAccountsForParentInput{ParentId: aws.String(o.RootID)},
	)
	requireNoErr(t, err, "list accounts for root")
	for _, a := range inRoot.Accounts {
		if aws.ToString(a.Id) == id {
			t.Fatal("removed account is still in the root")
		}
	}

	t.Run("removing twice", func(t *testing.T) {
		_, err := c.RemoveAccountFromOrganization(
			t.Context(),
			&awsorg.RemoveAccountFromOrganizationInput{
				AccountId: aws.String(id),
			},
		)
		requireAs[*types.AccountNotFoundException](t, err)
	})

	t.Run("unknown account", func(t *testing.T) {
		_, err := c.RemoveAccountFromOrganization(
			t.Context(),
			&awsorg.RemoveAccountFromOrganizationInput{
				AccountId: aws.String(unknownAccountID),
			},
		)
		requireAs[*types.AccountNotFoundException](t, err)
	})

	t.Run("malformed ID", func(t *testing.T) {
		_, err := c.RemoveAccountFromOrganization(
			t.Context(),
			&awsorg.RemoveAccountFromOrganizationInput{
				AccountId: aws.String("not-an-id"),
			},
		)
		requireInvalidInput(t, err, types.InvalidInputExceptionReasonInvalidPattern)
	})
}

func TestRemovingTheManagementAccountFails(t *testing.T) {
	c, o := newOrg(t)

	// The API reference documents two answers for this, without saying
	// which one RemoveAccountFromOrganization returns:
	// MasterCannotLeaveOrganizationException ("You can't remove a
	// management account from an organization") and
	// ConstraintViolationException ACCOUNT_CANNOT_LEAVE_ORGANIZATION
	// ("You attempted to remove the management account"). Either is AWS.
	_, err := c.RemoveAccountFromOrganization(
		t.Context(),
		&awsorg.RemoveAccountFromOrganizationInput{
			AccountId: aws.String(o.ManagementID),
		},
	)
	var master *types.MasterCannotLeaveOrganizationException
	var cv *types.ConstraintViolationException
	switch {
	case errors.As(err, &master):
	case errors.As(err, &cv) && cv.Reason == types.ConstraintViolationExceptionReasonAccountCannotLeaveOrganization:
	default:
		t.Fatalf("want MasterCannotLeaveOrganizationException or ConstraintViolationException "+
			"ACCOUNT_CANNOT_LEAVE_ORGANIZATION, got %v", err)
	}
	describeAccount(t, c, o.ManagementID)
}

func TestMoveAccount(t *testing.T) {
	c, o := newOrg(t)
	ctx := context.Background()
	id := createAccountID(t, c, "Mover", "mover@example.com")
	ou := createOU(t, c, o.RootID, "Workloads")

	_, err := c.MoveAccount(ctx, &awsorg.MoveAccountInput{
		AccountId: aws.String(
			id,
		),
		SourceParentId:      aws.String(o.RootID),
		DestinationParentId: aws.String(ou),
	})
	requireNoErr(t, err, "move account to OU")

	p := parentOf(t, c, id)
	requireEqual(t, aws.ToString(p.Id), ou, "parent after move")
	requireEqual(t, p.Type, types.ParentTypeOrganizationalUnit, "parent type after move")
	if !slices.Equal(accountsIn(t, c, ou), []string{id}) {
		t.Fatalf("accounts in OU = %v, want [%s]", accountsIn(t, c, ou), id)
	}
	if !slices.Equal(accountsIn(t, c, o.RootID), []string{o.ManagementID}) {
		t.Fatalf(
			"accounts in root = %v, want only the management account",
			accountsIn(t, c, o.RootID),
		)
	}
	// ListAccounts still lists every account, wherever it sits.
	if !slices.Contains(accountIDs(t, c), id) {
		t.Fatal("moved account is missing from ListAccounts")
	}

	_, err = c.MoveAccount(ctx, &awsorg.MoveAccountInput{
		AccountId: aws.String(
			id,
		),
		SourceParentId:      aws.String(ou),
		DestinationParentId: aws.String(o.RootID),
	})
	requireNoErr(t, err, "move account back to the root")
	requireEqual(t, aws.ToString(parentOf(t, c, id).Id), o.RootID, "parent after moving back")
}

func TestMoveAccountErrors(t *testing.T) {
	c, o, id, ou := moveFixture(t)
	empty := createOU(t, c, o.RootID, "Empty")

	runMoveCases(t, c, id, ou, []moveCase{
		{
			wantAs[*types.AccountNotFoundException](),
			"unknown account",
			unknownAccountID,
			ou,
			o.RootID,
		},
		{
			wantAs[*types.SourceParentNotFoundException](),
			"unknown source",
			id,
			unknownOUID(o),
			o.RootID,
		},
		{
			wantAs[*types.DestinationParentNotFoundException](),
			"unknown destination",
			id,
			ou,
			unknownOUID(o),
		},
		// DuplicateAccountException: "That account is already present in the
		// specified destination."
		{wantAs[*types.DuplicateAccountException](), "already in the destination", id, ou, ou},
		// The source exists but does not hold the account. MoveAccount's
		// reference does not say which of its errors this is; the two that fit
		// are AccountNotFoundException and SourceParentNotFoundException.
		{func(t *testing.T, err error) {
			t.Helper()
			var notFound *types.AccountNotFoundException
			var noSource *types.SourceParentNotFoundException
			if !errors.As(err, &notFound) && !errors.As(err, &noSource) {
				t.Fatalf(
					"want AccountNotFoundException or SourceParentNotFoundException, got %v",
					err,
				)
			}
		}, "wrong source", id, empty, o.RootID},
	})
}

func TestMoveAccountMalformedIDs(t *testing.T) {
	c, o, id, ou := moveFixture(t)
	pattern := wantInvalid(types.InvalidInputExceptionReasonInvalidPattern)

	runMoveCases(t, c, id, ou, []moveCase{
		{pattern, "malformed account", "123", ou, o.RootID},
		{pattern, "malformed source", id, "ou-bad", o.RootID},
		{pattern, "malformed destination", id, ou, "r-X"},
	})
}

func TestListAccountsForParentErrors(t *testing.T) {
	c, o := newOrg(t)
	ctx := context.Background()

	for _, parent := range []string{unknownRootID, unknownOUID(o)} {
		_, err := c.ListAccountsForParent(
			ctx,
			&awsorg.ListAccountsForParentInput{ParentId: aws.String(parent)},
		)
		requireAs[*types.ParentNotFoundException](t, err)
	}

	_, err := c.ListAccountsForParent(
		ctx,
		&awsorg.ListAccountsForParentInput{ParentId: aws.String("root")},
	)
	requireInvalidInput(t, err, types.InvalidInputExceptionReasonInvalidPattern)
}

// requireSameStatus fails unless two reports of one create-account request
// agree.
func requireSameStatus(t *testing.T, got, want types.CreateAccountStatus) {
	t.Helper()
	requireEqual(t, aws.ToString(got.Id), aws.ToString(want.Id), "request ID")
	requireEqual(t, got.State, want.State, "state")
	requireEqual(t, aws.ToString(got.AccountId), aws.ToString(want.AccountId), "account ID")
	requireEqual(t, aws.ToString(got.AccountName), aws.ToString(want.AccountName), "account name")
	requireEqual(t, got.FailureReason, want.FailureReason, "failure reason")
	if !aws.ToTime(got.RequestedTimestamp).Equal(aws.ToTime(want.RequestedTimestamp)) {
		t.Fatalf("requested timestamp %v, want %v", got.RequestedTimestamp, want.RequestedTimestamp)
	}
	if !aws.ToTime(got.CompletedTimestamp).Equal(aws.ToTime(want.CompletedTimestamp)) {
		t.Fatalf("completed timestamp %v, want %v", got.CompletedTimestamp, want.CompletedTimestamp)
	}
}

// listCreateAccountStatus reads every page of ListCreateAccountStatus.
func listCreateAccountStatus(
	t *testing.T,
	c *awsorg.Client,
	states []types.CreateAccountState,
) []types.CreateAccountStatus {
	t.Helper()

	var all []types.CreateAccountStatus
	p := awsorg.NewListCreateAccountStatusPaginator(
		c,
		&awsorg.ListCreateAccountStatusInput{States: states},
	)
	for p.HasMorePages() {
		page, err := p.NextPage(t.Context())
		requireNoErr(t, err, "list create account status")
		all = append(all, page.CreateAccountStatuses...)
	}
	return all
}

// accountsIn lists the IDs of the accounts directly in parentID.
func accountsIn(t *testing.T, c *awsorg.Client, parentID string) []string {
	t.Helper()

	var ids []string
	p := awsorg.NewListAccountsForParentPaginator(c, &awsorg.ListAccountsForParentInput{
		ParentId: aws.String(parentID),
	})
	for p.HasMorePages() {
		page, err := p.NextPage(t.Context())
		requireNoErr(t, err, "list accounts for "+parentID)
		for _, a := range page.Accounts {
			ids = append(ids, aws.ToString(a.Id))
		}
	}
	return ids
}

func managementEmail(t *testing.T, c *awsorg.Client) string {
	t.Helper()
	out, err := c.DescribeOrganization(t.Context(), &awsorg.DescribeOrganizationInput{})
	requireNoErr(t, err, "describe organization")
	return aws.ToString(out.Organization.MasterAccountEmail)
}

// wantInvalid checks for an InvalidInputException with the given reason.
func wantInvalid(reason types.InvalidInputExceptionReason) func(*testing.T, error) {
	return func(t *testing.T, err error) {
		t.Helper()
		requireInvalidInput(t, err, reason)
	}
}

// wantConstraint checks for a ConstraintViolationException with the given
// reason.
func wantConstraint(reason types.ConstraintViolationExceptionReason) func(*testing.T, error) {
	return func(t *testing.T, err error) {
		t.Helper()
		requireConstraint(t, err, reason)
	}
}

// manyTags returns n distinct tags.
func manyTags(n int) []types.Tag {
	tags := make([]types.Tag, n)
	for i := range tags {
		tags[i] = tag(fmt.Sprintf("k%02d", i), "v")
	}
	return tags
}

// devAccountInput fills in a valid name and email where in has none.
func devAccountInput(in awsorg.CreateAccountInput) awsorg.CreateAccountInput {
	if in.AccountName == nil {
		in.AccountName = aws.String("Dev")
	}
	if in.Email == nil {
		in.Email = aws.String("dev@example.com")
	}
	return in
}

// wantAs checks for the modeled SDK error type T.
func wantAs[T error]() func(*testing.T, error) {
	return func(t *testing.T, err error) {
		t.Helper()
		requireAs[T](t, err)
	}
}

// moveCase is a MoveAccount call expected to fail, and the check on its
// error.
type moveCase struct {
	check                              func(*testing.T, error)
	name, account, source, destination string
}

// moveFixture returns an organization with one member moved into an OU.
func moveFixture(t *testing.T) (c *awsorg.Client, o org, id, ou string) {
	t.Helper()
	c, o = newOrg(t)
	id = createAccountID(t, c, "Mover", "mover@example.com")
	ou = createOU(t, c, o.RootID, "Workloads")
	_, err := c.MoveAccount(t.Context(), &awsorg.MoveAccountInput{
		AccountId: aws.String(
			id,
		),
		SourceParentId:      aws.String(o.RootID),
		DestinationParentId: aws.String(ou),
	})
	requireNoErr(t, err, "move account to OU")
	return c, o, id, ou
}

// runMoveCases runs each case and checks that the account did not move.
func runMoveCases(t *testing.T, c *awsorg.Client, id, ou string, cases []moveCase) {
	t.Helper()
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			_, err := c.MoveAccount(t.Context(), &awsorg.MoveAccountInput{
				AccountId:           aws.String(tt.account),
				SourceParentId:      aws.String(tt.source),
				DestinationParentId: aws.String(tt.destination),
			})
			tt.check(t, err)
			requireEqual(t, aws.ToString(parentOf(t, c, id).Id), ou, "parent after a rejected move")
		})
	}
}
