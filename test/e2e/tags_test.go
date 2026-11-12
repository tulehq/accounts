//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"maps"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsorg "github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
)

func tag(k, v string) types.Tag {
	return types.Tag{Key: aws.String(k), Value: aws.String(v)}
}

func TestTagsOnEveryTaggableKind(t *testing.T) {
	// TagResource: accounts, the root and OUs are taggable (policies are out
	// of scope here).
	c, o := newOrg(t)

	resources := map[string]string{
		"member account":     createAccountID(t, c, "Tagged", "tagged@example.com"),
		"management account": o.ManagementID,
		"OU":                 createOU(t, c, o.RootID, "Tagged"),
		"root":               o.RootID,
	}
	for name, id := range resources {
		t.Run(name, func(t *testing.T) {
			requireEqual(t, len(tagsOf(t, c, id)), 0, "tags before tagging")

			_, err := c.TagResource(t.Context(), &awsorg.TagResourceInput{
				ResourceId: aws.String(id),
				Tags: []types.Tag{
					tag("env", "dev"),
					tag("owner", "platform"),
					tag("blank", ""),
				},
			})
			requireNoErr(t, err, "tag")
			requireTags(
				t,
				tagsOf(t, c, id),
				map[string]string{"env": "dev", "owner": "platform", "blank": ""},
			)

			// Tagging an existing key replaces its value.
			_, err = c.TagResource(t.Context(), &awsorg.TagResourceInput{
				ResourceId: aws.String(id), Tags: []types.Tag{tag("env", "prod")},
			})
			requireNoErr(t, err, "retag")
			requireTags(
				t,
				tagsOf(t, c, id),
				map[string]string{"env": "prod", "owner": "platform", "blank": ""},
			)

			_, err = c.UntagResource(t.Context(), &awsorg.UntagResourceInput{
				ResourceId: aws.String(id), TagKeys: []string{"owner", "blank"},
			})
			requireNoErr(t, err, "untag")
			requireTags(t, tagsOf(t, c, id), map[string]string{"env": "prod"})
		})
	}
}

func TestTagLimit(t *testing.T) {
	// 50 tags per root, OU or account (Quotas for AWS Organizations); one
	// more is ConstraintViolationException MAX_TAG_LIMIT_EXCEEDED, and "the
	// entire request fails" (TagResource).
	c, o := newOrg(t)
	ctx := context.Background()

	fifty := make([]types.Tag, 50)
	for i := range fifty {
		fifty[i] = tag(fmt.Sprintf("k%02d", i), "v")
	}
	_, err := c.TagResource(
		ctx,
		&awsorg.TagResourceInput{ResourceId: aws.String(o.RootID), Tags: fifty},
	)
	requireNoErr(t, err, "tag with 50 tags")
	requireEqual(t, len(tagsOf(t, c, o.RootID)), 50, "tag count")

	_, err = c.TagResource(ctx, &awsorg.TagResourceInput{
		ResourceId: aws.String(o.RootID), Tags: []types.Tag{tag("one-more", "v")},
	})
	requireConstraint(t, err, types.ConstraintViolationExceptionReasonMaxTagLimitExceeded)
	requireEqual(t, len(tagsOf(t, c, o.RootID)), 50, "tag count after rejected tag")

	// Also in a single request that takes an empty OU past the limit.
	ou := createOU(t, c, o.RootID, "Full")
	_, err = c.TagResource(ctx, &awsorg.TagResourceInput{
		ResourceId: aws.String(ou), Tags: append(fifty, tag("one-more", "v")),
	})
	requireConstraint(t, err, types.ConstraintViolationExceptionReasonMaxTagLimitExceeded)
	requireEqual(t, len(tagsOf(t, c, ou)), 0, "tags after rejected request")
}

func TestTagUnknownTargets(t *testing.T) {
	c, o := newOrg(t)

	// TargetNotFoundException: "We can't find a root, OU, account, or policy
	// with the TargetId that you specified."
	for name, id := range map[string]string{
		"account": unknownAccountID,
		"OU":      unknownOUID(o),
		"root":    unknownRootID,
	} {
		t.Run("unknown "+name, func(t *testing.T) {
			_, err := c.TagResource(t.Context(), &awsorg.TagResourceInput{
				ResourceId: aws.String(id), Tags: []types.Tag{tag("k", "v")},
			})
			requireAs[*types.TargetNotFoundException](t, err)

			_, err = c.UntagResource(t.Context(), &awsorg.UntagResourceInput{
				ResourceId: aws.String(id), TagKeys: []string{"k"},
			})
			requireAs[*types.TargetNotFoundException](t, err)

			_, err = c.ListTagsForResource(
				t.Context(),
				&awsorg.ListTagsForResourceInput{ResourceId: aws.String(id)},
			)
			requireAs[*types.TargetNotFoundException](t, err)
		})
	}
}

func TestTagValidation(t *testing.T) {
	c, _ := newOrg(t)
	member := createAccountID(t, c, "Member", "member@example.com")

	t.Run("malformed resource ID", func(t *testing.T) {
		// The reference fixes the ResourceId pattern but not which
		// InvalidInputException reason a mismatch carries, so only the type
		// is asserted.
		_, err := c.TagResource(t.Context(), &awsorg.TagResourceInput{
			ResourceId: aws.String("not-a-resource"), Tags: []types.Tag{tag("k", "v")},
		})
		requireAs[*types.InvalidInputException](t, err)

		_, err = c.ListTagsForResource(t.Context(), &awsorg.ListTagsForResourceInput{
			ResourceId: aws.String("not-a-resource"),
		})
		requireAs[*types.InvalidInputException](t, err)
	})

	// Tag: Key length 1 to 128, Value length 0 to 256 (API reference, Tag).
	invalid := []struct {
		name   string
		reason types.InvalidInputExceptionReason
		tags   []types.Tag
	}{
		{
			"duplicate key",
			types.InvalidInputExceptionReasonDuplicateTagKey,
			[]types.Tag{tag("env", "a"), tag("env", "b")},
		},
		{
			"key too long",
			types.InvalidInputExceptionReasonMaxLengthExceeded,
			[]types.Tag{tag(strings.Repeat("k", 129), "v")},
		},
		{
			"value too long",
			types.InvalidInputExceptionReasonMaxLengthExceeded,
			[]types.Tag{tag("k", strings.Repeat("v", 257))},
		},
	}
	for _, tt := range invalid {
		t.Run(tt.name, func(t *testing.T) {
			_, err := c.TagResource(t.Context(), &awsorg.TagResourceInput{
				ResourceId: aws.String(member), Tags: tt.tags,
			})
			requireInvalidInput(t, err, tt.reason)
			requireEqual(t, len(tagsOf(t, c, member)), 0, "tags after rejected request")
		})
	}

	t.Run("empty key", func(t *testing.T) {
		// Key has a minimum length of 1, but an empty string could be read as
		// INPUT_REQUIRED or MIN_LENGTH_EXCEEDED and the reference does not say
		// which, so only the type is asserted.
		_, err := c.TagResource(t.Context(), &awsorg.TagResourceInput{
			ResourceId: aws.String(member), Tags: []types.Tag{tag("", "v")},
		})
		requireAs[*types.InvalidInputException](t, err)
		requireEqual(t, len(tagsOf(t, c, member)), 0, "tags after rejected request")
	})
}

func TestTagLengthLimitsAreInclusive(t *testing.T) {
	c, _ := newOrg(t)
	member := createAccountID(t, c, "Member", "member@example.com")

	_, err := c.TagResource(t.Context(), &awsorg.TagResourceInput{
		ResourceId: aws.String(member),
		Tags:       []types.Tag{tag(strings.Repeat("k", 128), strings.Repeat("v", 256))},
	})
	requireNoErr(t, err, "tag at the length limits")
	requireTags(
		t,
		tagsOf(t, c, member),
		map[string]string{strings.Repeat("k", 128): strings.Repeat("v", 256)},
	)
}

func requireTags(t *testing.T, got, want map[string]string) {
	t.Helper()
	if !maps.Equal(got, want) {
		t.Fatalf("tags = %v, want %v", got, want)
	}
}
