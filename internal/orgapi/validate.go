package orgapi

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

// Rule is the length and pattern a string parameter must meet, as the
// Organizations API model states them. Lengths count characters, and the
// pattern must match the whole value.
type Rule struct {
	pattern *regexp.Regexp
	min     int
	max     int
}

// The parameter rules of the in-scope operations, from the Organizations API
// model. The model's patterns are written for a matcher that tests the whole
// value; each one here is anchored to say so.
var (
	AccountID = Rule{max: 12, pattern: regexp.MustCompile(`^\d{12}$`)}
	ParentID  = Rule{max: 100, pattern: regexp.MustCompile(
		`^(?:r-[0-9a-z]{4,32}|ou-[0-9a-z]{4,32}-[a-z0-9]{8,32})$`)}
	ChildID = Rule{max: 100, pattern: regexp.MustCompile(
		`^(?:\d{12}|ou-[0-9a-z]{4,32}-[a-z0-9]{8,32})$`)}
	OrganizationalUnitID = Rule{max: 68, pattern: regexp.MustCompile(
		`^ou-[0-9a-z]{4,32}-[a-z0-9]{8,32}$`)}
	CreateAccountRequestID = Rule{max: 36, pattern: regexp.MustCompile(
		`^car-[a-z0-9]{8,32}$`)}
	// TaggableResourceID also admits the policy, resource policy and
	// responsibility transfer IDs Organizations tags; this service holds none
	// of those, so they name no target here.
	TaggableResourceID = Rule{max: 130, pattern: regexp.MustCompile(
		`^(?:r-[0-9a-z]{4,32}|\d{12}|ou-[0-9a-z]{4,32}-[a-z0-9]{8,32}|` +
			`p-[0-9a-zA-Z_]{8,128}|rp-[0-9a-zA-Z_]{4,128}|rt-[0-9a-zA-Z_]{8,32})$`)}
	AccountName = Rule{min: 1, max: 50, pattern: regexp.MustCompile(`^[\x20-\x7E]+$`)}
	Email       = Rule{min: 6, max: 64, pattern: regexp.MustCompile(
		`^[^\s@]+@[^\s@]+\.[^\s@]+$`)}
	RoleName               = Rule{max: 64, pattern: regexp.MustCompile(`^[\w+=,.@-]{1,64}$`)}
	OrganizationalUnitName = Rule{min: 1, max: 128}
	TagKey                 = Rule{min: 1, max: 128, pattern: tagPattern}
	TagValue               = Rule{max: 256, pattern: tagPattern}
	NextToken              = Rule{max: 100000}
)

var tagPattern = regexp.MustCompile(`^[\p{L}\p{Z}\p{N}_.:/=+\-@]*$`)

// Require checks a required parameter: it must be present and meet the rule.
// An empty value counts as absent, which the JSON protocol cannot tell apart
// from a missing field for the required parameters, all of which must be
// non-empty anyway.
func (r Rule) Require(field, v string) error {
	if v == "" {
		return errRequired(field)
	}
	return r.Check(field, v)
}

// Check checks a value that is present against the rule.
func (r Rule) Check(field, v string) error {
	n := utf8.RuneCountInString(v)
	switch {
	case n < r.min:
		return ErrInvalidInputReason(ReasonMinLengthExceeded,
			fmt.Sprintf("%s must be at least %d characters long.", field, r.min))
	case n > r.max:
		return ErrInvalidInputReason(ReasonMaxLengthExceeded,
			fmt.Sprintf("%s must be at most %d characters long.", field, r.max))
	case r.pattern != nil && !r.pattern.MatchString(v):
		return ErrInvalidInputReason(ReasonInvalidPattern,
			fmt.Sprintf("%s does not match the required pattern.", field))
	}
	return nil
}

func errRequired(field string) error {
	return ErrInvalidInputReason(ReasonInputRequired,
		fmt.Sprintf("You must specify a value for %s.", field))
}

// Enum checks that v, when present, is one of values.
func Enum(field, v string, values ...string) error {
	if v == "" || slices.Contains(values, v) {
		return nil
	}
	return ErrInvalidInputReason(ReasonInvalidEnum,
		fmt.Sprintf("%s must be one of %s.", field, strings.Join(values, ", ")))
}

// RequireEnum is Enum for a required parameter.
func RequireEnum(field, v string, values ...string) error {
	if v == "" {
		return errRequired(field)
	}
	return Enum(field, v, values...)
}

// The MaxResults bounds every in-scope list operation shares.
const (
	minMaxResults = 1
	maxMaxResults = 20
)

// MaxResults checks a requested page size and returns it, or 0 when the
// request sets none.
func MaxResults(v *int) (int, error) {
	switch {
	case v == nil:
		return 0, nil
	case *v < minMaxResults:
		return 0, ErrInvalidInputReason(ReasonMinValueExceeded,
			fmt.Sprintf("MaxResults must be at least %d.", minMaxResults))
	case *v > maxMaxResults:
		return 0, ErrInvalidInputReason(ReasonMaxValueExceeded,
			fmt.Sprintf("MaxResults must be at most %d.", maxMaxResults))
	}
	return *v, nil
}

// systemTagPrefix starts the tag keys AWS reserves for its own use.
const systemTagPrefix = "aws:"

// TagKeyOf checks one tag key: the key rule, and that it is not one of the
// system keys AWS reserves.
func TagKeyOf(field, key string) error {
	if err := TagKey.Require(field, key); err != nil {
		return err
	}
	if strings.HasPrefix(strings.ToLower(key), systemTagPrefix) {
		return ErrInvalidInputReason(ReasonInvalidSystemTags,
			"You can't add, edit, or delete system tag keys because they're reserved for "+
				"AWS use.")
	}
	return nil
}

// Tags checks a list of tags: each key and value, and that no key appears
// twice. A tag must carry a value, though the value may be empty.
func Tags(tags []Tag) error {
	seen := make(map[string]bool, len(tags))
	for _, t := range tags {
		if err := TagKeyOf("Tag.Key", t.Key); err != nil {
			return err
		}
		if t.Value == nil {
			return errRequired("Tag.Value")
		}
		if err := TagValue.Check("Tag.Value", *t.Value); err != nil {
			return err
		}
		if seen[t.Key] {
			return ErrInvalidInputReason(ReasonDuplicateTagKey,
				"Tag keys must be unique among the tags attached to the same entity.")
		}
		seen[t.Key] = true
	}
	return nil
}

// reservedRolePrefix starts the role names AWS keeps for service-linked roles.
const reservedRolePrefix = "AWSServiceRoleFor"

// CheckRoleName checks CreateAccount's optional RoleName.
func CheckRoleName(v *string) error {
	if v == nil {
		return nil
	}
	if err := RoleName.Check("RoleName", *v); err != nil {
		return err
	}
	if strings.HasPrefix(*v, reservedRolePrefix) {
		return ErrInvalidInputReason(ReasonInvalidRoleName,
			"A role name can't begin with the reserved prefix "+reservedRolePrefix+".")
	}
	return nil
}
