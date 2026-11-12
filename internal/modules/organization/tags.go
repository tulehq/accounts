package organization

import (
	"github.com/gasmod/gas"

	"tule.dev/accounts/internal/orgapi"
)

func (m *Module) tagResource(ctx gas.Context) error {
	req, err := decode[orgapi.TagResourceRequest](ctx)
	if err != nil {
		return err
	}
	if err = orgapi.TaggableResourceID.Require("ResourceId", req.ResourceID); err != nil {
		return err
	}
	if req.Tags == nil {
		return orgapi.ErrInvalidInputReason(orgapi.ReasonInputRequired,
			"You must specify a value for Tags.")
	}
	tags, err := tagsOf(req.Tags)
	if err != nil {
		return err
	}

	if err = m.store.TagResource(ctx, req.ResourceID, tags); err != nil {
		return err
	}
	return orgapi.Write(ctx, orgapi.EmptyResponse{})
}

func (m *Module) untagResource(ctx gas.Context) error {
	req, err := decode[orgapi.UntagResourceRequest](ctx)
	if err != nil {
		return err
	}
	if err = orgapi.TaggableResourceID.Require("ResourceId", req.ResourceID); err != nil {
		return err
	}
	if req.TagKeys == nil {
		return orgapi.ErrInvalidInputReason(orgapi.ReasonInputRequired,
			"You must specify a value for TagKeys.")
	}
	for _, k := range req.TagKeys {
		if err = orgapi.TagKeyOf("TagKeys", k); err != nil {
			return err
		}
	}

	if err = m.store.UntagResource(ctx, req.ResourceID, req.TagKeys); err != nil {
		return err
	}
	return orgapi.Write(ctx, orgapi.EmptyResponse{})
}

func (m *Module) listTagsForResource(ctx gas.Context) error {
	req, err := decode[orgapi.ListTagsForResourceRequest](ctx)
	if err != nil {
		return err
	}
	if err = orgapi.TaggableResourceID.Require("ResourceId", req.ResourceID); err != nil {
		return err
	}
	// ListTagsForResource takes no MaxResults, so its pages are the default
	// size.
	page, err := pageOf(nil, req.NextToken)
	if err != nil {
		return err
	}

	out, err := m.store.ListTagsForResource(ctx, req.ResourceID, page)
	if err != nil {
		return err
	}
	resp := orgapi.ListTagsForResourceResponse{
		NextToken: out.NextToken,
		Tags:      make([]orgapi.ResponseTag, 0, len(out.Items)),
	}
	for _, t := range out.Items {
		resp.Tags = append(resp.Tags, orgapi.ResponseTag{Key: t.Key, Value: t.Value})
	}
	return orgapi.Write(ctx, resp)
}
