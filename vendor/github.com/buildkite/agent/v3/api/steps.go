package api

import (
	"context"
	"fmt"
)

// StepExportRequest represents a request for information about a step
type StepExportRequest struct {
	Attribute string `json:"attribute,omitempty"`
	Build     string `json:"build_id,omitempty"`
	Format    string `json:"format,omitempty"`
}

type StepExportResponse struct {
	Output string `json:"output"`
}

// StepExport gets an attribute from step
func (c *Client) StepExport(ctx context.Context, stepIdOrKey string, stepGetRequest *StepExportRequest) (*StepExportResponse, *Response, error) {
	u := fmt.Sprintf("steps/%s/export", stepIdOrKey)

	req, err := c.newRequest(ctx, "POST", u, stepGetRequest)
	if err != nil {
		return nil, nil, err
	}

	r := new(StepExportResponse)
	resp, err := c.doRequest(req, r)
	if err != nil {
		return nil, resp, err
	}

	return r, resp, err
}

// StepUpdate represents a change request to a step
type StepUpdate struct {
	IdempotencyUUID string `json:"idempotency_uuid,omitempty"`
	Build           string `json:"build_id,omitempty"`
	Attribute       string `json:"attribute,omitempty"`
	Value           string `json:"value,omitempty"`
	Append          bool   `json:"append,omitempty"`
}

// StepUpdate updates a step
func (c *Client) StepUpdate(ctx context.Context, stepIdOrKey string, stepUpdate *StepUpdate) (*Response, error) {
	u := fmt.Sprintf("steps/%s", stepIdOrKey)

	req, err := c.newRequest(ctx, "PUT", u, stepUpdate)
	if err != nil {
		return nil, err
	}

	return c.doRequest(req, nil)
}
