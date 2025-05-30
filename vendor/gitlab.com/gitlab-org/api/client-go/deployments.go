//
// Copyright 2021, Sander van Harmelen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gitlab

import (
	"fmt"
	"net/http"
	"time"
)

type (
	// DeploymentsServiceInterface defines all the API methods for the DeploymentsService
	DeploymentsServiceInterface interface {
		ListProjectDeployments(pid interface{}, opts *ListProjectDeploymentsOptions, options ...RequestOptionFunc) ([]*Deployment, *Response, error)
		GetProjectDeployment(pid interface{}, deployment int, options ...RequestOptionFunc) (*Deployment, *Response, error)
		CreateProjectDeployment(pid interface{}, opt *CreateProjectDeploymentOptions, options ...RequestOptionFunc) (*Deployment, *Response, error)
		UpdateProjectDeployment(pid interface{}, deployment int, opt *UpdateProjectDeploymentOptions, options ...RequestOptionFunc) (*Deployment, *Response, error)
		ApproveOrRejectProjectDeployment(pid interface{}, deployment int, opt *ApproveOrRejectProjectDeploymentOptions, options ...RequestOptionFunc) (*Response, error)
		DeleteProjectDeployment(pid interface{}, deployment int, options ...RequestOptionFunc) (*Response, error)
	}

	// DeploymentsService handles communication with the deployment related methods
	// of the GitLab API.
	//
	// GitLab API docs: https://docs.gitlab.com/ee/api/deployments.html
	DeploymentsService struct {
		client *Client
	}
)

var _ DeploymentsServiceInterface = (*DeploymentsService)(nil)

// Deployment represents the Gitlab deployment
type Deployment struct {
	ID          int          `json:"id"`
	IID         int          `json:"iid"`
	Ref         string       `json:"ref"`
	SHA         string       `json:"sha"`
	Status      string       `json:"status"`
	CreatedAt   *time.Time   `json:"created_at"`
	UpdatedAt   *time.Time   `json:"updated_at"`
	User        *ProjectUser `json:"user"`
	Environment *Environment `json:"environment"`
	Deployable  struct {
		ID         int        `json:"id"`
		Status     string     `json:"status"`
		Stage      string     `json:"stage"`
		Name       string     `json:"name"`
		Ref        string     `json:"ref"`
		Tag        bool       `json:"tag"`
		Coverage   float64    `json:"coverage"`
		CreatedAt  *time.Time `json:"created_at"`
		StartedAt  *time.Time `json:"started_at"`
		FinishedAt *time.Time `json:"finished_at"`
		Duration   float64    `json:"duration"`
		User       *User      `json:"user"`
		Commit     *Commit    `json:"commit"`
		Pipeline   struct {
			ID        int        `json:"id"`
			SHA       string     `json:"sha"`
			Ref       string     `json:"ref"`
			Status    string     `json:"status"`
			CreatedAt *time.Time `json:"created_at"`
			UpdatedAt *time.Time `json:"updated_at"`
		} `json:"pipeline"`
		Runner *Runner `json:"runner"`
	} `json:"deployable"`
}

// ListProjectDeploymentsOptions represents the available ListProjectDeployments() options.
//
// GitLab API docs:
// https://docs.gitlab.com/ee/api/deployments.html#list-project-deployments
type ListProjectDeploymentsOptions struct {
	ListOptions
	OrderBy     *string `url:"order_by,omitempty" json:"order_by,omitempty"`
	Sort        *string `url:"sort,omitempty" json:"sort,omitempty"`
	Environment *string `url:"environment,omitempty" json:"environment,omitempty"`
	Status      *string `url:"status,omitempty" json:"status,omitempty"`

	// Only for Gitlab versions less than 14
	UpdatedAfter  *time.Time `url:"updated_after,omitempty" json:"updated_after,omitempty"`
	UpdatedBefore *time.Time `url:"updated_before,omitempty" json:"updated_before,omitempty"`

	// Only for Gitlab 14 or higher
	FinishedAfter  *time.Time `url:"finished_after,omitempty" json:"finished_after,omitempty"`
	FinishedBefore *time.Time `url:"finished_before,omitempty" json:"finished_before,omitempty"`
}

// ListProjectDeployments gets a list of deployments in a project.
//
// GitLab API docs:
// https://docs.gitlab.com/ee/api/deployments.html#list-project-deployments
func (s *DeploymentsService) ListProjectDeployments(pid interface{}, opts *ListProjectDeploymentsOptions, options ...RequestOptionFunc) ([]*Deployment, *Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, nil, err
	}
	u := fmt.Sprintf("projects/%s/deployments", PathEscape(project))

	req, err := s.client.NewRequest(http.MethodGet, u, opts, options)
	if err != nil {
		return nil, nil, err
	}

	var ds []*Deployment
	resp, err := s.client.Do(req, &ds)
	if err != nil {
		return nil, resp, err
	}

	return ds, resp, nil
}

// GetProjectDeployment get a deployment for a project.
//
// GitLab API docs:
// https://docs.gitlab.com/ee/api/deployments.html#get-a-specific-deployment
func (s *DeploymentsService) GetProjectDeployment(pid interface{}, deployment int, options ...RequestOptionFunc) (*Deployment, *Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, nil, err
	}
	u := fmt.Sprintf("projects/%s/deployments/%d", PathEscape(project), deployment)

	req, err := s.client.NewRequest(http.MethodGet, u, nil, options)
	if err != nil {
		return nil, nil, err
	}

	d := new(Deployment)
	resp, err := s.client.Do(req, d)
	if err != nil {
		return nil, resp, err
	}

	return d, resp, nil
}

// CreateProjectDeploymentOptions represents the available
// CreateProjectDeployment() options.
//
// GitLab API docs:
// https://docs.gitlab.com/ee/api/deployments.html#create-a-deployment
type CreateProjectDeploymentOptions struct {
	Environment *string                `url:"environment,omitempty" json:"environment,omitempty"`
	Ref         *string                `url:"ref,omitempty" json:"ref,omitempty"`
	SHA         *string                `url:"sha,omitempty" json:"sha,omitempty"`
	Tag         *bool                  `url:"tag,omitempty" json:"tag,omitempty"`
	Status      *DeploymentStatusValue `url:"status,omitempty" json:"status,omitempty"`
}

// CreateProjectDeployment creates a project deployment.
//
// GitLab API docs:
// https://docs.gitlab.com/ee/api/deployments.html#create-a-deployment
func (s *DeploymentsService) CreateProjectDeployment(pid interface{}, opt *CreateProjectDeploymentOptions, options ...RequestOptionFunc) (*Deployment, *Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, nil, err
	}
	u := fmt.Sprintf("projects/%s/deployments", PathEscape(project))

	req, err := s.client.NewRequest(http.MethodPost, u, opt, options)
	if err != nil {
		return nil, nil, err
	}

	d := new(Deployment)
	resp, err := s.client.Do(req, &d)
	if err != nil {
		return nil, resp, err
	}

	return d, resp, nil
}

// UpdateProjectDeploymentOptions represents the available
// UpdateProjectDeployment() options.
//
// GitLab API docs:
// https://docs.gitlab.com/ee/api/deployments.html#update-a-deployment
type UpdateProjectDeploymentOptions struct {
	Status *DeploymentStatusValue `url:"status,omitempty" json:"status,omitempty"`
}

// UpdateProjectDeployment updates a project deployment.
//
// GitLab API docs:
// https://docs.gitlab.com/ee/api/deployments.html#update-a-deployment
func (s *DeploymentsService) UpdateProjectDeployment(pid interface{}, deployment int, opt *UpdateProjectDeploymentOptions, options ...RequestOptionFunc) (*Deployment, *Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, nil, err
	}
	u := fmt.Sprintf("projects/%s/deployments/%d", PathEscape(project), deployment)

	req, err := s.client.NewRequest(http.MethodPut, u, opt, options)
	if err != nil {
		return nil, nil, err
	}

	d := new(Deployment)
	resp, err := s.client.Do(req, &d)
	if err != nil {
		return nil, resp, err
	}

	return d, resp, nil
}

// ApproveOrRejectProjectDeploymentOptions represents the available
// ApproveOrRejectProjectDeployment() options.
//
// GitLab API docs:
// https://docs.gitlab.com/ee/api/deployments.html#approve-or-reject-a-blocked-deployment
type ApproveOrRejectProjectDeploymentOptions struct {
	Status        *DeploymentApprovalStatus `url:"status,omitempty" json:"status,omitempty"`
	Comment       *string                   `url:"comment,omitempty" json:"comment,omitempty"`
	RepresentedAs *string                   `url:"represented_as,omitempty" json:"represented_as,omitempty"`
}

// ApproveOrRejectProjectDeployment approve or reject a blocked deployment.
//
// GitLab API docs:
// https://docs.gitlab.com/ee/api/deployments.html#approve-or-reject-a-blocked-deployment
func (s *DeploymentsService) ApproveOrRejectProjectDeployment(pid interface{}, deployment int,
	opt *ApproveOrRejectProjectDeploymentOptions, options ...RequestOptionFunc,
) (*Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, err
	}
	u := fmt.Sprintf("projects/%s/deployments/%d/approval", PathEscape(project), deployment)

	req, err := s.client.NewRequest(http.MethodPost, u, opt, options)
	if err != nil {
		return nil, err
	}

	return s.client.Do(req, nil)
}

// DeleteProjectDeployment delete a project deployment.
//
// GitLab API docs:
// https://docs.gitlab.com/ee/api/deployments.html#delete-a-specific-deployment
func (s *DeploymentsService) DeleteProjectDeployment(pid interface{}, deployment int, options ...RequestOptionFunc) (*Response, error) {
	project, err := parseID(pid)
	if err != nil {
		return nil, err
	}
	u := fmt.Sprintf("projects/%s/deployments/%d", PathEscape(project), deployment)

	req, err := s.client.NewRequest(http.MethodDelete, u, nil, options)
	if err != nil {
		return nil, err
	}

	return s.client.Do(req, nil)
}
