// Copyright 2023 CUE Labs AG
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

package ociclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"cuelabs.dev/go/oci/ociregistry"
	"cuelabs.dev/go/oci/ociregistry/internal/ocirequest"
)

func (c *client) Repositories(ctx context.Context, startAfter string) ociregistry.Seq[string] {
	return c.pager(ctx, &ocirequest.Request{
		Kind:     ocirequest.ReqCatalogList,
		ListN:    c.listPageSize,
		ListLast: startAfter,
	}, func(resp *http.Response) ([]string, error) {
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		var catalog struct {
			Repos []string `json:"repositories"`
		}
		if err := json.Unmarshal(data, &catalog); err != nil {
			return nil, fmt.Errorf("cannot unmarshal catalog response: %v", err)
		}
		return catalog.Repos, nil
	})
}

func (c *client) Tags(ctx context.Context, repoName, startAfter string) ociregistry.Seq[string] {
	return c.pager(ctx, &ocirequest.Request{
		Kind:     ocirequest.ReqTagsList,
		Repo:     repoName,
		ListN:    c.listPageSize,
		ListLast: startAfter,
	}, func(resp *http.Response) ([]string, error) {
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		var tagsResponse struct {
			Repo string   `json:"name"`
			Tags []string `json:"tags"`
		}
		if err := json.Unmarshal(data, &tagsResponse); err != nil {
			return nil, fmt.Errorf("cannot unmarshal tags list response: %v", err)
		}
		return tagsResponse.Tags, nil
	})
}

func (c *client) Referrers(ctx context.Context, repoName string, digest ociregistry.Digest, artifactType string) ociregistry.Seq[ociregistry.Descriptor] {
	// TODO paging
	resp, err := c.doRequest(ctx, &ocirequest.Request{
		Kind:   ocirequest.ReqReferrersList,
		Repo:   repoName,
		Digest: string(digest),
		ListN:  c.listPageSize,
	})
	if err != nil {
		return ociregistry.ErrorIter[ociregistry.Descriptor](err)
	}

	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return ociregistry.ErrorIter[ociregistry.Descriptor](err)
	}
	var referrersResponse ocispec.Index
	if err := json.Unmarshal(data, &referrersResponse); err != nil {
		return ociregistry.ErrorIter[ociregistry.Descriptor](fmt.Errorf("cannot unmarshal referrers response: %v", err))
	}
	return ociregistry.SliceIter(referrersResponse.Manifests)
}

// pager returns an iterator for a list entry point. It starts by sending the given
// initial request and parses each response into its component items using
// parseResponse. It tries to use the Link header in each response to continue
// the iteration, falling back to using the "last" query parameter.
func (c *client) pager(ctx context.Context, initialReq *ocirequest.Request, parseResponse func(*http.Response) ([]string, error)) ociregistry.Seq[string] {
	return func(yield func(string, error) bool) {
		// We assume that the same scope is applicable to all page requests.
		req, err := newRequest(ctx, initialReq, nil)
		if err != nil {
			yield("", err)
			return
		}
		for {
			resp, err := c.do(req)
			if err != nil {
				yield("", err)
				return
			}
			items, err := parseResponse(resp)
			resp.Body.Close()
			if err != nil {
				yield("", err)
				return
			}
			// TODO sanity check that items are in lexical order?
			for _, item := range items {
				if !yield(item, nil) {
					return
				}
			}
			if len(items) < initialReq.ListN {
				// From the distribution spec:
				//     The response to such a request MAY return fewer than <int> results,
				//     but only when the total number of tags attached to the repository
				//     is less than <int>.
				return
			}
			req, err = nextLink(ctx, resp, initialReq, items[len(items)-1])
			if err != nil {
				yield("", fmt.Errorf("invalid Link header in response: %v", err))
				return
			}
		}
	}
}

// nextLink tries to form a request that can be sent to obtain the next page
// in a set of list results.
// The given response holds the response received from the previous
// list request; initialReq holds the request that initiated the listing,
// and last holds the final item returned in the previous response.
func nextLink(ctx context.Context, resp *http.Response, initialReq *ocirequest.Request, last string) (*http.Request, error) {
	link0 := resp.Header.Get("Link")
	if link0 == "" {
		// This is beyond the first page and there was no Link
		// in the previous response (the standard doesn't mandate
		// one), so add a "last" parameter to the initial request.
		rreq := *initialReq
		rreq.ListLast = last
		req, err := newRequest(ctx, &rreq, nil)
		if err != nil {
			// Given that we could form the initial request, this should
			// never happen.
			return nil, fmt.Errorf("cannot form next request: %v", err)
		}
		return req, nil
	}
	// Parse the link header according to RFC 5988.
	// TODO perhaps we shouldn't ignore the relation type?
	link, ok := strings.CutPrefix(link0, "<")
	if !ok {
		return nil, fmt.Errorf("no initial < character in Link=%q", link0)
	}
	link, _, ok = strings.Cut(link, ">")
	if !ok {
		return nil, fmt.Errorf("no > character in Link=%q", link0)
	}
	// Parse it with respect to the originating request, as it's probably relative.
	linkURL, err := resp.Request.URL.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("invalid URL in Link=%q", link0)
	}
	return http.NewRequestWithContext(ctx, "GET", linkURL.String(), nil)
}
