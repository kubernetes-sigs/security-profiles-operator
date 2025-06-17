package gitlab

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const (
	// GraphQLAPIEndpoint defines the endpoint URI for the GraphQL backend
	GraphQLAPIEndpoint = "/api/graphql"
)

type (
	GraphQLInterface interface {
		Do(ctx context.Context, query GraphQLQuery, response any) (*Response, error)
	}

	GraphQL struct {
		client *Client
	}

	GraphQLQuery struct {
		Query string `json:"query"`
	}

	GenericGraphQLErrors struct {
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}

	GraphQLResponseError struct {
		Err    error
		Errors GenericGraphQLErrors
	}
)

var _ GraphQLInterface = (*GraphQL)(nil)

func (e *GraphQLResponseError) Error() string {
	if len(e.Errors.Errors) == 0 {
		return fmt.Sprintf("%s (no additional error messages)", e.Err)
	}

	var sb strings.Builder
	sb.WriteString(e.Err.Error())
	sb.WriteString(" (GraphQL errors: ")

	for i, err := range e.Errors.Errors {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(err.Message)
	}
	sb.WriteString(")")

	return sb.String()
}

// Do sends a GraphQL query and returns the response in the given response argument
// The response must be JSON serializable. The *Response return value is the HTTP response
// and must be used to retrieve additional HTTP information, like status codes and also
// error messages from failed queries.
//
// Example:
//
//	var response struct {
//		Data struct {
//			Project struct {
//				ID string `json:"id"`
//			} `json:"project"`
//		} `json:"data"`
//	}
//	_, err := client.GraphQL.Do(context.Background(), GraphQLQuery{Query: `query { project(fullPath: "gitlab-org/gitlab") { id } }`}, &response)
//
// Attention: This API is experimental and may be subject to breaking changes to improve the API in the future.
func (g *GraphQL) Do(ctx context.Context, query GraphQLQuery, response any) (*Response, error) {
	request, err := g.client.NewRequest(http.MethodPost, "", query, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create GraphQL request: %w", err)
	}
	// Overwrite the path of the existing request, as otherwise client-go appends /api/v4 instead.
	request.URL.Path = GraphQLAPIEndpoint
	resp, err := g.client.Do(request, response)
	if err != nil {
		// return error, details can be read from Response
		if errResp, ok := err.(*ErrorResponse); ok { //nolint: errorlint
			var v GenericGraphQLErrors
			if json.Unmarshal(errResp.Body, &v) == nil {
				return resp, &GraphQLResponseError{
					Err:    err,
					Errors: v,
				}
			}
		}
		return resp, fmt.Errorf("failed to execute GraphQL query: %w", err)
	}
	return resp, nil
}
