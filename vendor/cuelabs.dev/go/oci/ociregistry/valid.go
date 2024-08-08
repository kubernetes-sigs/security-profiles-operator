package ociregistry

import (
	"regexp"

	"github.com/opencontainers/go-digest"
)

var (
	tagPattern      = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}$`)
	repoNamePattern = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*$`)
)

// IsValidRepoName reports whether the given repository
// name is valid according to the specification.
func IsValidRepoName(repoName string) bool {
	return repoNamePattern.MatchString(repoName)
}

// IsValidTag reports whether the digest d is valid
// according to the specification.
func IsValidTag(tag string) bool {
	return tagPattern.MatchString(tag)
}

// IsValidDigest reports whether the digest d is well formed.
func IsValidDigest(d string) bool {
	_, err := digest.Parse(d)
	return err == nil
}
