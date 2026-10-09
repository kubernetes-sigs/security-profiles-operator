/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	profilebasev1 "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
)

// restrictedDirectives contains CIL statements that alter global node state
// or should not be allowed within a namespace-scoped container profile.
var restrictedDirectives = map[string]struct{}{
	"block":            {},
	"blockstart":       {},
	"booleanif":        {},
	"category":         {},
	"categoryorder":    {},
	"class":            {},
	"classmap":         {},
	"classmapping":     {},
	"classorder":       {},
	"context":          {},
	"dominance":        {},
	"filecon":          {},
	"genfscon":         {},
	"level":            {},
	"levelrange":       {},
	"mls":              {},
	"netifcon":         {},
	"nodecon":          {},
	"optional":         {},
	"policycap":        {},
	"portcon":          {},
	"role":             {},
	"roletype":         {},
	"sensitivity":      {},
	"sensitivityorder": {},
	"sid":              {},
	"sidcontext":       {},
	"sidorder":         {},
	"tunable":          {},
	"tunableif":        {},
	"typepermissive":   {},
	"user":             {},
	"userrole":         {},
}

// inheritableTemplates are the container templates of udica, which selinuxd
// installs. A raw policy may inherit them with blockinherit, like the
// SelinuxProfile inherits system profiles. Inheriting any other block, like
// the one of a permissive profile, would sidestep the restricted directives.
var inheritableTemplates = map[string]struct{}{
	"config_container": {},
	"container":        {},
	"home_container":   {},
	"log_container":    {},
	"net_container":    {},
	"tmp_container":    {},
	"tty_container":    {},
	"virt_container":   {},
	"x_container":      {},
}

// templateNameRegex matches the names which blockinherit may refer to. It
// rules out the names of nested blocks, like container.process.
var templateNameRegex = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

var (
	// Ensure RawSelinuxProfile implements the StatusBaseUser and SecurityProfileBase interfaces.
	_ profilebasev1.StatusBaseUser      = &RawSelinuxProfile{}
	_ profilebasev1.SecurityProfileBase = &RawSelinuxProfile{}
)

// RawSelinuxProfileSpec defines the desired state of RawSelinuxProfile.
type RawSelinuxProfileSpec struct {
	// Common spec fields for all profiles.
	profilebasev1.SpecBase `json:",inline"`

	// Deliberately not +required: this is a served v1 API, and requiring a field
	// that was optional rejects every write to an object that already exists
	// without it, including its status updates and finalizer removal. MinLength
	// already rejects an empty policy. The blank line below keeps this out of
	// the generated CRD description.

	// policy is the raw SELinux policy module content.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=500000
	Policy string `json:"policy,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// RawSelinuxProfile is the Schema for the rawselinuxprofiles API.
//
// The name is used as the name of a CIL block, which has to start with a
// letter and must not contain dots. Existing objects are exempt, so that they
// can still be updated and deleted.
//
// The policy is placed into that block. Statements which change the global
// policy, like typepermissive, are rejected, but the statements may still
// refer to global types, attributes and blocks: allow rules for global types
// like container_t, typeattributeset and in statements can affect other
// workloads. Only cluster admins should be allowed to write raw SELinux
// profiles.
//
// +kubebuilder:validation:XValidation:rule="oldSelf.hasValue() || self.metadata.name.matches('^[a-z][-a-z0-9]*$')",optionalOldSelf=true,message="name must start with a letter and may only contain lowercase alphanumeric characters and '-'"
// +kubebuilder:storageversion
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=rawselinuxprofiles,shortName=rselp,scope=Cluster,categories=spo
// +kubebuilder:printcolumn:name="Usage",type="string",JSONPath=`.status.usage`
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=`.status.status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
//
//nolint:lll // CEL rules cannot be wrapped
type RawSelinuxProfile struct {
	metav1.TypeMeta `json:",inline"`
	// metadata contains the object metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// spec defines the desired state of the RawSelinuxProfile.
	// +optional
	//nolint:kubeapilinter // spec has no required fields and is a value by convention
	Spec RawSelinuxProfileSpec `json:"spec,omitzero"`
	// status contains the observed state of the RawSelinuxProfile.
	// +optional
	Status SelinuxProfileStatus `json:"status,omitzero"` //nolint:kubeapilinter // status is a value by convention
}

func (sp *RawSelinuxProfile) GetStatusBase() *profilebasev1.StatusBase {
	return &sp.Status.StatusBase
}

func (sp *RawSelinuxProfile) DeepCopyToStatusBaseIf() profilebasev1.StatusBaseUser {
	return sp.DeepCopy()
}

func (sp *RawSelinuxProfile) SetImplementationStatus() {
	sp.Status.Usage = sp.GetPolicyUsage()
}

// GetPolicyName gets the policy module name in the format that
// we're expecting for parsing. filepath.Base is defense-in-depth
// against path traversal; Kubernetes names cannot contain slashes.
func (sp *RawSelinuxProfile) GetPolicyName() string {
	return filepath.Base(sp.GetName())
}

// GetPolicyUsage is the representation of how a pod will call this
// SELinux module.
func (sp *RawSelinuxProfile) GetPolicyUsage() string {
	return selinuxPolicyUsage(sp.GetPolicyName())
}

func (sp *RawSelinuxProfile) ListProfilesByRecording(
	ctx context.Context,
	cli client.Client,
	recording, recordingNamespace string,
) ([]metav1.Object, error) {
	return profilebasev1.ListProfilesByRecording(
		ctx,
		cli,
		recording,
		recordingNamespace,
		&RawSelinuxProfileList{},
	)
}

func (sp *RawSelinuxProfile) ValidatePolicy() error {
	policy := sp.Spec.Policy

	if strings.TrimSpace(policy) == "" {
		return errors.New("policy must not be empty")
	}

	if !utf8.ValidString(policy) {
		return errors.New("policy must be valid UTF-8")
	}

	if strings.ContainsRune(policy, '\x00') {
		return errors.New("policy must not contain null bytes")
	}

	// depth counts the open parentheses, which must not drop below zero, so
	// that the policy cannot escape its block.
	depth := 0
	// statement is true if the next token is the keyword of a statement.
	statement := false
	inherit := inheritNone

	if err := scanCIL(policy, func(kind cilTokenKind, value string) error {
		switch inherit {
		case inheritNone:
		case inheritTemplate:
			if kind != cilSymbol || !templateNameRegex.MatchString(value) {
				return errSingleTemplate
			}

			if _, ok := inheritableTemplates[value]; !ok {
				return fmt.Errorf(
					"invalid policy: blockinherit of '%s' is not allowed, only of the container templates",
					value,
				)
			}

			inherit = inheritClose

			return nil
		case inheritClose:
			if kind != cilClose {
				return errSingleTemplate
			}

			inherit = inheritNone
		}

		switch kind {
		case cilOpen:
			depth++
			statement = true

			return nil
		case cilClose:
			depth--
			if depth < 0 {
				return errors.New(
					"invalid policy: unmatched closing parenthesis ')' allows block escape")
			}

			statement = false

			return nil
		case cilSymbol, cilString:
		}

		if !statement {
			return nil
		}

		statement = false

		// CIL takes the value of a string as keyword as well. Keywords are
		// case sensitive, matching them in any case is the safe side.
		directive := strings.ToLower(value)
		if _, ok := restrictedDirectives[directive]; ok {
			return fmt.Errorf(
				"invalid policy: use of restricted global directive '%s' is not allowed", directive)
		}

		if directive == "blockinherit" {
			inherit = inheritTemplate
		}

		return nil
	}); err != nil {
		return err
	}

	if depth != 0 {
		return errors.New("invalid policy: unbalanced parentheses")
	}

	return nil
}

// cilTokenKind is the kind of a token of a CIL policy.
type cilTokenKind int32

const (
	cilOpen cilTokenKind = iota
	cilClose
	cilSymbol
	cilString
)

// inheritState tracks a blockinherit statement: its template comes next, or
// the closing parenthesis.
type inheritState int32

const (
	inheritNone inheritState = iota
	inheritTemplate
	inheritClose
)

// errSingleTemplate rejects a blockinherit statement which does not name a
// single template.
var errSingleTemplate = errors.New(
	"invalid policy: blockinherit must name a single template, like (blockinherit container)",
)

// scanCIL calls token for each token of the policy, the way the CIL lexer and
// parser of libsepol split it: comments run from a ';' up to the end of the
// line, and strings are quoted with '"' and cannot span lines. Neither of
// them can open or close a statement, so counting the parentheses in them
// would let a policy escape its block.
func scanCIL(policy string, token func(kind cilTokenKind, value string) error) error {
	for i := 0; i < len(policy); {
		var err error

		switch c := policy[i]; {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++

			continue
		case c == ';':
			i = skipCILComment(policy, i+1)

			continue
		case c == '"':
			end := strings.IndexAny(policy[i+1:], "\"\n")
			if end < 0 || policy[i+1+end] != '"' {
				return errors.New("invalid policy: unterminated string")
			}

			err = token(cilString, policy[i+1:i+1+end])
			i += end + 2
		case c == '(':
			err = token(cilOpen, "(")
			i++
		case c == ')':
			err = token(cilClose, ")")
			i++
		case isCILSymbolCharacter(c):
			end := i + 1
			for end < len(policy) && isCILSymbolCharacter(policy[end]) {
				end++
			}

			err = token(cilSymbol, policy[i:end])
			i = end
		default:
			// The CIL lexer rejects any other character. It separates the
			// tokens here, so that a restricted directive next to it does not
			// go unnoticed.
			_, size := utf8.DecodeRuneInString(policy[i:])
			i += size

			continue
		}

		if err != nil {
			return err
		}
	}

	return nil
}

// skipCILComment returns the end of the comment whose text starts at start.
// The CIL parser skips the tokens of a comment up to the next newline token,
// so a string in a comment hides a carriage return, which ends the line
// otherwise.
func skipCILComment(policy string, start int) int {
	for i := start; i < len(policy); i++ {
		switch policy[i] {
		case '\n', '\r':
			return i
		case '"':
			// A quote without a closing one on the same line is a token of
			// its own.
			end := strings.IndexAny(policy[i+1:], "\"\n")
			if end >= 0 && policy[i+1+end] == '"' {
				i += end + 1
			}
		}
	}

	return len(policy)
}

// isCILSymbolCharacter returns whether c can be part of a symbol for the CIL
// lexer.
func isCILSymbolCharacter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
		strings.IndexByte("[].@=/*-_$%+!|&^:~`#{}'<>?,", c) >= 0
}

func (sp *RawSelinuxProfile) IsPartial() bool {
	return profilebasev1.IsPartial(sp)
}

func (sp *RawSelinuxProfile) IsDisabled() bool {
	return profilebasev1.IsDisabled(&sp.Spec.SpecBase)
}

func (sp *RawSelinuxProfile) IsReconcilable() bool {
	return profilebasev1.IsReconcilable(sp)
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// RawSelinuxProfileList contains a list of RawSelinuxProfile.
type RawSelinuxProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	// Items is the list of RawSelinuxProfile objects.
	Items []RawSelinuxProfile `json:"items"`
}

func init() { //nolint:gochecknoinits // required to init the scheme
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(GroupVersion, &RawSelinuxProfile{}, &RawSelinuxProfileList{})

		return nil
	})
}
