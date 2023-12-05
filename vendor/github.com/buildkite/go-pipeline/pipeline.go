package pipeline

import (
	"fmt"

	"github.com/buildkite/go-pipeline/ordered"
	"github.com/buildkite/interpolate"
)

// Pipeline models a pipeline.
//
// Standard caveats apply - see the package comment.
type Pipeline struct {
	Steps Steps          `yaml:"steps"`
	Env   *ordered.MapSS `yaml:"env,omitempty"`

	// RemainingFields stores any other top-level mapping items so they at least
	// survive an unmarshal-marshal round-trip.
	RemainingFields map[string]any `yaml:",inline"`
}

// MarshalJSON marshals a pipeline to JSON. Special handling is needed because
// yaml.v3 has "inline" but encoding/json has no concept of it.
func (p *Pipeline) MarshalJSON() ([]byte, error) {
	return inlineFriendlyMarshalJSON(p)
}

// UnmarshalOrdered unmarshals the pipeline from either []any (a legacy
// sequence of steps) or *ordered.MapSA (a modern pipeline configuration).
func (p *Pipeline) UnmarshalOrdered(o any) error {
	switch o := o.(type) {
	case *ordered.MapSA:
		// A pipeline can be a mapping.
		// Wrap in a secret type to avoid infinite recursion between this method
		// and ordered.Unmarshal.
		type wrappedPipeline Pipeline
		if err := ordered.Unmarshal(o, (*wrappedPipeline)(p)); err != nil {
			return fmt.Errorf("unmarshaling Pipeline: %w", err)
		}

	case []any:
		// A pipeline can be a sequence of steps.
		if err := ordered.Unmarshal(o, &p.Steps); err != nil {
			return fmt.Errorf("unmarshaling steps: %w", err)
		}

	default:
		return fmt.Errorf("unmarshaling Pipeline: unsupported type %T, want either *ordered.Map[string, any] or []any", o)
	}

	// Ensure Steps is never nil. Server side expects a sequence.
	if p.Steps == nil {
		p.Steps = Steps{}
	}
	return nil
}

// needed to plug a reggo map into a interpolate.Env
type mapGetter map[string]string

func (m mapGetter) Get(key string) (string, bool) {
	v, ok := m[key]
	return v, ok
}

// Interpolate interpolates variables defined in both env and p.Env into the
// pipeline.
// More specifically, it does these things:
//   - Interpolate pipeline.Env and copy the results into env to apply later.
//   - Interpolate any string value in the rest of the pipeline.
func (p *Pipeline) Interpolate(env map[string]string) error {
	if env == nil {
		env = map[string]string{}
	}

	// Preprocess any env that are defined in the top level block and place them
	// into env for later interpolation into the rest of the pipeline.
	if err := p.interpolateEnvBlock(env); err != nil {
		return err
	}

	tf := envInterpolator{env: mapGetter(env)}

	// Recursively go through the rest of the pipeline and perform environment
	// variable interpolation on strings. Interpolation is performed in-place.
	if err := interpolateSlice(tf, p.Steps); err != nil {
		return err
	}
	return interpolateMap(tf, p.RemainingFields)
}

// interpolateEnvBlock runs interpolate.Interpolate on each pair in p.Env,
// interpolating with the variables defined in env, and then adding the
// results back into both p.Env and env. Each environment variable can
// be interpolated into later environment variables, making the input ordering
// of p.Env potentially important.
func (p *Pipeline) interpolateEnvBlock(env map[string]string) error {
	return p.Env.Range(func(k, v string) error {
		// We interpolate both keys and values.
		intk, err := interpolate.Interpolate(mapGetter(env), k)
		if err != nil {
			return err
		}

		// v is always a string in this case.
		intv, err := interpolate.Interpolate(mapGetter(env), v)
		if err != nil {
			return err
		}

		p.Env.Replace(k, intk, intv)

		// Bonus part for the env block!
		// Add the results back into env.
		env[intk] = intv
		return nil
	})
}
