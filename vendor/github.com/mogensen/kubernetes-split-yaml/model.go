package main

// KubernetesAPI is a minimal struct for unmarshaling kubernetes configs into
type KubernetesAPI struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name      string `yaml:"name"`
		Namespace string `yaml:"namespace"`
		Labels    struct {
			Source string `yaml:"source"`
		} `yaml:"labels"`
	} `yaml:"metadata"`
	// X is not a KubernetesAPI field, but a convienient field for templating purposes
	X struct {
		NS        string
		Outdir    string
		ShortKind string
	}
}
