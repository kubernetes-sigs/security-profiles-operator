package apparmor

type aa interface {
	aaReader
	aaWriter
}

type aaReader interface {
	// Enabled checks whether AppArmor is enabled in the kernel.
	//
	// Requires direct read-only access to AppArmor's parameters/enabled file
	// or be called with root privileges via hostop.mountHostOp.
	Enabled() (bool, error)

	// Enforceable checks whether AppArmor is installed, enabled and that
	// policies are enforceable.
	Enforceable() (bool, error)

	// PolicyLoaded checks whether a policy is loaded in the kernel.
	//
	// Requires direct read-only access to AppArmor's profiles file
	// or be called with root privileges via hostop.mountHostOp.
	PolicyLoaded(policyName string) (bool, error)
}

type aaWriter interface {
	// DeletePolicy unload the AppArmor policy from the kernel, then
	// deletes the policy file.
	//
	// Must be called with root privileges.
	DeletePolicy(policyName string) error

	// LoadPolicy loads an AppArmor policy into the kernel.
	//
	// Must be called with root privileges.
	LoadPolicy(fileName string) error
}
