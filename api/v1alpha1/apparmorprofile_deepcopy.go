package v1alpha1

import "k8s.io/apimachinery/pkg/runtime"

// DeepCopyInto copies all properties of this object into another object of the
// same type that is provided as a pointer.
func (in *AppArmorProfile) DeepCopyInto(out *AppArmorProfile) {
	out.TypeMeta = in.TypeMeta
	out.ObjectMeta = in.ObjectMeta
	out.Spec = AppArmorProfileSpec{
		Rules:    in.Spec.Rules,
		Enforced: in.Spec.Enforced,
	}
}

// DeepCopyObject returns a generically typed copy of an object
func (in *AppArmorProfile) DeepCopyObject() runtime.Object {
	out := AppArmorProfile{}
	in.DeepCopyInto(&out)

	return &out
}

// DeepCopyObject returns a generically typed copy of an object
func (in *AppArmorProfileList) DeepCopyObject() runtime.Object {
	out := AppArmorProfileList{}
	out.TypeMeta = in.TypeMeta
	out.ListMeta = in.ListMeta

	if in.Items != nil {
		out.Items = make([]AppArmorProfile, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}

	return &out
}
