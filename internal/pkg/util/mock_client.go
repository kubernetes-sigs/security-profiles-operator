/*
Copyright 2022 The Kubernetes Authors.

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

package util

import (
	"context"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// A MockGetFn is used to mock client.Client's Get implementation.
type MockGetFn func(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error

// A MockListFn is used to mock client.Client's List implementation.
type MockListFn func(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error

// A MockCreateFn is used to mock client.Client's Create implementation.
type MockCreateFn func(ctx context.Context, obj client.Object, opts ...client.CreateOption) error

// A MockDeleteFn is used to mock client.Client's Delete implementation.
type MockDeleteFn func(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error

// A MockDeleteAllOfFn is used to mock client.Client's Delete implementation.
type MockDeleteAllOfFn func(ctx context.Context, obj client.Object, opts ...client.DeleteAllOfOption) error

// A MockUpdateFn is used to mock client.Client's Update implementation.
type MockUpdateFn func(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error

// A MockPatchFn is used to mock client.Client's Patch implementation.
type MockPatchFn func(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error

// A MockSubResourceWriterCreateFn is used to mock client.Client's SubResourceWriterCreate implementation.
type MockSubResourceWriterCreateFn func(
	ctx context.Context, obj, subResource client.Object, opts ...client.SubResourceCreateOption,
) error

// A MockSubResourceWriterUpdateFn is used to mock client.Client's SubResourceWriterUpdate implementation.
type MockSubResourceWriterUpdateFn func(
	ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption,
) error

// A MockSubResourceWriterPatchFn is used to mock client.Client's SubResourceWriterUpdate implementation.
type MockSubResourceWriterPatchFn func(
	ctx context.Context, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption,
) error

// A MockSubResourceReaderGetFn is used to mock client.Client's SubResourceReaderGet implementation.
type MockSubResourceReaderGetFn func(
	ctx context.Context, obj client.Object, subResource client.Object, opts ...client.SubResourceGetOption,
) error

// A MockSchemeFn is used to mock client.Client's Scheme implementation.
type MockSchemeFn func() *runtime.Scheme

// An ObjectFn operates on the supplied Object. You might use an ObjectFn to
// test or update the contents of an Object.
type ObjectFn func(obj client.Object) error

// An ObjectListFn operates on the supplied ObjectList. You might use an
// ObjectListFn to test or update the contents of an ObjectList.
type ObjectListFn func(obj client.ObjectList) error

// NewMockGetFn returns a MockGetFn that returns the supplied error.
func NewMockGetFn(err error, ofn ...ObjectFn) MockGetFn {
	return func(_ context.Context, _ client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
		for _, fn := range ofn {
			if err := fn(obj); err != nil {
				return err
			}
		}
		return err
	}
}

// NewMockListFn returns a MockListFn that returns the supplied error.
func NewMockListFn(err error, ofn ...ObjectListFn) MockListFn {
	return func(_ context.Context, obj client.ObjectList, _ ...client.ListOption) error {
		for _, fn := range ofn {
			if err := fn(obj); err != nil {
				return err
			}
		}
		return err
	}
}

// NewMockCreateFn returns a MockCreateFn that returns the supplied error.
func NewMockCreateFn(err error, ofn ...ObjectFn) MockCreateFn {
	return func(_ context.Context, obj client.Object, opts ...client.CreateOption) error {
		for _, fn := range ofn {
			if err := fn(obj); err != nil {
				return err
			}
		}
		return err
	}
}

// NewMockDeleteFn returns a MockDeleteFn that returns the supplied error.
func NewMockDeleteFn(err error, ofn ...ObjectFn) MockDeleteFn {
	return func(_ context.Context, obj client.Object, _ ...client.DeleteOption) error {
		for _, fn := range ofn {
			if err := fn(obj); err != nil {
				return err
			}
		}
		return err
	}
}

// NewMockDeleteAllOfFn returns a MockDeleteAllOfFn that returns the supplied error.
func NewMockDeleteAllOfFn(err error, ofn ...ObjectFn) MockDeleteAllOfFn {
	return func(_ context.Context, obj client.Object, _ ...client.DeleteAllOfOption) error {
		for _, fn := range ofn {
			if err := fn(obj); err != nil {
				return err
			}
		}
		return err
	}
}

// NewMockUpdateFn returns a MockUpdateFn that returns the supplied error.
func NewMockUpdateFn(err error, ofn ...ObjectFn) MockUpdateFn {
	return func(_ context.Context, obj client.Object, _ ...client.UpdateOption) error {
		for _, fn := range ofn {
			if err := fn(obj); err != nil {
				return err
			}
		}
		return err
	}
}

// NewMockPatchFn returns a MockPatchFn that returns the supplied error.
func NewMockPatchFn(err error, ofn ...ObjectFn) MockPatchFn {
	return func(_ context.Context, obj client.Object, _ client.Patch, _ ...client.PatchOption) error {
		for _, fn := range ofn {
			if err := fn(obj); err != nil {
				return err
			}
		}
		return err
	}
}

// NewMockSubResourceWriterCreateFn returns a MockSubResourceWriterCreateFn that returns the supplied error.
func NewMockSubResourceWriterCreateFn(err error, ofn ...ObjectFn) MockSubResourceWriterCreateFn {
	return func(_ context.Context, obj, subResource client.Object, _ ...client.SubResourceCreateOption) error {
		for _, fn := range ofn {
			if err := fn(obj); err != nil {
				return err
			}
		}
		return err
	}
}

// NewMockSubResourceWriterUpdateFn returns a MockSubResourceWriterUpdateFn that returns the supplied error.
func NewMockSubResourceWriterUpdateFn(err error, ofn ...ObjectFn) MockSubResourceWriterUpdateFn {
	return func(_ context.Context, obj client.Object, _ ...client.SubResourceUpdateOption) error {
		for _, fn := range ofn {
			if err := fn(obj); err != nil {
				return err
			}
		}
		return err
	}
}

// NewMockSubResourceWriterPatchFn returns a MockSubResourceWriterPatchFn that returns the supplied error.
func NewMockSubResourceWriterPatchFn(err error, ofn ...ObjectFn) MockSubResourceWriterPatchFn {
	return func(_ context.Context, obj client.Object, _ client.Patch, _ ...client.SubResourcePatchOption) error {
		for _, fn := range ofn {
			if err := fn(obj); err != nil {
				return err
			}
		}
		return err
	}
}

// NewMockSchemeFn returns a MockSchemeFn that returns the scheme.
func NewMockSchemeFn(scheme *runtime.Scheme) MockSchemeFn {
	return func() *runtime.Scheme {
		return scheme
	}
}

// MockClient implements controller-runtime's Client interface, allowing each
// method to be overridden for testing. The controller-runtime provides a fake
// client, but it is has surprising side effects (e.g. silently calling
// os.Exit(1)) and does not allow us control over the errors it returns.
type MockClient struct {
	MockGet         MockGetFn
	MockList        MockListFn
	MockCreate      MockCreateFn
	MockDelete      MockDeleteFn
	MockDeleteAllOf MockDeleteAllOfFn
	MockUpdate      MockUpdateFn
	MockPatch       MockPatchFn

	MockSubResourceWriterCreate MockSubResourceWriterCreateFn
	MockSubResourceWriterUpdate MockSubResourceWriterUpdateFn
	MockSubResourceWriterPatch  MockSubResourceWriterPatchFn

	MockSubResourceReaderGet MockSubResourceReaderGetFn

	MockScheme MockSchemeFn
}

// NewMockClient returns a MockClient that does nothing when its methods are
// called.
func NewMockClient() *MockClient {
	return &MockClient{
		MockGet:         NewMockGetFn(nil),
		MockList:        NewMockListFn(nil),
		MockCreate:      NewMockCreateFn(nil),
		MockDelete:      NewMockDeleteFn(nil),
		MockDeleteAllOf: NewMockDeleteAllOfFn(nil),
		MockUpdate:      NewMockUpdateFn(nil),
		MockPatch:       NewMockPatchFn(nil),

		MockSubResourceWriterCreate: NewMockSubResourceWriterCreateFn(nil),
		MockSubResourceWriterUpdate: NewMockSubResourceWriterUpdateFn(nil),
		MockSubResourceWriterPatch:  NewMockSubResourceWriterPatchFn(nil),

		MockScheme: NewMockSchemeFn(nil),
	}
}

func (c *MockClient) SubResource(subResource string) client.SubResourceClient {
	return &MockSubResource{
		SubResourceWriter: &MockSubResourceWriter{
			MockCreate: c.MockSubResourceWriterCreate,
			MockUpdate: c.MockSubResourceWriterUpdate,
			MockPatch:  c.MockSubResourceWriterPatch,
		},
		SubResourceReader: &MockSubResourceReader{
			MockGet: c.MockSubResourceReaderGet,
		},
	}
}

// Get calls MockClient's MockGet function.
func (c *MockClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	return c.MockGet(ctx, key, obj)
}

// List calls MockClient's MockList function.
func (c *MockClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	return c.MockList(ctx, list, opts...)
}

// Create calls MockClient's MockCreate function.
func (c *MockClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	return c.MockCreate(ctx, obj, opts...)
}

// Delete calls MockClient's MockDelete function.
func (c *MockClient) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	return c.MockDelete(ctx, obj, opts...)
}

// DeleteAllOf calls MockClient's DeleteAllOf function.
func (c *MockClient) DeleteAllOf(ctx context.Context, obj client.Object, opts ...client.DeleteAllOfOption) error {
	return c.MockDeleteAllOf(ctx, obj, opts...)
}

// Update calls MockClient's MockUpdate function.
func (c *MockClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	return c.MockUpdate(ctx, obj, opts...)
}

// Patch calls MockClient's MockPatch function.
func (c *MockClient) Patch(
	ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption,
) error {
	return c.MockPatch(ctx, obj, patch, opts...)
}

// Status returns status writer for sub-resource writer.
func (c *MockClient) Status() client.SubResourceWriter {
	return &MockSubResourceWriter{
		MockCreate: c.MockSubResourceWriterCreate,
		MockUpdate: c.MockSubResourceWriterUpdate,
		MockPatch:  c.MockSubResourceWriterPatch,
	}
}

// RESTMapper returns the REST mapper.
func (c *MockClient) RESTMapper() meta.RESTMapper {
	return nil
}

// Scheme calls MockClient's MockScheme function.
func (c *MockClient) Scheme() *runtime.Scheme {
	return c.MockScheme()
}

// MockSubResource provides mock functionality for sub-resource client.
type MockSubResource struct {
	client.SubResourceReader
	client.SubResourceWriter
}

// MockSubResourceWriter provides mock functionality for sub-resource writer.
type MockSubResourceWriter struct {
	MockCreate MockSubResourceWriterCreateFn
	MockUpdate MockSubResourceWriterUpdateFn
	MockPatch  MockSubResourceWriterPatchFn
}

func (m *MockSubResourceWriter) Create(
	ctx context.Context, obj, subResource client.Object, opts ...client.SubResourceCreateOption,
) error {
	return m.MockCreate(ctx, obj, subResource, opts...)
}

// Update status sub-resource.
func (m *MockSubResourceWriter) Update(
	ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption,
) error {
	return m.MockUpdate(ctx, obj, opts...)
}

// Patch mocks the patch method.
func (m *MockSubResourceWriter) Patch(
	ctx context.Context, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption,
) error {
	return m.MockPatch(ctx, obj, patch, opts...)
}

// MockSubResourceReader provides mock functionality for sub-resource reader.
type MockSubResourceReader struct {
	MockGet MockSubResourceReaderGetFn
}

func (m *MockSubResourceReader) Get(
	ctx context.Context, obj client.Object, subResource client.Object, opts ...client.SubResourceGetOption,
) error {
	return m.MockGet(ctx, obj, subResource, opts...)
}
