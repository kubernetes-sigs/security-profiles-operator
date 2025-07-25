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

// Code generated by counterfeiter. DO NOT EDIT.
package pullerfakes

import (
	"os"
	"sync"

	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/artifact"
)

type FakeImpl struct {
	PullStub        func(string, string, string, *v1.Platform, bool) (*artifact.PullResult, error)
	pullMutex       sync.RWMutex
	pullArgsForCall []struct {
		arg1 string
		arg2 string
		arg3 string
		arg4 *v1.Platform
		arg5 bool
	}
	pullReturns struct {
		result1 *artifact.PullResult
		result2 error
	}
	pullReturnsOnCall map[int]struct {
		result1 *artifact.PullResult
		result2 error
	}
	WriteFileStub        func(string, []byte, os.FileMode) error
	writeFileMutex       sync.RWMutex
	writeFileArgsForCall []struct {
		arg1 string
		arg2 []byte
		arg3 os.FileMode
	}
	writeFileReturns struct {
		result1 error
	}
	writeFileReturnsOnCall map[int]struct {
		result1 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeImpl) Pull(arg1 string, arg2 string, arg3 string, arg4 *v1.Platform, arg5 bool) (*artifact.PullResult, error) {
	fake.pullMutex.Lock()
	ret, specificReturn := fake.pullReturnsOnCall[len(fake.pullArgsForCall)]
	fake.pullArgsForCall = append(fake.pullArgsForCall, struct {
		arg1 string
		arg2 string
		arg3 string
		arg4 *v1.Platform
		arg5 bool
	}{arg1, arg2, arg3, arg4, arg5})
	stub := fake.PullStub
	fakeReturns := fake.pullReturns
	fake.recordInvocation("Pull", []interface{}{arg1, arg2, arg3, arg4, arg5})
	fake.pullMutex.Unlock()
	if stub != nil {
		return stub(arg1, arg2, arg3, arg4, arg5)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *FakeImpl) PullCallCount() int {
	fake.pullMutex.RLock()
	defer fake.pullMutex.RUnlock()
	return len(fake.pullArgsForCall)
}

func (fake *FakeImpl) PullCalls(stub func(string, string, string, *v1.Platform, bool) (*artifact.PullResult, error)) {
	fake.pullMutex.Lock()
	defer fake.pullMutex.Unlock()
	fake.PullStub = stub
}

func (fake *FakeImpl) PullArgsForCall(i int) (string, string, string, *v1.Platform, bool) {
	fake.pullMutex.RLock()
	defer fake.pullMutex.RUnlock()
	argsForCall := fake.pullArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2, argsForCall.arg3, argsForCall.arg4, argsForCall.arg5
}

func (fake *FakeImpl) PullReturns(result1 *artifact.PullResult, result2 error) {
	fake.pullMutex.Lock()
	defer fake.pullMutex.Unlock()
	fake.PullStub = nil
	fake.pullReturns = struct {
		result1 *artifact.PullResult
		result2 error
	}{result1, result2}
}

func (fake *FakeImpl) PullReturnsOnCall(i int, result1 *artifact.PullResult, result2 error) {
	fake.pullMutex.Lock()
	defer fake.pullMutex.Unlock()
	fake.PullStub = nil
	if fake.pullReturnsOnCall == nil {
		fake.pullReturnsOnCall = make(map[int]struct {
			result1 *artifact.PullResult
			result2 error
		})
	}
	fake.pullReturnsOnCall[i] = struct {
		result1 *artifact.PullResult
		result2 error
	}{result1, result2}
}

func (fake *FakeImpl) WriteFile(arg1 string, arg2 []byte, arg3 os.FileMode) error {
	var arg2Copy []byte
	if arg2 != nil {
		arg2Copy = make([]byte, len(arg2))
		copy(arg2Copy, arg2)
	}
	fake.writeFileMutex.Lock()
	ret, specificReturn := fake.writeFileReturnsOnCall[len(fake.writeFileArgsForCall)]
	fake.writeFileArgsForCall = append(fake.writeFileArgsForCall, struct {
		arg1 string
		arg2 []byte
		arg3 os.FileMode
	}{arg1, arg2Copy, arg3})
	stub := fake.WriteFileStub
	fakeReturns := fake.writeFileReturns
	fake.recordInvocation("WriteFile", []interface{}{arg1, arg2Copy, arg3})
	fake.writeFileMutex.Unlock()
	if stub != nil {
		return stub(arg1, arg2, arg3)
	}
	if specificReturn {
		return ret.result1
	}
	return fakeReturns.result1
}

func (fake *FakeImpl) WriteFileCallCount() int {
	fake.writeFileMutex.RLock()
	defer fake.writeFileMutex.RUnlock()
	return len(fake.writeFileArgsForCall)
}

func (fake *FakeImpl) WriteFileCalls(stub func(string, []byte, os.FileMode) error) {
	fake.writeFileMutex.Lock()
	defer fake.writeFileMutex.Unlock()
	fake.WriteFileStub = stub
}

func (fake *FakeImpl) WriteFileArgsForCall(i int) (string, []byte, os.FileMode) {
	fake.writeFileMutex.RLock()
	defer fake.writeFileMutex.RUnlock()
	argsForCall := fake.writeFileArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2, argsForCall.arg3
}

func (fake *FakeImpl) WriteFileReturns(result1 error) {
	fake.writeFileMutex.Lock()
	defer fake.writeFileMutex.Unlock()
	fake.WriteFileStub = nil
	fake.writeFileReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakeImpl) WriteFileReturnsOnCall(i int, result1 error) {
	fake.writeFileMutex.Lock()
	defer fake.writeFileMutex.Unlock()
	fake.WriteFileStub = nil
	if fake.writeFileReturnsOnCall == nil {
		fake.writeFileReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.writeFileReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *FakeImpl) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *FakeImpl) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}
