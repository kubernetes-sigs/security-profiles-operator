/*
Copyright 2025 The Kubernetes Authors.

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
	"flag"
	"testing"
)

func TestEnumValue(t *testing.T) {
	t.Parallel()

	// Test NewEnumValue
	enum := NewEnumValue([]string{"1.2", "1.3"}, "1.2")
	if enum == nil {
		t.Fatal("NewEnumValue should not return nil for valid input")
	}

	if enum.Default != "1.2" {
		t.Errorf("expected default '1.2', got '%s'", enum.Default)
	}

	// Test invalid constructor
	if NewEnumValue([]string{"1.2", "1.3"}, "1.1") != nil {
		t.Error("NewEnumValue should return nil when default not in enum")
	}

	if NewEnumValue([]string{}, "test") != nil {
		t.Error("NewEnumValue should return nil for empty enum")
	}

	// Test String method returns default initially
	if enum.String() != "1.2" {
		t.Errorf("expected default '1.2', got '%s'", enum.String())
	}

	// Test Set method with valid inputs
	if err := enum.Set("1.3"); err != nil {
		t.Errorf("Set failed for valid value: %v", err)
	}

	if enum.String() != "1.3" {
		t.Errorf("expected '1.3' after Set, got '%s'", enum.String())
	}

	// Test Set method with invalid inputs
	if err := enum.Set("1.1"); err == nil {
		t.Error("Set should fail for invalid value")
	}

	// Test case-insensitive matching
	enumCase := NewEnumValue([]string{"Debug", "Info"}, "Info")
	if err := enumCase.Set("debug"); err != nil {
		t.Errorf("Set should work case-insensitively: %v", err)
	}

	if enumCase.String() != "Debug" {
		t.Errorf("expected canonical case 'Debug', got '%s'", enumCase.String())
	}

	// Test flag.Value interface
	var _ flag.Value = enum

	// Test error message format
	err := enum.Set("invalid")

	expectedMsg := "allowed values are 1.2, 1.3"

	if err.Error() != expectedMsg {
		t.Errorf("expected error '%s', got '%s'", expectedMsg, err.Error())
	}
}
