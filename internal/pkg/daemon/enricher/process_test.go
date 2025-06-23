package enricher

import "testing"

func Test_extractSPORequestUID(t *testing.T) {
	type args struct {
		input string
	}
	tests := []struct {
		name      string
		args      args
		want      string
		foundWant bool
	}{
		{
			name:      "test basic",
			args:      args{input: "env SPO_EXEC_REQUEST_UID=dbbf5fca-c955-4922-99d2-27a50212071c ls"},
			want:      "dbbf5fca-c955-4922-99d2-27a50212071c",
			foundWant: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := extractSPORequestUID(tt.args.input)
			if got != tt.want {
				t.Errorf("extractSPORequestUID() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.foundWant {
				t.Errorf("extractSPORequestUID() got1 = %v, want %v", got1, tt.foundWant)
			}
		})
	}
}
