package auditor

import (
	"reflect"
	"testing"
)

func TestParseCapabilityMask(t *testing.T) {
	tests := []struct {
		name    string
		maskHex string
		want    []string
		wantErr bool
	}{
		{
			name:    "Empty mask",
			maskHex: "0000000000000000",
			want:    nil,
			wantErr: false,
		},
		{
			name:    "Single bit set (CAP_CHOWN)",
			maskHex: "0000000000000001",
			want:    []string{"CAP_CHOWN"},
			wantErr: false,
		},
		{
			name:    "Hex prefix (CAP_CHOWN)",
			maskHex: "0x0000000000000001",
			want:    []string{"CAP_CHOWN"},
			wantErr: false,
		},
		{
			name:    "Shorthand hex (CAP_CHOWN)",
			maskHex: "1",
			want:    []string{"CAP_CHOWN"},
			wantErr: false,
		},
		{
			name:    "Multiple bits set",
			maskHex: "0000000000000003", // bits 0 and 1
			want:    []string{"CAP_CHOWN", "CAP_DAC_OVERRIDE"},
			wantErr: false,
		},
		{
			name:    "Invalid hex string",
			maskHex: "invalidhex",
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCapabilityMask(tt.maskHex)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCapabilityMask() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseCapabilityMask() got = %v, want %v", got, tt.want)
			}
		})
	}
}
