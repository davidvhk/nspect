package auditor

import (
	"reflect"
	"testing"
)

func TestParseMountInfoLine(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		want    *MountInfo
		wantErr bool
	}{
		{
			name: "Valid mountinfo line",
			line: "23 28 8:1 / /rw-mount rw,relatime - ext4 /dev/sda1 rw,data=ordered",
			want: &MountInfo{
				MountID:      23,
				ParentID:     28,
				MajorMinor:   "8:1",
				Root:         "/",
				MountPoint:   "/rw-mount",
				MountOptions: []string{"rw", "relatime"},
				FSType:       "ext4",
				MountSource:  "/dev/sda1",
				SuperOptions: []string{"rw", "data=ordered"},
			},
			wantErr: false,
		},
		{
			name: "Valid mountinfo line with optional fields before separator",
			line: "23 28 8:1 / /rw-mount rw,relatime shared:1 - ext4 /dev/sda1 rw,data=ordered",
			want: &MountInfo{
				MountID:      23,
				ParentID:     28,
				MajorMinor:   "8:1",
				Root:         "/",
				MountPoint:   "/rw-mount",
				MountOptions: []string{"rw", "relatime"},
				FSType:       "ext4",
				MountSource:  "/dev/sda1",
				SuperOptions: []string{"rw", "data=ordered"},
			},
			wantErr: false,
		},
		{
			name:    "Invalid line - too few fields",
			line:    "23 28 8:1 / /rw-mount",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "Invalid line - missing separator",
			line:    "23 28 8:1 / /rw-mount rw,relatime ext4 /dev/sda1 rw,data=ordered",
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseMountInfoLine(tt.line)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseMountInfoLine() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseMountInfoLine() got = %+v, want %+v", got, tt.want)
			}
		})
	}
}
