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
				MountID:        23,
				ParentID:       28,
				MajorMinor:     "8:1",
				Root:           "/",
				MountPoint:     "/rw-mount",
				MountOptions:   []string{"rw", "relatime"},
				OptionalFields: nil,
				FSType:         "ext4",
				MountSource:    "/dev/sda1",
				SuperOptions:   []string{"rw", "data=ordered"},
			},
			wantErr: false,
		},
		{
			name: "Valid mountinfo line with optional fields before separator",
			line: "23 28 8:1 / /rw-mount rw,relatime shared:1 - ext4 /dev/sda1 rw,data=ordered",
			want: &MountInfo{
				MountID:        23,
				ParentID:       28,
				MajorMinor:     "8:1",
				Root:           "/",
				MountPoint:     "/rw-mount",
				MountOptions:   []string{"rw", "relatime"},
				OptionalFields: []string{"shared:1"},
				FSType:         "ext4",
				MountSource:    "/dev/sda1",
				SuperOptions:   []string{"rw", "data=ordered"},
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

func TestAuditMountsInternal(t *testing.T) {
	tests := []struct {
		name       string
		mounts     []MountInfo
		lsmProfile string
		wantRisks  int
		wantScore  int
	}{
		{
			name: "Insecure external volume missing all hardening flags",
			mounts: []MountInfo{
				{
					MountPoint:   "/data",
					MountSource:  "/dev/sdb1",
					FSType:       "ext4",
					MountOptions: []string{"rw", "relatime"},
				},
			},
			lsmProfile: "none",
			wantRisks:  4, // nosuid, nodev, noexec, nosymfollow
			wantScore:  50, // 100 - (15 + 15 + 10 + 10) = 50
		},
		{
			name: "Fully hardened external volume",
			mounts: []MountInfo{
				{
					MountPoint:   "/data",
					MountSource:  "/dev/sdb1",
					FSType:       "ext4",
					MountOptions: []string{"rw", "nosuid", "nodev", "noexec", "nosymfollow"},
				},
			},
			lsmProfile: "none",
			wantRisks:  0,
			wantScore:  100,
		},
		{
			name: "Insecure NFS mount",
			mounts: []MountInfo{
				{
					MountPoint:   "/nfs-share",
					MountSource:  "192.168.1.50:/share",
					FSType:       "nfs",
					MountOptions: []string{"rw", "sec=sys", "proto=udp", "vers=3"},
				},
			},
			lsmProfile: "none",
			wantRisks:  7, // 4 general flags + 3 nfs flags (sec=sys, proto=udp, NFSv3)
			wantScore:  34, // 100 - (15+15+10+10+10+3+3) = 34
		},
		{
			name: "Hardened NFS mount",
			mounts: []MountInfo{
				{
					MountPoint:   "/nfs-share",
					MountSource:  "192.168.1.50:/share",
					FSType:       "nfs4",
					MountOptions: []string{"rw", "nosuid", "nodev", "noexec", "nosymfollow", "sec=krb5p", "proto=tcp"},
				},
			},
			lsmProfile: "none",
			wantRisks:  0,
			wantScore:  100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := auditMountsInternal(tt.mounts, tt.lsmProfile)
			if len(res.Risks) != tt.wantRisks {
				t.Errorf("got %d risks, want %d risks. Risks: %+v", len(res.Risks), tt.wantRisks, res.Risks)
			}
			if res.Score != tt.wantScore {
				t.Errorf("got score %d, want score %d", res.Score, tt.wantScore)
			}
		})
	}
}

