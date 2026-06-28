package attr

import "testing"

func TestParsePath(t *testing.T) {
	const (
		uid     = "3f2c1a9b-4d5e-6f70-8a9b-0c1d2e3f4a5b"
		uidUnd  = "3f2c1a9b_4d5e_6f70_8a9b_0c1d2e3f4a5b"
		cid     = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
		hostCID = "0011223344556677889900aabbccddeeff00112233445566778899aabbccddee"
	)

	tests := []struct {
		name string
		path string
		want PodID
		ok   bool
	}{
		{
			name: "cgroupfs besteffort",
			path: "/kubepods/besteffort/pod" + uid + "/" + cid,
			want: PodID{UID: uid, ContainerID: cid, QoS: "besteffort"},
			ok:   true,
		},
		{
			name: "cgroupfs burstable",
			path: "/kubepods/burstable/pod" + uid + "/" + cid,
			want: PodID{UID: uid, ContainerID: cid, QoS: "burstable"},
			ok:   true,
		},
		{
			name: "cgroupfs guaranteed (no qos segment)",
			path: "/kubepods/pod" + uid + "/" + cid,
			want: PodID{UID: uid, ContainerID: cid, QoS: "guaranteed"},
			ok:   true,
		},
		{
			name: "systemd besteffort (underscored uid, cri-containerd)",
			path: "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod" + uidUnd + ".slice/cri-containerd-" + cid + ".scope",
			want: PodID{UID: uid, ContainerID: cid, QoS: "besteffort"},
			ok:   true,
		},
		{
			name: "systemd burstable",
			path: "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" + uidUnd + ".slice/cri-containerd-" + cid + ".scope",
			want: PodID{UID: uid, ContainerID: cid, QoS: "burstable"},
			ok:   true,
		},
		{
			name: "systemd guaranteed (no qos segment)",
			path: "/kubepods.slice/kubepods-pod" + uidUnd + ".slice/cri-containerd-" + cid + ".scope",
			want: PodID{UID: uid, ContainerID: cid, QoS: "guaranteed"},
			ok:   true,
		},
		{
			name: "k3d docker-nested cgroupfs",
			path: "/system.slice/docker-" + hostCID + ".scope/kubepods/besteffort/pod" + uid + "/" + cid,
			want: PodID{UID: uid, ContainerID: cid, QoS: "besteffort"},
			ok:   true,
		},
		{
			name: "crio runtime prefix",
			path: "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" + uidUnd + ".slice/crio-" + cid + ".scope",
			want: PodID{UID: uid, ContainerID: cid, QoS: "burstable"},
			ok:   true,
		},
		{
			name: "docker runtime prefix",
			path: "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod" + uidUnd + ".slice/docker-" + cid + ".scope",
			want: PodID{UID: uid, ContainerID: cid, QoS: "besteffort"},
			ok:   true,
		},
		{
			name: "pod without container leaf",
			path: "/kubepods/besteffort/pod" + uid,
			want: PodID{UID: uid, QoS: "besteffort"},
			ok:   true,
		},
		{name: "host systemd service", path: "/system.slice/sshd.service", ok: false},
		{name: "host user session", path: "/user.slice/user-1000.slice/session-3.scope", ok: false},
		{name: "root", path: "/", ok: false},
		{name: "kubepods root only", path: "/kubepods.slice", ok: false},
		{name: "kubepods qos but no pod", path: "/kubepods.slice/kubepods-besteffort.slice", ok: false},
		{name: "empty", path: "", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ParsePath(tt.path)
			if ok != tt.ok {
				t.Fatalf("ParsePath(%q) ok = %v, want %v", tt.path, ok, tt.ok)
			}
			if !ok {
				return
			}
			if got != tt.want {
				t.Errorf("ParsePath(%q)\n got = %+v\nwant = %+v", tt.path, got, tt.want)
			}
		})
	}
}
