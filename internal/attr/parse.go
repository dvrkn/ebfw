// Package attr maps node-level traffic to the Kubernetes pod that produced it.
//
// Two inputs are supported: a cgroup v2 id (from bpf_skb_cgroup_id in the egress
// monitor) and a pid (from the SSL_write uprobe). Both resolve to a cgroup path,
// which is parsed into a node-local identity (pod UID + container id + QoS) and,
// when an in-cluster Kubernetes API client is available, enriched to a
// namespace/name. Everything degrades gracefully: off-cluster or on a miss the
// resolver returns a zero-value PodInfo rather than failing.
package attr

import (
	"regexp"
	"strings"
)

// PodID is the node-local pod identity parsed from a cgroup path. It carries no
// namespace/name — those come from the Kubernetes API (see enricher).
type PodID struct {
	UID         string // canonical k8s pod UID (dashes, lowercased)
	ContainerID string // 64-hex container id (runtime prefix and .scope stripped)
	QoS         string // "guaranteed" | "burstable" | "besteffort"
}

// Recognises the kube cgroup hierarchy in either cgroup driver. The kubepods
// segment can appear anywhere in the path (k3d nests it under a Docker scope),
// so we locate it rather than anchoring at the cgroup root.
var (
	// systemd driver: kubepods-<qos>-pod<uid>.slice or (guaranteed) kubepods-pod<uid>.slice
	reSystemdPod = regexp.MustCompile(`^kubepods-(?:(besteffort|burstable)-)?pod([0-9a-fA-F_-]+)\.slice$`)
	// systemd driver QoS slice: kubepods-<qos>.slice
	reSystemdQoS = regexp.MustCompile(`^kubepods-(besteffort|burstable)\.slice$`)
	// cgroupfs driver: pod<uid> (uid keeps its dashes)
	reCgroupfsPod = regexp.MustCompile(`^pod([0-9a-fA-F-]+)$`)
	// container leaf, either driver: optional runtime prefix + 64-hex + optional .scope
	reContainer = regexp.MustCompile(`^(?:cri-containerd-|containerd-|crio-|docker-)?([0-9a-f]{64})(?:\.scope)?$`)
)

// ParsePath extracts the Kubernetes pod identity from a cgroup v2 path. It
// handles both the systemd and cgroupfs drivers, the guaranteed-QoS variant that
// omits the QoS segment, and k3d's Docker-nested paths. ok is false for non-pod
// cgroups (host daemons, the bare-host e2e curl, the agent itself) — callers
// treat that as "unknown" and skip attribution.
func ParsePath(path string) (PodID, bool) {
	segs := strings.Split(path, "/")

	// Locate the start of the kubepods subtree (may be nested).
	start := -1
	for i, s := range segs {
		if s == "kubepods" || s == "kubepods.slice" || strings.HasPrefix(s, "kubepods-") {
			start = i
			break
		}
	}
	if start < 0 {
		return PodID{}, false
	}

	var id PodID
	for _, s := range segs[start:] {
		switch {
		case s == "" || s == "kubepods" || s == "kubepods.slice":
			// subtree root: no info
		case reSystemdPod.MatchString(s):
			m := reSystemdPod.FindStringSubmatch(s)
			if m[1] != "" {
				id.QoS = m[1]
			}
			id.UID = normalizeUID(m[2])
		case reCgroupfsPod.MatchString(s):
			id.UID = normalizeUID(reCgroupfsPod.FindStringSubmatch(s)[1])
		case reSystemdQoS.MatchString(s):
			id.QoS = reSystemdQoS.FindStringSubmatch(s)[1]
		case s == "besteffort" || s == "burstable" || s == "guaranteed":
			id.QoS = s
		case reContainer.MatchString(s):
			id.ContainerID = reContainer.FindStringSubmatch(s)[1]
		}
	}

	if id.UID == "" {
		return PodID{}, false // matched kubepods root but no pod — not attributable
	}
	if id.QoS == "" {
		id.QoS = "guaranteed" // guaranteed pods have no QoS segment
	}
	return id, true
}

// normalizeUID converts a cgroup-encoded pod UID back to the canonical k8s form:
// the systemd driver replaces the UID's dashes with underscores, so undo that.
func normalizeUID(uid string) string {
	return strings.ToLower(strings.ReplaceAll(uid, "_", "-"))
}
