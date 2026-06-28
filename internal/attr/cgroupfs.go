package attr

import (
	"io/fs"
	"path/filepath"
	"strings"
	"syscall"
)

// buildInoIndex walks the cgroup v2 tree at root and maps every kube cgroup
// directory's inode to its cgroup path. On kernel 5.5+ the directory inode equals
// the value bpf_skb_cgroup_id returns (kernfs id == 64-bit inode), so the egress
// monitor's cgroup id keys directly into this map. Only directories whose path
// contains a "kubepods" segment are recorded — the kube subtree may be nested
// (e.g. under a Docker scope in k3d), so we match the segment rather than anchor
// at the root.
//
// The returned path is relative to root, i.e. the kernel cgroup path (leading
// "/"), which is what ParsePath consumes.
func buildInoIndex(root string) map[uint64]string {
	idx := map[uint64]string{}
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable dir: skip it, keep walking siblings
		}
		if !d.IsDir() {
			return nil
		}
		rel := strings.TrimPrefix(p, root)
		if !hasKubepodsSegment(rel) {
			return nil
		}
		var st syscall.Stat_t
		if syscall.Stat(p, &st) == nil {
			idx[st.Ino] = rel
		}
		return nil
	})
	return idx
}

// hasKubepodsSegment reports whether any path segment is (or starts with)
// "kubepods" — the start of the Kubernetes cgroup hierarchy in either driver.
func hasKubepodsSegment(path string) bool {
	for _, s := range strings.Split(path, "/") {
		if s == "kubepods" || s == "kubepods.slice" || strings.HasPrefix(s, "kubepods-") {
			return true
		}
	}
	return false
}
